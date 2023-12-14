use std::{env, str::FromStr};

use axum::{
    extract::{Path, Query, State},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, patch, post, put},
    Form, Router,
};
use http::{HeaderMap, Request};
use redis::Commands;
use serde::Deserialize;
use sqlx::types::Uuid;
use tower_cookies::{
    cookie::{time::Duration, SameSite},
    Cookie, Cookies,
};

use crate::{
    db::{
        app::{
            add_redirect_uri, create_app, delete_redirect_uri, get_app, get_apps, get_private_key,
            get_public_key, get_redirect_uris, remove_app, update_redirect_uri,
        },
        user::get_user,
    },
    error::{Error, Result},
    jwt::{gen_access_token, gen_refresh_token, verify_token},
    state::AppState,
};

use self::templates::{App, AppId, CreateNewApp, Home, Login, Uri};

pub mod templates;

pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(home_page))
        .route("/app/:app_id", get(app_page))
        .route("/app/:app_id", delete(delete_app))
        .route("/app/:app_id/uri", put(add_uri))
        .route("/app/:app_id/uri", patch(patch_uri))
        .route("/app/:app_id/uri", delete(delete_uri))
        .route("/app/new", get(new_app_page))
        .route("/app/new", post(create_new_app))
        .route_layer(middleware::from_fn_with_state(state, guard))
        .route("/login", get(login_page))
        .route("/login_redir", get(login_redir))
}

pub async fn guard<T>(
    State(mut state): State<AppState>,
    cookies: Cookies,
    req: Request<T>,
    next: Next<T>,
) -> Result<Response> {
    let access_token = &cookies.get("access");
    let refresh_token = &cookies.get("refresh");

    let steam_id = env::var("STEAM_ID").unwrap();

    let app_id = env::var("MAIN_APP_ID").unwrap();
    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    let public = get_public_key(&state.pg, uuid).await?;

    if access_token.is_none() && refresh_token.is_some() {
        let refresh_token = refresh_token
            .as_ref()
            .ok_or(Error::AuthMissingCookie)?
            .value();

        let public_key = get_public_key(&state.pg, uuid).await?;

        let user = verify_token(refresh_token, public_key.as_bytes())?;

        if user.steam.id != Some(steam_id) {
            return Err(Error::AuthMissingCookie);
        }

        let user_id = user.user_id;
        let token_key = format!("{app_id}:{user_id}");

        let token_valid: Option<String> = state
            .redis
            .zscore(&token_key, refresh_token)
            .map_err(|_| Error::RedisGetFail)?;

        token_valid.ok_or(Error::RedisGetEmpty)?;

        state
            .redis
            .zrem(&token_key, refresh_token)
            .map_err(|_| Error::RedisDelFail)?;

        let private_key = get_private_key(&state.pg, uuid).await?;

        let refresh_token = gen_refresh_token(&user, &app_id, private_key.as_bytes())?;
        let access_token = gen_access_token(&user, &app_id, private_key.as_bytes())?;

        state
            .redis
            .zadd(&token_key, &refresh_token, 1)
            .map_err(|_| Error::RedisSetFail)?;

        state
            .redis
            .expire(&refresh_token, 60 * 60 * 24 * 3)
            .map_err(|_| Error::RedisExpireFail)?;

        let mut refresh_cookie = Cookie::build("refresh", refresh_token)
            .path("/")
            .same_site(SameSite::Lax)
            .max_age(Duration::seconds(60 * 60 * 24 * 3))
            .http_only(true);

        let mut access_cookie = Cookie::build("access", access_token)
            .path("/")
            .same_site(SameSite::Lax)
            .max_age(Duration::seconds(60 * 5))
            .http_only(false);

        if env::var("DEV").is_err() {
            let domain = env::var("BASE_DOMAIN").unwrap();

            refresh_cookie = refresh_cookie.domain(domain.clone()).secure(true);

            access_cookie = access_cookie.domain(domain).secure(true);
        }

        let refresh_cookie = refresh_cookie.finish();
        let access_cookie = access_cookie.finish();

        cookies.add(refresh_cookie);
        cookies.add(access_cookie);
    } else if access_token.is_some() {
        let token = access_token.as_ref().ok_or(Error::AuthMissingCookie)?;
        let user = verify_token(token.value(), public.as_bytes())?;

        if user.steam.id != Some(steam_id) {
            return Err(Error::AuthMissingCookie);
        }
    } else {
        return Err(Error::AuthMissingCookie);
    }

    Ok(next.run(req).await)
}

async fn home_page(State(state): State<AppState>) -> Result<Home> {
    Ok(Home {
        apps: get_apps(&state.pg).await?,
    })
}

async fn new_app_page() -> CreateNewApp {
    CreateNewApp {}
}

#[derive(Deserialize)]
struct NewAppReq {
    name: String,
}

async fn create_new_app(
    State(state): State<AppState>,
    Form(body): Form<NewAppReq>,
) -> Result<impl IntoResponse> {
    let app_id = create_app(&state.pg, body.name).await?;

    let mut headers = HeaderMap::new();

    headers.insert(
        "HX-Location",
        format!("/dashboard/app/{app_id}").parse().unwrap(),
    );

    Ok((
        headers,
        Redirect::to(&format!("/dashboard/app/{app_id}")).into_response(),
    ))
}

async fn app_page(State(state): State<AppState>, Path(app_id): Path<String>) -> Result<App> {
    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    Ok(App {
        app: get_app(&state.pg, uuid).await?,
        redirect_uris: get_redirect_uris(&state.pg, uuid).await?,
    })
}

async fn login_page() -> Login {
    let app_id = env::var("MAIN_APP_ID").unwrap();

    Login { app_id }
}

#[derive(Deserialize)]
struct AddUriReq {
    uri: String,
}

async fn add_uri(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    Form(body): Form<AddUriReq>,
) -> Result<Uri> {
    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    let uri = add_redirect_uri(&state.pg, uuid, body.uri).await?;

    Ok(Uri {
        app: AppId { id: app_id },
        redirect: uri,
    })
}

#[derive(Deserialize)]
struct PatchUriReq {
    old_uri: String,
    new_uri: String,
}

async fn patch_uri(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    Form(body): Form<PatchUriReq>,
) -> Result<Uri> {
    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    let uri = update_redirect_uri(&state.pg, uuid, body.old_uri, body.new_uri).await?;

    Ok(Uri {
        app: AppId { id: app_id },
        redirect: uri,
    })
}

async fn delete_uri(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
    Form(body): Form<AddUriReq>,
) -> Result<()> {
    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    delete_redirect_uri(&state.pg, uuid, body.uri).await?;

    Ok(())
}

async fn delete_app(
    State(state): State<AppState>,
    Path(app_id): Path<String>,
) -> Result<impl IntoResponse> {
    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    remove_app(&state.pg, uuid).await?;

    let mut headers = HeaderMap::new();

    headers.insert("HX-Redirect", "/dashboard".parse().unwrap());

    Ok(headers.into_response())
}

#[derive(Deserialize)]
struct LoginRedir {
    code: String,
}

async fn login_redir(
    cookies: Cookies,
    State(mut state): State<AppState>,
    Query(query): Query<LoginRedir>,
) -> Result<Redirect> {
    let app_id = env::var("MAIN_APP_ID").unwrap();

    let key = format!("{}:code:{}", app_id, query.code);

    let user_id: Option<String> = state.redis.get(&key).map_err(|_| Error::RedisGetFail)?;
    let user_id = user_id.ok_or(Error::RedisGetEmpty)?;

    state.redis.del(&key).map_err(|_| Error::RedisDelFail)?;

    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    let user = get_user(&state.pg, uuid, &user_id)
        .await?
        .ok_or(Error::PgNone)?;

    let private_key = get_private_key(&state.pg, uuid).await?;

    let access_token = gen_access_token(&user, &app_id, private_key.as_bytes())?;
    let refresh_token = gen_refresh_token(&user, &app_id, private_key.as_bytes())?;

    let user_id = user.user_id;

    let token_key = format!("{app_id}:{user_id}");

    state
        .redis
        .zadd(&token_key, &refresh_token, 1)
        .map_err(|_| Error::RedisSetFail)?;

    state
        .redis
        .expire(&refresh_token, 60 * 60 * 24 * 3)
        .map_err(|_| Error::RedisExpireFail)?;

    let mut refresh_cookie = Cookie::build("refresh", refresh_token)
        .path("/")
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(60 * 60 * 24 * 3))
        .http_only(true);

    let mut access_cookie = Cookie::build("access", access_token)
        .path("/")
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(60 * 5))
        .http_only(true);

    if env::var("DEV").is_err() {
        let domain = env::var("BASE_DOMAIN").unwrap();

        refresh_cookie = refresh_cookie.domain(domain.clone()).secure(true);

        access_cookie = access_cookie.domain(domain).secure(true);
    }

    let refresh_cookie = refresh_cookie.finish();
    let access_cookie = access_cookie.finish();

    cookies.add(refresh_cookie);
    cookies.add(access_cookie);

    Ok(Redirect::to("/dashboard"))
}
