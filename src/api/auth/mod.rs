pub mod discord;
pub mod steam;

use std::env;
use std::str::FromStr;

use crate::db::app::{get_private_key, get_public_key};
use crate::db::user::get_user;
use crate::error::{Error, Result};
use crate::jwt::{gen_access_token, gen_refresh_token, verify_token};
use crate::state::AppState;
use axum::extract::State;
use axum::{extract::Path, routing::post};
use axum::{Json, Router};
use redis::Commands;
use serde::{Deserialize, Serialize};
use sqlx::types::Uuid;
use tower_cookies::cookie::time::Duration;
use tower_cookies::cookie::SameSite;
use tower_cookies::{Cookie, Cookies};

pub fn routes() -> Router<AppState> {
    Router::new()
        .nest("/discord", discord::routes())
        .nest("/steam", steam::routes())
        .route("/:app_id/token", post(gen_tokens))
        .route("/:app_id/token/refresh", post(refresh_tokens))
        .route("/:app_id/logout", post(logout))
}

#[derive(Debug, Serialize)]
struct Token {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    code: String,
}

async fn gen_tokens(
    cookies: Cookies,
    Path(app_id): Path<String>,
    State(mut state): State<AppState>,
    Json(query): Json<TokenRequest>,
) -> Result<()> {
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

    Ok(())
}

async fn refresh_tokens(
    cookies: Cookies,
    Path(app_id): Path<String>,
    State(mut state): State<AppState>,
) -> Result<()> {
    let refresh_cookie = &cookies.get("refresh").ok_or(Error::AuthMissingCookie)?;

    let refresh_token = refresh_cookie.value();

    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;
    let public_key = get_public_key(&state.pg, uuid).await?;

    let user = verify_token(refresh_token, public_key.as_bytes())?;
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

    Ok(())
}

#[derive(Serialize)]
struct Status {
    status: String,
}

async fn logout(
    cookies: Cookies,
    Path(app_id): Path<String>,
    State(mut state): State<AppState>,
) -> Result<Json<Status>> {
    let refresh_cookie = &cookies.get("refresh").ok_or(Error::AuthMissingCookie)?;

    let refresh_token = refresh_cookie.value();

    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;
    let public_key = get_public_key(&state.pg, uuid).await?;

    let user = verify_token(refresh_token, public_key.as_bytes())?;
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

    Ok(Json(Status {
        status: "success".to_string(),
    }))
}
