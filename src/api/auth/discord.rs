use std::str::FromStr;

use crate::db::app::validate_redirect_uri;
use crate::db::user::{create_user, get_user, Account};
use crate::error::{Error, Result};
use crate::state::AppState;
use axum::extract::{Path, Query};
use axum::routing::get;
use axum::Router;
use axum::{extract::State, response::Redirect};
use oauth2::reqwest::async_http_client;
use oauth2::TokenResponse;
use oauth2::{AuthorizationCode, CsrfToken, Scope};
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::Rng;
use redis::Commands;
use serde::Deserialize;
use sqlx::types::Uuid;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/:app_id/", get(auth_login))
        .route("/redirect", get(auth_redirect))
}

#[derive(Deserialize)]
struct LoginQuery {
    redirect_uri: String,
}

async fn auth_login(
    Path(app_id): Path<String>,
    Query(query): Query<LoginQuery>,
    State(mut state): State<AppState>,
) -> Result<Redirect> {
    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    validate_redirect_uri(&state.pg, uuid, &query.redirect_uri).await?;

    let (auth_url, _) = state
        .oauth
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .url();

    let (_, app_state) = auth_url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .ok_or(Error::AuthMissingState)?;

    state
        .redis
        .set(
            app_state.as_ref(),
            format!("{};{}", app_id, query.redirect_uri),
        )
        .map_err(|_| Error::RedisSetFail)?;

    state
        .redis
        .expire(app_state.as_ref(), 30)
        .map_err(|_| Error::RedisExpireFail)?;

    Ok(Redirect::to(auth_url.as_ref()))
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

async fn auth_redirect(
    Query(query): Query<AuthRequest>,
    State(mut state): State<AppState>,
) -> Result<Redirect> {
    let token = state
        .oauth
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
        .map_err(|_| Error::AuthTokenExchangeFail)?;

    let client = reqwest::Client::new();
    let user: Account = client
        .get("https://discordapp.com/api/users/@me")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|_| Error::AuthUserFetchFail)?
        .json()
        .await
        .map_err(|_| Error::AuthUserParseFail)?;

    let oauth_state: Option<String> = state
        .redis
        .get(query.state)
        .map_err(|_| Error::RedisGetFail)?;
    let oauth_state = oauth_state.ok_or(Error::RedisGetEmpty)?;

    let (app_id, redirect_uri) = oauth_state.split_once(";").ok_or(Error::RedisGetFail)?;

    let code: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let code_key = format!("{app_id}:code:{code}");
    let ttl = 30;

    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    if let None = get_user(&state.pg, uuid, &user.id.as_ref().map_or("", |id| &id)).await? {
        create_user(&state.pg, uuid, Some(&user), None).await?;
    }

    state
        .redis
        .set(&code_key, &user.id)
        .map_err(|_| Error::RedisSetFail)?;

    state
        .redis
        .expire(&code_key, ttl)
        .map_err(|_| Error::RedisExpireFail)?;

    Ok(Redirect::to(format!("{redirect_uri}?code={code}").as_ref()))
}
