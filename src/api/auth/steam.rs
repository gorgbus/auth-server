use axum::routing::get;
use axum::{
    extract::{Path, Query, State},
    response::Redirect,
    Router,
};
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::Rng;
use redis::Commands;
use serde_json::Value;
use sqlx::types::Uuid;
use std::env;
use std::str::FromStr;

use crate::db::app::validate_redirect_uri;
use crate::db::user::{create_user, get_user, Account};
use crate::error::Error;
use crate::{error::Result, state::AppState};
use serde::Deserialize;

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
    State(state): State<AppState>,
) -> Result<Redirect> {
    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    validate_redirect_uri(&state.pg, uuid, &query.redirect_uri).await?;

    let base_url = env::var("BASE_URL").unwrap();

    let return_to = format!(
        "{}/auth/steam/redirect?state={};{}",
        base_url, query.redirect_uri, app_id
    );

    let auth_url = format!(
        r"https://steamcommunity.com/openid/login?openid.ns=http://specs.openid.net/auth/2.0&openid.mode=checkid_setup&openid.return_to={}&openid.realm={}&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select",
        return_to, base_url
    );

    Ok(Redirect::to(&auth_url))
}

#[derive(Deserialize)]
struct AuthRequest {
    #[serde(rename = "openid.assoc_handle")]
    openid_assoc_handle: String,
    #[serde(rename = "openid.signed")]
    openid_signed: String,
    #[serde(rename = "openid.sig")]
    openid_sig: String,
    #[serde(rename = "openid.ns")]
    openid_ns: String,
    #[serde(rename = "openid.op_endpoint")]
    openid_op_endpoint: String,
    #[serde(rename = "openid.claimed_id")]
    openid_claimed_id: String,
    #[serde(rename = "openid.identity")]
    openid_identity: String,
    #[serde(rename = "openid.return_to")]
    openid_return_to: String,
    #[serde(rename = "openid.response_nonce")]
    openid_response_nonce: String,

    state: String,
}

#[derive(Deserialize)]
struct SteamUser {
    steamid: String,
    personaname: String,
    avatarhash: String,
}

async fn auth_redirect(
    Query(query): Query<AuthRequest>,
    State(mut state): State<AppState>,
) -> Result<Redirect> {
    let openid_query = format!(
        r"openid.assoc_handle={}&openid.signed={}&openid.sig={}&openid.ns={}&openid.mode=check_authentication&openid.op_endpoint={}&openid.claimed_id={}&openid.identity={}&openid.return_to={}&openid.response_nonce={}",
        query.openid_assoc_handle,
        query.openid_signed,
        query.openid_sig.replace("+", "%2B"),
        query.openid_ns,
        query.openid_op_endpoint,
        query.openid_claimed_id,
        query.openid_identity,
        query.openid_return_to,
        query.openid_response_nonce.replace("+", "%2B")
    );

    let client = reqwest::Client::new();

    let validation = client
        .get(format!(
            "https://steamcommunity.com/openid/login?{}",
            openid_query
        ))
        .send()
        .await
        .map_err(|_| Error::AuthUserFetchFail)?
        .text()
        .await
        .map_err(|_| Error::AuthUserParseFail)?;

    if !validation.contains("is_valid:true") {
        println!("{validation}");
        return Err(Error::AuthInvalidParams);
    }

    let steam_id64 = query
        .openid_claimed_id
        .replace("https://steamcommunity.com/openid/id/", "");

    let steam_api_url = format!(
        r"https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key={}&steamids={}",
        env::var("STEAM_API_KEY").unwrap(),
        steam_id64
    );

    let res: Value = client
        .get(steam_api_url)
        .send()
        .await
        .map_err(|_| Error::AuthUserFetchFail)?
        .json()
        .await
        .map_err(|_| Error::AuthUserParseFail)?;

    let user = res
        .get("response")
        .ok_or(Error::AuthMissingState)?
        .get("players")
        .ok_or(Error::AuthMissingState)?;

    let user: SteamUser =
        serde_json::from_value(user.get(0).ok_or(Error::AuthUserParseFail)?.to_owned())
            .map_err(|_| Error::AuthUserParseFail)?;

    let user = Account {
        id: Some(user.steamid),
        avatar: Some(user.avatarhash),
        username: Some(user.personaname),
    };

    let (redirect_uri, app_id) = query.state.split_once(";").ok_or(Error::RedisGetFail)?;

    let code: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let code_key = format!("{app_id}:code:{code}");
    let ttl = 30;

    let uuid = Uuid::from_str(&app_id).map_err(|_| Error::UuidFail)?;

    if let None = get_user(&state.pg, uuid, &user.id.as_ref().map_or("", |id| &id)).await? {
        create_user(&state.pg, uuid, None, Some(&user)).await?;
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
