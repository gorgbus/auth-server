use std::env;

use axum::extract::FromRef;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

#[derive(FromRef, Clone)]
pub struct AppState {
    pub oauth: BasicClient,
    pub redis: redis::Client,
    pub pg: sqlx::postgres::PgPool,
}

impl AppState {
    pub async fn new() -> Self {
        Self {
            oauth: oauth_client(),
            redis: redis_client(),
            pg: sqlx_pool().await,
        }
    }
}

fn oauth_client() -> BasicClient {
    let client_id = env::var("DISCORD_CLIENT_ID").unwrap();
    let client_secret = env::var("DISCORD_CLIENT_SECRET").unwrap();
    let redirect_url = format!("{}/auth/discord/redirect", env::var("BASE_URL").unwrap());

    let auth_url = "https://discord.com/api/oauth2/authorize?response_type=code".to_string();

    let token_url = "https://discord.com/api/oauth2/token".to_string();

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

fn redis_client() -> redis::Client {
    let password = env::var("REDIS_PASSWORD").unwrap();
    let addr = env::var("REDIS_ADDR").unwrap();

    let conn_str = format!("redis://default:{password}@{addr}");

    redis::Client::open(conn_str).unwrap()
}

async fn sqlx_pool() -> sqlx::postgres::PgPool {
    let url = env::var("POSTGRES_URL").unwrap();

    let pool = sqlx::postgres::PgPool::connect(&url).await.unwrap();

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    pool
}
