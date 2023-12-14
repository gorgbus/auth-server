use std::{env, net::SocketAddr};

use crate::error::Error;

use self::state::AppState;
use axum::{
    http::Uri,
    middleware,
    response::{IntoResponse, Response},
    Json, Router,
};
use db::app::create_app;
use dotenv::dotenv;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::json;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;

mod api;
mod dashboard;
mod db;
mod error;
mod jwt;
mod state;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let args: Vec<String> = env::args().collect();

    let state = AppState::new().await;

    if args.len() == 2 && args[1] == "init" {
        let app_id = create_app(&state.pg, "MAIN".to_string()).await.unwrap();

        println!("APP_ID: {app_id}");
    } else {
        let router = Router::new()
            .nest("/api", api::routes())
            .nest("/dashboard", dashboard::routes(state.clone()))
            .layer(middleware::map_response(main_response_mapper))
            .layer(CookieManagerLayer::new())
            .layer(
                CorsLayer::new()
                    .allow_origin(
                        env::var("ALLOWED_ORIGINS")
                            .unwrap()
                            .split(",")
                            .map(|o| o.parse().unwrap())
                            .collect::<Vec<_>>(),
                    )
                    .allow_headers([AUTHORIZATION, CONTENT_TYPE])
                    .allow_credentials(true),
            )
            .with_state(state);

        let port = env::var("PORT").unwrap().parse::<u16>().unwrap();
        let addr = format!("[::]:{port}").parse::<SocketAddr>().unwrap();

        println!("listening on {addr}");

        axum::Server::bind(&addr)
            .serve(router.into_make_service())
            .await
            .unwrap();
    }
}

async fn main_response_mapper(uri: Uri, res: Response) -> Response {
    let service_error = res.extensions().get::<Error>();
    let client_status_error = service_error.map(|se| se.client_status_and_error());

    if service_error.is_some() {
        println!("URI - {uri}");
        println!("ERROR - {:?}", service_error.unwrap());
        println!();
    }

    let error_response = client_status_error
        .as_ref()
        .map(|(status_code, client_error)| {
            let client_error_body = json!({
                "error": {
                    "type": client_error
                }
            });

            (*status_code, Json(client_error_body)).into_response()
        });

    error_response.unwrap_or(res)
}
