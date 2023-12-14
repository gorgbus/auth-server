use axum::Router;

use crate::state::AppState;

pub mod auth;

pub fn routes() -> Router<AppState> {
    Router::new().nest("/auth", auth::routes())
}
