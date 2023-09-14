use sqlx::{types::Uuid, FromRow, PgPool};

use crate::error::{Error, Result};

#[derive(Debug, FromRow)]
pub struct RedirectUri {
    pub app_id: Uuid,
    pub uri: String,
}

pub async fn validate_redirect_uri(pool: &PgPool, app_id: Uuid, uri: &str) -> Result<String> {
    let sql = "select * from redirect_uri where app_id = $1 and uri like $2";

    let res = sqlx::query_as::<_, RedirectUri>(sql).bind(app_id).bind(uri);

    let redirect_uri = res.fetch_one(pool).await.map_err(|_| Error::PgNone)?;

    Ok(redirect_uri.uri)
}
