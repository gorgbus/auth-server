use std::env;

use openssl::rsa::Rsa;
use sqlx::{types::Uuid, FromRow, PgPool, Row};

use crate::error::{Error, Result};

pub async fn validate_redirect_uri(pool: &PgPool, app_id: Uuid, uri: &str) -> Result<String> {
    let sql = "select uri from redirect_uri where app_id = $1 and uri like $2";

    Ok(sqlx::query(sql)
        .bind(app_id)
        .bind(uri)
        .fetch_one(pool)
        .await
        .map_err(|_| Error::PgNone)?
        .get("uri"))
}

pub async fn create_app(pool: &PgPool, name: String) -> Result<Uuid> {
    let rsa = Rsa::generate(2048).map_err(|_| Error::RsaGenFail)?;

    let private = rsa
        .private_key_to_pem()
        .map_err(|_| Error::RsaPrivatePEMFail)?;
    let public = rsa
        .public_key_to_pem()
        .map_err(|_| Error::RsaPublicPEMFail)?;

    let sql = r"
        insert into app
        (name, private_key, public_key)
        values ($1, PGP_SYM_ENCRYPT($2, $3), $4)
        returning id
    ";

    Ok(sqlx::query(sql)
        .bind(name)
        .bind(String::from_utf8(private).map_err(|_| Error::PgInsertFail)?)
        .bind(env::var("PRIVATE_KEY_ENC_KEY").unwrap())
        .bind(String::from_utf8(public).map_err(|_| Error::PgInsertFail)?)
        .fetch_one(pool)
        .await
        .map_err(|_| Error::PgInsertFail)?
        .get("id"))
}

pub async fn get_private_key(pool: &PgPool, app_id: Uuid) -> Result<String> {
    let sql = r"
        select PGP_SYM_DECRYPT(private_key::bytea, $1) as private_key
        from app
        where id = $2
    ";

    Ok(sqlx::query(sql)
        .bind(env::var("PRIVATE_KEY_ENC_KEY").unwrap())
        .bind(app_id)
        .fetch_one(pool)
        .await
        .map_err(|_| Error::PgFetchFail)?
        .get("private_key"))
}

pub async fn get_public_key(pool: &PgPool, app_id: Uuid) -> Result<String> {
    let sql = r"
        select public_key
        from app
        where id = $1
    ";

    Ok(sqlx::query(sql)
        .bind(app_id)
        .fetch_one(pool)
        .await
        .map_err(|_| Error::PgFetchFail)?
        .get("public_key"))
}

#[derive(Debug, FromRow)]
pub struct AppNames {
    pub name: String,
    pub id: Uuid,
}

pub async fn get_apps(pool: &PgPool) -> Result<Vec<AppNames>> {
    let sql = r"
        select name, id
        from app
    ";

    sqlx::query_as(sql)
        .fetch_all(pool)
        .await
        .map_err(|_| Error::PgFetchFail)
}

#[derive(FromRow, Debug)]
pub struct AppDB {
    pub id: Uuid,
    pub name: String,
    pub public_key: String,
}

pub async fn get_app(pool: &PgPool, app_id: Uuid) -> Result<AppDB> {
    let sql = r"
        select id, name, public_key
        from app
        where id = $1
    ";

    sqlx::query_as(sql)
        .bind(app_id)
        .fetch_one(pool)
        .await
        .map_err(|_| Error::PgFetchFail)
}

#[derive(Debug, FromRow)]
pub struct RedirectUri {
    pub uri: String,
}

pub async fn get_redirect_uris(pool: &PgPool, app_id: Uuid) -> Result<Vec<RedirectUri>> {
    let sql = r"
        select uri
        from redirect_uri
        where app_id = $1
    ";

    sqlx::query_as(sql)
        .bind(app_id)
        .fetch_all(pool)
        .await
        .map_err(|_| Error::PgFetchFail)
}

pub async fn add_redirect_uri(pool: &PgPool, app_id: Uuid, uri: String) -> Result<RedirectUri> {
    let sql = r"
        insert into redirect_uri
        (app_id, uri)
        values ($1, $2)
        returning uri
    ";

    sqlx::query_as(sql)
        .bind(app_id)
        .bind(uri)
        .fetch_one(pool)
        .await
        .map_err(|_| Error::PgInsertFail)
}

pub async fn delete_redirect_uri(pool: &PgPool, app_id: Uuid, uri: String) -> Result<()> {
    let sql = r"
        delete from redirect_uri
        where app_id = $1 and uri like $2
    ";

    sqlx::query(sql)
        .bind(app_id)
        .bind(uri)
        .execute(pool)
        .await
        .map_err(|_| Error::PgDeleteFail)?;

    Ok(())
}

pub async fn update_redirect_uri(
    pool: &PgPool,
    app_id: Uuid,
    old_uri: String,
    new_uri: String,
) -> Result<RedirectUri> {
    let sql = r"
        update redirect_uri
        set uri = $1
        where app_id = $2 and uri like $3
        returning uri
    ";

    sqlx::query_as(sql)
        .bind(new_uri)
        .bind(app_id)
        .bind(old_uri)
        .fetch_one(pool)
        .await
        .map_err(|_| Error::PgUpdateFail)
}

pub async fn remove_app(pool: &PgPool, app_id: Uuid) -> Result<()> {
    let sql = r"
        delete from app
        where id = $1
    ";

    sqlx::query(sql)
        .bind(app_id)
        .execute(pool)
        .await
        .map_err(|_| Error::PgDeleteFail)?;

    Ok(())
}
