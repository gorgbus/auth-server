use serde::{Deserialize, Serialize};
use sqlx::{types::Uuid, FromRow, PgPool, Type};

use crate::error::{Error, Result};

#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(skip)]
    pub app_id: Uuid,
    pub user_id: i32,
    pub discord: Account,
    pub steam: Account,
    pub admin: bool,
}

#[derive(Debug, FromRow, Type, Serialize, Deserialize, Clone)]
pub struct Account {
    pub id: Option<String>,
    pub avatar: Option<String>,
    pub username: Option<String>,
}

pub async fn get_user(pool: &PgPool, app_id: Uuid, id: &str) -> Result<Option<User>> {
    let sql = r"
        select * from users
        where app_id = $1 and ((discord).id like $2 or (steam).id like $3)
    ";

    let query = sqlx::query_as::<_, User>(sql)
        .bind(app_id)
        .bind(&id)
        .bind(&id)
        .bind(&id);

    let user = query.fetch_optional(pool).await.map_err(|e| {
        println!("{e:?}");

        return Error::PgFetchFail;
    })?;

    Ok(user)
}

pub async fn create_user(
    pool: &PgPool,
    app_id: Uuid,
    discord: Option<&Account>,
    steam: Option<&Account>,
) -> Result<()> {
    let sql = r"
        insert into users
        (app_id, steam, discord)
        values ($1, row($2, $3, $4), row($5, $6, $7))
    ";

    sqlx::query(sql)
        .bind(app_id)
        .bind(steam.map(|s| &s.id))
        .bind(steam.map(|s| &s.avatar))
        .bind(steam.map(|s| &s.username))
        .bind(discord.map(|d| &d.id))
        .bind(discord.map(|d| &d.avatar))
        .bind(discord.map(|d| &d.username))
        .execute(pool)
        .await
        .map_err(|_| Error::PgInsertFail)?;

    Ok(())
}

pub async fn update_user_steam(pool: &PgPool, app_id: Uuid, steam: &Account) -> Result<()> {
    let sql = r"
        update users
        set steam = row($1, $2, $3)
        where app_id = $4 and (steam).id like $5
    ";

    sqlx::query(sql)
        .bind(&steam.id)
        .bind(&steam.avatar)
        .bind(&steam.username)
        .bind(app_id)
        .bind(&steam.id)
        .execute(pool)
        .await
        .map_err(|_| Error::PgUpdateFail)?;

    Ok(())
}
