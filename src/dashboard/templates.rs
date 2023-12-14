use askama::Template;

use crate::db::app::{AppDB, AppNames, RedirectUri};

#[derive(Template)]
#[template(path = "index.html")]
pub struct Home {
    pub apps: Vec<AppNames>,
}

#[derive(Template)]
#[template(path = "new_app.html")]
pub struct CreateNewApp {}

#[derive(Debug, Template)]
#[template(path = "app.html")]
pub struct App {
    pub app: AppDB,
    pub redirect_uris: Vec<RedirectUri>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct Login {
    pub app_id: String,
}

pub struct AppId {
    pub id: String,
}

#[derive(Template)]
#[template(path = "uri.html")]
pub struct Uri {
    pub app: AppId,
    pub redirect: RedirectUri,
}
