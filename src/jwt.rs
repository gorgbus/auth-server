use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::{
    db::user::User,
    error::{Error, Result},
};

const KEYS: Lazy<Keys> = Lazy::new(|| Keys {
    access: Key::new(env::var("JWT_ACCESS_KEY").unwrap().as_bytes()),
    refresh: Key::new(env::var("JWT_REFRESH_KEY").unwrap().as_bytes()),
});

pub fn gen_access_token(user: &User, app_id: &String) -> Result<String> {
    let claims = Claims::new(&user, app_id, 300)?;

    encode(&Header::default(), &claims, &KEYS.access.encoding).map_err(|_| Error::JwtAccessGenFail)
}

pub fn gen_refresh_token(user: &User, app_id: &String) -> Result<String> {
    let claims = Claims::new(&user, app_id, 60 * 60 * 24 * 3)?;

    encode(&Header::default(), &claims, &KEYS.refresh.encoding)
        .map_err(|_| Error::JwtRefreshGenFail)
}

pub fn verify_refresh_token(token: &str) -> Result<User> {
    let token_data = decode::<Claims>(
        token,
        &KEYS.refresh.decoding,
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| Error::JwtInvalidToken)?;

    Ok(token_data.claims.user)
}

struct Keys {
    access: Key,
    refresh: Key,
}

struct Key {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Key {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    user: User,
    app_id: String,
    exp: usize,
}

impl Claims {
    fn new(user: &User, app_id: &String, exp: usize) -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::JwtClaimsGenFail)?
            .as_secs() as usize;

        Ok(Self {
            user: user.clone(),
            app_id: app_id.to_string(),
            exp: now + exp,
        })
    }
}
