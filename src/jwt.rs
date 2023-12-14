use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::{
    db::user::User,
    error::{Error, Result},
};

pub fn gen_access_token(user: &User, app_id: &String, private_key: &[u8]) -> Result<String> {
    let claims = Claims::new(&user, app_id, 300)?;

    let encoding_key =
        EncodingKey::from_rsa_pem(private_key).map_err(|_| Error::JwtEncodeGenFail)?;

    encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)
        .map_err(|_| Error::JwtAccessGenFail)
}

pub fn gen_refresh_token(user: &User, app_id: &String, private_key: &[u8]) -> Result<String> {
    let claims = Claims::new(&user, app_id, 60 * 60 * 24 * 3)?;

    let encoding_key =
        EncodingKey::from_rsa_pem(private_key).map_err(|_| Error::JwtEncodeGenFail)?;

    encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)
        .map_err(|_| Error::JwtRefreshGenFail)
}

pub fn verify_token(token: &str, public_key: &[u8]) -> Result<User> {
    let decoding_key =
        DecodingKey::from_rsa_pem(public_key).map_err(|_| Error::JwtDecodeGenFail)?;

    let token_data = decode::<Claims>(token, &decoding_key, &Validation::new(Algorithm::RS256))
        .map_err(|_| Error::JwtInvalidToken)?;

    Ok(token_data.claims.user)
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
