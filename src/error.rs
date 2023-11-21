use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    AuthTokenExchangeFail,
    AuthUserFetchFail,
    AuthUserParseFail,
    AuthMissingState,
    AuthMissingCookie,
    AuthInvalidParams,

    RedisSetFail,
    RedisExpireFail,
    RedisGetFail,
    RedisDelFail,
    RedisGetEmpty,

    PgNone,
    PgFetchFail,
    PgInsertFail,
    PgUpdateFail,

    UuidFail,

    JwtAccessGenFail,
    JwtRefreshGenFail,
    JwtClaimsGenFail,
    JwtInvalidToken,
}

#[derive(Serialize)]
#[allow(non_camel_case_types)]
pub enum ClientError {
    NO_AUTH,
    SERVICE_ERROR,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();

        response.extensions_mut().insert(self);

        response
    }
}

impl Error {
    pub fn client_status_and_error(&self) -> (StatusCode, ClientError) {
        match self {
            Self::RedisGetEmpty
            | Self::JwtAccessGenFail
            | Self::JwtRefreshGenFail
            | Self::JwtInvalidToken
            | Self::AuthMissingState
            | Self::AuthInvalidParams => (StatusCode::FORBIDDEN, ClientError::NO_AUTH),

            Self::AuthMissingCookie => (StatusCode::UNAUTHORIZED, ClientError::NO_AUTH),

            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ClientError::SERVICE_ERROR,
            ),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}
