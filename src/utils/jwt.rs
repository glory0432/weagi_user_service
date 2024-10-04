use crate::ServiceState;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub static DECODE_HEADER: Lazy<Validation> = Lazy::new(|| Validation::default());
pub static ENCODE_HEADER: Lazy<Header> = Lazy::new(|| Header::default());

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct UserClaims {
    pub iat: i64,
    pub exp: i64,
    pub uid: i64,
    pub sid: i64,
}

impl UserClaims {
    pub fn new(duration: Duration, user_id: i64, session_id: i64) -> Self {
        // Use the standard library to fetch the current timestamp for simplicity.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        Self {
            iat: now,
            exp: now + duration.as_secs() as i64,
            uid: user_id,
            sid: session_id,
        }
    }

    pub fn decode(
        token: &str,
        key: &str,
    ) -> Result<TokenData<Self>, jsonwebtoken::errors::Error> {
        jsonwebtoken::decode::<UserClaims>(token, &DecodingKey::from_secret(key.as_ref()), &DECODE_HEADER)
    }

    pub fn encode(&self, key: &str) -> Result<String, jsonwebtoken::errors::Error> {
        jsonwebtoken::encode(&ENCODE_HEADER, self, &EncodingKey::from_secret(key.as_ref()))
    }
}

pub fn generate_token_pair(
    state: Arc<ServiceState>,
    user_id: i64,
    session_id: i64,
) -> Result<(String, String), jsonwebtoken::errors::Error> {
    // Generate a new access token
    let access_token = UserClaims::new(
        Duration::from_secs(state.config.jwt.access_token_expired_date),
        user_id,
        session_id,
    )
    .encode(&state.config.jwt.access_token_secret)?;

    // Generate a new refresh token
    let refresh_token = UserClaims::new(
        Duration::from_secs(state.config.jwt.refresh_token_expired_date),
        user_id,
        session_id,
    )
    .encode(&state.config.jwt.refresh_token_secret)?;

    Ok((access_token, refresh_token))
}

#[async_trait::async_trait]
impl FromRequestParts<ServiceState> for UserClaims {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServiceState,
    ) -> Result<Self, Self::Rejection> {
        // Improved error handling by mapping the original error to a clear message
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    "Invalid authorization header".to_string(),
                )
            })?;

        // Improved error handling in token decoding
        let user_claims =
            UserClaims::decode(bearer.token(), &state.config.jwt.access_token_secret)
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".to_string()))?
                .claims;

        // Uncomment and handle session checks accordingly
        // service::session::check(&state.redis, &user_claims).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(user_claims)
    }
}

pub trait UserClaimsRequest {
    fn get_user_id(&self) -> Result<i64, String>;
    fn get_user_claims(&self) -> Result<UserClaims, String>;
}

// Provide a more helpful error message
impl UserClaimsRequest for axum::extract::Request {
    fn get_user_id(&self) -> Result<i64, String> {
        self.extensions()
            .get::<UserClaims>()
            .map(|u| u.uid)
            .ok_or_else(|| "User must be logged in to access this resource".to_string())
    }

    fn get_user_claims(&self) -> Result<UserClaims, String> {
        self.extensions()
            .get::<UserClaims>()
            .cloned()
            .ok_or_else(|| "User must be logged in to access this information".to_string())
    }
}
