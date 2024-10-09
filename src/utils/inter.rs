use axum::{
    async_trait,
    body::{self, Bytes},
    extract::{FromRequest, Request},
    http::StatusCode,
    response::IntoResponse,
};
use hex::decode;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;

use crate::ServiceState;
type HmacSha256 = Hmac<Sha256>;
static SECRET_KEY: &[u8] = b"your-secret-key";

pub struct VerifiedRequest;

#[async_trait]
impl FromRequest<Arc<ServiceState>> for VerifiedRequest {
    type Rejection = (StatusCode, String);

    async fn from_request(
        req: Request,
        _state: &Arc<ServiceState>,
    ) -> Result<Self, Self::Rejection> {
        let headers = req.headers();
        let signature = headers
            .get("X-Signature")
            .map(|value| value.as_ref().to_owned())
            .ok_or((StatusCode::UNAUTHORIZED, "Signature missing".to_string()))?;

        let whole_body = body::to_bytes(req.into_body(), usize::MAX)
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to read body".to_string()))?;

        let mut mac = HmacSha256::new_from_slice(SECRET_KEY).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid secret key".to_string(),
            )
        })?;
        mac.update(&whole_body);

        mac.verify_slice(&signature)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature".to_string()))?;

        Ok(VerifiedRequest)
    }
}
