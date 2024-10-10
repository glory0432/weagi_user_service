use std::sync::Arc;

use crate::ServiceState;
use axum::extract::State;
use axum::{body, extract::Request, http::StatusCode, middleware::Next, response::IntoResponse};
use base64::prelude::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

pub async fn verify_signature(
    State(state): State<Arc<ServiceState>>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (parts, body) = req.into_parts();
    let signature = parts
        .headers
        .get("X-Signature")
        .ok_or((StatusCode::UNAUTHORIZED, "Signature missing".to_string()))?;
    let signature_str = signature.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid signature header".to_string(),
        )
    })?;

    let signature_bytes = BASE64_STANDARD.decode(signature_str).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Base64 decoding failed".to_string(),
        )
    })?;

    let whole_body = body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to read body".to_string()))?;
    let mut mac = HmacSha256::new_from_slice(state.config.secret.inter_secret_key.as_bytes())
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid secret key".to_string(),
            )
        })?;
    mac.update(&whole_body);

    mac.verify_slice(&signature_bytes)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature".to_string()))?;

    Ok(next
        .run(Request::from_parts(parts, whole_body.into()))
        .await)
}
