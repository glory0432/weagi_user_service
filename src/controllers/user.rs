use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use sea_orm::TransactionTrait;
use tracing::{info, warn};

use crate::{dto::response::VerifyResponse, repositories::user, utils::initdata, ServiceState};

pub async fn verify(
    State(state): State<Arc<ServiceState>>,
    TypedHeader(Authorization(creds)): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Validate the authorization token
    if !initdata::validate_initdata(creds.token(), &state.config.bot_token) {
        warn!("Invalid Authorization token");
        return Err((
            StatusCode::FORBIDDEN,
            "Invalid Authorization token".to_string(),
        ));
    }

    // Try to begin a new transaction
    let transaction = state.db.begin().await.map_err(|e| {
        let error_message = format!("Failed to start a database transaction: {}", e);
        warn!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    // Determine the user ID from the token
    let user_id = initdata::get_user_id(creds.token());
    if user_id == 0 {
        return Err((StatusCode::BAD_REQUEST, "Invalid user ID".to_string()));
    }

    // Check if the user already exists
    match user::exist_by_user_id(&transaction, user_id).await {
        Ok(true) => {
            let user_info = user::find_by_user_id(&transaction, user_id)
                .await
                .map_err(|e| {
                    let error_message = format!("Failed to find the registered user: {}", e);
                    warn!("{}", error_message);
                    (StatusCode::INTERNAL_SERVER_ERROR, error_message)
                })?;
        }
        Ok(false) => {
            let id = user::save(&transaction, user_id).await.map_err(|e| {
                let error_message = format!("Failed to save user: {}", e);
                warn!("{}", error_message);
                (StatusCode::INTERNAL_SERVER_ERROR, error_message)
            })?;
            let user_info = user::find_by_id(&transaction, id).await.map_err(|e| {
                let error_message = format!("Failed to find the registered user: {}", e);
                warn!("{}", error_message);
                (StatusCode::INTERNAL_SERVER_ERROR, error_message)
            })?;
        }
        Err(e) => {
            let error_message = format!("Failed to check if user exists: {}", e);
            warn!("{}", error_message);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, error_message));
        }
    }

    transaction.commit().await.map_err(|e| {
        let error_message = format!("Failed to commit transaction: {}", e);
        warn!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    info!("Successfully verified with initData");

    // Build the response
    let response = Json(VerifyResponse::default()).into_response();

    Ok(response)
}
