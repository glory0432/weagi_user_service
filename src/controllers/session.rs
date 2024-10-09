use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use sea_orm::TransactionTrait;
use tracing::{error, info};

use crate::{
    dto::{request::SetSessionRequest, response::GetSessionResponse},
    entity, repositories,
    utils::{self, inter::VerifiedRequest, jwt::UserClaims},
    ServiceState,
};

pub async fn set_session(
    State(state): State<Arc<ServiceState>>,
    _: VerifiedRequest,
    user: UserClaims,
    Json(req): Json<SetSessionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("📥 Get session data request from the user {}", user.uid);

    let transaction = state.db.begin().await.map_err(|e| {
        let error_message = format!("Failed to start a database transaction: {}", e);
        error!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    let session_data = repositories::session::find_by_id(&transaction, user.sid)
        .await
        .map_err(|e| {
            let error_message = format!("Failed to find session by ID: {}", e);
            error!("{}", error_message);
            (StatusCode::INTERNAL_SERVER_ERROR, error_message)
        })?;

    if session_data.is_none() {
        let error_message = "Session data not found".to_string();
        error!("{}", error_message);
        return Err((StatusCode::NOT_FOUND, error_message));
    }

    let session_data = session_data.unwrap();

    transaction.commit().await.map_err(|e| {
        let error_message = format!("Failed to commit transaction: {}", e);
        error!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    info!(
        "✅ Successfully sent the session data of the user {}.",
        user.uid
    );

    let response = Json(GetSessionResponse::default()).into_response();
    Ok(response)
}

pub async fn get_session(
    State(state): State<Arc<ServiceState>>,
    user: UserClaims,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("📥 Get session data request from the user {}", user.uid);

    let transaction = state.db.begin().await.map_err(|e| {
        let error_message = format!("Failed to start a database transaction: {}", e);
        error!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    let session_key = utils::session::SessionKey { user_id: user.uid };

    let session_model: entity::session::Model =
        match utils::session::get(&state.redis, &session_key)
            .await
            .map_err(|e| {
                let error_message = format!("Failed to get session from Redis: {}", e);
                error!("{}", error_message);
                (StatusCode::INTERNAL_SERVER_ERROR, error_message)
            })? {
            Some(model) => model,
            None => {
                let session_data = repositories::session::find_by_id(&transaction, user.sid)
                    .await
                    .map_err(|e| {
                        let error_message = format!("Failed to find session by ID: {}", e);
                        error!("{}", error_message);
                        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
                    })?;

                if session_data.is_none() {
                    let error_message = "Session data not found".to_string();
                    error!("{}", error_message);
                    return Err((StatusCode::NOT_FOUND, error_message));
                }
                transaction.commit().await.map_err(|e| {
                    let error_message = format!("Failed to commit transaction: {}", e);
                    error!("{}", error_message);
                    (StatusCode::INTERNAL_SERVER_ERROR, error_message)
                })?;
                let session_data = session_data.unwrap();
                utils::session::set(&state.redis, (&session_key, &session_data))
                    .await
                    .map_err(|e| {
                        let error_message = format!("Failed to set session in Redis: {}", e);
                        error!("{}", error_message);
                        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
                    })?;

                session_data
            }
        };

    info!(
        "✅ Successfully sent the session data of the user {}.",
        user.uid
    );

    let response = Json(GetSessionResponse {
        subscription_status: session_model.subscription_status,
        credits_remaining: session_model.credits_remaining,
        preferences: session_model.preferences.clone(),
        session_metadata: session_model.session_metadata.clone(),
    })
    .into_response();
    Ok(response)
}
