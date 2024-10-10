use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use sea_orm::{ActiveModelTrait, Set, TransactionTrait};
use tracing::{error, info};

use crate::{
    dto::{request::SetSessionRequest, response::GetSessionResponse},
    entity,
    utils::{self, jwt::UserClaims, session::SessionKey},
    ServiceState,
};

pub async fn set_session(
    State(state): State<Arc<ServiceState>>,
    user: UserClaims,
    Json(req): Json<SetSessionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("📥 Get session data request from the user {}", user.uid);

    let transaction = state.db.begin().await.map_err(|e| {
        let error_message = format!("Failed to start a database transaction: {}", e);
        error!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    let session_data = utils::session::get_session_by_user_id(state.clone(), user.uid)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let updated_model = entity::session::ActiveModel {
        id: Set(session_data.id),
        user_id: Set(session_data.user_id),
        subscription_status: Set({
            if req.subscription_status.is_some() {
                req.subscription_status.unwrap()
            } else {
                session_data.subscription_status
            }
        }),
        credits_remaining: Set({
            if req.credits_remaining.is_some() {
                req.credits_remaining.unwrap()
            } else {
                session_data.credits_remaining
            }
        }),
        last_active_timestamp: Set(session_data.last_active_timestamp),
        preferences: Set({
            if req.preferences.is_some() {
                req.preferences.unwrap()
            } else {
                session_data.preferences
            }
        }),
        session_metadata: Set({
            if req.session_metadata.is_some() {
                req.session_metadata.unwrap()
            } else {
                session_data.session_metadata
            }
        }),
        created_at: Set(session_data.created_at),
        updated_at: Set(session_data.updated_at),
    };

    let updated_data: entity::session::Model =
        updated_model.update(&transaction).await.map_err(|e| {
            let error_message = format!("Error updating the conversation data: {}", e);
            error!("{}", error_message);
            (StatusCode::INTERNAL_SERVER_ERROR, error_message)
        })?;
    let session_key = SessionKey { user_id: user.uid };
    utils::session::set(&state.redis, (&session_key, &updated_data))
        .await
        .map_err(|e| {
            let error_message = format!("Failed to set session in Redis: {}", e);
            error!("{}", error_message);
            (StatusCode::INTERNAL_SERVER_ERROR, error_message)
        })?;
    transaction.commit().await.map_err(|e| {
        let error_message = format!("Failed to commit transaction: {}", e);
        error!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    info!("✅ Successfully sent the session data of the user {}.", 0);

    let response = Json(GetSessionResponse::default()).into_response();
    Ok(response)
}

pub async fn get_session(
    State(state): State<Arc<ServiceState>>,
    user: UserClaims,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("📥 Get session data request from the user {}", user.uid);

    let session_model = utils::session::get_session_by_user_id(state.clone(), user.uid)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let response = Json(GetSessionResponse {
        subscription_status: session_model.subscription_status,
        credits_remaining: session_model.credits_remaining,
        preferences: session_model.preferences.clone(),
        session_metadata: session_model.session_metadata.clone(),
    })
    .into_response();
    Ok(response)
}
