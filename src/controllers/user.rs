use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use sea_orm::TransactionTrait;
use tracing::{error, info};

use crate::{
    dto::{request::RefreshRequest, response::UserResponse},
    repositories::{session, user},
    utils::{initdata, jwt, jwt::UserClaims},
    ServiceState,
};

pub async fn login(
    State(state): State<Arc<ServiceState>>,
    TypedHeader(Authorization(creds)): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !initdata::validate_initdata(creds.token(), &state.config.bot_token) {
        error!("Invalid Authorization token");
        return Err((
            StatusCode::FORBIDDEN,
            "Invalid Authorization token".to_string(),
        ));
    }
    let user_id = initdata::get_user_id(creds.token());
    if user_id == 0 {
        return Err((StatusCode::BAD_REQUEST, "Invalid user ID".to_string()));
    }

    info!("📥 Login request from the user {}", user_id);

    let transaction = state.db.begin().await.map_err(|e| {
        let error_message = format!("Failed to start a database transaction: {}", e);
        error!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    let mut session_table_id: uuid::Uuid = uuid::Uuid::new_v4();
    match user::exist_by_user_id(&transaction, user_id).await {
        Ok(true) => {
            let user_info = user::find_by_user_id(&transaction, user_id)
                .await
                .map_err(|e| {
                    let error_message = format!("Failed to find the registered user: {}", e);
                    error!("{}", error_message);
                    (StatusCode::INTERNAL_SERVER_ERROR, error_message)
                })?;
            let session_info = match user_info {
                Some(_) => session::find_by_user_id(&transaction, user_id)
                    .await
                    .map_err(|e| {
                        let error_message =
                            format!("Failed to find the corresponding session: {}", e);
                        error!("{}", error_message);
                        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
                    })?,
                None => {
                    let error_message = "There is no such user with the user id".to_string();
                    error!("{}", error_message);
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, error_message));
                }
            };

            session_info
                .map(|session_info| {
                    session_table_id = session_info.id;
                })
                .ok_or_else(|| {
                    let error_message = "There is no such session with the user id".to_string();
                    error!("{}", error_message);
                    (StatusCode::INTERNAL_SERVER_ERROR, error_message)
                })?;
        }

        Ok(false) => {
            user::save(&transaction, user_id).await.map_err(|e| {
                let error_message = format!("Failed to save user: {}", e);
                error!("{}", error_message);
                (StatusCode::INTERNAL_SERVER_ERROR, error_message)
            })?;

            session_table_id = session::save(&transaction, user_id).await.map_err(|e| {
                let error_message = format!("Failed to save session: {}", e);
                error!("{}", error_message);
                (StatusCode::INTERNAL_SERVER_ERROR, error_message)
            })?;
        }

        Err(e) => {
            let error_message = format!("Failed to check if user exists: {}", e);
            error!("{}", error_message);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, error_message));
        }
    }

    transaction.commit().await.map_err(|e| {
        let error_message = format!("Failed to commit transaction: {}", e);
        error!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    info!(
        "✅ Successfully verified with initData of the user {}.",
        user_id
    );

    let (access_token, refresh_token) =
        jwt::generate_token_pair(state.clone(), user_id, session_table_id).map_err(|e| {
            let error_message = format!("Failed to encode new access token: {}", e);
            error!("{}", error_message);
            (StatusCode::INTERNAL_SERVER_ERROR, error_message)
        })?;

    let response = Json(UserResponse {
        access_token,
        refresh_token,
    })
    .into_response();

    Ok(response)
}

pub async fn refresh(
    State(state): State<Arc<ServiceState>>,
    TypedHeader(Authorization(creds)): TypedHeader<Authorization<Bearer>>,
    Json(req): Json<RefreshRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !initdata::validate_initdata(creds.token(), &state.config.bot_token) {
        error!("Invalid Authorization token");
        return Err((
            StatusCode::FORBIDDEN,
            "Invalid Authorization token".to_string(),
        ));
    }
    let user_id = initdata::get_user_id(creds.token());
    if user_id == 0 {
        error!("Invalid user ID from the token");
        return Err((StatusCode::BAD_REQUEST, "Invalid user ID".to_string()));
    }
    info!("📥 Refresh request from the user {}", user_id);

    let transaction = state.db.begin().await.map_err(|e| {
        let error_message = format!("Failed to start a database transaction: {}", e);
        error!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    let user_claims =
        UserClaims::decode(&req.refresh_token, &state.config.jwt.refresh_token_secret).map_err(
            |e| {
                let error_message = format!("Failed to decode refresh token: {}", e);
                error!("{}", error_message);
                (StatusCode::UNAUTHORIZED, error_message)
            },
        )?;
    let user_info = user::find_by_user_id(&transaction, user_id)
        .await
        .map_err(|e| {
            let error_message = format!("Failed to find the registered user: {}", e);
            error!("{}", error_message);
            (StatusCode::INTERNAL_SERVER_ERROR, error_message)
        })?;
    let session_info = session::find_by_user_id(&transaction, user_id)
        .await
        .map_err(|e| {
            let error_message = format!("Failed to find the registered session: {}", e);
            error!("{}", error_message);
            (StatusCode::INTERNAL_SERVER_ERROR, error_message)
        })?;

    if user_info.is_none() || session_info.is_none() {
        let error_message = format!(
            "There is no record of the registered user or session with the userId: {}",
            user_id
        );
        error!("{}", error_message);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, error_message));
    }

    if user_claims.claims.uid != user_info.unwrap().user_id
        || user_claims.claims.sid != session_info.unwrap().id
    {
        error!(
            "User ID or Session ID in claims does not match user ID or session ID from database"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid refresh token".to_string(),
        ));
    }

    transaction.commit().await.map_err(|e| {
        let error_message = format!("Failed to commit transaction: {}", e);
        error!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    let (access_token, refresh_token) = jwt::generate_token_pair(
        state.clone(),
        user_claims.claims.uid,
        user_claims.claims.sid,
    )
    .map_err(|e| {
        let error_message = format!("Failed to encode new access token: {}", e);
        error!("{}", error_message);
        (StatusCode::INTERNAL_SERVER_ERROR, error_message)
    })?;

    info!(
        "✅ Successfully token refresh with initData and refresh token of the user {}.",
        user_id
    );

    let response = Json(UserResponse {
        access_token,
        refresh_token,
    })
    .into_response();

    Ok(response)
}
