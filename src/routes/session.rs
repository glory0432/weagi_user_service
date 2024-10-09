use std::sync::Arc;

use crate::controllers::{session, user};
use crate::ServiceState;
use axum::routing::{get, post};

pub fn add_routers(router: axum::Router<Arc<ServiceState>>) -> axum::Router<Arc<ServiceState>> {
    router
        .route("/api/auth/session", get(session::get_session))
        .route("/api/auth/session", post(user::refresh))
}
