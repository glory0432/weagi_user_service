use std::sync::Arc;

use crate::controllers::user;
use crate::ServiceState;
use axum::routing::{get, post};

pub fn add_routers(router: axum::Router<Arc<ServiceState>>) -> axum::Router<Arc<ServiceState>> {
    router
        .route("/api/session", get(user::login))
        .route("/api/session", post(user::refresh))
}
