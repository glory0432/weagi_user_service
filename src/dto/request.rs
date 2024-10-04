use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}
