use serde::Serialize;
#[derive(Debug, Clone, Default, Serialize)]
pub struct VerifyResponse {
    pub access_token: String,
    pub refresh_token: String,
}
