use std::env;
#[derive(Debug, Clone, Default)]
pub struct JWTConfig {
    pub secret: String,
    pub refresh_token_expired_date: u64,
    pub access_token_expired_date: u64,
}

impl JWTConfig {
    pub fn init_from_env(&mut self) -> Result<(), String> {
        // Retrieve and set the secret from the environment
        self.secret =
            env::var("JWT_SECRET").map_err(|_| "JWT_SECRET not set in environment".to_string())?;

        // Retrieve and parse the refresh token expiration date
        self.refresh_token_expired_date = env::var("JWT_REFRESH_TOKEN_EXPIRED_DATE")
            .map_err(|_| "JWT_REFRESH_TOKEN_EXPIRED_DATE not set in environment".to_string())?
            .parse::<u64>()
            .map_err(|_| "JWT_REFRESH_TOKEN_EXPIRED_DATE is not a valid u64".to_string())?;

        // Retrieve and parse the access token expiration date
        self.access_token_expired_date = env::var("JWT_ACCESS_TOKEN_EXPIRED_DATE")
            .map_err(|_| "JWT_ACCESS_TOKEN_EXPIRED_DATE not set in environment".to_string())?
            .parse::<u64>()
            .map_err(|_| "JWT_ACCESS_TOKEN_EXPIRED_DATE is not a valid u64".to_string())?;

        Ok(())
    }
}
