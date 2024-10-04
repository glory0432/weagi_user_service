use chrono::Utc;
use hex;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;
use tracing::{error, info, warn};
use url::form_urlencoded;

pub fn get_user_id(init_data: &str) -> i64 {
    info!("Parsing init_data to extract user_id.");
    let parsed_data: HashMap<_, _> = form_urlencoded::parse(init_data.as_bytes())
        .into_owned()
        .collect();

    if let Some(hash) = parsed_data.get("user") {
        match serde_json::from_str::<Value>(hash) {
            Ok(v) => {
                if let Some(map) = v.as_object() {
                    if let Some(id) = map.get("id").and_then(|id| id.as_i64()) {
                        return id;
                    } else {
                        error!("ID not found or not a valid i64");
                    }
                } else {
                    error!("Failed to parse JSON into an object.");
                }
            }
            Err(e) => {
                error!("Failed to parse JSON: {}", e);
            }
        }
    } else {
        error!("User data not found in the init_data.");
    }

    // Return 0 in case of any errors
    0
}

pub fn validate_initdata(init_data: &str, bot_token: &str) -> bool {
    if init_data.contains("query_id") && init_data.contains("hash=") {
        let parsed_data: HashMap<_, _> = form_urlencoded::parse(init_data.as_bytes())
            .into_owned()
            .collect();

        let received_hash = match parsed_data.get("hash") {
            Some(hash) => hash.clone(),
            None => return false,
        };

        let mut data = parsed_data.clone();
        data.remove("hash");

        let mut sorted_data: Vec<_> = data.iter().collect();
        sorted_data.sort();
        let data_check_string = sorted_data
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("\n");

        let mut mac =
            Hmac::<Sha256>::new_from_slice(b"WebAppData").expect("HMAC can take key of any size");
        mac.update(bot_token.as_bytes());
        let secret_key = mac.finalize().into_bytes();

        let mut mac =
            Hmac::<Sha256>::new_from_slice(&secret_key).expect("HMAC can take key of any size");
        mac.update(data_check_string.as_bytes());
        let calculated_hash = mac.finalize().into_bytes();

        let received_hash = match hex::decode(received_hash) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to decode hex string: {}", e);
                return false;
            }
        };

        if !cryptographic_hash_matches(&calculated_hash, received_hash.as_slice()) {
            warn!("Provided hash does not match the calculated hash.");
            return false;
        }

        // match data.get("auth_date") {
        //     Some(auth_date_str) => {
        //         if let Ok(auth_date) = auth_date_str.parse::<i64>() {
        //             let current_time = Utc::now().timestamp();
        //             if current_time - auth_date > 86400 {
        //                 warn!("Authentication time is outdated.");
        //                 return false;
        //             }
        //         } else {
        //             error!("Failed to parse auth_date.");
        //             return false;
        //         }
        //     }
        //     None => {
        //         warn!("auth_date missing from init_data.");
        //         return false;
        //     }
        // }

        true
    } else {
        error!("init_data does not contain required parameters.");
        false
    }
}

fn cryptographic_hash_matches(calculated: &[u8], received: &[u8]) -> bool {
    calculated.iter().zip(received).all(|(a, b)| a == b)
}
