// src/auth/jwt.rs
use axum::{
    async_trait,
    http::request::Parts,
    RequestPartsExt,
};
use axum_extra::{TypedHeader, headers::{authorization::Bearer, Authorization}};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use axum::extract::FromRequestParts;
use axum::http::StatusCode;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32, // user id
    pub exp: usize,
}

pub struct AuthUser {
    pub user_id: i32,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Missing authorization header".to_string()))?;

        let token_data = decode::<Claims>(
            bearer.token(),
            &DecodingKey::from_secret(b"your-secret-key"),
            &Validation::default(),
        )
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid token".to_string()))?;

        Ok(AuthUser {
            user_id: token_data.claims.sub,
        })
    }
}


pub fn create_token(user_id: i32) -> Result<String, anyhow::Error> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 24 * 3600; // 24 hours from now

    let claims = Claims {
        sub: user_id,
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"your-secret-key"),
    )
        .map_err(|e| anyhow::anyhow!("Failed to create token: {}", e))
}
