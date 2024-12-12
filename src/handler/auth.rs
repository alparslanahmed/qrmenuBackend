// src/handlers/auth.rs
use sea_orm::{ColumnTrait, QueryFilter};
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use sea_orm::{DatabaseConnection, EntityTrait, Set};
use serde::{Deserialize, Serialize};
use entity::user::{self, ActiveModel};
use crate::{auth::jwt::create_token, AppState};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    token: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let user = user::Entity::find()
        .filter(user::Column::Email.eq(payload.email))
        .one(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()))?;

    if !verify(payload.password, &user.password).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Password verification error: {}", e),
        )
    })? {
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
    }

    let token = create_token(user.id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Token creation error: {}", e),
        )
    })?;

    Ok(Json(LoginResponse { token }))
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    email: String,
    password: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let password_hash = hash(payload.password.as_bytes(), DEFAULT_COST).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Password hashing error: {}", e),
        )
    })?;

    let user = ActiveModel {
        email: Set(payload.email),
        password: Set(password_hash),
        ..Default::default()
    };

    user::Entity::insert(user)
        .exec(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    Ok(StatusCode::CREATED)
}
