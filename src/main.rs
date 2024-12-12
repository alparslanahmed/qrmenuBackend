mod handler;
mod auth;

use axum::{
    routing::get,
    Router,
};
use axum::routing::post;
use dotenv::dotenv;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use tower_http::cors::CorsLayer;
use crate::auth::jwt::AuthUser;

#[tokio::main]
async fn main() {
    dotenv().ok(); // This line loads the environment variables from the ".env" file.

    // Connect to the database
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set.");
    let mut opt = ConnectOptions::new(database_url.to_owned());
    opt.sqlx_logging_level(log::LevelFilter::Info); // Set SQLx log level
    let db: DatabaseConnection = Database::connect(opt).await.expect("Failed to connect to the database.");

    let state = AppState { db };

    let app = Router::new()
        .route("/auth/login", post(handler::auth::login))
        .route("/auth/register", post(handler::auth::register))
        .route("/protected", get(protected_route))
        .layer(CorsLayer::permissive())
        .with_state(state);
    
    let host = std::env::var("HOST").expect("HOST must be set.");
    let port = std::env::var("PORT").expect("PORT must be set.");
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port)).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Example protected route using the AuthUser extractor
pub async fn protected_route(auth: AuthUser) -> String {
    format!("Hello user {}!", auth.user_id)
}


#[derive(Clone)]
struct AppState {
    db: DatabaseConnection,
}