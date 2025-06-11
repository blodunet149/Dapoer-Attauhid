mod auth;
mod db;
mod models;

use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::Key,
    http::header::AUTHORIZATION,
    middleware::Logger,
    web, App, HttpServer, HttpResponse, Result,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use models::Child;
use sqlx::SqlitePool;
use std::env;

use actix_web::http::header::HeaderMap;


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET not set");

    let pool = db::init_pool(&database_url).await;

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(jwt_secret.clone()))
            .wrap(Logger::default())
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(), // not used, we rely on JWT
            ))
            .service(
                web::resource("/login")
                    .route(web::post().to(auth::login))
            )
            .service(
                web::resource("/children")
                    .route(web::get().to(children))
            )
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

/// Middleware helper: ekstrak NIK dari header Authorization: Bearer <token>
fn parent_nik_from_header(
    // use actix_web::http::header::{HeaderMap, AUTHORIZATION};
headers: &HeaderMap,
    jwt_secret: &str,
) -> Option<String> {
    let auth_header = headers.get(AUTHORIZATION)?.to_str().ok()?;
    if !auth_header.starts_with("Bearer ") {
        return None;
    }
    let token = auth_header.trim_start_matches("Bearer ").trim();
    let validation = Validation::new(Algorithm::HS256);
    decode::<serde_json::Value>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .ok()
    .and_then(|data| data.claims["sub"].as_str().map(|s| s.to_owned()))
}

/// GET /children – mengembalikan daftar anak milik parent yg login
async fn children(
    pool: web::Data<SqlitePool>,
    jwt_secret: web::Data<String>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    let nik_parent = match parent_nik_from_header(req.headers(), &jwt_secret) {
        Some(nik) => nik,
        None => return Ok(HttpResponse::Unauthorized().finish()),
    };

    let rows: Vec<Child> = sqlx::query_as::<_, Child>(
        "SELECT nik, parent_nik, name FROM children WHERE parent_nik = ?"
    )
    .bind(nik_parent)
    .fetch_all(pool.get_ref())
    .await
    .map_err(|e| {
        eprintln!("DB error: {e}");
        actix_web::error::ErrorInternalServerError("db")
    })?;

    Ok(HttpResponse::Ok().json(rows))
}
