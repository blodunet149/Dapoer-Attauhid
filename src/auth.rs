use actix_web::{HttpResponse, web};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::models::{LoginRequest, Parent};

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub async fn login(
    pool: web::Data<SqlitePool>,
    data: web::Json<LoginRequest>,
    secret: web::Data<String>,
) -> HttpResponse {
    // cari parent
    let result = sqlx::query_as::<_, Parent>(
        "SELECT nik, name, password_hash FROM parents WHERE nik = ?",
    )
    .bind(&data.nik)
    .fetch_optional(pool.get_ref())
    .await;

    let parent = match result {
        Ok(Some(p)) => p,
        _ => return HttpResponse::Unauthorized().body("NIK / password salah"),
    };

    // verifikasi password
    let parsed_hash = PasswordHash::new(&parent.password_hash).unwrap();
    if Argon2::default()
        .verify_password(data.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return HttpResponse::Unauthorized().body("NIK / password salah");
    }

    // generate JWT 7 hari
    let exp = (time::OffsetDateTime::now_utc() + time::Duration::days(7)).unix_timestamp() as usize;
    let claims = Claims {
        sub: parent.nik.clone(),
        exp,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.get_ref().as_bytes()),
    )
    .unwrap();

    HttpResponse::Ok().json(serde_json::json!({
        "token": token,
        "name": parent.name
    }))
}
