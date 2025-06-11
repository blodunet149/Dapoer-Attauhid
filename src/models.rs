use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Serialize, FromRow)]
pub struct Child {
    pub nik: String,
    pub parent_nik: String,
    pub name: String,
}

#[derive(Debug, FromRow)]
pub struct Parent {
    pub nik: String,
    pub name: String,
    pub password_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub nik: String,
    pub password: String,
}
