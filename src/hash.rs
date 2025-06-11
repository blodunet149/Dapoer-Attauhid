use argon2::{Argon2, PasswordHasher};
use rand_core::OsRng;
use password_hash::SaltString;

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    hash
}
