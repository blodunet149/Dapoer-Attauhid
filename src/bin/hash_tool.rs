use argon2::{Argon2, PasswordHasher};
use password_hash::SaltString;
use rand_core::OsRng;

fn main() {
    let password = b"rahasia";
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2.hash_password(password, &salt).unwrap().to_string();
    println!("Hash: {}", hash);
}
