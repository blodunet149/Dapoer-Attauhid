use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

pub async fn init_pool(database_url: &str) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .expect("cannot connect to DB")
}
