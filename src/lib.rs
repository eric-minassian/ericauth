pub mod config;
pub mod db;
pub mod routes;
pub mod state;

pub struct User {
    pub email: String,
    pub password_hash: String,
}

pub const USER_TABLE_NAME: &str = "UsersTable";
