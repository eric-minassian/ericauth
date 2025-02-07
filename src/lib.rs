pub mod encryption;
pub mod password;
pub mod session;
pub mod user;

use aws_sdk_dynamodb::{types::AttributeValue, Client};
use lambda_http::Error;

const USERS_TABLE_NAME: &str = "UsersTable";
const SESSIONS_TABLE_NAME: &str = "SessionsTable";

pub struct User {
    pub email: String,
    pub password_hash: String,
}

pub async fn get_user(client: &Client, email: String) -> Result<Option<User>, Error> {
    let res = client
        .get_item()
        .table_name(USERS_TABLE_NAME)
        .key("email", AttributeValue::S(email.to_string()))
        .send()
        .await?;

    match res.item {
        Some(item) => {
            if let Some(AttributeValue::S(password_hash)) = item.get("password_hash") {
                Ok(Some(User {
                    email: email.to_string(),
                    password_hash: password_hash.clone(),
                }))
            } else {
                Err(Error::from("missing password_hash"))
            }
        }
        None => Ok(None),
    }
}

pub async fn insert_user(
    client: &Client,
    email: String,
    password_hash: String,
) -> Result<(), Error> {
    client
        .put_item()
        .table_name(USERS_TABLE_NAME)
        .item("email", AttributeValue::S(email))
        .item("password_hash", AttributeValue::S(password_hash))
        .send()
        .await?;

    Ok(())
}

pub fn generate_random_recovery_code() -> Result<String, &'static str> {
    let mut recovery_code_bytes = [0u8; 10];
    getrandom::fill(&mut recovery_code_bytes).map_err(|_| "Invalid Recovery Code")?;

    Ok(base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        &recovery_code_bytes,
    )
    .to_uppercase())
}
