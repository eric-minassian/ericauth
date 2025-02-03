use aws_sdk_dynamodb::{types::AttributeValue, Client};
use lambda_http::Error;

const USER_TABLE_NAME: &str = "UsersTable";

pub struct User {
    pub email: String,
    pub password_hash: String,
}

pub async fn get_user(client: &Client, email: String) -> Result<Option<User>, Error> {
    let res = client
        .get_item()
        .table_name(USER_TABLE_NAME)
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
        .table_name(USER_TABLE_NAME)
        .item("email", AttributeValue::S(email))
        .item("password_hash", AttributeValue::S(password_hash))
        .send()
        .await?;

    Ok(())
}
