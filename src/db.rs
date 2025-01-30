use aws_sdk_dynamodb::types::AttributeValue;

use crate::config::USER_TABLE_NAME;

#[derive(Debug)]
pub enum DatabaseError {
    UserNotFound,
    SDKError(aws_sdk_dynamodb::Error),
    IncorrectDataType,
}

impl From<aws_sdk_dynamodb::Error> for DatabaseError {
    fn from(err: aws_sdk_dynamodb::Error) -> Self {
        DatabaseError::SDKError(err)
    }
}

#[derive(Debug)]
pub struct User {
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug)]
pub struct Database {
    ddb_client: aws_sdk_dynamodb::Client,
}

impl Database {
    pub fn new(ddb_client: aws_sdk_dynamodb::Client) -> Self {
        Self { ddb_client }
    }

    pub async fn insert_user(&mut self, email: String, password_hash: String) {
        // self.users.insert(
        //     email.clone(),
        //     User {
        //         email,
        //         password_hash,
        //     },
        // );
        self.ddb_client
            .put_item()
            .table_name(USER_TABLE_NAME)
            .item("email", AttributeValue::S(email))
            .item("password_hash", AttributeValue::S(password_hash))
            .send()
            .await
            .expect("Failed to insert user");
    }

    pub async fn get_user(&self, email: &str) -> Result<Option<User>, DatabaseError> {
        let res = self
            .ddb_client
            .get_item()
            .table_name(USER_TABLE_NAME)
            .key("email", AttributeValue::S(email.to_string()))
            .send()
            .await
            .map_err(|e| DatabaseError::SDKError(e.into()))?;

        match res.item {
            Some(item) => {
                if let Some(AttributeValue::S(password_hash)) = item.get("password_hash") {
                    Ok(Some(User {
                        email: email.to_string(),
                        password_hash: password_hash.clone(),
                    }))
                } else {
                    Err(DatabaseError::IncorrectDataType)
                }
            }
            None => Ok(None),
        }
    }
}
