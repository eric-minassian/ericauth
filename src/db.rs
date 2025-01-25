use aws_sdk_dynamodb::types::AttributeValue;

use crate::config::USER_TABLE_NAME;

#[derive(Debug)]
enum DatabaseError {
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

    pub async fn get_user(&self, email: &str) -> Option<User> {
        // self.ddb_client
        //     .get_item()
        //     .table_name(USER_TABLE_NAME)
        //     .key("email", AttributeValue::S(email.to_string()))
        //     .send()
        //     .await
        //     .expect("Failed to get user")
        //     .item
        //     .map(|item| {
        //         let email = item.get("email").unwrap().s.as_ref().unwrap().to_string();
        //         let password_hash = item
        //             .get("password_hash")
        //             .unwrap()
        //             .as_s()
        //             .as_ref()
        //             .unwrap()
        //             .to_string();
        //         User {
        //             email,
        //             password_hash,
        //         }
        //     })
        unimplemented!()
    }

    pub async fn get_password_hash(&self, email: &str) -> Result<Option<String>, DatabaseError> {
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
                    Ok(Some(password_hash.clone()))
                } else {
                    Err(DatabaseError::IncorrectDataType)
                }
            }
            None => Ok(None),
        }
    }
}
