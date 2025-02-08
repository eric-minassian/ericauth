use std::{env, sync::LazyLock};

use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};
use serde_dynamo::aws_sdk_dynamodb_1::{from_item, to_item};
use uuid::Uuid;

use super::Database;

static USERS_TABLE_NAME: LazyLock<String> = LazyLock::new(|| {
    env::var("USERS_TABLE_NAME").expect("USERS_TABLE_NAME environment variable must be set")
});

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
}

impl Database {
    pub async fn get_user_by_email(&self, email: String) -> Result<Option<User>, String> {
        let response = self
            .ddb_client
            .get_item()
            .table_name(&*USERS_TABLE_NAME)
            .key("email", AttributeValue::S(email))
            .send()
            .await
            .map_err(|_| "Failed to get user by email")?;

        if let Some(item) = response.item {
            Ok(Some(from_item::<User>(item).unwrap()))
        } else {
            Ok(None)
        }
    }

    pub async fn insert_user(&self, email: String, password_hash: String) -> Result<Uuid, String> {
        if self.get_user_by_email(email.clone()).await?.is_some() {
            return Err("Email already in use".to_string());
        }

        let user = User {
            id: Uuid::new_v4(),
            email,
            password_hash,
        };

        let item = to_item(&user).map_err(|_| "Failed to serialize user")?;

        self.ddb_client
            .put_item()
            .table_name(&*USERS_TABLE_NAME)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|_| "Failed to insert user")?;

        Ok(user.id)
    }
}
