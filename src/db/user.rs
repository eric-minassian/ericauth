use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};
use serde_dynamo::aws_sdk_dynamodb_1::{from_item, to_item};
use uuid::Uuid;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct UserTable {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
}

impl DynamoDb {
    pub async fn get_user_by_email(&self, email: String) -> Result<Option<UserTable>, String> {
        let response = self
            .client
            .query()
            .table_name(&self.users_table)
            .index_name(&self.users_email_index)
            .key_condition_expression("email = :email")
            .expression_attribute_values(":email", AttributeValue::S(email))
            .send()
            .await
            .map_err(|e| format!("DynamoDB query failed: {}", e))?;

        if let Some(item) = response.items.and_then(|items| items.into_iter().next()) {
            let user = from_item::<UserTable>(item)
                .map_err(|e| format!("Failed to deserialize user: {}", e))?;
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn insert_user(&self, email: String, password_hash: String) -> Result<Uuid, String> {
        if self.get_user_by_email(email.clone()).await?.is_some() {
            return Err("Email already in use".to_string());
        }

        let user = UserTable {
            id: Uuid::new_v4(),
            email,
            password_hash,
        };

        let item = to_item(&user).map_err(|_| "Failed to serialize user")?;

        self.client
            .put_item()
            .table_name(&self.users_table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|_| "Failed to insert user")?;

        Ok(user.id)
    }
}
