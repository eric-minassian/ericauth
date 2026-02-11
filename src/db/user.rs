use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};
use serde_dynamo::aws_sdk_dynamodb_1::{from_item, to_item};
use uuid::Uuid;

use crate::error::AuthError;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct UserTable {
    pub id: Uuid,
    pub email: String,
    #[serde(default)]
    pub password_hash: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub recovery_codes: Vec<String>,
}

impl DynamoDb {
    pub async fn get_user_by_email(&self, email: String) -> Result<Option<UserTable>, AuthError> {
        let response = self
            .client
            .query()
            .table_name(&self.users_table)
            .index_name(&self.users_email_index)
            .key_condition_expression("email = :email")
            .expression_attribute_values(":email", AttributeValue::S(email))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB query failed: {e}")))?;

        if let Some(item) = response.items.and_then(|items| items.into_iter().next()) {
            let user = from_item::<UserTable>(item)
                .map_err(|e| AuthError::Internal(format!("Failed to deserialize user: {e}")))?;
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn insert_user(
        &self,
        email: String,
        password_hash: Option<String>,
        created_at: String,
        updated_at: String,
        scopes: Vec<String>,
        recovery_codes: Vec<String>,
    ) -> Result<Uuid, AuthError> {
        if self.get_user_by_email(email.clone()).await?.is_some() {
            return Err(AuthError::Conflict("email already in use".to_string()));
        }

        let user = UserTable {
            id: Uuid::new_v4(),
            email,
            password_hash,
            created_at,
            updated_at,
            scopes,
            recovery_codes,
        };

        let item = to_item(&user)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize user: {e}")))?;

        self.client
            .put_item()
            .table_name(&self.users_table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to insert user: {e}")))?;

        Ok(user.id)
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserTable>, AuthError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.users_table)
            .key("id", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB get user failed: {e}")))?;

        match response.item {
            Some(item) => {
                let user = from_item::<UserTable>(item)
                    .map_err(|e| AuthError::Internal(format!("Failed to deserialize user: {e}")))?;
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    pub async fn update_user_scopes(
        &self,
        user_id: &str,
        scopes: Vec<String>,
    ) -> Result<(), AuthError> {
        let scopes_av = serde_dynamo::aws_sdk_dynamodb_1::to_attribute_value(&scopes)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize scopes: {e}")))?;

        self.client
            .update_item()
            .table_name(&self.users_table)
            .key("id", AttributeValue::S(user_id.to_string()))
            .update_expression("SET scopes = :scopes")
            .expression_attribute_values(":scopes", scopes_av)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to update user scopes: {e}")))?;

        Ok(())
    }

    pub async fn remove_recovery_code(
        &self,
        user_id: &str,
        code_hash: &str,
    ) -> Result<(), AuthError> {
        // Get current user to find the index of the code
        let user = self
            .get_user_by_id(user_id)
            .await?
            .ok_or_else(|| AuthError::NotFound("user not found".into()))?;

        let new_codes: Vec<String> = user
            .recovery_codes
            .into_iter()
            .filter(|c| c != code_hash)
            .collect();

        let codes_av = serde_dynamo::aws_sdk_dynamodb_1::to_attribute_value(&new_codes)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize recovery codes: {e}")))?;

        self.client
            .update_item()
            .table_name(&self.users_table)
            .key("id", AttributeValue::S(user_id.to_string()))
            .update_expression("SET recovery_codes = :codes")
            .expression_attribute_values(":codes", codes_av)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to remove recovery code: {e}")))?;

        Ok(())
    }
}
