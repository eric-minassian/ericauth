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
    #[serde(default)]
    pub mfa_totp_secret: Option<String>,
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
        let user = UserTable {
            id: Uuid::new_v5(&Uuid::NAMESPACE_DNS, email.as_bytes()),
            email,
            password_hash,
            created_at,
            updated_at,
            scopes,
            recovery_codes,
            mfa_totp_secret: None,
        };

        let item = to_item(&user)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize user: {e}")))?;

        self.client
            .put_item()
            .table_name(&self.users_table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(id)")
            .send()
            .await
            .map_err(|e| {
                let service_err = e.into_service_error();
                if service_err.is_conditional_check_failed_exception() {
                    AuthError::Conflict("email already in use".to_string())
                } else {
                    AuthError::Internal(format!("Failed to insert user: {service_err}"))
                }
            })?;

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

    pub async fn delete_user_by_id(&self, user_id: &str) -> Result<bool, AuthError> {
        let response = self
            .client
            .delete_item()
            .table_name(&self.users_table)
            .key("id", AttributeValue::S(user_id.to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to delete user: {e}")))?;

        Ok(response.attributes.is_some())
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

    pub async fn replace_recovery_codes(
        &self,
        user_id: &str,
        recovery_codes: Vec<String>,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        let codes_av = serde_dynamo::aws_sdk_dynamodb_1::to_attribute_value(&recovery_codes)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize recovery codes: {e}")))?;

        self.client
            .update_item()
            .table_name(&self.users_table)
            .key("id", AttributeValue::S(user_id.to_string()))
            .update_expression("SET recovery_codes = :codes, updated_at = :updated_at")
            .expression_attribute_values(":codes", codes_av)
            .expression_attribute_values(":updated_at", AttributeValue::S(updated_at.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to replace recovery codes: {e}")))?;

        Ok(())
    }

    pub async fn update_password_hash(
        &self,
        user_id: &str,
        password_hash: String,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        self.client
            .update_item()
            .table_name(&self.users_table)
            .key("id", AttributeValue::S(user_id.to_string()))
            .update_expression("SET password_hash = :password_hash, updated_at = :updated_at")
            .expression_attribute_values(":password_hash", AttributeValue::S(password_hash))
            .expression_attribute_values(":updated_at", AttributeValue::S(updated_at.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to update password hash: {e}")))?;

        Ok(())
    }

    pub async fn update_mfa_totp_secret(
        &self,
        user_id: &str,
        mfa_totp_secret: Option<String>,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        let mut update_item = self
            .client
            .update_item()
            .table_name(&self.users_table)
            .key("id", AttributeValue::S(user_id.to_string()))
            .expression_attribute_values(":updated_at", AttributeValue::S(updated_at.to_string()));

        if let Some(secret) = mfa_totp_secret {
            update_item = update_item
                .update_expression(
                    "SET mfa_totp_secret = :mfa_totp_secret, updated_at = :updated_at",
                )
                .expression_attribute_values(":mfa_totp_secret", AttributeValue::S(secret));
        } else {
            update_item = update_item
                .update_expression("REMOVE mfa_totp_secret SET updated_at = :updated_at");
        }

        update_item
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to update MFA TOTP secret: {e}")))?;

        Ok(())
    }
}
