use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialTable {
    pub credential_id: String,
    pub user_id: String,
    pub passkey_json: String,
    pub created_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
}

impl DynamoDb {
    pub async fn insert_credential(
        &self,
        credential_id: &str,
        user_id: &str,
        passkey_json: &str,
        created_at: &str,
    ) -> Result<(), AuthError> {
        self.client
            .put_item()
            .table_name(&self.credentials_table)
            .item(
                "credential_id",
                AttributeValue::S(credential_id.to_string()),
            )
            .item("user_id", AttributeValue::S(user_id.to_string()))
            .item("passkey_json", AttributeValue::S(passkey_json.to_string()))
            .item("created_at", AttributeValue::S(created_at.to_string()))
            .condition_expression("attribute_not_exists(credential_id)")
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to insert credential: {e}")))?;

        Ok(())
    }

    pub async fn get_credentials_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<CredentialTable>, AuthError> {
        let response = self
            .client
            .query()
            .table_name(&self.credentials_table)
            .index_name(&self.credentials_user_id_index)
            .key_condition_expression("user_id = :uid")
            .expression_attribute_values(":uid", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB query credentials failed: {e}")))?;

        let items = response.items.unwrap_or_default();
        let mut credentials = Vec::with_capacity(items.len());
        for item in items {
            let cred = serde_dynamo::aws_sdk_dynamodb_1::from_item::<CredentialTable>(item)
                .map_err(|e| {
                    AuthError::Internal(format!("Failed to deserialize credential: {e}"))
                })?;
            credentials.push(cred);
        }

        Ok(credentials)
    }

    pub async fn get_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<CredentialTable>, AuthError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.credentials_table)
            .key(
                "credential_id",
                AttributeValue::S(credential_id.to_string()),
            )
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB get credential failed: {e}")))?;

        match response.item {
            Some(item) => {
                let cred = serde_dynamo::aws_sdk_dynamodb_1::from_item::<CredentialTable>(item)
                    .map_err(|e| {
                        AuthError::Internal(format!("Failed to deserialize credential: {e}"))
                    })?;
                Ok(Some(cred))
            }
            None => Ok(None),
        }
    }

    pub async fn update_credential(
        &self,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), AuthError> {
        self.client
            .update_item()
            .table_name(&self.credentials_table)
            .key(
                "credential_id",
                AttributeValue::S(credential_id.to_string()),
            )
            .update_expression("SET passkey_json = :pj")
            .expression_attribute_values(":pj", AttributeValue::S(passkey_json.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to update credential: {e}")))?;

        Ok(())
    }

    pub async fn delete_credential(&self, credential_id: &str) -> Result<(), AuthError> {
        self.client
            .delete_item()
            .table_name(&self.credentials_table)
            .key(
                "credential_id",
                AttributeValue::S(credential_id.to_string()),
            )
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to delete credential: {e}")))?;

        Ok(())
    }
}
