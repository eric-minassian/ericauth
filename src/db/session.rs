use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AuthError;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionTable {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: i64,
    pub ip_address: String,
}

impl DynamoDb {
    pub async fn insert_session(
        &self,
        id: String,
        user_id: Uuid,
        expires_at: i64,
        ip_address: String,
    ) -> Result<(), AuthError> {
        let session = SessionTable {
            id,
            user_id,
            expires_at,
            ip_address,
        };

        let item = serde_dynamo::aws_sdk_dynamodb_1::to_item(&session)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize session: {e}")))?;

        self.client
            .put_item()
            .table_name(&self.sessions_table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to insert session: {e}")))?;

        Ok(())
    }

    pub async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        self.client
            .delete_item()
            .table_name(&self.sessions_table)
            .key("id", AttributeValue::S(id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to delete session: {e}")))?;

        Ok(())
    }

    pub async fn get_session_by_id(&self, id: &str) -> Result<Option<SessionTable>, AuthError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.sessions_table)
            .key("id", AttributeValue::S(id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB get session failed: {e}")))?;

        match response.item {
            Some(item) => {
                let session = serde_dynamo::aws_sdk_dynamodb_1::from_item::<SessionTable>(item)
                    .map_err(|e| {
                        AuthError::Internal(format!("Failed to deserialize session: {e}"))
                    })?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }
}
