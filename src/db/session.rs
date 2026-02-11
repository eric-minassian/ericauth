use aws_sdk_dynamodb::types::AttributeValue;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_dynamo::aws_sdk_dynamodb_1::{from_item, to_item};
use uuid::Uuid;

use crate::error::AuthError;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionTable {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: DateTime<chrono::Utc>,
}

impl DynamoDb {
    pub async fn insert_session(
        &self,
        id: String,
        user_id: Uuid,
        expires_at: DateTime<chrono::Utc>,
    ) -> Result<(), AuthError> {
        let session = SessionTable {
            id,
            user_id,
            expires_at,
        };

        let item = to_item(&session)
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
                let session = from_item::<SessionTable>(item).map_err(|e| {
                    AuthError::Internal(format!("Failed to deserialize session: {e}"))
                })?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }
}
