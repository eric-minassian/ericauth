use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_dynamo::aws_sdk_dynamodb_1::to_item;
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
}
