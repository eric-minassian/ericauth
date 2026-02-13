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
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub last_seen_at: i64,
    #[serde(default)]
    pub user_agent: Option<String>,
}

#[derive(Clone)]
pub struct NewSession {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: i64,
    pub ip_address: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub user_agent: Option<String>,
}

impl DynamoDb {
    pub async fn insert_session(&self, new_session: NewSession) -> Result<(), AuthError> {
        let session = SessionTable {
            id: new_session.id,
            user_id: new_session.user_id,
            expires_at: new_session.expires_at,
            ip_address: new_session.ip_address,
            created_at: new_session.created_at,
            last_seen_at: new_session.last_seen_at,
            user_agent: new_session.user_agent,
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

    pub async fn get_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<SessionTable>, AuthError> {
        let response = self
            .client
            .query()
            .table_name(&self.sessions_table)
            .index_name(&self.sessions_user_id_index)
            .key_condition_expression("user_id = :user_id")
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB query sessions failed: {e}")))?;

        let items = response.items.unwrap_or_default();

        items
            .into_iter()
            .map(|item| {
                serde_dynamo::aws_sdk_dynamodb_1::from_item::<SessionTable>(item)
                    .map_err(|e| AuthError::Internal(format!("Failed to deserialize session: {e}")))
            })
            .collect()
    }

    pub async fn update_session_last_seen(
        &self,
        id: &str,
        last_seen_at: i64,
    ) -> Result<(), AuthError> {
        self.client
            .update_item()
            .table_name(&self.sessions_table)
            .key("id", AttributeValue::S(id.to_string()))
            .update_expression("SET last_seen_at = :last_seen_at")
            .expression_attribute_values(
                ":last_seen_at",
                AttributeValue::N(last_seen_at.to_string()),
            )
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to update session activity: {e}")))?;

        Ok(())
    }
}
