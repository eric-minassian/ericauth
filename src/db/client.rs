use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientTable {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub client_name: String,
}

impl DynamoDb {
    pub async fn get_client(&self, client_id: &str) -> Result<Option<ClientTable>, AuthError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.clients_table)
            .key("client_id", AttributeValue::S(client_id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB get client failed: {e}")))?;

        match response.item {
            Some(item) => {
                let client = serde_dynamo::aws_sdk_dynamodb_1::from_item::<ClientTable>(item)
                    .map_err(|e| {
                        AuthError::Internal(format!("Failed to deserialize client: {e}"))
                    })?;
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }
}
