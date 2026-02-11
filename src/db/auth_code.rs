use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthCodeTable {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub auth_time: i64,
    pub expires_at: i64,
    #[serde(default)]
    pub used_at: Option<i64>,
}

impl DynamoDb {
    pub async fn insert_auth_code(&self, auth_code: &AuthCodeTable) -> Result<(), AuthError> {
        let item = serde_dynamo::aws_sdk_dynamodb_1::to_item(auth_code)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize auth code: {e}")))?;

        self.client
            .put_item()
            .table_name(&self.auth_codes_table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to insert auth code: {e}")))?;

        Ok(())
    }

    pub async fn redeem_auth_code(&self, code: &str) -> Result<Option<AuthCodeTable>, AuthError> {
        let now = chrono::Utc::now().timestamp();

        // Conditional update: mark as used only if not already used and not expired
        let result = self
            .client
            .update_item()
            .table_name(&self.auth_codes_table)
            .key("code", AttributeValue::S(code.to_string()))
            .update_expression("SET used_at = :now")
            .condition_expression(
                "attribute_exists(code) AND attribute_not_exists(used_at) AND expires_at > :now",
            )
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await;

        match result {
            Ok(output) => {
                if let Some(attrs) = output.attributes {
                    let auth_code =
                        serde_dynamo::aws_sdk_dynamodb_1::from_item::<AuthCodeTable>(attrs)
                            .map_err(|e| {
                                AuthError::Internal(format!("Failed to deserialize auth code: {e}"))
                            })?;
                    Ok(Some(auth_code))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                let service_err = e.into_service_error();
                if service_err.is_conditional_check_failed_exception() {
                    Ok(None)
                } else {
                    Err(AuthError::Internal(format!(
                        "Failed to redeem auth code: {service_err}"
                    )))
                }
            }
        }
    }
}
