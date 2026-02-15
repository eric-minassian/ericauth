use serde_dynamo::aws_sdk_dynamodb_1::{from_item, to_item};

use crate::{audit::AuditEventRecord, error::AuthError};

use super::DynamoDb;

impl DynamoDb {
    pub async fn insert_audit_event(&self, event: &AuditEventRecord) -> Result<(), AuthError> {
        let item = to_item(event)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize audit event: {e}")))?;

        self.client
            .put_item()
            .table_name(&self.audit_events_table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(id)")
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to insert audit event: {e}")))?;

        Ok(())
    }

    pub async fn list_audit_events(&self) -> Result<Vec<AuditEventRecord>, AuthError> {
        let response = self
            .client
            .scan()
            .table_name(&self.audit_events_table)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to list audit events: {e}")))?;

        let mut events: Vec<AuditEventRecord> = response
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|item| {
                from_item::<AuditEventRecord>(item).map_err(|e| {
                    AuthError::Internal(format!("Failed to deserialize audit event: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        events.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });

        Ok(events)
    }
}
