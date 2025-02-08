use std::{env, sync::LazyLock};

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_dynamo::aws_sdk_dynamodb_1::to_item;
use uuid::Uuid;

use super::Database;

static SESSIONS_TABLE_NAME: LazyLock<String> =
    LazyLock::new(|| env::var("SESSIONS_TABLE_NAME").unwrap_or("SessionsTable".to_string()));

#[derive(Serialize, Deserialize)]
pub struct SessionTable {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: DateTime<chrono::Utc>,
}

impl Database {
    pub async fn insert_session(
        &self,
        id: String,
        user_id: Uuid,
        expires_at: DateTime<chrono::Utc>,
    ) -> Result<(), String> {
        let session = SessionTable {
            id,
            user_id,
            expires_at,
        };

        let item = to_item(&session).map_err(|_| "Failed to serialize session")?;

        self.ddb_client
            .put_item()
            .table_name(&*SESSIONS_TABLE_NAME)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|_| "Failed to insert session")?;

        Ok(())
    }
}
