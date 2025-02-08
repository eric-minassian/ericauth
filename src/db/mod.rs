mod users;

use aws_config::SdkConfig;

pub struct Database {
    ddb_client: aws_sdk_dynamodb::Client,
}

impl Database {
    pub async fn new() -> Self {
        let config = aws_config::load_from_env().await;
        let ddb_client = aws_sdk_dynamodb::Client::new(&config);
        Self { ddb_client }
    }

    pub fn with_config(config: &SdkConfig) -> Self {
        let ddb_client = aws_sdk_dynamodb::Client::new(config);

        Self { ddb_client }
    }
}
