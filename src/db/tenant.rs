use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};
use serde_dynamo::aws_sdk_dynamodb_1::{from_item, to_item};

use crate::error::AuthError;

use super::{client::ClientTable, DynamoDb};

#[derive(Clone, Serialize, Deserialize)]
pub struct ProjectTable {
    pub project_id: String,
    pub name: String,
    pub client_ids: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TenantTable {
    pub tenant_id: String,
    pub name: String,
    pub projects: Vec<ProjectTable>,
}

impl DynamoDb {
    pub async fn insert_tenant(&self, tenant: TenantTable) -> Result<(), AuthError> {
        let item = to_item(&tenant)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize tenant: {e}")))?;

        self.client
            .put_item()
            .table_name(&self.tenants_table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(tenant_id)")
            .send()
            .await
            .map_err(|e| {
                let service_err = e.into_service_error();
                if service_err.is_conditional_check_failed_exception() {
                    AuthError::Conflict("tenant already exists".to_string())
                } else {
                    AuthError::Internal(format!("Failed to insert tenant: {service_err}"))
                }
            })?;

        Ok(())
    }

    pub async fn list_tenants(&self) -> Result<Vec<TenantTable>, AuthError> {
        let response = self
            .client
            .scan()
            .table_name(&self.tenants_table)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB list tenants failed: {e}")))?;

        let mut tenants = response
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|item| {
                from_item::<TenantTable>(item)
                    .map_err(|e| AuthError::Internal(format!("Failed to deserialize tenant: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        tenants.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));
        Ok(tenants)
    }

    pub async fn get_tenant(&self, tenant_id: &str) -> Result<Option<TenantTable>, AuthError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.tenants_table)
            .key("tenant_id", AttributeValue::S(tenant_id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB get tenant failed: {e}")))?;

        match response.item {
            Some(item) => {
                let tenant = from_item::<TenantTable>(item).map_err(|e| {
                    AuthError::Internal(format!("Failed to deserialize tenant: {e}"))
                })?;
                Ok(Some(tenant))
            }
            None => Ok(None),
        }
    }

    pub async fn delete_tenant(&self, tenant_id: &str) -> Result<(), AuthError> {
        self.client
            .delete_item()
            .table_name(&self.tenants_table)
            .key("tenant_id", AttributeValue::S(tenant_id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to delete tenant: {e}")))?;

        Ok(())
    }

    pub async fn add_project_to_tenant(
        &self,
        tenant_id: &str,
        project: ProjectTable,
    ) -> Result<(), AuthError> {
        let mut tenant = self
            .get_tenant(tenant_id)
            .await?
            .ok_or_else(|| AuthError::NotFound("tenant not found".to_string()))?;

        if tenant
            .projects
            .iter()
            .any(|existing| existing.project_id == project.project_id)
        {
            return Err(AuthError::Conflict("project already exists".to_string()));
        }

        tenant.projects.push(project);

        let item = to_item(&tenant)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize tenant: {e}")))?;

        self.client
            .put_item()
            .table_name(&self.tenants_table)
            .set_item(Some(item))
            .condition_expression("attribute_exists(tenant_id)")
            .send()
            .await
            .map_err(|e| {
                let service_err = e.into_service_error();
                if service_err.is_conditional_check_failed_exception() {
                    AuthError::NotFound("tenant not found".to_string())
                } else {
                    AuthError::Internal(format!("Failed to add project to tenant: {service_err}"))
                }
            })?;

        Ok(())
    }

    pub async fn get_client_for_tenant(
        &self,
        tenant_id: Option<&str>,
        client_id: &str,
    ) -> Result<Option<ClientTable>, AuthError> {
        let Some(client) = self.get_client(client_id).await? else {
            return Ok(None);
        };

        let Some(tenant_id) = tenant_id else {
            return Ok(Some(client));
        };

        let Some(tenant) = self.get_tenant(tenant_id).await? else {
            return Ok(None);
        };

        let in_tenant = tenant
            .projects
            .iter()
            .any(|project| project.client_ids.iter().any(|id| id == client_id));

        if in_tenant {
            Ok(Some(client))
        } else {
            Ok(None)
        }
    }
}
