use std::env;

use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlConfig {
    pub sp_entity_id: String,
    pub sp_acs_url: String,
    pub idp_entity_id: String,
    pub idp_sso_url: String,
}

impl SamlConfig {
    pub fn from_issuer_url(issuer_url: &str) -> Self {
        Self {
            sp_entity_id: format!("{issuer_url}/saml/sp"),
            sp_acs_url: format!("{issuer_url}/saml/acs"),
            idp_entity_id: format!("{issuer_url}/saml/idp"),
            idp_sso_url: format!("{issuer_url}/saml/sso"),
        }
    }

    pub fn from_env(issuer_url: &str) -> Self {
        let defaults = Self::from_issuer_url(issuer_url);

        Self {
            sp_entity_id: env::var("SAML_SP_ENTITY_ID").unwrap_or(defaults.sp_entity_id),
            sp_acs_url: env::var("SAML_SP_ACS_URL").unwrap_or(defaults.sp_acs_url),
            idp_entity_id: env::var("SAML_IDP_ENTITY_ID").unwrap_or(defaults.idp_entity_id),
            idp_sso_url: env::var("SAML_IDP_SSO_URL").unwrap_or(defaults.idp_sso_url),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.sp_entity_id.trim().is_empty() {
            return Err("invalid SAML SP entity ID");
        }

        if self.idp_entity_id.trim().is_empty() {
            return Err("invalid SAML IdP entity ID");
        }

        validate_url(&self.sp_acs_url, "invalid SAML SP ACS URL")?;
        validate_url(&self.idp_sso_url, "invalid SAML IdP SSO URL")?;

        Ok(())
    }

    pub fn sp_metadata_xml(&self) -> Result<String, &'static str> {
        self.validate()?;

        Ok(format!(
            "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"{}\"><SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"{}\" index=\"0\" isDefault=\"true\"/></SPSSODescriptor></EntityDescriptor>",
            escape_xml(&self.sp_entity_id),
            escape_xml(&self.sp_acs_url),
        ))
    }

    pub fn idp_metadata_xml(&self) -> Result<String, &'static str> {
        self.validate()?;

        Ok(format!(
            "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"{}\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{}\"/></IDPSSODescriptor></EntityDescriptor>",
            escape_xml(&self.idp_entity_id),
            escape_xml(&self.idp_sso_url),
        ))
    }
}

fn validate_url(value: &str, error: &'static str) -> Result<(), &'static str> {
    let parsed = Url::parse(value).map_err(|_| error)?;

    if parsed.host_str().is_none() {
        return Err(error);
    }

    Ok(())
}

fn escape_xml(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> SamlConfig {
        SamlConfig {
            sp_entity_id: "https://auth.test.example.com/saml/sp".to_string(),
            sp_acs_url: "https://auth.test.example.com/saml/acs".to_string(),
            idp_entity_id: "https://idp.test.example.com/saml".to_string(),
            idp_sso_url: "https://idp.test.example.com/saml/sso".to_string(),
        }
    }

    #[test]
    fn test_sp_metadata_serialization() {
        let xml = sample_config().sp_metadata_xml().unwrap();

        assert!(xml.contains("<EntityDescriptor"));
        assert!(xml.contains("entityID=\"https://auth.test.example.com/saml/sp\""));
        assert!(xml.contains("<SPSSODescriptor"));
        assert!(xml.contains("AssertionConsumerService"));
        assert!(xml.contains("Location=\"https://auth.test.example.com/saml/acs\""));
    }

    #[test]
    fn test_idp_metadata_serialization() {
        let xml = sample_config().idp_metadata_xml().unwrap();

        assert!(xml.contains("<EntityDescriptor"));
        assert!(xml.contains("entityID=\"https://idp.test.example.com/saml\""));
        assert!(xml.contains("<IDPSSODescriptor"));
        assert!(xml.contains("SingleSignOnService"));
        assert!(xml.contains("Location=\"https://idp.test.example.com/saml/sso\""));
    }

    #[test]
    fn test_validate_rejects_empty_entity_id() {
        let mut config = sample_config();
        config.sp_entity_id = " ".to_string();

        assert_eq!(config.validate(), Err("invalid SAML SP entity ID"));
    }

    #[test]
    fn test_validate_rejects_invalid_url() {
        let mut config = sample_config();
        config.idp_sso_url = "not-a-url".to_string();

        assert_eq!(config.validate(), Err("invalid SAML IdP SSO URL"));
    }
}
