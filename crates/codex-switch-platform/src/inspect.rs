use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use codex_switch_domain::{
    SourceType, SwitchError,
    session::{AuthMode, fingerprint_account, mask_account_label},
};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthInspection {
    pub auth_mode: AuthMode,
    pub source_type: SourceType,
    pub account_label_masked: String,
    pub account_fingerprint: String,
    pub email: Option<String>,
    pub subject: Option<String>,
    pub account_id: Option<String>,
    pub last_refresh_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct AuthDocument {
    #[serde(rename = "OPENAI_API_KEY")]
    pub openai_api_key: Option<String>,
    pub auth_mode: Option<String>,
    pub last_refresh: Option<String>,
    pub tokens: Option<AuthTokens>,
}

#[derive(Debug, Deserialize)]
pub struct AuthTokens {
    pub id_token: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub account_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    email: Option<String>,
    sub: Option<String>,
}

pub fn inspect_auth_json(contents: &str) -> Result<AuthInspection, SwitchError> {
    let document: AuthDocument = serde_json::from_str(contents)?;
    let token_claims = document
        .tokens
        .as_ref()
        .and_then(|tokens| tokens.id_token.as_deref())
        .and_then(extract_claims_from_id_token);
    let source_type = if document.openai_api_key.is_some()
        || matches!(document.auth_mode.as_deref(), Some("api_key"))
    {
        SourceType::ApiKey
    } else if document
        .tokens
        .as_ref()
        .is_some_and(|tokens| tokens.refresh_token.is_some() || tokens.access_token.is_some())
    {
        SourceType::ChatGpt
    } else {
        SourceType::Unknown
    };

    let auth_mode = match source_type {
        SourceType::ApiKey => AuthMode::ApiKey,
        SourceType::ChatGpt => AuthMode::ChatGpt,
        SourceType::Unknown => AuthMode::Unknown,
    };

    let email = token_claims.as_ref().and_then(|claims| claims.email.clone());
    let subject = token_claims.as_ref().and_then(|claims| claims.sub.clone());
    let account_id = document.tokens.as_ref().and_then(|tokens| tokens.account_id.clone());

    let raw_account = if let Some(email) = &email {
        email.clone()
    } else if let Some(account_id) = &account_id {
        account_id.clone()
    } else if let Some(subject) = &subject {
        subject.clone()
    } else if let Some(api_key) = &document.openai_api_key {
        api_key.clone()
    } else {
        "unknown".to_string()
    };

    let last_refresh_at = document
        .last_refresh
        .as_deref()
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|dt| dt.with_timezone(&Utc));

    Ok(AuthInspection {
        auth_mode,
        source_type,
        account_label_masked: mask_account_label(&raw_account),
        account_fingerprint: fingerprint_account(&raw_account),
        email,
        subject,
        account_id,
        last_refresh_at,
    })
}

fn extract_claims_from_id_token(token: &str) -> Option<JwtClaims> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_auth_json_prefers_email_claim() {
        let payload =
            URL_SAFE_NO_PAD.encode(r#"{"email":"teammate@example.com","sub":"acct_123"}"#);
        let json = format!(
            r#"{{
                "auth_mode":"chatgpt",
                "last_refresh":"2026-04-13T00:00:00Z",
                "tokens": {{
                    "id_token":"aaa.{payload}.ccc",
                    "access_token":"access",
                    "refresh_token":"refresh",
                    "account_id":"acct_123"
                }}
            }}"#
        );
        let inspection = inspect_auth_json(&json).expect("inspection");
        assert_eq!(inspection.source_type, SourceType::ChatGpt);
        assert_eq!(inspection.account_label_masked, "te***@example.com");
        assert_eq!(inspection.email.as_deref(), Some("teammate@example.com"));
        assert_eq!(inspection.subject.as_deref(), Some("acct_123"));
        assert_eq!(inspection.account_id.as_deref(), Some("acct_123"));
    }

    #[test]
    fn inspect_auth_json_keeps_account_id_for_discovery_without_email_claim() {
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"acct_456"}"#);
        let json = format!(
            r#"{{
                "auth_mode":"chatgpt",
                "tokens": {{
                    "id_token":"aaa.{payload}.ccc",
                    "refresh_token":"refresh",
                    "account_id":"acct_456"
                }}
            }}"#
        );

        let inspection = inspect_auth_json(&json).expect("inspection");

        assert_eq!(inspection.account_label_masked, "acct_***56");
        assert_eq!(inspection.subject.as_deref(), Some("acct_456"));
        assert_eq!(inspection.account_id.as_deref(), Some("acct_456"));
    }
}
