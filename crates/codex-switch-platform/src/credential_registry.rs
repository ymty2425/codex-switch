use std::collections::BTreeSet;

use codex_switch_domain::{CredentialRef, OfficialCredentialStore, SourceType, SystemEntry};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::inspect::AuthInspection;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialDiscoveryRule {
    pub name: String,
    pub source_type: Option<SourceType>,
    pub service: String,
    pub account: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CredentialDiscoveryRegistry {
    rules: Vec<CredentialDiscoveryRule>,
}

impl CredentialDiscoveryRegistry {
    #[must_use]
    pub fn new(custom_rules: Vec<CredentialDiscoveryRule>) -> Self {
        Self { rules: custom_rules }
    }

    #[must_use]
    pub fn standard_rules() -> Vec<CredentialDiscoveryRule> {
        vec![
            CredentialDiscoveryRule {
                name: "openai-account-id".to_string(),
                source_type: Some(SourceType::ChatGpt),
                service: "openai".to_string(),
                account: "{account_id}".to_string(),
                label: None,
            },
            CredentialDiscoveryRule {
                name: "openai-email".to_string(),
                source_type: Some(SourceType::ChatGpt),
                service: "openai".to_string(),
                account: "{email}".to_string(),
                label: None,
            },
            CredentialDiscoveryRule {
                name: "openai-subject".to_string(),
                source_type: Some(SourceType::ChatGpt),
                service: "openai".to_string(),
                account: "{subject}".to_string(),
                label: None,
            },
            CredentialDiscoveryRule {
                name: "chatgpt-account-id".to_string(),
                source_type: Some(SourceType::ChatGpt),
                service: "chatgpt".to_string(),
                account: "{account_id}".to_string(),
                label: None,
            },
            CredentialDiscoveryRule {
                name: "chatgpt-email".to_string(),
                source_type: Some(SourceType::ChatGpt),
                service: "chatgpt".to_string(),
                account: "{email}".to_string(),
                label: None,
            },
            CredentialDiscoveryRule {
                name: "chatgpt-subject".to_string(),
                source_type: Some(SourceType::ChatGpt),
                service: "chatgpt".to_string(),
                account: "{subject}".to_string(),
                label: None,
            },
        ]
    }

    #[must_use]
    pub fn discover(
        &self,
        inspection: &AuthInspection,
        store: &dyn OfficialCredentialStore,
    ) -> Vec<SystemEntry> {
        if !store.is_available() {
            return Vec::new();
        }

        let mut discovered = Vec::new();
        let mut seen = BTreeSet::new();

        for rule in &self.rules {
            if rule.source_type.is_some_and(|source_type| source_type != inspection.source_type) {
                continue;
            }

            let Some(reference) = expand_rule(rule, inspection) else {
                continue;
            };

            let key = dedupe_key(&reference);
            if !seen.insert(key) {
                continue;
            }

            let Ok(records) = store.read(&[reference.clone()]) else {
                continue;
            };

            for record in records {
                discovered.push(SystemEntry {
                    reference: record.reference,
                    masked_value_hint: mask_secret_value(record.secret.expose_secret()),
                });
            }
        }

        discovered
    }
}

impl Default for CredentialDiscoveryRegistry {
    fn default() -> Self {
        Self::new(Self::standard_rules())
    }
}

fn expand_rule(
    rule: &CredentialDiscoveryRule,
    inspection: &AuthInspection,
) -> Option<CredentialRef> {
    let label = match rule.label.as_deref() {
        Some(label) => {
            let expanded = expand_template(label, inspection)?;
            if expanded.is_empty() { None } else { Some(expanded) }
        }
        None => None,
    };

    Some(CredentialRef {
        service: expand_template(&rule.service, inspection)?,
        account: expand_template(&rule.account, inspection)?,
        label,
    })
}

fn expand_template(template: &str, inspection: &AuthInspection) -> Option<String> {
    let mut rendered = template.to_string();
    for (placeholder, value) in [
        ("{email}", inspection.email.as_deref()),
        ("{subject}", inspection.subject.as_deref()),
        ("{account_id}", inspection.account_id.as_deref()),
    ] {
        if rendered.contains(placeholder) {
            let value = value?;
            rendered = rendered.replace(placeholder, value);
        }
    }

    if rendered.contains('{') || rendered.contains('}') {
        return None;
    }

    Some(rendered)
}

fn dedupe_key(reference: &CredentialRef) -> String {
    format!(
        "{}:{}:{}",
        reference.service,
        reference.account,
        reference.label.as_deref().unwrap_or_default()
    )
}

fn mask_secret_value(secret: &str) -> String {
    let chars = secret.chars().collect::<Vec<_>>();
    if chars.is_empty() {
        return "unknown".to_string();
    }
    if chars.len() <= 4 {
        return "*".repeat(chars.len());
    }
    if chars.len() <= 8 {
        let prefix = chars.iter().take(2).collect::<String>();
        let suffix = chars[chars.len().saturating_sub(2)..].iter().collect::<String>();
        return format!("{prefix}…{suffix}");
    }

    let prefix = chars.iter().take(3).collect::<String>();
    let suffix = chars[chars.len().saturating_sub(4)..].iter().collect::<String>();
    format!("{prefix}…{suffix}")
}

#[cfg(test)]
mod tests {
    use codex_switch_domain::{AuthMode, CredentialMode, Result, SecretRecord, SwitchError};
    use secrecy::SecretString;

    use super::*;

    #[derive(Debug)]
    struct MockStore {
        available: Vec<SecretRecord>,
    }

    impl OfficialCredentialStore for MockStore {
        fn kind(&self) -> CredentialMode {
            CredentialMode::System
        }

        fn is_available(&self) -> bool {
            true
        }

        fn read(&self, refs: &[CredentialRef]) -> Result<Vec<SecretRecord>> {
            let mut matched = Vec::new();
            for wanted in refs {
                if let Some(record) =
                    self.available.iter().find(|record| &record.reference == wanted)
                {
                    matched.push(record.clone());
                }
            }
            if matched.is_empty() {
                Err(SwitchError::CredentialUnavailable("No matching system credential".to_string()))
            } else {
                Ok(matched)
            }
        }

        fn write(&self, _records: &[SecretRecord]) -> Result<()> {
            Ok(())
        }

        fn delete(&self, _refs: &[CredentialRef]) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn registry_discovers_matching_system_entry_from_templates() {
        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "openai-account".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Primary session".to_string()),
        }]);
        let inspection = AuthInspection {
            auth_mode: AuthMode::ChatGpt,
            source_type: SourceType::ChatGpt,
            account_label_masked: "pe***@example.com".to_string(),
            account_fingerprint: "fingerprint".to_string(),
            email: Some("person@example.com".to_string()),
            subject: Some("acct_123".to_string()),
            account_id: Some("acct_123".to_string()),
            last_refresh_at: None,
        };
        let store = MockStore {
            available: vec![SecretRecord {
                reference: CredentialRef {
                    service: "openai".to_string(),
                    account: "acct_123".to_string(),
                    label: Some("Primary session".to_string()),
                },
                secret: SecretString::new("secret-token".into()),
            }],
        };

        let discovered = registry.discover(&inspection, &store);

        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].reference.service, "openai");
        assert_eq!(discovered[0].masked_value_hint, "sec…oken");
    }

    #[test]
    fn registry_skips_rules_when_required_placeholder_is_missing() {
        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "email-based".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "openai".to_string(),
            account: "{email}".to_string(),
            label: None,
        }]);
        let inspection = AuthInspection {
            auth_mode: AuthMode::ChatGpt,
            source_type: SourceType::ChatGpt,
            account_label_masked: "acct_***56".to_string(),
            account_fingerprint: "fingerprint".to_string(),
            email: None,
            subject: Some("acct_456".to_string()),
            account_id: Some("acct_456".to_string()),
            last_refresh_at: None,
        };
        let store = MockStore { available: Vec::new() };

        let discovered = registry.discover(&inspection, &store);

        assert!(discovered.is_empty());
    }
}
