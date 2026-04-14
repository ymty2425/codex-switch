use std::collections::BTreeSet;

use codex_switch_domain::{
    CredentialRef, OfficialCredentialStore, SourceType, SystemEntry, session::mask_account_label,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialDiscoveryTraceStatus {
    Matched,
    LookupMissed,
    MissingInput,
    SourceTypeMismatch,
    DuplicateCandidate,
    StoreUnavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialDiscoveryTraceEntry {
    pub rule_name: String,
    pub service: Option<String>,
    pub account_label_masked: Option<String>,
    pub label: Option<String>,
    pub status: CredentialDiscoveryTraceStatus,
    pub detail: String,
}

impl CredentialDiscoveryRegistry {
    #[must_use]
    pub fn new(custom_rules: Vec<CredentialDiscoveryRule>) -> Self {
        Self { rules: custom_rules }
    }

    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
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

            let Ok(reference) = expand_rule(rule, inspection) else {
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

    #[must_use]
    pub fn trace(
        &self,
        inspection: &AuthInspection,
        store: Option<&dyn OfficialCredentialStore>,
    ) -> Vec<CredentialDiscoveryTraceEntry> {
        let mut trace = Vec::new();
        let mut seen = BTreeSet::new();

        for rule in &self.rules {
            if rule.source_type.is_some_and(|source_type| source_type != inspection.source_type) {
                trace.push(CredentialDiscoveryTraceEntry {
                    rule_name: rule.name.clone(),
                    service: None,
                    account_label_masked: None,
                    label: None,
                    status: CredentialDiscoveryTraceStatus::SourceTypeMismatch,
                    detail: format!(
                        "Rule expects {:?}, but the current auth source is {:?}.",
                        rule.source_type.unwrap(),
                        inspection.source_type
                    ),
                });
                continue;
            }

            let expanded = match expand_rule(rule, inspection) {
                Ok(reference) => reference,
                Err(missing) => {
                    trace.push(CredentialDiscoveryTraceEntry {
                        rule_name: rule.name.clone(),
                        service: None,
                        account_label_masked: None,
                        label: rule.label.clone(),
                        status: CredentialDiscoveryTraceStatus::MissingInput,
                        detail: format!(
                            "Rule could not expand because {} is unavailable in auth.json.",
                            missing.join(", ")
                        ),
                    });
                    continue;
                }
            };

            let key = dedupe_key(&expanded);
            let service = Some(expanded.service.clone());
            let account_label_masked = Some(mask_account_label(&expanded.account));
            let label = expanded.label.clone();
            if !seen.insert(key) {
                trace.push(CredentialDiscoveryTraceEntry {
                    rule_name: rule.name.clone(),
                    service,
                    account_label_masked,
                    label,
                    status: CredentialDiscoveryTraceStatus::DuplicateCandidate,
                    detail: "Rule expands to a credential candidate that was already attempted."
                        .to_string(),
                });
                continue;
            }

            let Some(store) = store else {
                trace.push(CredentialDiscoveryTraceEntry {
                    rule_name: rule.name.clone(),
                    service,
                    account_label_masked,
                    label,
                    status: CredentialDiscoveryTraceStatus::StoreUnavailable,
                    detail: "No system credential store is available for lookup on this machine."
                        .to_string(),
                });
                continue;
            };

            match store.read(&[expanded.clone()]) {
                Ok(records) if !records.is_empty() => trace.push(CredentialDiscoveryTraceEntry {
                    rule_name: rule.name.clone(),
                    service,
                    account_label_masked,
                    label,
                    status: CredentialDiscoveryTraceStatus::Matched,
                    detail: "Credential lookup matched at least one system entry.".to_string(),
                }),
                _ => trace.push(CredentialDiscoveryTraceEntry {
                    rule_name: rule.name.clone(),
                    service,
                    account_label_masked,
                    label,
                    status: CredentialDiscoveryTraceStatus::LookupMissed,
                    detail: "Credential lookup completed but no matching system entry was found."
                        .to_string(),
                }),
            }
        }

        trace
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
) -> std::result::Result<CredentialRef, Vec<&'static str>> {
    let label = match rule.label.as_deref() {
        Some(label) => match expand_template(label, inspection) {
            Ok(expanded) if expanded.is_empty() => None,
            Ok(expanded) => Some(expanded),
            Err(missing) => return Err(missing),
        },
        None => None,
    };

    Ok(CredentialRef {
        service: expand_template(&rule.service, inspection)?,
        account: expand_template(&rule.account, inspection)?,
        label,
    })
}

fn expand_template(
    template: &str,
    inspection: &AuthInspection,
) -> std::result::Result<String, Vec<&'static str>> {
    let mut rendered = template.to_string();
    let mut missing = Vec::new();
    for (placeholder, name, value) in [
        ("{email}", "email", inspection.email.as_deref()),
        ("{subject}", "subject", inspection.subject.as_deref()),
        ("{account_id}", "account_id", inspection.account_id.as_deref()),
    ] {
        if rendered.contains(placeholder) {
            let value = match value {
                Some(value) => value,
                None => {
                    missing.push(name);
                    continue;
                }
            };
            rendered = rendered.replace(placeholder, value);
        }
    }

    if !missing.is_empty() {
        return Err(missing);
    }

    if rendered.contains('{') || rendered.contains('}') {
        return Err(vec!["template"]);
    }

    Ok(rendered)
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

        fn store_name(&self) -> &'static str {
            "mock_system_store"
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

    #[test]
    fn trace_reports_match_and_missing_input_states() {
        let registry = CredentialDiscoveryRegistry::new(vec![
            CredentialDiscoveryRule {
                name: "account-id".to_string(),
                source_type: Some(SourceType::ChatGpt),
                service: "openai".to_string(),
                account: "{account_id}".to_string(),
                label: None,
            },
            CredentialDiscoveryRule {
                name: "subject".to_string(),
                source_type: Some(SourceType::ChatGpt),
                service: "openai".to_string(),
                account: "{subject}".to_string(),
                label: None,
            },
        ]);
        let inspection = AuthInspection {
            auth_mode: AuthMode::ChatGpt,
            source_type: SourceType::ChatGpt,
            account_label_masked: "pe***@example.com".to_string(),
            account_fingerprint: "fingerprint".to_string(),
            email: Some("person@example.com".to_string()),
            subject: None,
            account_id: Some("acct_123".to_string()),
            last_refresh_at: None,
        };
        let store = MockStore {
            available: vec![SecretRecord {
                reference: CredentialRef {
                    service: "openai".to_string(),
                    account: "acct_123".to_string(),
                    label: None,
                },
                secret: SecretString::new("secret-token".into()),
            }],
        };

        let trace = registry.trace(&inspection, Some(&store));

        assert_eq!(trace.len(), 2);
        assert_eq!(trace[0].status, CredentialDiscoveryTraceStatus::Matched);
        assert_eq!(trace[0].account_label_masked.as_deref(), Some("acct_***23"));
        assert_eq!(trace[1].status, CredentialDiscoveryTraceStatus::MissingInput);
        assert!(trace[1].detail.contains("subject"));
    }
}
