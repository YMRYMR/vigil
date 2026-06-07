//! UI-independent firewall/active-response status model.
//!
//! This module keeps firewall backend facts and active-response counters in a
//! small pure model so status rendering can be tested without WFP, nftables, or
//! XDP access.

use super::FirewallBackend;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallBackendState {
    pub label: String,
    pub available: bool,
    pub outbound_block_supported: Option<bool>,
    pub observed_isolation_active: Option<bool>,
}

impl FirewallBackendState {
    pub fn from_backend(backend: &dyn FirewallBackend) -> Self {
        Self {
            label: backend.label().to_string(),
            available: backend.is_available(),
            outbound_block_supported: backend.outbound_block_supported(),
            observed_isolation_active: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ActiveResponseState {
    pub isolated: bool,
    pub blocked_ip_count: usize,
    pub blocked_process_count: usize,
    pub blocked_domain_count: usize,
    pub suspended_process_count: usize,
    pub frozen_autorun_count: usize,
}

impl From<crate::security::active_response::Status> for ActiveResponseState {
    fn from(status: crate::security::active_response::Status) -> Self {
        Self {
            isolated: status.isolated,
            blocked_ip_count: status
                .blocked_rules
                .saturating_sub(status.blocked_processes),
            blocked_process_count: status.blocked_processes,
            blocked_domain_count: status.blocked_domains,
            suspended_process_count: status.suspended_processes,
            frozen_autorun_count: usize::from(status.frozen_autoruns),
        }
    }
}

impl From<crate::security::active_response::FirewallRuleList> for ActiveResponseState {
    fn from(rules: crate::security::active_response::FirewallRuleList) -> Self {
        Self::from(&rules)
    }
}

impl From<&crate::security::active_response::FirewallRuleList> for ActiveResponseState {
    fn from(rules: &crate::security::active_response::FirewallRuleList) -> Self {
        Self {
            isolated: rules.isolated,
            blocked_ip_count: rules.blocked_ips.len(),
            blocked_process_count: rules.blocked_processes.len(),
            blocked_domain_count: rules.blocked_domains.len(),
            suspended_process_count: rules.suspended_processes.len(),
            frozen_autorun_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallStatusModel {
    pub backend_label: String,
    pub backend_available: bool,
    pub isolation_active: bool,
    pub blocked_ip_count: usize,
    pub blocked_process_count: usize,
    pub blocked_domain_count: usize,
    pub suspended_process_count: usize,
    pub frozen_autorun_count: usize,
    pub outbound_block_supported: Option<bool>,
    pub warnings: Vec<String>,
}

pub fn build_firewall_status_model(
    backend: FirewallBackendState,
    response: ActiveResponseState,
) -> FirewallStatusModel {
    let mut warnings = Vec::new();

    if !backend.available {
        warnings.push(format!(
            "Firewall backend '{}' is unavailable.",
            backend.label
        ));
    }

    if response.isolated {
        warnings.push("Network isolation is active.".to_string());
    }

    if backend.outbound_block_supported.is_none() {
        warnings.push("Outbound blocking support is unknown for this backend.".to_string());
    }

    if let Some(observed) = backend.observed_isolation_active {
        if observed != response.isolated {
            warnings.push(format!(
                "Isolation state mismatch: active-response state is {}, backend reports {}.",
                bool_label(response.isolated),
                bool_label(observed)
            ));
        }
    }

    FirewallStatusModel {
        backend_label: backend.label,
        backend_available: backend.available,
        isolation_active: response.isolated,
        blocked_ip_count: response.blocked_ip_count,
        blocked_process_count: response.blocked_process_count,
        blocked_domain_count: response.blocked_domain_count,
        suspended_process_count: response.suspended_process_count,
        frozen_autorun_count: response.frozen_autorun_count,
        outbound_block_supported: backend.outbound_block_supported,
        warnings,
    }
}

pub fn current_model() -> FirewallStatusModel {
    build_firewall_status_model(
        FirewallBackendState::from_backend(super::get_backend()),
        crate::security::active_response::list_rules().into(),
    )
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "active"
    } else {
        "inactive"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(available: bool) -> FirewallBackendState {
        FirewallBackendState {
            label: "test-firewall".to_string(),
            available,
            outbound_block_supported: Some(true),
            observed_isolation_active: None,
        }
    }

    #[test]
    fn available_backend_with_no_active_response_state_has_no_warnings() {
        let model = build_firewall_status_model(backend(true), ActiveResponseState::default());

        assert_eq!(model.backend_label, "test-firewall");
        assert!(model.backend_available);
        assert!(!model.isolation_active);
        assert_eq!(model.blocked_ip_count, 0);
        assert_eq!(model.blocked_process_count, 0);
        assert_eq!(model.blocked_domain_count, 0);
        assert!(model.warnings.is_empty());
    }

    #[test]
    fn unavailable_backend_adds_warning() {
        let model = build_firewall_status_model(backend(false), ActiveResponseState::default());

        assert_eq!(
            model.warnings,
            vec!["Firewall backend 'test-firewall' is unavailable."]
        );
    }

    #[test]
    fn isolation_active_adds_warning() {
        let model = build_firewall_status_model(
            backend(true),
            ActiveResponseState {
                isolated: true,
                ..ActiveResponseState::default()
            },
        );

        assert!(model
            .warnings
            .contains(&"Network isolation is active.".to_string()));
    }

    #[test]
    fn outbound_support_unknown_adds_warning() {
        let mut backend = backend(true);
        backend.outbound_block_supported = None;

        let model = build_firewall_status_model(backend, ActiveResponseState::default());

        assert!(model
            .warnings
            .contains(&"Outbound blocking support is unknown for this backend.".to_string()));
    }

    #[test]
    fn nonzero_response_counts_are_preserved() {
        let model = build_firewall_status_model(
            backend(true),
            ActiveResponseState {
                blocked_ip_count: 2,
                blocked_process_count: 3,
                blocked_domain_count: 4,
                suspended_process_count: 5,
                frozen_autorun_count: 1,
                ..ActiveResponseState::default()
            },
        );

        assert_eq!(model.blocked_ip_count, 2);
        assert_eq!(model.blocked_process_count, 3);
        assert_eq!(model.blocked_domain_count, 4);
        assert_eq!(model.suspended_process_count, 5);
        assert_eq!(model.frozen_autorun_count, 1);
    }

    #[test]
    fn isolation_state_mismatch_adds_warning_when_detected() {
        let mut backend = backend(true);
        backend.observed_isolation_active = Some(true);

        let model = build_firewall_status_model(backend, ActiveResponseState::default());

        assert_eq!(
            model.warnings,
            vec![
                "Isolation state mismatch: active-response state is inactive, backend reports active."
            ]
        );
    }

    #[test]
    fn active_response_status_derives_blocked_ip_count() {
        let response = ActiveResponseState::from(crate::security::active_response::Status {
            blocked_rules: 7,
            blocked_processes: 3,
            blocked_domains: 2,
            suspended_processes: 1,
            frozen_autoruns: true,
            isolated: false,
        });

        assert_eq!(response.blocked_ip_count, 4);
        assert_eq!(response.blocked_process_count, 3);
        assert_eq!(response.blocked_domain_count, 2);
        assert_eq!(response.suspended_process_count, 1);
        assert_eq!(response.frozen_autorun_count, 1);
    }
}
