#[allow(clippy::collapsible_if, dead_code, unused_imports)]
pub mod active_response;
pub mod auto_response;
pub mod file_quarantine;
#[allow(clippy::println_empty_string, dead_code, unused_must_use)]
pub mod firewall;
pub mod integrity;
#[cfg(any(target_os = "linux", test))]
pub mod linux_command_plan;
#[cfg(any(target_os = "linux", test))]
pub mod linux_firewall_backend;
#[cfg(any(target_os = "linux", test))]
pub mod linux_firewall_executor;
pub mod operator_provenance;
pub mod policy;
pub mod quarantine;
pub mod registry;
pub mod response_rules;
pub mod tamper;
pub mod update;
#[cfg(windows)]
pub mod windows_wfp;

#[cfg(test)]
mod tests {
    #[test]
    fn active_response_facade_exports_remain_available() {
        let _: fn(u32, &str, &str) -> Result<String, String> =
            crate::security::active_response::apply_quarantine_profile;
        let _: fn() -> Result<String, String> =
            crate::security::active_response::revert_frozen_autoruns;
    }
}
