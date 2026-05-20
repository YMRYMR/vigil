//! Linux nftables/iptables firewall backend.
//!
//! Routes through the existing executor bridge in `linux_firewall_executor.rs`
//! which handles nftables-preferred / iptables-fallback selection.

use super::{
    Action, Direction, Filter, FirewallBackend, FirewallProfileState, FirewallSnapshot, Profile,
};
use crate::security::linux_command_plan::{
    ip_link_set, ip_link_show, resolvectl_flush_caches, ss_kill_tcp_connection,
    systemd_resolve_flush_caches, LinuxCommandRunner, StdLinuxCommandRunner,
};
use crate::security::linux_firewall_backend::{
    capture_iptables_policy_snapshot, firewall_backend_restore_plan, select_firewall_backend,
    LinuxFirewallBackend,
};
use crate::security::linux_firewall_executor::{
    execute_selected_delete_plan, execute_selected_isolate_plan,
    execute_selected_remote_block_plan, execute_selected_uid_block_plan,
    execute_system_isolate_plan, execute_system_restore_plan, LinuxFirewallRestoreState,
};
use std::cell::RefCell;
use std::sync::Mutex;

pub struct NftablesBackend {
    restore_state: Mutex<Option<LinuxFirewallRestoreState>>,
}

impl NftablesBackend {
    pub fn new() -> Self {
        Self {
            restore_state: Mutex::new(None),
        }
    }

    fn runner(&self) -> StdLinuxCommandRunner {
        StdLinuxCommandRunner
    }
}

impl FirewallBackend for NftablesBackend {
    fn label(&self) -> &'static str {
        "nftables"
    }

    fn is_available(&self) -> bool {
        crate::platform::command_paths::resolve("nft").is_ok()
            || crate::platform::command_paths::resolve("iptables").is_ok()
    }

    fn snapshot_profiles(&self) -> Result<FirewallSnapshot, String> {
        let runner = self.runner();
        let backend = select_firewall_backend(&runner);
        match backend {
            LinuxFirewallBackend::Nftables => {
                let output = runner
                    .stdout(&crate::security::linux_command_plan::nft_list_ruleset())
                    .unwrap_or_default();
                let has_vigil_table = output.contains("table inet vigil");
                Ok(FirewallSnapshot {
                    profiles: vec![FirewallProfileState {
                        name: "iptables".into(),
                        enabled: has_vigil_table,
                        inbound_action: if has_vigil_table {
                            "DROP".into()
                        } else {
                            "ACCEPT".into()
                        },
                        outbound_action: if has_vigil_table {
                            "DROP".into()
                        } else {
                            "ACCEPT".into()
                        },
                    }],
                })
            }
            LinuxFirewallBackend::Iptables => {
                let snapshot = capture_iptables_policy_snapshot(&runner)?;
                let profiles: Vec<FirewallProfileState> = snapshot
                    .chains
                    .iter()
                    .map(|chain| FirewallProfileState {
                        name: chain.chain.clone(),
                        enabled: true,
                        inbound_action: if chain.chain == "INPUT" || chain.chain == "FORWARD" {
                            chain.policy.clone()
                        } else {
                            "ACCEPT".into()
                        },
                        outbound_action: if chain.chain == "OUTPUT" {
                            chain.policy.clone()
                        } else {
                            "ACCEPT".into()
                        },
                    })
                    .collect();
                Ok(FirewallSnapshot { profiles })
            }
        }
    }

    fn apply_isolation(&self, rule_name: &str) -> Result<(), String> {
        let runner = self.runner();
        let result =
            execute_selected_isolate_plan(&runner, rule_name).map_err(|(msg, _state)| msg)?;
        *self.restore_state.lock().unwrap() = result.restore_state;
        Ok(())
    }

    fn restore_profiles(&self, _snapshot: &FirewallSnapshot) -> Result<(), String> {
        let state = self
            .restore_state
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| "no isolation restore state available".to_string())?;
        execute_system_restore_plan(&state)?;
        Ok(())
    }

    fn add_block_rule(&self, rule_name: &str, target: &str) -> Result<(), String> {
        let runner = self.runner();
        execute_selected_remote_block_plan(&runner, rule_name, target)?;
        Ok(())
    }

    fn add_block_program_rule(
        &self,
        rule_name: &str,
        pid: u32,
        _path: &str,
        direction: &str,
    ) -> Result<(), String> {
        let uid = read_uid_for_pid(pid)?;
        let runner = self.runner();
        execute_selected_uid_block_plan(&runner, rule_name, direction, uid)?;
        Ok(())
    }

    fn delete_rule(&self, rule_name: &str) -> Result<(), String> {
        execute_selected_delete_plan(&self.runner(), rule_name)
    }

    fn rule_present(&self, rule_name: &str) -> Result<bool, String> {
        let runner = self.runner();
        let backend = select_firewall_backend(&runner);
        match backend {
            LinuxFirewallBackend::Nftables => {
                let output = runner.stdout(
                    &crate::security::linux_command_plan::nft_list_chain_handles(
                        crate::security::linux_command_plan::NFT_OUTPUT_CHAIN,
                    ),
                )?;
                Ok(output.contains(&format!("Vigil:{rule_name}")))
            }
            LinuxFirewallBackend::Iptables => {
                let output =
                    runner.stdout(&crate::security::linux_command_plan::iptables_list_rules())?;
                Ok(output.contains(&format!("Vigil:{rule_name}")))
            }
        }
    }

    fn isolation_controls_active(
        &self,
        _firewall_snapshot: Option<&FirewallSnapshot>,
    ) -> Result<bool, String> {
        let runner = self.runner();
        let backend = select_firewall_backend(&runner);
        match backend {
            LinuxFirewallBackend::Nftables => {
                let output =
                    runner.stdout(&crate::security::linux_command_plan::nft_list_ruleset())?;
                Ok(output.contains("table inet vigil")
                    && output.contains("isolin")
                    && output.contains("drop"))
            }
            LinuxFirewallBackend::Iptables => {
                let snapshot = capture_iptables_policy_snapshot(&runner)?;
                Ok(snapshot.chains.iter().all(|c| c.policy == "DROP"))
            }
        }
    }

    fn kill_tcp_connection(&self, local: &str, remote: &str) -> Result<(), String> {
        let (local_ip, local_port_str) = local
            .rsplit_once(':')
            .ok_or_else(|| format!("invalid local address: {local}"))?;
        let (remote_ip, remote_port_str) = remote
            .rsplit_once(':')
            .ok_or_else(|| format!("invalid remote address: {remote}"))?;
        let local_port: u16 = local_port_str
            .parse()
            .map_err(|_| format!("invalid local port: {local_port_str}"))?;
        let remote_port: u16 = remote_port_str
            .parse()
            .map_err(|_| format!("invalid remote port: {remote_port_str}"))?;
        self.runner().status(&ss_kill_tcp_connection(
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        ))
    }

    fn terminate_active_connections(&self) -> Result<usize, String> {
        let runner = self.runner();
        let output = runner.stdout(
            &crate::security::linux_command_plan::ss_kill_tcp_connection(
                "0.0.0.0", 0, "0.0.0.0", 0,
            ),
        );
        // Enumerate ESTABLISHED connections via ss and kill each.
        let ss_output = runner
            .stdout(&crate::security::linux_command_plan::LinuxCommand::new(
                "ss",
                ["-t", "-n", "state", "established"],
            ))
            .unwrap_or_default();
        let mut killed = 0usize;
        for line in ss_output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            let local = parts[3];
            let remote = parts[4];
            let (lip, lp) = match local.rsplit_once(':') {
                Some(p) => p,
                None => continue,
            };
            let (rip, rp) = match remote.rsplit_once(':') {
                Some(p) => p,
                None => continue,
            };
            let lport: u16 = match lp.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let rport: u16 = match rp.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if runner
                .status(
                    &crate::security::linux_command_plan::ss_kill_tcp_connection(
                        lip, lport, rip, rport,
                    ),
                )
                .is_ok()
            {
                killed += 1;
            }
        }
        Ok(killed)
    }

    fn add_domain_block(&self, domain: &str, marker: &str) -> Result<(), String> {
        let path = "/etc/hosts";
        let mut content = std::fs::read_to_string(path).unwrap_or_default();
        if !content.trim_end().ends_with('\n') {
            content.push('\n');
        }
        content.push_str(&format!("127.0.0.1 {domain}\n"));
        content.push_str(&format!("::1 {domain}\n"));
        content.push_str(&format!("{marker}\n"));
        std::fs::write(path, &content).map_err(|e| format!("failed to write hosts file: {e}"))?;
        Ok(())
    }

    fn remove_domain_block(&self, domain: &str, marker: &str) -> Result<(), String> {
        let path = "/etc/hosts";
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("failed to read hosts file: {e}"))?;
        let filtered: Vec<&str> = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                let is_domain_line = trimmed.split_whitespace().any(|part| part == domain);
                !is_domain_line && !trimmed.eq_ignore_ascii_case(marker.trim())
            })
            .collect();
        std::fs::write(path, filtered.join("\n") + "\n")
            .map_err(|e| format!("failed to write hosts file: {e}"))?;
        Ok(())
    }

    fn flush_dns(&self) -> Result<(), String> {
        let runner = self.runner();
        if runner.status(&resolvectl_flush_caches()).is_ok() {
            return Ok(());
        }
        runner.status(&systemd_resolve_flush_caches())
    }
}

fn read_uid_for_pid(pid: u32) -> Result<u32, String> {
    let status_path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(&status_path)
        .map_err(|e| format!("read /proc/{pid}/status: {e}"))?;
    for line in content.lines() {
        if let Some(uid_str) = line.strip_prefix("Uid:") {
            if let Some(uid) = uid_str.split_whitespace().next() {
                return uid
                    .parse::<u32>()
                    .map_err(|_| format!("invalid Uid in /proc/{pid}/status: {uid}"));
            }
        }
    }
    Err(format!("could not read effective uid for pid {pid}"))
}
