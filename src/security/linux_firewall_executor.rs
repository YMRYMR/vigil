//! Linux firewall backend plan execution helpers.
//!
//! This is the narrow runtime bridge between backend-specific command plans and
//! an injectable command runner. It keeps execution sequencing testable before
//! the large platform active-response file is migrated to call it directly.

#[cfg(target_os = "linux")]
use super::linux_command_plan::StdLinuxCommandRunner;
use super::linux_command_plan::{LinuxCommand, LinuxCommandRunner};
use super::linux_firewall_backend::{
    capture_iptables_policy_snapshot, firewall_backend_block_remote_plan,
    firewall_backend_block_uid_plan, firewall_backend_isolate_plan,
    firewall_backend_restore_plan, firewall_backend_setup_plan, select_firewall_backend,
    IptablesPolicySnapshot, LinuxFirewallBackend,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxFirewallRestoreState {
    pub backend: LinuxFirewallBackend,
    pub iptables_policy_snapshot: Option<IptablesPolicySnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedLinuxFirewallPlan {
    pub backend: LinuxFirewallBackend,
    pub commands: Vec<LinuxCommand>,
    pub restore_state: Option<LinuxFirewallRestoreState>,
}

pub fn execute_firewall_plan(
    runner: &impl LinuxCommandRunner,
    backend: LinuxFirewallBackend,
    commands: Vec<LinuxCommand>,
    restore_state: Option<LinuxFirewallRestoreState>,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    for command in &commands {
        runner.status(command)?;
    }
    Ok(ExecutedLinuxFirewallPlan {
        backend,
        commands,
        restore_state,
    })
}

fn capture_restore_state(
    runner: &impl LinuxCommandRunner,
    backend: LinuxFirewallBackend,
) -> Result<LinuxFirewallRestoreState, String> {
    let iptables_policy_snapshot = match backend {
        LinuxFirewallBackend::Nftables => None,
        LinuxFirewallBackend::Iptables => Some(capture_iptables_policy_snapshot(runner)?),
    };
    Ok(LinuxFirewallRestoreState {
        backend,
        iptables_policy_snapshot,
    })
}

#[allow(dead_code)]
pub fn execute_selected_setup_plan(
    runner: &impl LinuxCommandRunner,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    let backend = select_firewall_backend(runner);
    execute_firewall_plan(
        runner,
        backend,
        firewall_backend_setup_plan(backend),
        None,
    )
}

pub fn execute_selected_isolate_plan(
    runner: &impl LinuxCommandRunner,
    rule_name: &str,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    let backend = select_firewall_backend(runner);
    let restore_state = capture_restore_state(runner, backend)?;
    let mut commands = firewall_backend_setup_plan(backend);
    commands.extend(firewall_backend_isolate_plan(backend, rule_name));
    execute_firewall_plan(runner, backend, commands, Some(restore_state))
}

pub fn execute_restore_plan(
    runner: &impl LinuxCommandRunner,
    restore_state: &LinuxFirewallRestoreState,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    let commands = firewall_backend_restore_plan(
        restore_state.backend,
        restore_state.iptables_policy_snapshot.as_ref(),
    )?;
    execute_firewall_plan(runner, restore_state.backend, commands, None)
}

pub fn execute_selected_remote_block_plan(
    runner: &impl LinuxCommandRunner,
    rule_name: &str,
    target: &str,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    let backend = select_firewall_backend(runner);
    let mut commands = firewall_backend_setup_plan(backend);
    commands.extend(firewall_backend_block_remote_plan(
        backend, rule_name, target,
    ));
    execute_firewall_plan(runner, backend, commands, None)
}

pub fn execute_selected_uid_block_plan(
    runner: &impl LinuxCommandRunner,
    rule_name: &str,
    direction: &str,
    uid: u32,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    let backend = select_firewall_backend(runner);
    let mut commands = firewall_backend_setup_plan(backend);
    commands.extend(firewall_backend_block_uid_plan(
        backend, rule_name, direction, uid,
    ));
    execute_firewall_plan(runner, backend, commands, None)
}

#[cfg(target_os = "linux")]
pub fn execute_system_isolate_plan(rule_name: &str) -> Result<ExecutedLinuxFirewallPlan, String> {
    execute_selected_isolate_plan(&StdLinuxCommandRunner, rule_name)
}

#[cfg(target_os = "linux")]
pub fn execute_system_restore_plan(
    restore_state: &LinuxFirewallRestoreState,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    execute_restore_plan(&StdLinuxCommandRunner, restore_state)
}

#[cfg(target_os = "linux")]
pub fn execute_system_remote_block_plan(
    rule_name: &str,
    target: &str,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    execute_selected_remote_block_plan(&StdLinuxCommandRunner, rule_name, target)
}

#[cfg(target_os = "linux")]
pub fn execute_system_uid_block_plan(
    rule_name: &str,
    direction: &str,
    uid: u32,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    execute_selected_uid_block_plan(&StdLinuxCommandRunner, rule_name, direction, uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct RecordingRunner {
        nft_available: bool,
        fail_program: Option<&'static str>,
        commands: RefCell<Vec<LinuxCommand>>,
    }

    impl RecordingRunner {
        fn new(nft_available: bool) -> Self {
            Self {
                nft_available,
                fail_program: None,
                commands: RefCell::new(Vec::new()),
            }
        }

        fn failing(nft_available: bool, fail_program: &'static str) -> Self {
            Self {
                nft_available,
                fail_program: Some(fail_program),
                commands: RefCell::new(Vec::new()),
            }
        }
    }

    impl LinuxCommandRunner for RecordingRunner {
        fn status(&self, command: &LinuxCommand) -> Result<(), String> {
            self.commands.borrow_mut().push(command.clone());
            if self.fail_program == Some(command.program) {
                Err(format!("{} failed", command.program))
            } else {
                Ok(())
            }
        }

        fn stdout(&self, command: &LinuxCommand) -> Result<String, String> {
            if command.program == "nft" && self.nft_available {
                Ok("table inet vigil".to_string())
            } else if command.program == "iptables" {
                Ok(
                    "Chain INPUT (policy ACCEPT)\nChain FORWARD (policy DROP)\nChain OUTPUT (policy ACCEPT)\n"
                        .to_string(),
                )
            } else {
                Err("not available".to_string())
            }
        }
    }

    #[test]
    fn selected_isolate_uses_nftables_setup_and_rules_when_available() {
        let runner = RecordingRunner::new(true);
        let executed = execute_selected_isolate_plan(&runner, "isolate").unwrap();
        assert_eq!(executed.backend, LinuxFirewallBackend::Nftables);
        assert_eq!(executed.commands.len(), 7);
        assert!(executed
            .commands
            .iter()
            .all(|command| command.program == "nft"));
        assert_eq!(runner.commands.borrow().len(), executed.commands.len());
        assert_eq!(
            executed.restore_state,
            Some(LinuxFirewallRestoreState {
                backend: LinuxFirewallBackend::Nftables,
                iptables_policy_snapshot: None,
            })
        );
    }

    #[test]
    fn selected_isolate_falls_back_to_iptables_when_nft_probe_fails() {
        let runner = RecordingRunner::new(false);
        let executed = execute_selected_isolate_plan(&runner, "isolate").unwrap();
        assert_eq!(executed.backend, LinuxFirewallBackend::Iptables);
        assert_eq!(
            executed.commands,
            vec![
                LinuxCommand::new("iptables", ["-P", "INPUT", "DROP"]),
                LinuxCommand::new("iptables", ["-P", "FORWARD", "DROP"]),
                LinuxCommand::new("iptables", ["-P", "OUTPUT", "DROP"]),
            ]
        );
        assert_eq!(
            executed.restore_state,
            Some(LinuxFirewallRestoreState {
                backend: LinuxFirewallBackend::Iptables,
                iptables_policy_snapshot: Some(IptablesPolicySnapshot {
                    chains: vec![
                        super::super::linux_firewall_backend::IptablesChainPolicy {
                            chain: "INPUT".to_string(),
                            policy: "ACCEPT".to_string(),
                        },
                        super::super::linux_firewall_backend::IptablesChainPolicy {
                            chain: "FORWARD".to_string(),
                            policy: "DROP".to_string(),
                        },
                        super::super::linux_firewall_backend::IptablesChainPolicy {
                            chain: "OUTPUT".to_string(),
                            policy: "ACCEPT".to_string(),
                        },
                    ],
                }),
            })
        );
    }

    #[test]
    fn remote_block_runs_setup_before_block_rule() {
        let runner = RecordingRunner::new(true);
        let executed =
            execute_selected_remote_block_plan(&runner, "block-v6", "2606:4700:4700::1111")
                .unwrap();
        assert_eq!(executed.backend, LinuxFirewallBackend::Nftables);
        assert_eq!(executed.commands.len(), 5);

        let last = executed.commands.last().unwrap();
        assert_eq!(last.program, "nft");
        assert_eq!(last.args[4], "output");
        assert_eq!(last.args[5], "ip6");
        assert_eq!(last.args[6], "daddr");
        assert_eq!(executed.restore_state, None);
    }

    #[test]
    fn uid_block_uses_backend_specific_command() {
        let nft_runner = RecordingRunner::new(true);
        let nft = execute_selected_uid_block_plan(&nft_runner, "uid", "out", 1000).unwrap();
        assert_eq!(nft.backend, LinuxFirewallBackend::Nftables);
        assert!(nft
            .commands
            .last()
            .unwrap()
            .args
            .iter()
            .any(|arg| arg == "skuid"));

        let iptables_runner = RecordingRunner::new(false);
        let iptables =
            execute_selected_uid_block_plan(&iptables_runner, "uid", "out", 1000).unwrap();
        assert_eq!(iptables.backend, LinuxFirewallBackend::Iptables);
        assert!(iptables
            .commands
            .last()
            .unwrap()
            .args
            .iter()
            .any(|arg| arg == "--uid-owner"));
        assert_eq!(iptables.restore_state, None);
    }

    #[test]
    fn execution_stops_on_first_command_failure() {
        let runner = RecordingRunner::failing(true, "nft");
        let err = execute_selected_isolate_plan(&runner, "isolate").unwrap_err();
        assert!(err.contains("nft failed"));
        assert_eq!(runner.commands.borrow().len(), 1);
    }

    #[test]
    fn restore_uses_backend_captured_during_isolation() {
        let iptables_runner = RecordingRunner::new(false);
        let isolated = execute_selected_isolate_plan(&iptables_runner, "isolate").unwrap();
        let restore_state = isolated.restore_state.as_ref().unwrap();

        let restore_runner = RecordingRunner::new(true);
        let restored = execute_restore_plan(&restore_runner, restore_state).unwrap();
        assert_eq!(restored.backend, LinuxFirewallBackend::Iptables);
        assert_eq!(
            restored.commands,
            vec![
                LinuxCommand::new("iptables", ["-P", "INPUT", "ACCEPT"]),
                LinuxCommand::new("iptables", ["-P", "FORWARD", "DROP"]),
                LinuxCommand::new("iptables", ["-P", "OUTPUT", "ACCEPT"]),
            ]
        );
    }

    #[test]
    fn restore_uses_selected_backend() {
        let nft_runner = RecordingRunner::new(true);
        let nft_isolated = execute_selected_isolate_plan(&nft_runner, "isolate").unwrap();
        let nft_restore = execute_restore_plan(&nft_runner, nft_isolated.restore_state.as_ref().unwrap())
            .unwrap();
        assert_eq!(nft_restore.backend, LinuxFirewallBackend::Nftables);
        assert_eq!(
            nft_restore.commands,
            vec![LinuxCommand::new(
                "nft",
                ["delete", "table", "inet", "vigil"]
            )]
        );
    }
}
