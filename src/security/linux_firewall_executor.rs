//! Linux firewall backend plan execution helpers.
//!
//! This is the narrow runtime bridge between backend-specific command plans and
//! an injectable command runner. It keeps execution sequencing testable before
//! the large platform active-response file is migrated to call it directly.

#[cfg(target_os = "linux")]
use super::linux_command_plan::StdLinuxCommandRunner;
use super::linux_command_plan::{
    iptables_delete_rule, nft_delete_rule_by_handle, nft_flush_chain, nft_list_chain_handles,
    nft_list_ruleset, nft_parse_handle_by_comment, LinuxCommand, LinuxCommandRunner,
    NFT_FORWARD_CHAIN, NFT_INPUT_CHAIN, NFT_ISOL_FORWARD_CHAIN, NFT_ISOL_IN_CHAIN,
    NFT_ISOL_OUT_CHAIN, NFT_OUTPUT_CHAIN,
};
use super::linux_firewall_backend::{
    capture_iptables_policy_snapshot, firewall_backend_block_remote_plan,
    firewall_backend_block_uid_plan, firewall_backend_isolate_plan, firewall_backend_restore_plan,
    firewall_backend_setup_plan, select_firewall_backend, IptablesPolicySnapshot,
    LinuxFirewallBackend,
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

fn nft_table_exists(runner: &impl LinuxCommandRunner) -> bool {
    runner
        .stdout(&nft_list_ruleset())
        .map(|ruleset| {
            ruleset.lines().any(|line| {
                let mut parts = line.split_whitespace();
                matches!(parts.next(), Some("table"))
                    && matches!(parts.next(), Some("inet"))
                    && matches!(parts.next(), Some("vigil"))
            })
        })
        .unwrap_or(false)
}

fn selected_setup_commands(
    runner: &impl LinuxCommandRunner,
    backend: LinuxFirewallBackend,
) -> Vec<LinuxCommand> {
    match backend {
        LinuxFirewallBackend::Nftables if nft_table_exists(runner) => Vec::new(),
        _ => firewall_backend_setup_plan(backend),
    }
}

#[allow(dead_code)]
pub fn execute_selected_setup_plan(
    runner: &impl LinuxCommandRunner,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    let backend = select_firewall_backend(runner);
    execute_firewall_plan(
        runner,
        backend,
        selected_setup_commands(runner, backend),
        None,
    )
}

pub fn execute_selected_isolate_plan(
    runner: &impl LinuxCommandRunner,
    rule_name: &str,
) -> Result<ExecutedLinuxFirewallPlan, (String, Option<LinuxFirewallRestoreState>)> {
    let backend = select_firewall_backend(runner);
    let restore_state = match capture_restore_state(runner, backend) {
        Ok(s) => s,
        Err(e) => return Err((e, None)),
    };
    let mut commands = Vec::new();
    if backend == LinuxFirewallBackend::Nftables && nft_table_exists(runner) {
        commands.push(nft_flush_chain(NFT_ISOL_IN_CHAIN));
        commands.push(nft_flush_chain(NFT_ISOL_FORWARD_CHAIN));
        commands.push(nft_flush_chain(NFT_ISOL_OUT_CHAIN));
    } else {
        commands.extend(selected_setup_commands(runner, backend));
    }
    commands.extend(firewall_backend_isolate_plan(backend, rule_name));
    for command in &commands {
        if let Err(e) = runner.status(command) {
            return Err((e, Some(restore_state)));
        }
    }
    Ok(ExecutedLinuxFirewallPlan {
        backend,
        commands,
        restore_state: Some(restore_state),
    })
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
    let mut commands = selected_setup_commands(runner, backend);
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
    let mut commands = selected_setup_commands(runner, backend);
    commands.extend(firewall_backend_block_uid_plan(
        backend, rule_name, direction, uid,
    ));
    execute_firewall_plan(runner, backend, commands, None)
}

#[cfg(target_os = "linux")]
pub fn execute_system_isolate_plan(rule_name: &str) -> Result<ExecutedLinuxFirewallPlan, String> {
    execute_selected_isolate_plan(&StdLinuxCommandRunner, rule_name).map_err(|(msg, _state)| msg)
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

pub fn execute_selected_delete_plan(
    runner: &impl LinuxCommandRunner,
    rule_name: &str,
) -> Result<(), String> {
    let backend = select_firewall_backend(runner);
    match backend {
        LinuxFirewallBackend::Nftables => {
            // Check both main chains and isolation sub-chains so that
            // isolation rules and remote/UID block rules are both found.
            for chain in &[
                NFT_INPUT_CHAIN,
                NFT_OUTPUT_CHAIN,
                NFT_FORWARD_CHAIN,
                NFT_ISOL_IN_CHAIN,
                NFT_ISOL_FORWARD_CHAIN,
                NFT_ISOL_OUT_CHAIN,
            ] {
                let output = match runner.stdout(&nft_list_chain_handles(chain)) {
                    Ok(o) => o,
                    // Chain may not exist yet (first isolation) - skip.
                    Err(_) => continue,
                };
                if let Some(handle) = nft_parse_handle_by_comment(&output, rule_name) {
                    runner.status(&nft_delete_rule_by_handle(chain, handle))?;
                }
            }
            Ok(())
        }
        LinuxFirewallBackend::Iptables => {
            let mut deleted_any = false;
            for chain in &["INPUT", "OUTPUT", "FORWARD"] {
                if runner
                    .status(&iptables_delete_rule(chain, rule_name))
                    .is_ok()
                {
                    deleted_any = true;
                }
            }
            if deleted_any {
                Ok(())
            } else {
                Err(format!(
                    "failed to delete firewall rule {rule_name} from all chains"
                ))
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub fn execute_system_delete_plan(rule_name: &str) -> Result<(), String> {
    execute_selected_delete_plan(&StdLinuxCommandRunner, rule_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct RecordingRunner {
        nft_available: bool,
        nft_ruleset_output: &'static str,
        fail_program: Option<&'static str>,
        commands: RefCell<Vec<LinuxCommand>>,
    }

    impl RecordingRunner {
        fn new(nft_available: bool) -> Self {
            Self {
                nft_available,
                nft_ruleset_output: if nft_available {
                    "table inet vigil"
                } else {
                    ""
                },
                fail_program: None,
                commands: RefCell::new(Vec::new()),
            }
        }

        fn nft_without_table() -> Self {
            Self {
                nft_available: true,
                nft_ruleset_output: "",
                fail_program: None,
                commands: RefCell::new(Vec::new()),
            }
        }

        fn failing(nft_available: bool, fail_program: &'static str) -> Self {
            Self {
                nft_available,
                nft_ruleset_output: if nft_available {
                    "table inet vigil"
                } else {
                    ""
                },
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
                Ok(self.nft_ruleset_output.to_string())
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
        assert_eq!(executed.commands.len(), 6);
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
    fn remote_block_runs_setup_before_first_nft_rule() {
        let runner = RecordingRunner::nft_without_table();
        let executed =
            execute_selected_remote_block_plan(&runner, "block-v6", "2606:4700:4700::1111")
                .unwrap();
        assert_eq!(executed.backend, LinuxFirewallBackend::Nftables);
        assert_eq!(executed.commands.len(), 11);

        let last = executed.commands.last().unwrap();
        assert_eq!(last.program, "nft");
        assert_eq!(last.args[4], "output");
        assert_eq!(last.args[5], "ip6");
        assert_eq!(last.args[6], "daddr");
        assert_eq!(executed.restore_state, None);
    }

    #[test]
    fn remote_block_skips_setup_when_nft_table_already_exists() {
        let runner = RecordingRunner::new(true);
        let executed =
            execute_selected_remote_block_plan(&runner, "block-v6", "2606:4700:4700::1111")
                .unwrap();
        assert_eq!(executed.backend, LinuxFirewallBackend::Nftables);
        assert_eq!(executed.commands.len(), 1);
        assert_eq!(executed.commands[0].program, "nft");
        assert_eq!(executed.commands[0].args[4], "output");
        assert_eq!(executed.commands[0].args[5], "ip6");
        assert_eq!(executed.commands[0].args[6], "daddr");
    }

    #[test]
    fn remote_block_does_not_skip_setup_for_different_table_name() {
        let runner = RecordingRunner {
            nft_available: true,
            nft_ruleset_output: "table inet vigil2 {",
            fail_program: None,
            commands: RefCell::new(Vec::new()),
        };
        let executed =
            execute_selected_remote_block_plan(&runner, "block-v6", "2606:4700:4700::1111")
                .unwrap();
        assert_eq!(executed.backend, LinuxFirewallBackend::Nftables);
        assert_eq!(executed.commands.len(), 11);
        assert_eq!(
            executed.commands.first(),
            Some(&LinuxCommand::new("nft", ["add", "table", "inet", "vigil"]))
        );
    }

    #[test]
    fn uid_block_uses_backend_specific_command() {
        let nft_runner = RecordingRunner::new(true);
        let nft = execute_selected_uid_block_plan(&nft_runner, "uid", "out", 1000).unwrap();
        assert_eq!(nft.backend, LinuxFirewallBackend::Nftables);
        assert_eq!(nft.commands.len(), 1);
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
        let (err, restore_state) = execute_selected_isolate_plan(&runner, "isolate").unwrap_err();
        assert!(err.contains("nft failed"));
        assert_eq!(runner.commands.borrow().len(), 1);
        assert!(restore_state.is_some());
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
        let nft_restore =
            execute_restore_plan(&nft_runner, nft_isolated.restore_state.as_ref().unwrap())
                .unwrap();
        assert_eq!(nft_restore.backend, LinuxFirewallBackend::Nftables);
        assert_eq!(
            nft_restore.commands,
            vec![
                LinuxCommand::new("nft", ["flush", "chain", "inet", "vigil", "isolin"]),
                LinuxCommand::new("nft", ["flush", "chain", "inet", "vigil", "isolforward"]),
                LinuxCommand::new("nft", ["flush", "chain", "inet", "vigil", "isolout"]),
            ]
        );
    }
}
