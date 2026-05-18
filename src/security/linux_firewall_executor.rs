//! Linux firewall backend plan execution helpers.
//!
//! This is the narrow runtime bridge between backend-specific command plans and
//! an injectable command runner. It keeps execution sequencing testable before
//! the large platform active-response file is migrated to call it directly.

#[cfg(target_os = "linux")]
use super::linux_command_plan::StdLinuxCommandRunner;
use super::linux_command_plan::{LinuxCommand, LinuxCommandRunner};
use super::linux_firewall_backend::{
    firewall_backend_block_remote_plan, firewall_backend_block_uid_plan,
    firewall_backend_isolate_plan, firewall_backend_restore_plan, firewall_backend_setup_plan,
    select_firewall_backend, LinuxFirewallBackend,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedLinuxFirewallPlan {
    pub backend: LinuxFirewallBackend,
    pub commands: Vec<LinuxCommand>,
}

pub fn execute_firewall_plan(
    runner: &impl LinuxCommandRunner,
    backend: LinuxFirewallBackend,
    commands: Vec<LinuxCommand>,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    for command in &commands {
        runner.status(command)?;
    }
    Ok(ExecutedLinuxFirewallPlan { backend, commands })
}

#[allow(dead_code)]
pub fn execute_selected_setup_plan(
    runner: &impl LinuxCommandRunner,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    let backend = select_firewall_backend(runner);
    execute_firewall_plan(runner, backend, firewall_backend_setup_plan(backend))
}

pub fn execute_selected_isolate_plan(
    runner: &impl LinuxCommandRunner,
    rule_name: &str,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    let backend = select_firewall_backend(runner);
    let mut commands = firewall_backend_setup_plan(backend);
    commands.extend(firewall_backend_isolate_plan(backend, rule_name));
    execute_firewall_plan(runner, backend, commands)
}

pub fn execute_selected_restore_plan(
    runner: &impl LinuxCommandRunner,
) -> Result<ExecutedLinuxFirewallPlan, String> {
    let backend = select_firewall_backend(runner);
    execute_firewall_plan(runner, backend, firewall_backend_restore_plan(backend))
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
    execute_firewall_plan(runner, backend, commands)
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
    execute_firewall_plan(runner, backend, commands)
}

#[cfg(target_os = "linux")]
pub fn execute_system_isolate_plan(rule_name: &str) -> Result<ExecutedLinuxFirewallPlan, String> {
    execute_selected_isolate_plan(&StdLinuxCommandRunner, rule_name)
}

#[cfg(target_os = "linux")]
pub fn execute_system_restore_plan() -> Result<ExecutedLinuxFirewallPlan, String> {
    execute_selected_restore_plan(&StdLinuxCommandRunner)
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
    }

    #[test]
    fn execution_stops_on_first_command_failure() {
        let runner = RecordingRunner::failing(true, "nft");
        let err = execute_selected_isolate_plan(&runner, "isolate").unwrap_err();
        assert!(err.contains("nft failed"));
        assert_eq!(runner.commands.borrow().len(), 1);
    }

    #[test]
    fn restore_uses_selected_backend() {
        let nft_runner = RecordingRunner::new(true);
        let nft = execute_selected_restore_plan(&nft_runner).unwrap();
        assert_eq!(nft.backend, LinuxFirewallBackend::Nftables);
        assert_eq!(
            nft.commands,
            vec![LinuxCommand::new(
                "nft",
                ["delete", "table", "inet", "vigil"]
            )]
        );

        let iptables_runner = RecordingRunner::new(false);
        let iptables = execute_selected_restore_plan(&iptables_runner).unwrap();
        assert_eq!(iptables.backend, LinuxFirewallBackend::Iptables);
        assert_eq!(iptables.commands.len(), 3);
    }
}
