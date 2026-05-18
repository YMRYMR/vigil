//! Linux command planning helpers for active response.
//!
//! This module intentionally separates command construction from command
//! execution. The current Linux active-response implementation still invokes
//! commands directly, but these planners provide a tested target shape for the
//! follow-up refactor that will route iptables/ip/ss/hosts-file operations
//! through an injectable runner.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCommand {
    pub program: &'static str,
    pub args: Vec<String>,
}

impl LinuxCommand {
    pub fn new(program: &'static str, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

pub trait LinuxCommandRunner {
    fn status(&self, command: &LinuxCommand) -> Result<(), String>;
    fn stdout(&self, command: &LinuxCommand) -> Result<String, String>;
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default, Clone, Copy)]
pub struct StdLinuxCommandRunner;

#[cfg(target_os = "linux")]
impl LinuxCommandRunner for StdLinuxCommandRunner {
    fn status(&self, command: &LinuxCommand) -> Result<(), String> {
        use crate::platform::command_paths;

        let status = std::process::Command::new(command_paths::resolve(command.program)?)
            .args(&command.args)
            .status()
            .map_err(|e| format!("failed to spawn {}: {e}", command.program))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{} failed with status {status}", command.program))
        }
    }

    fn stdout(&self, command: &LinuxCommand) -> Result<String, String> {
        use crate::platform::command_paths;

        let output = std::process::Command::new(command_paths::resolve(command.program)?)
            .args(&command.args)
            .output()
            .map_err(|e| format!("failed to spawn {}: {e}", command.program))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(format!(
                "{} failed: {}",
                command.program,
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
}

pub fn iptables_list_rules() -> LinuxCommand {
    LinuxCommand::new("iptables", ["-L", "-n"])
}

pub fn iptables_set_policy(chain: &str, policy: &str) -> LinuxCommand {
    LinuxCommand::new("iptables", ["-P", chain, policy])
}

pub fn iptables_insert_block_all(rule_name: &str, direction: &str) -> LinuxCommand {
    let chain = chain_for_direction(direction);
    LinuxCommand::new(
        "iptables",
        [
            "-I",
            chain,
            "1",
            "-m",
            "comment",
            "--comment",
            &iptables_comment(rule_name),
            "-j",
            "DROP",
        ],
    )
}

pub fn iptables_insert_block_remote(rule_name: &str, target: &str) -> LinuxCommand {
    LinuxCommand::new(
        "iptables",
        [
            "-I",
            "OUTPUT",
            "1",
            "-d",
            target,
            "-m",
            "comment",
            "--comment",
            &iptables_comment(rule_name),
            "-j",
            "DROP",
        ],
    )
}

pub fn iptables_insert_block_uid(rule_name: &str, direction: &str, uid: u32) -> LinuxCommand {
    let chain = chain_for_direction(direction);
    let uid = uid.to_string();
    let mut args = vec!["-I".to_string(), chain.to_string(), "1".to_string()];
    if chain == "OUTPUT" {
        args.extend([
            "-m".to_string(),
            "owner".to_string(),
            "--uid-owner".to_string(),
            uid,
        ]);
    }
    args.extend([
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        iptables_comment(rule_name),
        "-j".to_string(),
        "DROP".to_string(),
    ]);
    LinuxCommand::new("iptables", args)
}

pub fn iptables_delete_rule(chain: &str, rule_name: &str) -> LinuxCommand {
    LinuxCommand::new(
        "iptables",
        [
            "-D",
            chain,
            "-m",
            "comment",
            "--comment",
            &iptables_comment(rule_name),
            "-j",
            "DROP",
        ],
    )
}

pub fn ip_link_set(adapter_name: &str, enabled: bool) -> LinuxCommand {
    LinuxCommand::new(
        "ip",
        [
            "link",
            "set",
            "dev",
            adapter_name,
            if enabled { "up" } else { "down" },
        ],
    )
}

pub fn ip_link_show(up_only: bool) -> LinuxCommand {
    if up_only {
        LinuxCommand::new("ip", ["-o", "link", "show", "up"])
    } else {
        LinuxCommand::new("ip", ["-o", "link", "show"])
    }
}

pub fn ss_kill_tcp_connection(
    local_ip: &str,
    local_port: u16,
    remote_ip: &str,
    remote_port: u16,
) -> LinuxCommand {
    LinuxCommand::new(
        "ss",
        [
            "-K",
            "dst",
            remote_ip,
            "dport",
            "=",
            &remote_port.to_string(),
            "src",
            local_ip,
            "sport",
            "=",
            &local_port.to_string(),
        ],
    )
}

pub fn resolvectl_flush_caches() -> LinuxCommand {
    LinuxCommand::new("resolvectl", ["flush-caches"])
}

pub fn systemd_resolve_flush_caches() -> LinuxCommand {
    LinuxCommand::new("systemd-resolve", ["--flush-caches"])
}

fn chain_for_direction(direction: &str) -> &'static str {
    match direction {
        "in" => "INPUT",
        "out" => "OUTPUT",
        _ => "OUTPUT",
    }
}

fn iptables_comment(rule_name: &str) -> String {
    format!("Vigil:{rule_name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingRunner {
        stdout: String,
    }

    impl LinuxCommandRunner for RecordingRunner {
        fn status(&self, command: &LinuxCommand) -> Result<(), String> {
            assert!(!command.program.is_empty());
            Ok(())
        }

        fn stdout(&self, command: &LinuxCommand) -> Result<String, String> {
            assert!(!command.program.is_empty());
            Ok(self.stdout.clone())
        }
    }

    #[test]
    fn planned_firewall_isolation_sets_default_drop_policies() {
        assert_eq!(
            iptables_set_policy("INPUT", "DROP"),
            LinuxCommand::new("iptables", ["-P", "INPUT", "DROP"])
        );
        assert_eq!(
            iptables_set_policy("FORWARD", "DROP"),
            LinuxCommand::new("iptables", ["-P", "FORWARD", "DROP"])
        );
        assert_eq!(
            iptables_set_policy("OUTPUT", "DROP"),
            LinuxCommand::new("iptables", ["-P", "OUTPUT", "DROP"])
        );
    }

    #[test]
    fn planned_remote_block_matches_current_iptables_shape() {
        assert_eq!(
            iptables_insert_block_remote("block-example", "203.0.113.10"),
            LinuxCommand::new(
                "iptables",
                [
                    "-I",
                    "OUTPUT",
                    "1",
                    "-d",
                    "203.0.113.10",
                    "-m",
                    "comment",
                    "--comment",
                    "Vigil:block-example",
                    "-j",
                    "DROP",
                ],
            )
        );
    }

    #[test]
    fn planned_uid_block_keeps_output_owner_match_explicit() {
        assert_eq!(
            iptables_insert_block_uid("process-block", "out", 1000),
            LinuxCommand::new(
                "iptables",
                [
                    "-I",
                    "OUTPUT",
                    "1",
                    "-m",
                    "owner",
                    "--uid-owner",
                    "1000",
                    "-m",
                    "comment",
                    "--comment",
                    "Vigil:process-block",
                    "-j",
                    "DROP",
                ],
            )
        );
    }

    #[test]
    fn planned_input_process_block_does_not_emit_owner_match() {
        assert_eq!(
            iptables_insert_block_uid("process-block", "in", 1000),
            LinuxCommand::new(
                "iptables",
                [
                    "-I",
                    "INPUT",
                    "1",
                    "-m",
                    "comment",
                    "--comment",
                    "Vigil:process-block",
                    "-j",
                    "DROP",
                ],
            )
        );
    }

    #[test]
    fn planned_delete_rule_checks_each_chain_by_comment() {
        assert_eq!(
            iptables_delete_rule("OUTPUT", "block-example"),
            LinuxCommand::new(
                "iptables",
                [
                    "-D",
                    "OUTPUT",
                    "-m",
                    "comment",
                    "--comment",
                    "Vigil:block-example",
                    "-j",
                    "DROP",
                ],
            )
        );
    }

    #[test]
    fn planned_adapter_commands_use_ip_link_set() {
        assert_eq!(
            ip_link_set("eth0", false),
            LinuxCommand::new("ip", ["link", "set", "dev", "eth0", "down"])
        );
        assert_eq!(
            ip_link_set("eth0", true),
            LinuxCommand::new("ip", ["link", "set", "dev", "eth0", "up"])
        );
        assert_eq!(
            ip_link_show(true),
            LinuxCommand::new("ip", ["-o", "link", "show", "up"])
        );
    }

    #[test]
    fn planned_tcp_kill_matches_ss_k_shape() {
        assert_eq!(
            ss_kill_tcp_connection("10.0.0.2", 44321, "203.0.113.10", 443),
            LinuxCommand::new(
                "ss",
                [
                    "-K",
                    "dst",
                    "203.0.113.10",
                    "dport",
                    "=",
                    "443",
                    "src",
                    "10.0.0.2",
                    "sport",
                    "=",
                    "44321",
                ],
            )
        );
    }

    #[test]
    fn runner_trait_can_be_mocked_without_root() {
        let runner = RecordingRunner {
            stdout: "ok".to_string(),
        };
        runner
            .status(&iptables_insert_block_remote("x", "203.0.113.1"))
            .unwrap();
        assert_eq!(runner.stdout(&iptables_list_rules()).unwrap(), "ok");
    }
}
