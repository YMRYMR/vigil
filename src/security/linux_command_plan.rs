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

pub const NFT_TABLE: &str = "vigil";
pub const NFT_INPUT_CHAIN: &str = "input";
pub const NFT_OUTPUT_CHAIN: &str = "output";
pub const NFT_FORWARD_CHAIN: &str = "forward";

pub fn nft_list_ruleset() -> LinuxCommand {
    LinuxCommand::new("nft", ["list", "ruleset"])
}

pub fn nft_add_table() -> LinuxCommand {
    LinuxCommand::new("nft", ["add", "table", "inet", NFT_TABLE])
}

pub fn nft_add_filter_chain(chain: &str, hook: &str, priority: i32, policy: &str) -> LinuxCommand {
    LinuxCommand::new(
        "nft",
        [
            "add",
            "chain",
            "inet",
            NFT_TABLE,
            chain,
            &format!("{{ type filter hook {hook} priority {priority}; policy {policy}; }}"),
        ],
    )
}

pub fn nft_delete_table() -> LinuxCommand {
    LinuxCommand::new("nft", ["delete", "table", "inet", NFT_TABLE])
}

pub fn nft_insert_block_all(rule_name: &str, direction: &str) -> LinuxCommand {
    let chain = nft_chain_for_direction(direction);
    LinuxCommand::new(
        "nft",
        [
            "insert",
            "rule",
            "inet",
            NFT_TABLE,
            chain,
            "counter",
            "comment",
            &nft_comment(rule_name),
            "drop",
        ],
    )
}

pub fn nft_insert_block_remote(rule_name: &str, target: &str) -> LinuxCommand {
    let family = nft_addr_family(target);
    LinuxCommand::new(
        "nft",
        [
            "insert",
            "rule",
            "inet",
            NFT_TABLE,
            NFT_OUTPUT_CHAIN,
            family,
            "daddr",
            target,
            "counter",
            "comment",
            &nft_comment(rule_name),
            "drop",
        ],
    )
}

pub fn nft_insert_block_uid(rule_name: &str, direction: &str, uid: u32) -> LinuxCommand {
    let chain = nft_chain_for_direction(direction);
    let uid = uid.to_string();
    let mut args = vec![
        "insert".to_string(),
        "rule".to_string(),
        "inet".to_string(),
        NFT_TABLE.to_string(),
        chain.to_string(),
    ];
    if chain == NFT_OUTPUT_CHAIN {
        args.extend(["meta".to_string(), "skuid".to_string(), uid]);
    }
    args.extend([
        "counter".to_string(),
        "comment".to_string(),
        nft_comment(rule_name),
        "drop".to_string(),
    ]);
    LinuxCommand::new("nft", args)
}

pub fn nft_flush_chain(chain: &str) -> LinuxCommand {
    LinuxCommand::new("nft", ["flush", "chain", "inet", NFT_TABLE, chain])
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

fn nft_chain_for_direction(direction: &str) -> &'static str {
    match direction {
        "in" => NFT_INPUT_CHAIN,
        "forward" => NFT_FORWARD_CHAIN,
        "out" => NFT_OUTPUT_CHAIN,
        _ => NFT_OUTPUT_CHAIN,
    }
}
