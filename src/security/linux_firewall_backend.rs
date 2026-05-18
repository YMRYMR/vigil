//! Linux firewall backend selection and command sequencing.
//!
//! This module keeps backend choice and high-level firewall command sequences
//! separate from command construction. It is intentionally not wired into the
//! live active-response path yet; the goal is to make the nftables-preferred,
//! iptables-fallback behavior explicit and unit-testable before runtime use.
#![cfg_attr(not(test), allow(dead_code))]

use super::linux_command_plan::{
    iptables_insert_block_remote, iptables_insert_block_uid, iptables_list_rules,
    iptables_set_policy, nft_add_chain, nft_add_filter_chain, nft_add_table, nft_flush_chain,
    nft_insert_block_all_into, nft_insert_block_remote, nft_insert_block_uid, nft_insert_jump_rule,
    nft_list_ruleset, LinuxCommand, LinuxCommandRunner, NFT_FORWARD_CHAIN, NFT_INPUT_CHAIN,
    NFT_ISOL_FORWARD_CHAIN, NFT_ISOL_IN_CHAIN, NFT_ISOL_OUT_CHAIN, NFT_OUTPUT_CHAIN,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxFirewallBackend {
    Nftables,
    Iptables,
}

impl LinuxFirewallBackend {
    pub fn label(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Iptables => "iptables",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesChainPolicy {
    pub chain: String,
    pub policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesPolicySnapshot {
    pub chains: Vec<IptablesChainPolicy>,
}

impl IptablesPolicySnapshot {
    pub fn from_iptables_list(output: &str) -> Result<Self, String> {
        let mut chains = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix("Chain ") else {
                continue;
            };
            let Some((chain, policy_part)) = rest.split_once(" (policy ") else {
                continue;
            };
            let Some(policy) = policy_part.strip_suffix(')') else {
                continue;
            };
            if matches!(chain, "INPUT" | "FORWARD" | "OUTPUT") {
                chains.push(IptablesChainPolicy {
                    chain: chain.to_string(),
                    policy: policy.to_string(),
                });
            }
        }

        for required in ["INPUT", "FORWARD", "OUTPUT"] {
            if !chains.iter().any(|chain| chain.chain == required) {
                return Err(format!(
                    "iptables policy snapshot did not include the {required} chain"
                ));
            }
        }

        Ok(Self { chains })
    }
}
/// Prefer nftables when it is usable, otherwise fall back to iptables.
///
/// The probe is intentionally read-only: `nft list ruleset` requires enough
/// privilege to inspect the ruleset but does not mutate host firewall state.
pub fn select_firewall_backend(runner: &impl LinuxCommandRunner) -> LinuxFirewallBackend {
    if runner.stdout(&nft_list_ruleset()).is_ok() {
        LinuxFirewallBackend::Nftables
    } else {
        LinuxFirewallBackend::Iptables
    }
}

pub fn capture_iptables_policy_snapshot(
    runner: &impl LinuxCommandRunner,
) -> Result<IptablesPolicySnapshot, String> {
    let output = runner.stdout(&iptables_list_rules())?;
    IptablesPolicySnapshot::from_iptables_list(&output)
}
pub fn firewall_backend_setup_plan(backend: LinuxFirewallBackend) -> Vec<LinuxCommand> {
    match backend {
        LinuxFirewallBackend::Nftables => vec![
            nft_add_table(),
            nft_add_filter_chain(NFT_INPUT_CHAIN, "input", 0, "accept"),
            nft_add_filter_chain(NFT_FORWARD_CHAIN, "forward", 0, "accept"),
            nft_add_filter_chain(NFT_OUTPUT_CHAIN, "output", 0, "accept"),
            nft_add_chain(NFT_ISOL_IN_CHAIN),
            nft_add_chain(NFT_ISOL_FORWARD_CHAIN),
            nft_add_chain(NFT_ISOL_OUT_CHAIN),
            nft_insert_jump_rule(NFT_INPUT_CHAIN, NFT_ISOL_IN_CHAIN),
            nft_insert_jump_rule(NFT_FORWARD_CHAIN, NFT_ISOL_FORWARD_CHAIN),
            nft_insert_jump_rule(NFT_OUTPUT_CHAIN, NFT_ISOL_OUT_CHAIN),
        ],
        LinuxFirewallBackend::Iptables => Vec::new(),
    }
}

pub fn firewall_backend_isolate_plan(
    backend: LinuxFirewallBackend,
    rule_name: &str,
) -> Vec<LinuxCommand> {
    match backend {
        LinuxFirewallBackend::Nftables => vec![
            nft_insert_block_all_into(NFT_ISOL_IN_CHAIN, rule_name),
            nft_insert_block_all_into(NFT_ISOL_FORWARD_CHAIN, rule_name),
            nft_insert_block_all_into(NFT_ISOL_OUT_CHAIN, rule_name),
        ],
        LinuxFirewallBackend::Iptables => vec![
            iptables_set_policy("INPUT", "DROP"),
            iptables_set_policy("FORWARD", "DROP"),
            iptables_set_policy("OUTPUT", "DROP"),
        ],
    }
}

pub fn firewall_backend_restore_plan(
    backend: LinuxFirewallBackend,
    iptables_snapshot: Option<&IptablesPolicySnapshot>,
) -> Result<Vec<LinuxCommand>, String> {
    match backend {
        LinuxFirewallBackend::Nftables => Ok(vec![
            nft_flush_chain(NFT_ISOL_IN_CHAIN),
            nft_flush_chain(NFT_ISOL_FORWARD_CHAIN),
            nft_flush_chain(NFT_ISOL_OUT_CHAIN),
        ]),
        LinuxFirewallBackend::Iptables => {
            let snapshot = iptables_snapshot.ok_or_else(|| {
                "iptables restore requires a captured chain-policy snapshot".to_string()
            })?;
            Ok(snapshot
                .chains
                .iter()
                .map(|chain| iptables_set_policy(&chain.chain, &chain.policy))
                .collect())
        }
    }
}

pub fn firewall_backend_block_remote_plan(
    backend: LinuxFirewallBackend,
    rule_name: &str,
    target: &str,
) -> Vec<LinuxCommand> {
    match backend {
        LinuxFirewallBackend::Nftables => vec![nft_insert_block_remote(rule_name, target)],
        LinuxFirewallBackend::Iptables => vec![iptables_insert_block_remote(rule_name, target)],
    }
}

pub fn firewall_backend_block_uid_plan(
    backend: LinuxFirewallBackend,
    rule_name: &str,
    direction: &str,
    uid: u32,
) -> Vec<LinuxCommand> {
    match backend {
        LinuxFirewallBackend::Nftables => vec![nft_insert_block_uid(rule_name, direction, uid)],
        LinuxFirewallBackend::Iptables => {
            vec![iptables_insert_block_uid(rule_name, direction, uid)]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ProbeRunner {
        nft_available: bool,
    }

    impl LinuxCommandRunner for ProbeRunner {
        fn status(&self, _command: &LinuxCommand) -> Result<(), String> {
            Ok(())
        }

        fn stdout(&self, command: &LinuxCommand) -> Result<String, String> {
            if command.program == "nft" && self.nft_available {
                Ok("table inet filter".to_string())
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
    fn selects_nftables_when_probe_succeeds() {
        let runner = ProbeRunner {
            nft_available: true,
        };
        assert_eq!(
            select_firewall_backend(&runner),
            LinuxFirewallBackend::Nftables
        );
    }

    #[test]
    fn falls_back_to_iptables_when_nft_probe_fails() {
        let runner = ProbeRunner {
            nft_available: false,
        };
        assert_eq!(
            select_firewall_backend(&runner),
            LinuxFirewallBackend::Iptables
        );
    }

    #[test]
    fn captures_iptables_chain_policies_from_list_output() {
        let runner = ProbeRunner {
            nft_available: false,
        };
        let snapshot = capture_iptables_policy_snapshot(&runner).unwrap();
        assert_eq!(
            snapshot,
            IptablesPolicySnapshot {
                chains: vec![
                    IptablesChainPolicy {
                        chain: "INPUT".to_string(),
                        policy: "ACCEPT".to_string(),
                    },
                    IptablesChainPolicy {
                        chain: "FORWARD".to_string(),
                        policy: "DROP".to_string(),
                    },
                    IptablesChainPolicy {
                        chain: "OUTPUT".to_string(),
                        policy: "ACCEPT".to_string(),
                    },
                ],
            }
        );
    }

    #[test]
    fn nftables_setup_creates_vigil_table_and_chains() {
        let plan = firewall_backend_setup_plan(LinuxFirewallBackend::Nftables);
        assert_eq!(plan.len(), 10);
        assert_eq!(
            plan[0],
            LinuxCommand::new("nft", ["add", "table", "inet", "vigil"])
        );
        assert_eq!(plan[1].args[4], "input");
        assert_eq!(plan[2].args[4], "forward");
        assert_eq!(plan[3].args[4], "output");
        assert_eq!(plan[4].args[4], "isolin");
        assert_eq!(plan[5].args[4], "isolforward");
        assert_eq!(plan[6].args[4], "isolout");
        assert_eq!(
            plan[7],
            LinuxCommand::new(
                "nft",
                ["insert", "rule", "inet", "vigil", "input", "jump", "isolin"]
            )
        );
        assert_eq!(
            plan[8],
            LinuxCommand::new(
                "nft",
                [
                    "insert",
                    "rule",
                    "inet",
                    "vigil",
                    "forward",
                    "jump",
                    "isolforward"
                ]
            )
        );
        assert_eq!(
            plan[9],
            LinuxCommand::new(
                "nft",
                ["insert", "rule", "inet", "vigil", "output", "jump", "isolout"]
            )
        );
    }

    #[test]
    fn iptables_setup_is_empty_because_existing_tables_are_used() {
        assert!(firewall_backend_setup_plan(LinuxFirewallBackend::Iptables).is_empty());
    }

    #[test]
    fn nftables_isolation_uses_separate_chains_without_changing_main_chains() {
        let plan = firewall_backend_isolate_plan(LinuxFirewallBackend::Nftables, "isolate");
        assert_eq!(plan.len(), 3);
        assert!(plan.iter().all(|command| command.program == "nft"));
        assert!(plan
            .iter()
            .all(|command| command.args.iter().any(|arg| arg == "drop")));
        assert_eq!(plan[0].args[4], "isolin");
        assert_eq!(plan[1].args[4], "isolforward");
        assert_eq!(plan[2].args[4], "isolout");
    }

    #[test]
    fn iptables_isolation_preserves_existing_policy_shape() {
        let plan = firewall_backend_isolate_plan(LinuxFirewallBackend::Iptables, "isolate");
        assert_eq!(
            plan,
            vec![
                LinuxCommand::new("iptables", ["-P", "INPUT", "DROP"]),
                LinuxCommand::new("iptables", ["-P", "FORWARD", "DROP"]),
                LinuxCommand::new("iptables", ["-P", "OUTPUT", "DROP"]),
            ]
        );
    }

    #[test]
    fn restore_plan_matches_backend() {
        assert_eq!(
            firewall_backend_restore_plan(LinuxFirewallBackend::Nftables, None).unwrap(),
            vec![
                LinuxCommand::new("nft", ["flush", "chain", "inet", "vigil", "isolin"]),
                LinuxCommand::new("nft", ["flush", "chain", "inet", "vigil", "isolforward"]),
                LinuxCommand::new("nft", ["flush", "chain", "inet", "vigil", "isolout"]),
            ]
        );
        assert_eq!(
            firewall_backend_restore_plan(
                LinuxFirewallBackend::Iptables,
                Some(&IptablesPolicySnapshot {
                    chains: vec![
                        IptablesChainPolicy {
                            chain: "INPUT".to_string(),
                            policy: "ACCEPT".to_string(),
                        },
                        IptablesChainPolicy {
                            chain: "FORWARD".to_string(),
                            policy: "DROP".to_string(),
                        },
                        IptablesChainPolicy {
                            chain: "OUTPUT".to_string(),
                            policy: "ACCEPT".to_string(),
                        },
                    ],
                }),
            )
            .unwrap(),
            vec![
                LinuxCommand::new("iptables", ["-P", "INPUT", "ACCEPT"]),
                LinuxCommand::new("iptables", ["-P", "FORWARD", "DROP"]),
                LinuxCommand::new("iptables", ["-P", "OUTPUT", "ACCEPT"]),
            ]
        );
    }

    #[test]
    fn iptables_restore_requires_a_snapshot() {
        let err = firewall_backend_restore_plan(LinuxFirewallBackend::Iptables, None).unwrap_err();
        assert!(err.contains("snapshot"));
    }

    #[test]
    fn remote_block_plan_keeps_ipv6_family_when_using_nftables() {
        let plan = firewall_backend_block_remote_plan(
            LinuxFirewallBackend::Nftables,
            "block-v6",
            "2606:4700:4700::1111",
        );
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].program, "nft");
        assert_eq!(plan[0].args[4], "output");
        assert_eq!(plan[0].args[5], "ip6");
        assert_eq!(plan[0].args[6], "daddr");
    }

    #[test]
    fn uid_block_plan_matches_backend() {
        let nft =
            firewall_backend_block_uid_plan(LinuxFirewallBackend::Nftables, "uid", "out", 1000);
        assert_eq!(nft[0].program, "nft");
        assert!(nft[0].args.iter().any(|arg| arg == "skuid"));

        let iptables =
            firewall_backend_block_uid_plan(LinuxFirewallBackend::Iptables, "uid", "out", 1000);
        assert_eq!(iptables[0].program, "iptables");
        assert!(iptables[0].args.iter().any(|arg| arg == "--uid-owner"));
    }
}
