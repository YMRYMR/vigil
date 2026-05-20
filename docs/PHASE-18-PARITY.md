# Phase 18+19 — Windows/Linux Parity & Native Firewall Engine

## Status: ✅ Complete (Phase 18), 🚧 In Progress (Phase 19)

## Overview

Phase 18 ensured both platforms are equally safe and useful. Phase 19 replaces the OS firewall with Vigil's own WFP (Windows) / nftables+XDP (Linux) engine, with kernel-level filtering, boot persistence, and crash-safe lifecycle.

## Active-response + Firewall parity matrix

| Function | Windows backend | Linux backend |
|---|---|---|
| `is_supported` | ✅ | ✅ |
| `supports_isolation` | ✅ | ✅ |
| `is_elevated` | ✅ | ✅ (euid + caps) |
| `snapshot_profiles` | ✅ (PowerShell) | ✅ (nftables + iptables) |
| `apply_isolation` | ✅ (PowerShell) | ✅ (nftables / iptables) |
| `restore_profiles` | ✅ (PowerShell) | ✅ (nftables + iptables) |
| `add_block_rule` | ✅ (WFP API) | ✅ (nftables / iptables) |
| `add_block_program_rule` | ✅ (netsh fallback) | ✅ (iptables UID match) |
| `delete_rule` | ✅ (WFP API) | ✅ (handle-based nft deletion) |
| `rule_present` | ✅ (WFP registry / netsh) | ✅ (iptables -C / nft handle) |
| `kill_tcp_connection` | ✅ (SetTcpEntry, IPv4) | ✅ (ss -K, IPv4+IPv6) |
| `terminate_active_connections` | ✅ (PowerShell + SetTcpEntry) | ✅ (ss enumeration) |
| `suspend_process` | ✅ (per-thread) | ✅ (SIGSTOP) |
| `resume_process` | ✅ (per-thread) | ✅ (SIGCONT) |
| `add_domain_block` | ✅ (hosts file) | ✅ (hosts file) |
| `remove_domain_block` | ✅ (hosts file) | ✅ (hosts file) |
| `flush_dns` | ✅ (ipconfig) | ✅ (resolvectl / systemd-resolve) |
| `snapshot_active_adapters` | ✅ | ✅ |
| `disable_active_adapters` | ✅ | ✅ |
| `enable_active_adapters` | ✅ | ✅ |
| `enable_all_network_adapters` | ✅ | ✅ |

## Platform-specific implementations

### Windows: WFP (`src/security/firewall/wfp.rs`)
- `Fwpuclnt.dll` loaded dynamically via `LoadLibrary`/`GetProcAddress`
- Versioned API symbols: `FwpmEngineOpen0`, `FwpmFilterAdd0`, `FwpmFilterDeleteByKey0`
- IP rules use `FWPM_LAYER_ALE_AUTH_CONNECT_V4` with `FWPM_CONDITION_IP_REMOTE_ADDRESS`
- Program rules use netsh fallback (WFP ALE app-container SID filtering deferred)
- Profile management via PowerShell (`Get/Set-NetFirewallProfile`)

### Linux: nftables (`src/security/firewall/nftables.rs`)
- nftables-preferred / iptables-fallback via executor bridge
- `vigil` nftables table with jump chains (input/forward/output → isolin/isolforward/isolout)
- Rule lookup by comment handle via `nft --handle list chain`
- Boot persistence: config saved to `/etc/nftables/vigil.conf`

### Linux: XDP/eBPF (`src/security/firewall/xdp.rs`, `xdp_firewall.bpf.c`)
- Kernel-level packet filtering at NIC driver level (before iptables)
- Auto-disable heartbeat: 30s without Vigil userspace → all traffic passes
- Only TCP/UDP filtered; ICMP/ARP always pass
- IPv4-only for now; IPv6 passes through

## FirewallBackend trait (`src/security/firewall/mod.rs`)

16 methods: `label`, `is_available`, `snapshot_profiles`, `apply_isolation`, `restore_profiles`, `add_block_rule`, `add_block_program_rule`, `delete_rule`, `rule_present`, `isolation_controls_active`, `outbound_block_supported`, `kill_tcp_connection`, `terminate_active_connections`, `add_domain_block`, `remove_domain_block`, `flush_dns`, `save_boot_config`, `load_boot_config`.

## CLI commands

| Command | Description |
|---|---|
| `vigil --firewall status` | Show backend, profiles, isolation |
| `vigil --firewall list` | Rule summary (blocked IPs/processes/domains) |
| `vigil --firewall export` | Full state as JSON |
| `vigil --firewall panic` | Emergency restore (restore_machine + brute-force) |
| `vigil --uninstall-firewall` | Remove all Vigil rules, restore OS defaults |

## Safety guarantees

- Fresh install does nothing — OS firewall handles traffic
- WFP filters persist across restarts (kernel objects); nftables/XDP survive process death
- XDP auto-disables after 30s without heartbeat — cannot brick
- Break-glass watchdog clears Vigil filters on crash
- `reconcile_firewall_rules` re-applies missing rules on startup
- `cleanup_on_uninstall` restores OS firewall to pre-Vigil state

## Expected latency bounds

| Event source | Platform | Expected p95 | Notes |
|---|---|---|---|
| ETW | Windows | < 100 ms | Real-time kernel callbacks — sub-ms delivery |
| eBPF | Linux | < 200 ms | `inet_sock_set_state` tracepoint — ms-level |
| Polling | Both | < 6000 ms | Configurable poll interval, default 5s |
