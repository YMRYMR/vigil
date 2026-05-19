# Phase 18 — Windows/Linux Detection and Response Parity

## Status: Foundations in place

## Overview

Windows and Linux are Vigil's active support targets. Phase 18 ensures both platforms are equally safe, explainable, and useful without expanding the supported OS surface.

## Completed items

| Item | Status |
|------|--------|
| **Monitor trait unification** — `handle_realtime_event` shared handler eliminates duplicated code between ETW and eBPF paths. | ✅ Done |
| **Active-response parity audit** — all 22 active-response functions audited. Linux has full parity for every non-Windows-specific action. | ✅ Done |
| **Latency benchmark tool** (`vigil-benchmark`) — measures p50/p95/p99 detection latency, auto-detects event source, generates JSON/HTML reports. | ✅ Done |
| **Service parity checker** (`vigil-service-check`) — validates service installation, enabled status, privileges, fail-open behaviour on both platforms. | ✅ Done |

## Expected latency bounds

| Event source | Platform | Expected p95 | Notes |
|---|---|---|---|
| ETW | Windows | < 100 ms | Real-time kernel callbacks — sub-ms delivery |
| eBPF | Linux | < 200 ms | `inet_sock_set_state` tracepoint — ms-level |
| Polling | Both | < 6000 ms | Configurable poll interval, default 5s |

## Active-response parity matrix

| Function | Windows | Linux |
|---|---|---|
| `is_supported` | ✅ | ✅ |
| `supports_isolation` | ✅ | ✅ |
| `is_elevated` | ✅ | ✅ (euid + caps) |
| `snapshot_firewall_profiles` | ✅ | ✅ (iptables) |
| `apply_firewall_isolation` | ✅ | ✅ (nftables-based) |
| `restore_firewall_profiles` | ✅ | ✅ (nftables + iptables) |
| `add_block_rule` | ✅ | ✅ (iptables/nftables) |
| `add_block_program_rule` | ✅ | ✅ (iptables UID match) |
| `delete_rule` | ✅ | ✅ (handle-based nft deletion) |
| `kill_tcp_connection` | ✅ (IPv4) | ✅ (IPv4 + IPv6) |
| `suspend_process` | ✅ (per-thread) | ✅ (SIGSTOP) |
| `resume_process` | ✅ (per-thread) | ✅ (SIGCONT) |
| `add_domain_block` | ✅ (hosts file) | ✅ (hosts file) |
| `remove_domain_block` | ✅ (hosts file) | ✅ (hosts file) |
| `snapshot_active_adapters` | ✅ | ✅ |
| `disable_active_adapters` | ✅ | ✅ |
| `enable_active_adapters` | ✅ | ✅ |
| `enable_all_network_adapters` | ✅ | ✅ |

## Tools

### `vigil-benchmark`

```bash
# Quick smoke test
cargo run --bin vigil_benchmark -- --quick

# Full benchmark with JSON + HTML report
cargo run --bin vigil_benchmark -- --count 100 --html report.html

# Install service first, then benchmark
cargo run --bin vigil_benchmark -- --install

# Custom target
cargo run --bin vigil_benchmark -- --target 1.1.1.1:443 --count 200
```

### `vigil-service-check`

```bash
# Read-only check
cargo run --bin vigil_service_check

# Repair mode
cargo run --bin vigil_service_check --fix
```

## Remaining work

- [ ] **Full end-to-end detection test**: subscribe to Vigil's broadcast channel from the benchmark tool and measure actual event delivery latency (not just TCP connect time). Currently blocked on cross-process channel access.
- [ ] **Windows/Linux test fixtures**: add regression tests that cover both OS families.
- [ ] **Autorun snapshot/revert on Linux**: snapshot and restore XDG autostart entries and systemd user units (currently Windows-only).
