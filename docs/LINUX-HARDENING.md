# Linux hardening notes

This document records Linux-specific service and active-response expectations so
Linux behaviour can be reviewed at the same level of detail as Windows behaviour.

## Boot-time service hardening

The Linux boot-time service should run with the smallest practical systemd
sandbox that still allows Vigil to monitor host network/process activity and
restore connectivity after containment.

The installed unit should:

- keep the service headless by passing `--service-mode`;
- use the shared data directory passed through `--data-dir`;
- avoid gaining new privileges after startup;
- bound capabilities to the networking, BPF, performance-monitoring, and process
  control capabilities Vigil needs for Linux monitoring and response;
- make the filesystem read-only except for the configured Vigil data directory
  and the host locations that containment/recovery intentionally manages;
- keep a sane restart policy so repeated failures do not trap the machine in an
  unusable state together with the pre-login fail-open guard.

## Linux capability expectations

The preferred long-term shape is per-action capability reporting in the UI:

| Area | Typical Linux requirement | Notes |
| --- | --- | --- |
| Network/process polling | regular user for reduced visibility; root/capabilities for full visibility | The UI should say when Linux has fallen back to reduced visibility. |
| eBPF realtime monitoring | `CAP_BPF` and usually `CAP_PERFMON`; older kernels may require broader privileges | Diagnostics should distinguish missing capability, missing BTF, and verifier errors. |
| Firewall isolation/rules | `CAP_NET_ADMIN` or root | Prefer nftables when available, with iptables fallback. |
| TCP connection kill | root or relevant networking capability plus `ss -K` support | Failure should degrade cleanly, not leave partial state. |
| Process suspend/resume | same UID or `CAP_KILL`/root depending target | The UI should explain when a PID cannot be controlled. |
| Adapter isolation | `CAP_NET_ADMIN` or root | Always preserve enough state for restore and break-glass recovery. |
| Hosts-file domain block | root or write access to `/etc/hosts` | Restore must only remove Vigil-owned marker blocks. |
| systemd service install/uninstall | root | Installer should never self-elevate unexpectedly. |

## Active-response parity TODOs

These are the next Linux refinements after service hardening:

1. Add a Linux active-response backend trait and a mocked command runner so
   iptables/ip/ss/hosts-file behaviour can be unit-tested without root.
2. Add nftables as the preferred firewall backend and keep iptables as fallback.
3. Improve executable-path blocking. The current UID-based Linux fallback can
   overblock unrelated processes that share the same effective UID; the UI and
   backend should either use a more precise isolation primitive or label the
   action as broader than Windows path blocking.
4. Add explicit privilege diagnostics to Settings/Inspector so Linux operators
   know whether realtime monitoring, response actions, and recovery are fully
   available.
5. Exercise break-glass recovery for both firewall-policy isolation and adapter
   cutoff on Linux VMs before widening release claims.
