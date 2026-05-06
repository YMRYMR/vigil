# Contributing to Vigil

Thank you for taking the time to contribute! This document explains how to
report bugs, propose features, and submit pull requests.

---

## Table of contents

1. [Code of conduct](#code-of-conduct)
2. [Reporting bugs](#reporting-bugs)
3. [Requesting features](#requesting-features)
4. [Development setup](#development-setup)
5. [Pull request process](#pull-request-process)
6. [Coding style](#coding-style)
7. [Testing requirements](#testing-requirements)
8. [Fuzzing](#fuzzing)
9. [Platform notes](#platform-notes)

---

## Code of conduct

Be respectful. Vigil is a security tool used to protect real people's
machines — treat every contributor and user accordingly.

---

## Reporting bugs

Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) issue template.
Please include:

- Vigil version (`Help` tab footer, or release version)
- Operating system and version
- Whether you are running as Administrator / root
- Steps to reproduce
- What you expected vs what actually happened
- Relevant lines from the log file

For security vulnerabilities, please **do not** open a public issue. Email the
maintainer directly instead.

---

## Requesting features

Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) issue
template. Before opening one, check the [ROADMAP](ROADMAP.md) — the feature may
already be planned.

---

## Development setup

Vigil's active support targets are Windows and Linux. See
[`docs/SUPPORTED-PLATFORMS.md`](docs/SUPPORTED-PLATFORMS.md) before adding
platform-specific work.

**Prerequisites**

| Tool | Minimum version | Notes |
|------|----------------|-------|
| Rust stable | 1.75 | Install via [rustup](https://rustup.rs) |
| just | any | Optional but recommended — `cargo install just` |
| Git | any | |

**Windows extras** needed to embed the `.ico` resource:

- Windows SDK (`rc.exe`) installed with Visual Studio, or
- `llvm-rc` included with LLVM

**Linux extras** needed for the egui/eframe backend and eBPF support:

```sh
sudo apt-get install libgtk-3-dev libxdo-dev libayatana-appindicator3-dev
```

For eBPF real-time monitoring, the binary needs Linux capabilities:

```sh
sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_dac_read_search,cap_dac_override+ep target/release/vigil
```

Without these capabilities, Vigil falls back to `/proc/net/tcp` polling.

**Clone and build**

```sh
git clone https://github.com/YMRYMR/vigil.git
cd vigil
cargo build
cargo build --release
cargo test
```

Or with `just`:

```sh
just ci
```

---

## Pull request process

1. **Open an issue first** for non-trivial changes so the approach can be agreed before you invest significant time writing code.
2. Fork the repository and create a branch:
   ```sh
   git checkout -b feature/my-new-detection-rule
   ```
3. Make your changes. Every PR must:
   - Pass `cargo fmt --check`
   - Pass `cargo clippy -- -D warnings`
   - Pass `cargo test`
   - Build cleanly on Windows and Linux.
4. Write or update tests for any changed logic. Scoring rules in `src/score.rs` **must** have unit tests.
5. Update `ROADMAP.md` if you complete a backlog item.
6. Open the PR against `master` and fill in the PR template.
7. A maintainer will review and either merge or request changes.

---

## Coding style

- **Format:** `cargo fmt`.
- **Lints:** `cargo clippy -- -D warnings`.
- **Unsafe:** avoid unless absolutely necessary. All `unsafe` blocks must have a safety comment explaining the invariant.
- **Platform-specific code:** define Windows and Linux behavior explicitly. Use `#[cfg(windows)]`, `#[cfg(target_os = "linux")]`, or clear unsupported fallbacks where needed.
- **Startup safety:** supported-platform startup paths must fail open. A Vigil bug, hang, network failure, advisory-cache failure, package-inventory failure, or service-mode error must not repeatedly prevent the machine from reaching a usable login/session state.
- **No `println!` / `eprintln!`** in non-test library code — use `tracing::info!`, `tracing::warn!`, or `tracing::error!` instead.
- **Error handling:** prefer `?` propagation and `tracing::warn!` for non-fatal errors over `unwrap()` / `expect()` in hot paths.
- **UI code:** follow the existing egui 0.34 patterns.

---

## Testing requirements

| Area | What to test |
|------|-------------|
| `src/score.rs` | Every new scoring rule needs at least one unit test |
| `src/config.rs` | Any new config field needs a round-trip / merge test |
| `src/process/` | New platform-specific paths need `#[cfg(...)]` test gates |
| UI (`src/ui/`) | Visual-only changes do not need automated tests; logic helpers should be tested |

Run the full suite with:

```sh
cargo test
```

## Fuzzing

Vigil keeps a small continuous fuzzing setup for parser-style code paths. The
current fuzz target exercises the TLS ClientHello parser used by the monitoring
stack.

To run it locally:

```sh
cd fuzz
cargo fuzz run parse_client_hello
```

---

## Platform notes

### Windows

- Real-time monitoring uses ETW and requires Administrator rights. The fallback polling path always works.
- The `windows` crate features used are listed in `Cargo.toml`; add new features there if you need additional Win32 APIs.
- Boot-time monitoring uses a scheduled task and must fail open if startup is unsafe.

### Linux

- eBPF real-time monitoring via aya (`sock:inet_sock_set_state` tracepoint) requires `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`, `CAP_DAC_READ_SEARCH`, and `CAP_DAC_OVERRIDE`; it falls back to `/proc/net/tcp` polling if unavailable.
- Active response: network isolation via iptables, TCP kill via `ss -K`, process suspend/resume via SIGSTOP/SIGCONT, IP blocking via iptables comment rules, and domain blocking via `/etc/hosts`. Actions are gated on `CAP_NET_ADMIN` or root where needed.
- Boot-time monitoring uses a systemd unit and must fail open if startup is unsafe.
- System tray uses libappindicator on supported desktop environments.
- GTK3 and libayatana-appindicator are required at link time.

---

*Vigil is built with care. Thank you for helping make it better.*
