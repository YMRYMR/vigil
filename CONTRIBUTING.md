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
8. [Platform notes](#platform-notes)

---

## Code of conduct

Be respectful. Vigil is a security tool used to protect real people's
machines — treat every contributor and user accordingly.

---

## Reporting bugs

Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) issue template.
Please include:

- Vigil version (`Help` tab → footer, or `vigil --version`)
- Operating system and version
- Whether you are running as Administrator / root
- Steps to reproduce
- What you expected vs what actually happened
- Relevant lines from the log file (`<exe-dir>/logs/`)

For security vulnerabilities, please **do not** open a public issue.
Email the maintainer directly instead.

---

## Requesting features

Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) issue
template.  Before opening one, check the [ROADMAP](ROADMAP.md) — the feature
may already be planned.

---

## Development setup

**Prerequisites**

| Tool | Minimum version | Notes |
|------|----------------|-------|
| Rust (stable) | 1.75 | Install via [rustup](https://rustup.rs) |
| just | any | Optional but recommended — `cargo install just` |
| Git | any | |

**Windows extras** (needed to embed the `.ico` resource):

- Windows SDK (`rc.exe`) — installed with Visual Studio, or
- `llvm-rc` — included with LLVM

**Linux extras** (needed for the egui/eframe backend and eBPF support):

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
cargo build                # debug
cargo build --release      # optimised
cargo test                 # run all tests
```

Or with `just`:

```sh
just ci    # fmt-check + lint + test (same checks as CI)
```

---

## Pull request process

1. **Open an issue first** for non-trivial changes so the approach can be
   agreed before you invest significant time writing code.
2. Fork the repository and create a branch:
   ```sh
   git checkout -b feature/my-new-detection-rule
   ```
3. Make your changes.  Every PR must:
   - Pass `cargo fmt --check`
   - Pass `cargo clippy -- -D warnings`
   - Pass `cargo test`
   - Build cleanly on all three platforms (Windows, macOS, Linux) — the CI
     matrix will verify this automatically.
4. Write or update tests for any changed logic.  Scoring rules in
   `src/score.rs` **must** have unit tests.
5. Update `ROADMAP.md` if you complete a backlog item.
6. Open the PR against `main` and fill in the PR template.
7. A maintainer will review and either merge or request changes.

---

## Coding style

- **Format:** `cargo fmt` (default Rust style — no custom config).
- **Lints:** `cargo clippy -- -D warnings`.  All warnings are errors in CI.
- **Unsafe:** avoid unless absolutely necessary.  All `unsafe` blocks must
  have a safety comment explaining the invariant.
- **Platform-specific code:** gate with `#[cfg(windows)]` / `#[cfg(not(windows))]`.
  Every feature must have a meaningful fallback on non-Windows platforms.
- **No `println!` / `eprintln!`** in non-test code — use `tracing::info!`,
  `tracing::warn!`, or `tracing::error!` instead.
- **Error handling:** prefer `?` propagation and `tracing::warn!` for
  non-fatal errors over `unwrap()` / `expect()` in hot paths.
- **UI code:** follow the existing egui 0.34 patterns (`ui.interact()` before
  child widgets for reliable click detection; `Frame::NONE`, `Panel::top/right`,
  `exact_size`).

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

---

## Platform notes

### Windows

- Real-time monitoring uses ETW (Event Tracing for Windows) and requires
  Administrator rights.  The fallback polling path always works.
- The `windows` crate features used are listed in `Cargo.toml` —
  add new features there if you need additional Win32 APIs.

### macOS

- Monitoring uses the polling path (no ETW equivalent on macOS).
- Tray icon and notifications use platform-native APIs via `tray-icon` and
  `notify-rust`.

### Linux

- eBPF real-time monitoring via aya 0.13 (`sock:inet_sock_set_state`
  tracepoint) — requires `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`,
  `CAP_DAC_READ_SEARCH`, and `CAP_DAC_OVERRIDE`; falls back to
  `/proc/net/tcp` polling if unavailable.
- Active response: network isolation via iptables, TCP kill via `ss -K`,
  process suspend/resume via SIGSTOP/SIGCONT, IP blocking via iptables
  comment rules, domain blocking via `/etc/hosts`. All gated on
  `CAP_NET_ADMIN` (checked from `/proc/self/status`) or root.
- System tray via libappindicator (GNOME AppIndicator); uses themed icon
  names — install PNG icons at
  `~/.local/share/icons/hicolor/32x32/apps/`.
- GTK3 and libayatana-appindicator are required at link time (see setup
  above).

---

*Vigil is built with care.  Thank you for helping make it better.*
