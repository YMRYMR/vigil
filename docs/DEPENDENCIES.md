# Dependency Inventory

Vigil is a Rust application. Direct language dependencies are declared in `Cargo.toml`, and exact resolved dependency versions are recorded in `Cargo.lock` for reproducible application builds.

## Runtime dependencies

The direct runtime dependencies are grouped below for reviewability. `Cargo.toml` remains the source of truth.

### Async runtime and application shell

- `tokio`
- `egui`
- `eframe`
- `notify-rust`
- `single-instance`
- `open`

### Serialization, logging, and time

- `serde`
- `serde_json`
- `serde_yaml`
- `tracing`
- `tracing-subscriber`
- `tracing-appender`
- `chrono`

### Process, network, and detection data

- `sysinfo`
- `dashmap`
- `maxminddb`
- `notify`
- `dns-lookup`
- `ipnetwork`
- `libc`

### Cryptography and integrity

- `ed25519-dalek`
- `base64`
- `hmac`
- `sha2`
- `getrandom`

### Autostart, tray, and platform UI

- `auto-launch`
- `tray-icon` on non-Linux targets
- `ksni` on Linux
- `image`

### Platform-specific monitoring

- `windows` and `winreg` on Windows
- `aya` and `bytes` on Linux

## Build dependencies

- `png`
- `winres` on Windows

## Patched crates

`Cargo.toml` patches `libappindicator` and `gtk` to local stubs to keep unused Linux-only `tray-icon` transitive dependencies out of the lockfile on targets where Vigil does not compile that code path.

## Review process

Dependency changes should be reviewed through pull requests. GitHub dependency review, Snyk, and normal CI must pass before merging dependency updates.
