//! Linux eBPF-based real-time TCP connection monitoring.
//!
//! Attaches to the `sock:inet_sock_set_state` tracepoint for sub-100ms
//! connect/accept/close events with full process context (PID, UID, cgroup).
//!
//! **Current status:** stub module. Returns `false` on all platforms.
//! Full integration with the `aya` crate (pure-Rust eBPF) is planned for
//! when a Linux development environment is available for testing.
//!
//! ## Planned architecture
//!
//! 1. Load a BPF program attached to `tracepoint/sock/inet_sock_set_state`
//!    via `aya::Bpf::load()` and `aya::BpfLoader`.
//! 2. Read events from a `PerfEventArray` ring buffer in a background thread.
//! 3. Map each event to `RawConn` (same type used by ETW and `/proc/net/tcp`).
//! 4. Send over `mpsc::UnboundedSender<RawConn>` to the monitor hub.
//! 5. If eBPF is unavailable (old kernel, missing `CAP_BPF`), fall back to
//!    `/proc/net/tcp` polling transparently.

use super::poll::RawConn;

/// Try to start the eBPF monitoring source.
///
/// Returns `true` if eBPF is active, `false` if unavailable (wrong platform,
/// insufficient privileges, or not yet implemented).
pub fn start(_tx: tokio::sync::mpsc::UnboundedSender<RawConn>) -> bool {
    // Stub: not yet implemented.
    // On Linux with aya integrated, this would:
    //   1. Load BPF object from embedded bytecode
    //   2. Attach to sock:inet_sock_set_state tracepoint
    //   3. Spawn reader thread feeding _tx
    //   4. Return true on success
    tracing::debug!("eBPF monitoring not yet available — using polling fallback");
    false
}
