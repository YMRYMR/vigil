//! Linux eBPF-based real-time TCP connection monitoring.
//!
//! Attaches to the `sock:inet_sock_set_state` tracepoint for sub-100ms
//! connect/accept/close events with full process context (PID, sport, dport).
//!
//! ## Architecture
//!
//! 1. Load a pre-compiled BPF program (embedded as `BPF_OBJ`) attached to
//!    `tracepoint/sock/inet_sock_set_state` via `aya::EbpfLoader`.
//! 2. Read events from a `PerfEventArray` in a background thread.
//! 3. Map each event to `RawConn` (same type used by ETW and `/proc/net/tcp`).
//! 4. Send over `mpsc::UnboundedSender<RawConn>` to the monitor hub.
//! 5. If eBPF is unavailable (old kernel, missing `CAP_BPF`), fall back to
//!    `/proc/net/tcp` polling transparently.

use super::poll::RawConn;

// ── Non-Linux stub ───────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
pub fn start(_tx: tokio::sync::mpsc::UnboundedSender<RawConn>) -> bool {
    tracing::debug!("eBPF monitoring not available on this platform");
    false
}

// ── Linux eBPF implementation ────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::super::poll::RawConn;
    use aya::maps::perf::PerfEventArray;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::sync::mpsc;

    /// Event struct matching the BPF program's `struct tcp_event`.
    /// Layout must be identical to the C struct in ebpf_tcp_state.bpf.c.
    #[repr(C)]
    #[derive(Debug)]
    struct TcpEvent {
        pid: u32,
        family: u16,
        sport: u16,
        dport: u16,
        _pad: u16,
        saddr: u32,
        daddr: u32,
        saddr_v6: [u8; 16],
        daddr_v6: [u8; 16],
        oldstate: i32,
        newstate: i32,
    }

    // Include pre-compiled BPF object.
    // Source: src/monitor/ebpf_tcp_state.bpf.c
    // Compiled: clang -target bpf -O2 -g -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu
    include!("ebpf_bytecode.rs");

    /// TCP state constants matching kernel enum.
    const TCP_ESTABLISHED: i32 = 1;
    const TCP_SYN_SENT: i32 = 2;
    const TCP_SYN_RECV: i32 = 3;
    const TCP_FIN_WAIT1: i32 = 4;
    const TCP_FIN_WAIT2: i32 = 5;
    const TCP_TIME_WAIT: i32 = 6;
    const TCP_CLOSE: i32 = 7;
    const TCP_CLOSE_WAIT: i32 = 8;
    const TCP_LAST_ACK: i32 = 9;
    const TCP_LISTEN: i32 = 10;
    const TCP_CLOSING: i32 = 11;

    fn state_to_str(state: i32) -> &'static str {
        match state {
            TCP_ESTABLISHED => "ESTABLISHED",
            TCP_SYN_SENT => "SYN_SENT",
            TCP_SYN_RECV => "SYN_RECV",
            TCP_FIN_WAIT1 => "FIN_WAIT1",
            TCP_FIN_WAIT2 => "FIN_WAIT2",
            TCP_TIME_WAIT => "TIME_WAIT",
            TCP_CLOSE => "CLOSED",
            TCP_CLOSE_WAIT => "CLOSE_WAIT",
            TCP_LAST_ACK => "LAST_ACK",
            TCP_LISTEN => "LISTEN",
            TCP_CLOSING => "CLOSING",
            _ => "UNKNOWN",
        }
    }

    pub fn start(tx: mpsc::UnboundedSender<RawConn>) -> bool {
        match try_start(tx) {
            Ok(()) => {
                tracing::info!("eBPF tracepoint active — real-time TCP monitoring on Linux");
                true
            }
            Err(e) => {
                tracing::warn!("eBPF failed to start ({e}) — falling back to polling");
                false
            }
        }
    }

    fn try_start(tx: mpsc::UnboundedSender<RawConn>) -> Result<(), String> {
        use aya::EbpfLoader;
        use aya::programs::TracePoint;
        use std::convert::TryFrom;

        // Load the BPF object.
        let mut bpf = EbpfLoader::new()
            .load(BPF_OBJ)
            .map_err(|e| format!("BPF load failed: {e}"))?;

        // Attach to the sock:inet_sock_set_state tracepoint.
        let program: &mut TracePoint = bpf
            .program_mut("trace_inet_sock_set_state")
            .ok_or("BPF program 'trace_inet_sock_set_state' not found")?
            .try_into()
            .map_err(|e| format!("program type mismatch: {e}"))?;

        program
            .load()
            .map_err(|e| format!("BPF program load failed: {e}"))?;

        program
            .attach("sock", "inet_sock_set_state")
            .map_err(|e| format!("BPF attach failed: {e}"))?;

        // Get the perf event array map.
        let mut perf_array = PerfEventArray::try_from(
            bpf.take_map("events").ok_or("BPF map 'events' not found")?,
        )
        .map_err(|e| format!("perf event array error: {e}"))?;

        // Open a buffer for each online CPU.
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let mut buffers = Vec::new();
        for cpu in 0..num_cpus as u32 {
            let buf = perf_array
                .open(cpu, None)
                .map_err(|e| format!("perf buffer open failed for cpu {cpu}: {e}"))?;
            buffers.push(buf);
        }

        // Spawn background reader thread.
        std::thread::Builder::new()
            .name("vigil-ebpf".into())
            .spawn(move || {
                reader_loop(&mut buffers, tx);
            })
            .map_err(|e| format!("failed to spawn eBPF reader thread: {e}"))?;

        // Keep BPF object alive for the lifetime of the process.
        std::mem::forget(bpf);
        // Keep perf_array alive (the map fd must stay open).
        std::mem::forget(perf_array);

        Ok(())
    }

    fn reader_loop(
        buffers: &mut Vec<aya::maps::perf::PerfEventArrayBuffer<aya::maps::MapData>>,
        tx: mpsc::UnboundedSender<RawConn>,
    ) {
        use bytes::BytesMut;

        // Pre-allocate read buffers (one per CPU).
        let mut out_bufs: Vec<BytesMut> = (0..buffers.len())
            .map(|_| BytesMut::with_capacity(std::mem::size_of::<TcpEvent>()))
            .collect();

        loop {
            for buf in buffers.iter_mut() {
                // Reset output buffers for reuse.
                for ob in &mut out_bufs {
                    ob.clear();
                }

                let events = match buf.read_events(&mut out_bufs) {
                    Ok(ev) => ev,
                    Err(_) => continue,
                };

                if events.lost > 0 {
                    tracing::debug!("eBPF: {} events lost", events.lost);
                }

                for data in out_bufs.iter() {
                    if data.len() < std::mem::size_of::<TcpEvent>() {
                        continue;
                    }

                    let event: &TcpEvent =
                        unsafe { &*(data.as_ptr() as *const TcpEvent) };

                    let raw = event_to_raw_conn(event);
                    if tx.send(raw).is_err() {
                        return;
                    }
                }
            }

            // Brief sleep to avoid busy-looping when idle.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn event_to_raw_conn(event: &TcpEvent) -> RawConn {
        let (local_ip, remote_ip) = if event.family == 10 {
            // AF_INET6
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&event.saddr_v6);
            dst.copy_from_slice(&event.daddr_v6);
            (
                Ipv6Addr::from(src).to_string(),
                Ipv6Addr::from(dst).to_string(),
            )
        } else {
            // AF_INET (family == 2)
            (
                Ipv4Addr::from(event.saddr.to_be()).to_string(),
                Ipv4Addr::from(event.daddr.to_be()).to_string(),
            )
        };

        let status = state_to_str(event.newstate).to_string();
        let is_listen = status == "LISTEN";

        RawConn {
            pid: event.pid,
            local_ip,
            local_port: event.sport,
            remote_ip: if is_listen { String::new() } else { remote_ip },
            remote_port: if is_listen { 0 } else { event.dport },
            status,
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::start;
