//! ETW (Event Tracing for Windows) real-time TCP connection monitor.
//!
//! Attaches to (or starts) the **NT Kernel Logger** session with the
//! `EVENT_TRACE_FLAG_NETWORK_TCPIP` flag set, giving sub-millisecond
//! notification of new TCP connections and disconnects.
//!
//! # Privilege requirement
//! Opening / modifying the NT Kernel Logger requires **Administrator** rights.
//! `start()` returns `false` gracefully when that is not the case; the caller
//! falls back to the poll-based monitor in that situation.
//!
//! # Cross-platform
//! The entire implementation is `#[cfg(windows)]`-gated.  On other platforms
//! `start()` is a zero-cost stub that always returns `false`.

use super::poll::RawConn;
use tokio::sync::mpsc::UnboundedSender;

/// Try to start the ETW kernel session for real-time TCP monitoring.
///
/// On success a dedicated OS thread is spawned that feeds `RawConn` events
/// into `tx` the moment the kernel observes a new TCP connection.
/// Returns `true` if the session is running, `false` otherwise (most likely
/// the process is not running as Administrator).
pub fn start(tx: UnboundedSender<RawConn>) -> bool {
    #[cfg(windows)]
    return win::start(tx);

    // Non-Windows: nothing to do.
    #[cfg(not(windows))]
    {
        drop(tx);
        false
    }
}

// ── Windows implementation ────────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use super::{RawConn, UnboundedSender};
    use std::ffi::OsStr;
    use std::net::Ipv4Addr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::OnceLock;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
    use windows::Win32::System::Diagnostics::Etw::{
        CloseTrace, ControlTraceW, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE,
        EVENT_RECORD, EVENT_TRACE_CONTROL, EVENT_TRACE_FLAG, EVENT_TRACE_LOGFILEW,
        EVENT_TRACE_PROPERTIES,
    };

    // ── Win32 constants ────────────────────────────────────────────────────────

    // WNODE_HEADER.Flags (plain u32 field)
    const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;

    // EVENT_TRACE_PROPERTIES.LogFileMode (plain u32 field)
    const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x0000_0100;

    // EnableFlags — must be wrapped in the EVENT_TRACE_FLAG newtype
    const TCPIP_FLAG: EVENT_TRACE_FLAG = EVENT_TRACE_FLAG(0x0001_0000); // NETWORK_TCPIP

    // ControlTraceW control codes — EVENT_TRACE_CONTROL newtype
    const CONTROL_UPDATE: EVENT_TRACE_CONTROL = EVENT_TRACE_CONTROL(3);

    // EVENT_TRACE_LOGFILEW.Anonymous1.ProcessTraceMode (plain u32 union field)
    const PROCESS_TRACE_MODE_REAL_TIME: u32 = 0x0000_0100;
    const PROCESS_TRACE_MODE_EVENT_RECORD: u32 = 0x1000_0000;

    // EVENT_HEADER.Flags bitmask — classic (MOF) kernel events carry this flag
    const EVENT_HEADER_FLAG_CLASSIC_HEADER: u16 = 0x0100;

    // PROCESSTRACE_HANDLE sentinel for "invalid"
    const INVALID_TRACE_HANDLE: u64 = u64::MAX;

    // Classic TCP/IP kernel event opcodes (NT Kernel Logger MOF events)
    const OPCODE_CONNECT: u8 = 12; // outgoing TCP connect established
    const OPCODE_ACCEPT: u8 = 18; // incoming TCP connection accepted

    // NT Kernel Logger session GUID (SystemTraceControlGuid)
    const SYSTEM_TRACE_GUID: windows::core::GUID = windows::core::GUID {
        data1: 0x9E81_4AAD,
        data2: 0x3204,
        data3: 0x11D2,
        data4: [0x9A, 0x82, 0x00, 0x60, 0x08, 0xA8, 0x69, 0x39],
    };

    // ── Global connection sender ───────────────────────────────────────────────

    /// Set exactly once when the ETW session starts.
    /// The `ProcessTrace` callback uses this to forward parsed events.
    static CONN_TX: OnceLock<UnboundedSender<RawConn>> = OnceLock::new();

    // ── Public entry point ────────────────────────────────────────────────────

    pub fn start(tx: UnboundedSender<RawConn>) -> bool {
        // Guard against being called twice (shouldn't happen, but be safe).
        if CONN_TX.set(tx).is_err() {
            return true; // already running
        }

        if !unsafe { ensure_session() } {
            return false;
        }

        // Spawn the ProcessTrace thread.  It blocks until the session ends
        // or the process exits — we never explicitly stop the kernel logger.
        std::thread::Builder::new()
            .name("vigil-etw".into())
            .spawn(etw_thread)
            .is_ok()
    }

    // ── Session management ────────────────────────────────────────────────────

    /// Open or attach to the NT Kernel Logger with TCP/IP events enabled.
    /// Returns `false` on hard failures (no admin, etc.).
    unsafe fn ensure_session() -> bool {
        let name = session_name_wide();
        let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name.len() * 2;
        let mut buf = vec![0u8; props_size];
        fill_props(&mut buf, props_size, &name);

        let mut handle = CONTROLTRACE_HANDLE::default();
        let ret = StartTraceW(
            &mut handle,
            PCWSTR(name.as_ptr()),
            buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
        );

        if ret == ERROR_SUCCESS {
            return true; // we started a new session
        }

        if ret == ERROR_ALREADY_EXISTS {
            // NT Kernel Logger already running — attempt to update EnableFlags
            // so that NETWORK_TCPIP events are included.
            let mut upd = vec![0u8; props_size];
            fill_props(&mut upd, props_size, &name);
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(name.as_ptr()),
                upd.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                CONTROL_UPDATE,
            );
            // Even if the update failed, the flag may already be set.
            // We still try to open the trace below.
            return true;
        }

        // Any other error (ACCESS_DENIED = 5, etc.) — give up.
        false
    }

    /// Populate an `EVENT_TRACE_PROPERTIES` buffer for the NT Kernel Logger.
    unsafe fn fill_props(buf: &mut [u8], props_size: usize, name: &[u16]) {
        let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*p).Wnode.BufferSize = props_size as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*p).Wnode.ClientContext = 1; // QPC clock resolution
        (*p).Wnode.Guid = SYSTEM_TRACE_GUID;
        (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*p).EnableFlags = TCPIP_FLAG;
        (*p).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        // Write the session name into the bytes immediately following the struct.
        let dst = buf
            .as_mut_ptr()
            .add(std::mem::size_of::<EVENT_TRACE_PROPERTIES>()) as *mut u16;
        std::ptr::copy_nonoverlapping(name.as_ptr(), dst, name.len());
    }

    // ── ProcessTrace thread ───────────────────────────────────────────────────

    fn etw_thread() {
        let mut name = session_name_wide();

        let mut log_file = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(name.as_mut_ptr()),
            ..EVENT_TRACE_LOGFILEW::default()
        };

        unsafe {
            // Anonymous union fields require an unsafe block.
            log_file.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            log_file.Anonymous2.EventRecordCallback = Some(etw_callback);

            let trace = OpenTraceW(&mut log_file);
            if trace.Value == INVALID_TRACE_HANDLE {
                return;
            }

            // Blocks until the session is stopped or the process exits.
            let _ = ProcessTrace(std::slice::from_ref(&trace), None, None);
            let _ = CloseTrace(trace);
        }
    }

    // ── Event callback ────────────────────────────────────────────────────────

    /// Called by `ProcessTrace` for every kernel event on the NT Kernel Logger.
    ///
    /// We filter to classic (MOF) TCP connect/accept opcodes and parse the
    /// fixed-layout `TcpIpV4` payload directly — no TDH required.
    unsafe extern "system" fn etw_callback(event: *mut EVENT_RECORD) {
        let ev = &*event;

        // Only classic (MOF) kernel events carry this flag.
        if ev.EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER == 0 {
            return;
        }

        let opcode = ev.EventHeader.EventDescriptor.Opcode;
        if opcode != OPCODE_CONNECT && opcode != OPCODE_ACCEPT {
            return;
        }

        // Classic TcpIpV4 payload layout (minimum 20 bytes):
        //   [0..4]  PID   (u32 LE)
        //   [4..8]  size  (u32 LE, unused here)
        //   [8..12] daddr (4 bytes, network/big-endian byte order)
        //  [12..16] saddr (4 bytes, network byte order)
        //  [16..18] dport (u16 big-endian)
        //  [18..20] sport (u16 big-endian)
        // Version 2+ appends a connid u32 — we ignore it.
        if ev.UserDataLength < 20 {
            return;
        }

        let data = std::slice::from_raw_parts(ev.UserData as *const u8, ev.UserDataLength as usize);

        let pid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        // Network byte order → individual octets → Ipv4Addr::new (no swap needed).
        let daddr = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
        let saddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dport = u16::from_be_bytes([data[16], data[17]]);
        let sport = u16::from_be_bytes([data[18], data[19]]);

        // Map to (local, remote) depending on event direction:
        //   connect (12) → outgoing: local = saddr:sport,  remote = daddr:dport
        //   accept  (18) → incoming: local = daddr:dport,  remote = saddr:sport
        let (local_ip, local_port, remote_ip, remote_port) = if opcode == OPCODE_CONNECT {
            (saddr, sport, daddr, dport)
        } else {
            (daddr, dport, saddr, sport)
        };

        // Skip pure loopback-to-loopback IPC (not threat-relevant).
        if remote_ip.is_loopback() && local_ip.is_loopback() {
            return;
        }

        let conn = RawConn {
            pid,
            local_ip: local_ip.to_string(),
            local_port,
            remote_ip: remote_ip.to_string(),
            remote_port,
            status: "ESTABLISHED".to_string(),
        };

        if let Some(tx) = CONN_TX.get() {
            let _ = tx.send(conn);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn session_name_wide() -> Vec<u16> {
        OsStr::new("NT Kernel Logger")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}
