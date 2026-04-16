//! Cross-platform connection polling.
//!
//! Returns a snapshot of all active TCP/UDP connections with PIDs.
//! On Windows: `GetExtendedTcpTable` / `GetExtendedUdpTable` (Win32 IpHelper).
//! On Linux:   `/proc/net/tcp` + `/proc/net/tcp6`.
//! On macOS:   falls back to parsing `netstat` output.

use std::net::Ipv4Addr;

/// A raw connection record from the OS, before scoring / enrichment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawConn {
    pub pid: u32,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String, // empty string when LISTEN
    pub remote_port: u16,  // 0 when LISTEN
    pub status: String,    // "ESTABLISHED" | "LISTEN" | "SYN_SENT" | …
}

/// The set of statuses we care about (ignore TIME_WAIT, CLOSE, etc.)
const KEEP_STATUSES: &[&str] = &[
    "ESTABLISHED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RECV",
    "CLOSE_WAIT",
];

// ── Public API ────────────────────────────────────────────────────────────────

/// Collect all current TCP connections that have a PID and a status we care about.
pub fn poll() -> Vec<RawConn> {
    let mut conns = platform_poll();
    conns.retain(|c| c.pid != 0 && KEEP_STATUSES.contains(&c.status.as_str()));
    conns
}

// ── Windows ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
fn platform_poll() -> Vec<RawConn> {
    let mut out = Vec::new();
    out.extend(windows_tcp());
    out
}

#[cfg(windows)]
fn windows_tcp() -> Vec<RawConn> {
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };

    let mut out = Vec::new();

    unsafe {
        // First call: get required size
        let mut size: u32 = 0;
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            2, /*AF_INET*/
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        let mut buf: Vec<u8> = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut size,
            false,
            2,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != NO_ERROR.0 {
            return out;
        }

        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        for row in rows {
            let local_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
            let local_port = (row.dwLocalPort as u16).to_be();
            let remote_ip = Ipv4Addr::from(u32::from_be(row.dwRemoteAddr));
            let remote_port = (row.dwRemotePort as u16).to_be();

            let status = tcp_state_str(row.dwState);
            let is_listen = status == "LISTEN";

            out.push(RawConn {
                pid: row.dwOwningPid,
                local_ip: local_ip.to_string(),
                local_port,
                remote_ip: if is_listen {
                    String::new()
                } else {
                    remote_ip.to_string()
                },
                remote_port: if is_listen { 0 } else { remote_port },
                status: status.to_string(),
            });
        }
    }

    out
}

#[cfg(windows)]
fn tcp_state_str(state: u32) -> &'static str {
    // MIB_TCP_STATE values
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECV",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

// ── Linux ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn platform_poll() -> Vec<RawConn> {
    let mut out = Vec::new();
    let inode_to_pid = linux_inode_pid_map();
    out.extend(linux_parse_proc("/proc/net/tcp", false, &inode_to_pid));
    out.extend(linux_parse_proc("/proc/net/tcp6", true, &inode_to_pid));
    out
}

#[cfg(target_os = "linux")]
fn linux_parse_proc(
    path: &str,
    ipv6: bool,
    inode_to_pid: &std::collections::HashMap<u64, u32>,
) -> Vec<RawConn> {
    use std::fs;
    let Ok(content) = fs::read_to_string(path) else {
        return vec![];
    };
    linux_parse_proc_content(&content, ipv6, inode_to_pid)
}

#[cfg(target_os = "linux")]
fn linux_parse_proc_content(
    content: &str,
    ipv6: bool,
    inode_to_pid: &std::collections::HashMap<u64, u32>,
) -> Vec<RawConn> {
    let mut out = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 12 {
            continue;
        }

        let (local_ip, local_port) = parse_linux_addr(fields[1], ipv6);
        let (remote_ip, remote_port) = parse_linux_addr(fields[2], ipv6);
        let state_hex = u8::from_str_radix(fields[3], 16).unwrap_or(0);
        let inode = fields[11].parse::<u64>().unwrap_or(0);
        let pid = inode_to_pid.get(&inode).copied().unwrap_or(0);

        let status = linux_state_str(state_hex);
        let is_listen = status == "LISTEN";

        out.push(RawConn {
            pid,
            local_ip,
            local_port,
            remote_ip: if is_listen { String::new() } else { remote_ip },
            remote_port: if is_listen { 0 } else { remote_port },
            status,
        });
    }
    out
}

#[cfg(target_os = "linux")]
fn linux_inode_pid_map() -> std::collections::HashMap<u64, u32> {
    linux_inode_pid_map_from(std::path::Path::new("/proc"))
}

#[cfg(target_os = "linux")]
fn linux_inode_pid_map_from(proc_root: &std::path::Path) -> std::collections::HashMap<u64, u32> {
    use std::collections::HashMap;
    use std::fs;

    let mut map = HashMap::new();
    let Ok(proc_dir) = fs::read_dir(proc_root) else {
        return map;
    };

    for entry in proc_dir.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };

        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(fd_dir) else {
            continue;
        };

        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            if let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            {
                map.entry(inode).or_insert(pid);
            }
        }
    }

    map
}

#[cfg(target_os = "linux")]
fn parse_linux_addr(s: &str, ipv6: bool) -> (String, u16) {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return (String::new(), 0);
    }
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
    let ip = if ipv6 {
        // 32 hex chars, in groups of 8, each u32 little-endian
        let raw = parts[0];
        if raw.len() == 32 {
            let mut words = [0u32; 4];
            for (i, chunk) in raw.as_bytes().chunks(8).enumerate() {
                if let Ok(s) = std::str::from_utf8(chunk) {
                    words[i] = u32::from_str_radix(s, 16).map(u32::from_le).unwrap_or(0);
                }
            }
            Ipv6Addr::from(unsafe { std::mem::transmute::<[u32; 4], [u8; 16]>(words) }).to_string()
        } else {
            String::new()
        }
    } else {
        let n = u32::from_str_radix(parts[0], 16).unwrap_or(0);
        Ipv4Addr::from(n.to_be()).to_string()
    };
    (ip, port)
}

#[cfg(target_os = "linux")]
fn linux_state_str(state: u8) -> &'static str {
    match state {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSED",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

// ── macOS ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn platform_poll() -> Vec<RawConn> {
    macos_netstat()
}

#[cfg(target_os = "macos")]
fn macos_netstat() -> Vec<RawConn> {
    use std::process::Command;
    let Ok(out) = Command::new("netstat").args(["-anv", "-p", "tcp"]).output() else {
        return vec![];
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut conns = Vec::new();

    for line in text.lines().skip(2) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Proto Local Foreign State … pid
        if fields.len() < 6 {
            continue;
        }
        if !fields[0].starts_with("tcp") {
            continue;
        }

        let status = fields[5].to_uppercase();
        let pid: u32 = fields.last().and_then(|s| s.parse().ok()).unwrap_or(0);

        let (local_ip, local_port) = split_addr(fields[3]);
        let (remote_ip, remote_port) = split_addr(fields[4]);
        let is_listen = status == "LISTEN";

        conns.push(RawConn {
            pid,
            local_ip,
            local_port,
            remote_ip: if is_listen { String::new() } else { remote_ip },
            remote_port: if is_listen { 0 } else { remote_port },
            status,
        });
    }
    conns
}

// ── Fallback for other platforms ──────────────────────────────────────────────

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn platform_poll() -> Vec<RawConn> {
    vec![]
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Split "ip:port" or "ip.port" (macOS uses ".") → (ip, port).
#[cfg(target_os = "macos")]
fn split_addr(s: &str) -> (String, u16) {
    // Try last ':' first (IPv4:port or [IPv6]:port), then last '.'
    if let Some(pos) = s.rfind(':') {
        let ip = s[..pos].trim_matches(|c| c == '[' || c == ']').to_string();
        let port = s[pos + 1..].parse().unwrap_or(0);
        return (ip, port);
    }
    if let Some(pos) = s.rfind('.') {
        let ip = s[..pos].to_string();
        let port = s[pos + 1..].parse().unwrap_or(0);
        return (ip, port);
    }
    (s.to_string(), 0)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::{linux_inode_pid_map_from, linux_parse_proc_content};

    #[cfg(target_os = "linux")]
    use std::fs;

    #[cfg(target_os = "linux")]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(target_os = "linux")]
    fn temp_proc_root() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("vigil-proc-{unique}-{}", std::process::id()))
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn inode_map_resolves_socket_owner() {
        use std::os::unix::fs::symlink;

        let root = temp_proc_root();
        fs::create_dir_all(root.join("1234/fd")).unwrap();
        symlink("socket:[4242]", root.join("1234/fd/3")).unwrap();

        let map = linux_inode_pid_map_from(&root);
        assert_eq!(map.get(&4242), Some(&1234));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn parser_uses_inode_pid_map() {
        let mut map = std::collections::HashMap::new();
        map.insert(4242, 1234);

        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 0200007F:0050 01 00000000:00000000 00:00000000 00000000   100        0 4242 1 0000000000000000 100 0 0 10 0\n";

        let rows = linux_parse_proc_content(content, false, &map);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 1234);
        assert_eq!(rows[0].local_ip, "127.0.0.1");
        assert_eq!(rows[0].remote_ip, "127.0.0.2");
        assert_eq!(rows[0].status, "ESTABLISHED");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn parser_falls_back_to_pid_zero_when_inode_unmapped() {
        let map = std::collections::HashMap::new();
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 0200007F:0050 01 00000000:00000000 00:00000000 00000000   100        0 9999 1 0000000000000000 100 0 0 10 0\n";

        let rows = linux_parse_proc_content(content, false, &map);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 0);
    }
}
