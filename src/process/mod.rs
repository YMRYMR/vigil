//! Process metadata collection.
//!
//! `collect(pid)` does a single pass over the process table (via sysinfo)
//! and returns everything the scorer and UI need.

pub mod publisher;

use sysinfo::{Pid, ProcessesToUpdate, System};

/// All process context attached to a connection.
#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub name:         String,   // "chrome.exe"
    pub name_key:     String,   // "chrome"   (lowercase, .exe stripped — for scoring)
    pub path:         String,   // full exe path, empty if inaccessible
    pub user:         String,
    pub parent_name:  String,
    pub parent_pid:   u32,
    /// Full ancestor chain: [(name, pid), …] from immediate parent to root.
    /// Capped at 8 levels to avoid runaway walks on deep trees.
    pub ancestors:    Vec<(String, u32)>,
    pub service_name: String,   // Windows SCM service name, if any
    pub publisher:    String,   // PE CompanyName, Windows only
}

impl ProcessInfo {
    /// Fallback when the process is inaccessible.
    pub fn unknown(pid: u32) -> Self {
        Self {
            name:     format!("<{pid}>"),
            name_key: format!("<{pid}>"),
            ..Default::default()
        }
    }
}

// ── Collector ─────────────────────────────────────────────────────────────────

/// Collect process metadata for `pid`.
///
/// `svc_map` maps pid → Windows service name (built once per poll cycle on
/// Windows; empty on other platforms).
pub fn collect(pid: u32, svc_map: &std::collections::HashMap<u32, String>) -> ProcessInfo {
    let mut sys = System::new();
    let spid = Pid::from_u32(pid);
    sys.refresh_processes(ProcessesToUpdate::Some(&[spid]), true);

    let proc = match sys.process(spid) {
        Some(p) => p,
        None => return ProcessInfo::unknown(pid),
    };

    let name = proc.name().to_string_lossy().to_string();
    let name_key = crate::config::normalise_name(&name);

    let path = proc
        .exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let user = proc
        .user_id()
        .map(|uid| uid.to_string())
        .unwrap_or_default();

    // Walk the ancestor chain up to 8 levels.
    // We re-use the same System to avoid re-scanning the process table.
    let ancestors = walk_ancestors(proc.parent(), &mut sys);
    let (parent_name, parent_pid) = ancestors
        .first()
        .cloned()
        .unwrap_or_default();

    let service_name = svc_map.get(&pid).cloned().unwrap_or_default();
    let publisher = publisher::get_publisher(&path);

    ProcessInfo {
        name,
        name_key,
        path,
        user,
        parent_name,
        parent_pid,
        ancestors,
        service_name,
        publisher,
    }
}

/// Walk up the process tree starting from `start_pid`, returning
/// `[(name, pid), …]` from immediate parent to root, capped at 8 levels.
fn walk_ancestors(
    start_pid: Option<Pid>,
    sys: &mut System,
) -> Vec<(String, u32)> {
    const MAX_DEPTH: usize = 8;
    let mut chain = Vec::new();
    let mut current = start_pid;

    while let Some(ppid) = current {
        if chain.len() >= MAX_DEPTH {
            break;
        }
        sys.refresh_processes(ProcessesToUpdate::Some(&[ppid]), true);
        match sys.process(ppid) {
            Some(pp) => {
                let pname = pp.name().to_string_lossy().to_string();
                let ppid_u32 = ppid.as_u32();
                // Guard against cycles (pid == parent pid)
                if chain.iter().any(|(_, id)| *id == ppid_u32) {
                    break;
                }
                chain.push((pname, ppid_u32));
                current = pp.parent();
            }
            None => break,
        }
    }
    chain
}

// ── Windows service map ───────────────────────────────────────────────────────

/// Build a `pid → service_name` map from the Windows SCM.
/// Returns an empty map on non-Windows or if enumeration fails.
pub fn build_service_map() -> std::collections::HashMap<u32, String> {
    #[cfg(windows)]
    return windows_service_map();

    #[cfg(not(windows))]
    std::collections::HashMap::new()
}

#[cfg(windows)]
fn windows_service_map() -> std::collections::HashMap<u32, String> {
    use windows::Win32::System::Services::{
        EnumServicesStatusExW, OpenSCManagerW, SC_ENUM_PROCESS_INFO,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
        ENUM_SERVICE_STATUS_PROCESSW,
    };

    let mut map = std::collections::HashMap::new();

    unsafe {
        let scm = match OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) {
            Ok(h) => h,
            Err(_) => return map,
        };

        let mut bytes_needed: u32 = 0;
        let mut services_returned: u32 = 0;
        let mut resume_handle: u32 = 0;

        // First call: get required buffer size
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            None,
        );

        if bytes_needed == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(
                windows::Win32::Foundation::HANDLE(scm.0)
            );
            return map;
        }

        // Second call: fill buffer
        let mut buf: Vec<u8> = vec![0u8; bytes_needed as usize];
        resume_handle = 0;

        if EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buf),
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            None,
        )
        .is_ok()
        {
            let entries = std::slice::from_raw_parts(
                buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                services_returned as usize,
            );
            for entry in entries {
                let pid = entry.ServiceStatusProcess.dwProcessId;
                if pid != 0 {
                    let name = entry.lpServiceName.to_string().unwrap_or_default();
                    map.insert(pid, name);
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(
            windows::Win32::Foundation::HANDLE(scm.0)
        );
    }

    map
}
