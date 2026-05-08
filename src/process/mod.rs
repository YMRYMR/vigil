//! Process metadata collection.
//!
//! `collect(pid)` does a single pass over the process table (via sysinfo)
//! and returns everything the scorer and UI need.

pub mod publisher;

use sysinfo::{Pid, ProcessesToUpdate, System};

/// All process context attached to a connection.
#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub name: String,     // "chrome.exe"
    pub name_key: String, // "chrome"   (lowercase, .exe stripped — for scoring)
    pub path: String,     // full exe path, empty if inaccessible
    pub user: String,
    pub parent_name: String,
    pub parent_pid: u32,
    pub parent_user: String,
    pub command_line: String,
    /// Full ancestor chain: [(name, pid), …] from immediate parent to root.
    /// Capped at 8 levels to avoid runaway walks on deep trees.
    pub ancestors: Vec<(String, u32)>,
    pub service_name: String, // Windows SCM service name, if any
    pub publisher: String,    // PE CompanyName, Windows only
}

impl ProcessInfo {
    /// Fallback when the process is inaccessible.
    pub fn unknown(pid: u32) -> Self {
        Self {
            name: format!("<{pid}>"),
            name_key: format!("<{pid}>"),
            ..Default::default()
        }
    }
}

/// Collect process metadata for `pid`.
///
/// `svc_map` maps pid → Windows service name (built once per poll cycle on
/// Windows; empty on other platforms).
///
/// ## ETW race-condition mitigation
/// When ETW fires sub-millisecond after a kernel connection event, the target
/// process may not yet appear in sysinfo's snapshot — or may already be gone
/// for short-lived spawners.  We retry once with a 100 ms delay before giving
/// up; this catches most of the "`<pid>`" ghost rows that would otherwise fire.
pub fn collect(pid: u32, svc_map: &std::collections::HashMap<u32, String>) -> ProcessInfo {
    let mut sys = System::new();
    let spid = Pid::from_u32(pid);
    sys.refresh_processes(ProcessesToUpdate::Some(&[spid]), true);

    if sys.process(spid).is_none() {
        std::thread::sleep(std::time::Duration::from_millis(100));
        sys.refresh_processes(ProcessesToUpdate::Some(&[spid]), true);
    }

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
    let command_line = join_cmdline(proc.cmd());
    let parent_pid_opt = proc.parent();
    let ancestors = walk_ancestors(parent_pid_opt, &mut sys);
    let (parent_name, parent_pid) = ancestors.first().cloned().unwrap_or_default();
    let parent_user = parent_pid_opt
        .and_then(|ppid| {
            sys.refresh_processes(ProcessesToUpdate::Some(&[ppid]), true);
            sys.process(ppid)
                .and_then(|pp| pp.user_id().map(|uid| uid.to_string()))
        })
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
        parent_user,
        command_line,
        ancestors,
        service_name,
        publisher,
    }
}

fn walk_ancestors(start_pid: Option<Pid>, sys: &mut System) -> Vec<(String, u32)> {
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

fn join_cmdline(parts: &[std::ffi::OsString]) -> String {
    parts
        .iter()
        .map(|part| part.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn build_services_by_pid() -> std::collections::HashMap<u32, Vec<String>> {
    #[cfg(windows)]
    return windows_services_by_pid();

    #[cfg(not(windows))]
    std::collections::HashMap::new()
}

pub fn build_service_map() -> std::collections::HashMap<u32, String> {
    primary_service_name_map(build_services_by_pid())
}

fn primary_service_name_map(
    services_by_pid: std::collections::HashMap<u32, Vec<String>>,
) -> std::collections::HashMap<u32, String> {
    services_by_pid
        .into_iter()
        .filter_map(|(pid, names)| {
            names
                .into_iter()
                .rev()
                .find(|name| !name.trim().is_empty())
                .map(|name| (pid, name))
        })
        .collect()
}

#[cfg(any(windows, test))]
fn remember_service_name(
    map: &mut std::collections::HashMap<u32, Vec<String>>,
    pid: u32,
    name: String,
) {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return;
    }

    let names = map.entry(pid).or_default();
    if names
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(trimmed))
    {
        return;
    }
    names.push(trimmed.to_string());
}

#[cfg(windows)]
fn windows_services_by_pid() -> std::collections::HashMap<u32, Vec<String>> {
    use windows::Win32::System::Services::{
        EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW, SC_ENUM_PROCESS_INFO,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
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
            let _ =
                windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(scm.0));
            return map;
        }

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
                    remember_service_name(&mut map, pid, name);
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(scm.0));
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remember_service_name_skips_blank_and_duplicates() {
        let mut map = std::collections::HashMap::new();
        remember_service_name(&mut map, 42, "   ".to_string());
        remember_service_name(&mut map, 42, "Dnscache".to_string());
        remember_service_name(&mut map, 42, "dnscache".to_string());
        remember_service_name(&mut map, 42, "LanmanWorkstation".to_string());

        assert_eq!(
            map.get(&42),
            Some(&vec![
                "Dnscache".to_string(),
                "LanmanWorkstation".to_string()
            ])
        );
    }

    #[test]
    fn primary_service_name_map_keeps_last_service_per_pid_for_live_process_context() {
        let mut grouped = std::collections::HashMap::new();
        grouped.insert(
            42,
            vec!["Dnscache".to_string(), "LanmanWorkstation".to_string()],
        );
        grouped.insert(7, vec!["Spooler".to_string()]);

        let primary = primary_service_name_map(grouped);
        assert_eq!(
            primary.get(&42).map(String::as_str),
            Some("LanmanWorkstation")
        );
        assert_eq!(primary.get(&7).map(String::as_str), Some("Spooler"));
    }
}
