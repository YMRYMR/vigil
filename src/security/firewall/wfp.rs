//! Windows Filtering Platform (WFP) backend.
//!
//! Uses dynamic loading of fwpmu.dll (LoadLibrary + GetProcAddress) to avoid
//! requiring the Windows SDK fwpmu.lib at build time. The DLL is available on
//! all Windows Vista+ systems.

use super::{FirewallBackend, FirewallProfileState, FirewallSnapshot};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::sync::Mutex;

// WFP filter action constants
mod guid_consts {
    use super::GUID;
    pub const ALE_AUTH_CONNECT_V4: GUID = GUID {
        Data1: 0x9b42e81e,
        Data2: 0x12a6,
        Data3: 0x4b4d,
        Data4: [0x8d, 0x5b, 0x3c, 0xd2, 0xc4, 0xd9, 0x4a, 0xaf],
    };
    pub const ALE_AUTH_RECV_ACCEPT_V4: GUID = GUID {
        Data1: 0xe1cdd7a0,
        Data2: 0x43e2,
        Data3: 0x4f6d,
        Data4: [0x8b, 0x23, 0x3e, 0x7a, 0x9f, 0x5c, 0x6d, 0x4a],
    };
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GUID {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [u8; 8],
}

pub struct WfpBackend {
    engine_handle: Mutex<Option<isize>>,
}

impl WfpBackend {
    pub fn new() -> Self {
        Self {
            engine_handle: Mutex::new(None),
        }
    }

    fn ensure_open(&self) -> Result<isize, String> {
        let mut handle = self.engine_handle.lock().unwrap();
        if let Some(h) = *handle {
            return Ok(h);
        }
        let wfp = WfpDynamic::load()?;
        let mut h: isize = 0;
        let status = wfp.engine_open(
            std::ptr::null(),
            0x0001,
            std::ptr::null(),
            std::ptr::null(),
            &mut h,
        );
        if status != 0 {
            return Err(format!("FwpmEngineOpen failed: {status}"));
        }
        *handle = Some(h);
        Ok(h)
    }
}

struct WfpDynamic {
    engine_open:
        unsafe extern "system" fn(*const u16, u32, *const u8, *const u8, *mut isize) -> u32,
}

impl WfpDynamic {
    fn load() -> Result<Self, String> {
        unsafe {
            let lib = LoadLibraryA("fwpmu.dll\0".as_ptr() as *const i8);
            if lib == 0 {
                return Err("fwpmu.dll not available".into());
            }
            Ok(Self {
                engine_open: std::mem::transmute(
                    GetProcAddress(lib, "FwpmEngineOpen\0".as_ptr() as *const i8)
                        .ok_or("FwpmEngineOpen not found")?,
                ),
            })
        }
    }

    fn engine_open(
        &self,
        server: *const u16,
        authn: u32,
        identity: *const u8,
        session: *const u8,
        handle: *mut isize,
    ) -> u32 {
        unsafe { (self.engine_open)(server, authn, identity, session, handle) }
    }
}

impl FirewallBackend for WfpBackend {
    fn label(&self) -> &'static str {
        "WFP (stub)"
    }

    fn is_available(&self) -> bool {
        self.ensure_open().is_ok()
    }

    fn snapshot_profiles(&self) -> Result<FirewallSnapshot, String> {
        snapshot_profiles_powershell()
    }

    fn apply_isolation(&self, _rule_name: &str) -> Result<(), String> {
        Err("WFP isolation not yet implemented - requires full FwpmFilterAdd binding".into())
    }

    fn restore_profiles(&self, snapshot: &FirewallSnapshot) -> Result<(), String> {
        for profile in &snapshot.profiles {
            run_powershell(&format!(
                "Set-NetFirewallProfile -Profile {} -Enabled ${} -DefaultInboundAction {} -DefaultOutboundAction {}",
                profile.name,
                if profile.enabled { "true" } else { "false" },
                profile.inbound_action,
                profile.outbound_action,
            ))?;
        }
        Ok(())
    }

    fn add_block_rule(&self, rule_name: &str, target: &str) -> Result<(), String> {
        add_netsh_rule(rule_name, target)
    }

    fn add_block_program_rule(
        &self,
        rule_name: &str,
        _pid: u32,
        path: &str,
        direction: &str,
    ) -> Result<(), String> {
        let dir = match direction {
            "in" => "in",
            _ => "out",
        };
        netsh_cmd("add", rule_name, dir, "block", Some(path))
    }

    fn delete_rule(&self, rule_name: &str) -> Result<(), String> {
        netsh_cmd("delete", rule_name, "", "", None::<&str>)
    }

    fn rule_present(&self, rule_name: &str) -> Result<bool, String> {
        rule_present_netsh(rule_name)
    }

    fn isolation_controls_active(&self, _fs: Option<&FirewallSnapshot>) -> Result<bool, String> {
        let current = snapshot_profiles_powershell()?;
        Ok(current.profiles.iter().all(|p| {
            p.enabled
                && p.inbound_action.eq_ignore_ascii_case("Block")
                && p.outbound_action.eq_ignore_ascii_case("Block")
        }))
    }

    fn kill_tcp_connection(&self, local: &str, remote: &str) -> Result<(), String> {
        use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, NO_ERROR};
        use windows::Win32::NetworkManagement::IpHelper::{
            SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCP_STATE_DELETE_TCB,
        };
        let local: std::net::SocketAddr = local
            .parse()
            .map_err(|_| format!("invalid local: {local}"))?;
        let remote: std::net::SocketAddr = remote
            .parse()
            .map_err(|_| format!("invalid remote: {remote}"))?;
        let l = match local {
            std::net::SocketAddr::V4(a) => a,
            _ => return Err("IPv6 not supported".into()),
        };
        let r = match remote {
            std::net::SocketAddr::V4(a) => a,
            _ => return Err("IPv6 not supported".into()),
        };
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 {
                State: MIB_TCP_STATE_DELETE_TCB,
            },
            dwLocalAddr: u32::from_be_bytes(l.ip().octets()),
            dwLocalPort: u32::from(l.port().to_be()),
            dwRemoteAddr: u32::from_be_bytes(r.ip().octets()),
            dwRemotePort: u32::from(r.port().to_be()),
        };
        let status = unsafe { SetTcpEntry(&row) };
        if status == NO_ERROR.0 {
            Ok(())
        } else if status == ERROR_ACCESS_DENIED.0 {
            Err("permission denied".into())
        } else {
            Err(format!("OS error: {status}"))
        }
    }

    fn terminate_active_connections(&self) -> Result<usize, String> {
        let output = run_powershell(
            "Get-NetTCPConnection -State Established | Where-Object { $_.LocalAddress -notmatch ':' -and $_.RemoteAddress -notmatch ':' } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort | ConvertTo-Json -Compress",
        )?;
        let sessions = parse_tcp_sessions(&output)?;
        let mut n = 0;
        for s in &sessions {
            if self
                .kill_tcp_connection(
                    &format!("{}:{}", s.local_addr, s.local_port),
                    &format!("{}:{}", s.remote_addr, s.remote_port),
                )
                .is_ok()
            {
                n += 1;
            }
        }
        Ok(n)
    }

    fn add_domain_block(&self, domain: &str, marker: &str) -> Result<(), String> {
        modify_hosts(&hosts_path()?, |c| {
            c.push_str(&format!("127.0.0.1 {domain}\n::1 {domain}\n{marker}\n"));
        })
    }

    fn remove_domain_block(&self, domain: &str, marker: &str) -> Result<(), String> {
        modify_hosts(&hosts_path()?, |c| {
            *c = c
                .lines()
                .filter(|l| !l.contains(domain) && !l.trim().eq_ignore_ascii_case(marker.trim()))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
        })
    }

    fn flush_dns(&self) -> Result<(), String> {
        let s = hidden_command("ipconfig")?
            .args(["/flushdns"])
            .status()
            .map_err(|e| format!("spawn ipconfig: {e}"))?;
        if s.success() {
            Ok(())
        } else {
            Err("ipconfig /flushdns failed".into())
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const CREATE_NO_WINDOW: u32 = 0x08000000;

fn run_powershell(script: &str) -> Result<String, String> {
    let r = crate::platform::command_paths::resolve("powershell")?;
    let o = std::process::Command::new(r)
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .map_err(|e| format!("spawn PowerShell: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        Err(format!(
            "PowerShell failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ))
    }
}

fn hidden_command(program: &str) -> Result<std::process::Command, String> {
    let mut c = std::process::Command::new(crate::platform::command_paths::resolve(program)?);
    c.creation_flags(CREATE_NO_WINDOW);
    Ok(c)
}

fn hosts_path() -> Result<PathBuf, String> {
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buf = [0u16; 260];
    let len = unsafe { GetSystemWindowsDirectoryW(Some(&mut buf)) };
    if len > 0 && len < buf.len() as u32 {
        Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize]))
            .join(r"System32\drivers\etc\hosts"))
    } else {
        Err("could not determine Windows directory".into())
    }
}

fn modify_hosts(path: &PathBuf, f: impl FnOnce(&mut String)) -> Result<(), String> {
    let mut c = std::fs::read_to_string(path).unwrap_or_default();
    if !c.trim_end().ends_with('\n') {
        c.push('\n');
    }
    f(&mut c);
    std::fs::write(path, &c).map_err(|e| format!("write hosts: {e}"))
}

fn snapshot_profiles_powershell() -> Result<FirewallSnapshot, String> {
    let o = run_powershell(
        "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress",
    )?;
    if o.trim().is_empty() || o.trim() == "null" {
        return Ok(FirewallSnapshot { profiles: vec![] });
    }
    let v: serde_json::Value = serde_json::from_str(&o).map_err(|e| format!("parse JSON: {e}"))?;
    let entries = if v.is_array() {
        v.as_array().cloned().unwrap_or_default()
    } else {
        vec![v]
    };
    Ok(FirewallSnapshot {
        profiles: entries
            .into_iter()
            .filter_map(|e| {
                Some(FirewallProfileState {
                    name: e.get("Name")?.as_str()?.to_string(),
                    enabled: e.get("Enabled").and_then(|v| v.as_bool()).unwrap_or(false),
                    inbound_action: e
                        .get("DefaultInboundAction")
                        .and_then(|v| v.as_str())
                        .unwrap_or("NotConfigured")
                        .to_string(),
                    outbound_action: e
                        .get("DefaultOutboundAction")
                        .and_then(|v| v.as_str())
                        .unwrap_or("NotConfigured")
                        .to_string(),
                })
            })
            .collect(),
    })
}

fn add_netsh_rule(rule_name: &str, target: &str) -> Result<(), String> {
    let s = hidden_command("netsh")?
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={rule_name}"),
            "dir=out",
            "action=block",
            &format!("remoteip={target}"),
            "profile=any",
            "enable=yes",
        ])
        .status()
        .map_err(|e| format!("spawn netsh: {e}"))?;
    if s.success() {
        Ok(())
    } else {
        Err(format!("netsh add failed for {target}"))
    }
}

fn netsh_cmd(
    action: &str,
    rule_name: &str,
    dir: &str,
    action_type: &str,
    program: Option<&str>,
) -> Result<(), String> {
    let mut c = hidden_command("netsh")?;
    c.args([
        "advfirewall",
        "firewall",
        action,
        "rule",
        &format!("name={rule_name}"),
    ]);
    if !dir.is_empty() {
        c.arg(&format!("dir={dir}"));
    }
    if !action_type.is_empty() {
        c.arg(&format!("action={action_type}"));
    }
    if let Some(p) = program {
        c.arg(&format!("program={p}"));
    }
    c.arg("profile=any").arg("enable=yes");
    let s = c.status().map_err(|e| format!("spawn netsh: {e}"))?;
    if s.success() {
        Ok(())
    } else {
        Err(format!("netsh {action} failed for {rule_name}"))
    }
}

fn rule_present_netsh(rule_name: &str) -> Result<bool, String> {
    let o = hidden_command("netsh")?
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={rule_name}"),
        ])
        .output()
        .map_err(|e| format!("spawn netsh: {e}"))?;
    let merged = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
    .to_ascii_lowercase();
    if merged.contains("no rules match") {
        return Ok(false);
    }
    Ok(o.status.success())
}

fn parse_tcp_sessions(json: &str) -> Result<Vec<TcpSession>, String> {
    if json.trim().is_empty() || json.trim() == "null" {
        return Ok(vec![]);
    }
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("parse TCP JSON: {e}"))?;
    let entries = if v.is_array() {
        v.as_array().cloned().unwrap_or_default()
    } else {
        vec![v]
    };
    Ok(entries
        .into_iter()
        .filter_map(|e| {
            Some(TcpSession {
                local_addr: e.get("LocalAddress")?.as_str()?.to_string(),
                local_port: e.get("LocalPort")?.as_u64()? as u16,
                remote_addr: e.get("RemoteAddress")?.as_str()?.to_string(),
                remote_port: e.get("RemotePort")?.as_u64()? as u16,
            })
        })
        .collect())
}

struct TcpSession {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
}

// ── Dynamic loading ──────────────────────────────────────────────────────────

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lpFileName: *const i8) -> isize;
    fn GetProcAddress(hModule: isize, lpProcName: *const i8)
        -> Option<unsafe extern "system" fn()>;
    fn FreeLibrary(hModule: isize) -> u32;
}
