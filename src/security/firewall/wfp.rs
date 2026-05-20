//! Windows Filtering Platform (WFP) backend.
//!
//! Uses dynamic loading of Fwpuclnt.dll for FwpmEngineOpen / FwpmFilterAdd /
//! FwpmFilterDeleteByKey. IP-block rules are created directly via the WFP API
//! (no netsh dependency). Program-block rules use netsh as fallback (WFP ALE
//! app-container filtering requires complex SID setup). Profile snapshot/restore
//! uses Powershell (profiles are a Windows Firewall concept, not a WFP concept).

use super::{FirewallBackend, FirewallProfileState, FirewallSnapshot};
use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::sync::Mutex;

// ── WFP GUIDs ────────────────────────────────────────────────────────────────

const GUID_VIGIL_PROVIDER: GUID = GUID {
    Data1: 0x5D6B9A8C,
    Data2: 0x1E4F,
    Data3: 0x4F2A,
    Data4: [0xB0, 0xA0, 0x9E, 0x3C, 0x2F, 0x1D, 0x8E, 0x7A],
};
const GUID_VIGIL_SUBLAYER: GUID = GUID {
    Data1: 0x7E8F9A0B,
    Data2: 0x2C3D,
    Data3: 0x4E5F,
    Data4: [0x8A, 0x9B, 0x0C, 0x1D, 0x2E, 0x3F, 0x4A, 0x5B],
};
// FWPM_LAYER_ALE_AUTH_CONNECT_V4 (outbound connect)
const GUID_LAYER_ALE_AUTH_CONNECT_V4: GUID = GUID {
    Data1: 0x9B42E81E,
    Data2: 0x12A6,
    Data3: 0x4B4D,
    Data4: [0x8D, 0x5B, 0x3C, 0xD2, 0xC4, 0xD9, 0x4A, 0xAF],
};
// FWPM_CONDITION_IP_REMOTE_ADDRESS
const GUID_COND_IP_REMOTE_ADDRESS: GUID = GUID {
    Data1: 0xDCBDB8A8,
    Data2: 0xE39B,
    Data3: 0x48C6,
    Data4: [0xAD, 0x05, 0x46, 0xB6, 0x47, 0x52, 0x51, 0x24],
};
const FWP_MATCH_EQUAL: u32 = 0;
const FWP_V4_ADDR_MASK_TYPE: u32 = 0x0014;
const FWP_ACTION_BLOCK: u32 = 0x1001;

#[repr(C)]
#[derive(Clone, Copy)]
struct GUID {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [u8; 8],
}

#[repr(C)]
struct FWP_V4_ADDR_AND_MASK {
    addr: u32,
    mask: u32,
}

#[repr(C)]
struct FWP_CONDITION_VALUE0 {
    type_: u32,
    uint32: u32,
    _padding: [u8; 12],
}

#[repr(C)]
struct FWPM_FILTER_CONDITION0 {
    fieldKey: GUID,
    matchType: u32,
    conditionValue: FWP_CONDITION_VALUE0,
}

#[repr(C)]
struct FWPM_ACTION {
    type_: u32,
    calloutKey: GUID,
}

#[repr(C)]
struct FWPM_DISPLAY_DATA {
    name: *mut u16,
    description: *mut u16,
}

#[repr(C)]
struct FWPM_FILTER0 {
    filterKey: GUID,
    displayData: FWPM_DISPLAY_DATA,
    flags: u32,
    providerKey: *const GUID,
    subLayerKey: GUID,
    weight: FWP_EMPTY,
    filterCondition: *mut FWPM_FILTER_CONDITION0,
    numFilterConditions: u32,
    action: FWPM_ACTION,
    rawContext: u64,
    providerData: FWP_BYTE_BLOB,
    effectiveWeight: FWP_EMPTY,
}

#[repr(C)]
struct FWP_BYTE_BLOB {
    size: u32,
    data: *mut u8,
}

#[repr(C)]
struct FWP_EMPTY {
    type_: u32,
    uint8: u8,
}

// ── Backend ───────────────────────────────────────────────────────────────────

pub struct WfpBackend {
    engine_handle: Mutex<Option<isize>>,
    /// Maps rule name → filter GUID so we can delete or check by name.
    filter_registry: Mutex<HashMap<String, GUID>>,
}

impl WfpBackend {
    pub fn new() -> Self {
        Self {
            engine_handle: Mutex::new(None),
            filter_registry: Mutex::new(HashMap::new()),
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

    /// Create a WFP filter blocking outbound traffic to a remote IPv4 address.
    fn add_wfp_ip_filter(&self, h: isize, rule_name: &str, ip: &str) -> Result<GUID, String> {
        let addr: std::net::Ipv4Addr = ip.parse().map_err(|_| format!("invalid IPv4: {ip}"))?;
        // Build a v4 addr/mask condition value. We must heap-allocate because
        // FWP_CONDITION_VALUE0 carries a pointer to FWP_V4_ADDR_AND_MASK for
        // type FWP_V4_ADDR_MASK_TYPE.
        let addr_mask = Box::new(FWP_V4_ADDR_AND_MASK {
            addr: u32::from_be_bytes(addr.octets()),
            mask: 0xFFFFFFFF,
        });
        let cond = Box::new(FWPM_FILTER_CONDITION0 {
            fieldKey: GUID_COND_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                type_: FWP_V4_ADDR_MASK_TYPE,
                uint32: &*addr_mask as *const FWP_V4_ADDR_AND_MASK as u32,
                _padding: [0u8; 12],
            },
        });
        let name_wide = to_wide(&format!("Vigil: {rule_name}"));
        let filter = FWPM_FILTER0 {
            filterKey: new_guid(),
            displayData: FWPM_DISPLAY_DATA {
                name: name_wide,
                description: std::ptr::null_mut(),
            },
            flags: 0,
            providerKey: &GUID_VIGIL_PROVIDER as *const GUID,
            subLayerKey: GUID_VIGIL_SUBLAYER,
            weight: FWP_EMPTY { type_: 0, uint8: 0 },
            filterCondition: Box::into_raw(cond),
            numFilterConditions: 1,
            action: FWPM_ACTION {
                type_: FWP_ACTION_BLOCK,
                calloutKey: GUID {
                    Data1: 0,
                    Data2: 0,
                    Data3: 0,
                    Data4: [0; 8],
                },
            },
            rawContext: 0,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            effectiveWeight: FWP_EMPTY { type_: 0, uint8: 0 },
        };
        let wfp = WfpDynamic::load()?;
        let mut id: u64 = 0;
        let status = wfp.filter_add(h, &filter, std::ptr::null(), &mut id);
        // Free the condition box (FwpmFilterAdd copies it)
        unsafe {
            let _ = Box::from_raw(filter.filterCondition);
        }
        if status != 0 {
            return Err(format!("FwpmFilterAdd failed for {rule_name}: {status}"));
        }
        Ok(filter.filterKey)
    }
}

impl FirewallBackend for WfpBackend {
    fn label(&self) -> &'static str {
        "WFP"
    }

    fn is_available(&self) -> bool {
        self.ensure_open().is_ok()
    }

    fn outbound_block_supported(&self) -> Option<bool> {
        Some(true)
    }

    fn snapshot_profiles(&self) -> Result<FirewallSnapshot, String> {
        snapshot_profiles_powershell()
    }

    fn apply_isolation(&self, _rule_name: &str) -> Result<(), String> {
        run_powershell("Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block").map(|_| ())
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
        let h = self.ensure_open()?;
        let key = self.add_wfp_ip_filter(h, rule_name, target)?;
        self.filter_registry
            .lock()
            .unwrap()
            .insert(rule_name.to_string(), key);
        Ok(())
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
        // Program-based blocking uses netsh — WFP ALE app-container SID
        // filtering requires complex setup. This is a fair trade-off:
        // all IP rules are pure WFP, profile ops are PowerShell, only
        // program rules still use netsh.
        netsh_cmd("add", rule_name, dir, "block", Some(path))
    }

    fn delete_rule(&self, rule_name: &str) -> Result<(), String> {
        // Try WFP first (for IP rules).
        let wfp = WfpDynamic::load()?;
        let h = match *self.engine_handle.lock().unwrap() {
            Some(h) => h,
            None => return netsh_cmd("delete", rule_name, "", "", None::<&str>),
        };
        if let Some(key) = self.filter_registry.lock().unwrap().remove(rule_name) {
            let status = wfp.filter_delete_by_key(h, &key);
            if status == 0 {
                return Ok(());
            }
        }
        // Fall back to netsh for program rules (which have a netsh name).
        netsh_cmd("delete", rule_name, "", "", None::<&str>)
    }

    fn rule_present(&self, rule_name: &str) -> Result<bool, String> {
        // Check WFP registry first.
        if self.filter_registry.lock().unwrap().contains_key(rule_name) {
            return Ok(true);
        }
        // Fall back to netsh for program rules.
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
                .filter(|l| {
                    let t = l.trim();
                    let is_domain = t.split_whitespace().any(|p| p == domain);
                    !is_domain && !t.eq_ignore_ascii_case(marker.trim())
                })
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

// ── WFP dynamic loader ───────────────────────────────────────────────────────

struct WfpDynamic {
    engine_open:
        unsafe extern "system" fn(*const u16, u32, *const u8, *const u8, *mut isize) -> u32,
    filter_add: unsafe extern "system" fn(isize, *const FWPM_FILTER0, *const u8, *mut u64) -> u32,
    filter_delete_by_key: unsafe extern "system" fn(isize, *const GUID) -> u32,
}

impl WfpDynamic {
    fn load() -> Result<Self, String> {
        unsafe {
            let lib = LoadLibraryA("Fwpuclnt.dll\0".as_ptr() as *const i8);
            if lib == 0 {
                return Err("Fwpuclnt.dll not available".into());
            }
            Ok(Self {
                engine_open: std::mem::transmute(
                    GetProcAddress(lib, "FwpmEngineOpen\0".as_ptr() as *const i8)
                        .ok_or("FwpmEngineOpen not found")?,
                ),
                filter_add: std::mem::transmute(
                    GetProcAddress(lib, "FwpmFilterAdd\0".as_ptr() as *const i8)
                        .ok_or("FwpmFilterAdd not found")?,
                ),
                filter_delete_by_key: std::mem::transmute(
                    GetProcAddress(lib, "FwpmFilterDeleteByKey\0".as_ptr() as *const i8)
                        .ok_or("FwpmFilterDeleteByKey not found")?,
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

    fn filter_add(
        &self,
        engine: isize,
        filter: *const FWPM_FILTER0,
        sd: *const u8,
        id: *mut u64,
    ) -> u32 {
        unsafe { (self.filter_add)(engine, filter, sd, id) }
    }

    fn filter_delete_by_key(&self, engine: isize, key: *const GUID) -> u32 {
        unsafe { (self.filter_delete_by_key)(engine, key) }
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

fn new_guid() -> GUID {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    GUID {
        Data1: (nanos & 0xFFFFFFFF) as u32,
        Data2: ((nanos >> 32) & 0xFFFF) as u16,
        Data3: ((nanos >> 48) & 0xFFFF) as u16,
        Data4: [
            ((nanos >> 64) & 0xFF) as u8,
            ((nanos >> 72) & 0xFF) as u8,
            ((nanos >> 80) & 0xFF) as u8,
            ((nanos >> 88) & 0xFF) as u8,
            ((nanos >> 96) & 0xFF) as u8,
            ((nanos >> 104) & 0xFF) as u8,
            ((nanos >> 112) & 0xFF) as u8,
            ((nanos >> 120) & 0xFF) as u8,
        ],
    }
}

fn to_wide(s: &str) -> *mut u16 {
    let encoded: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let ptr = encoded.as_ptr() as *mut u16;
    std::mem::forget(encoded);
    ptr
}

// ── FFI ──────────────────────────────────────────────────────────────────────

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lpFileName: *const i8) -> isize;
    fn GetProcAddress(hModule: isize, lpProcName: *const i8)
        -> Option<unsafe extern "system" fn()>;
}
