#[cfg(target_os = "linux")]
use super::super::linux_command_plan::{
    nft_flush_chain, nft_list_ruleset, LinuxCommandRunner, StdLinuxCommandRunner,
    NFT_ISOL_FORWARD_CHAIN, NFT_ISOL_IN_CHAIN, NFT_ISOL_OUT_CHAIN,
};
#[cfg(target_os = "linux")]
use super::super::linux_firewall_backend::{
    capture_iptables_policy_snapshot, IptablesPolicySnapshot,
};
#[cfg(target_os = "linux")]
use super::super::linux_firewall_executor::execute_system_isolate_plan;
#[allow(unused_imports)]
use super::{
    socket_addr_from_text, unix_now, AutorunEntry, AutorunSnapshot, FirewallProfileState,
    FirewallSnapshot, NetworkAdapterState, NetworkSnapshot, SocketKillError, SocketKillTarget,
    State, TcpSessionState, ISOLATE_RULE_IN, ISOLATE_RULE_OUT,
};
#[allow(unused_imports)]
use std::net::SocketAddr;
#[allow(unused_imports)]
use std::path::PathBuf;
use std::process::Command;
#[allow(unused_imports)]
use std::time::Duration;

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::platform::command_paths;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::windows::process::CommandExt;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, HANDLE, INVALID_HANDLE_VALUE, NO_ERROR,
    };
    use windows::Win32::NetworkManagement::IpHelper::{
        SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCP_STATE_DELETE_TCB,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread, ResumeThread, SuspendThread,
        PROCESS_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
    };
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::{RegKey, HKEY};
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    pub struct AutorunRevertResult {
        pub removed_additions: usize,
        pub restored_entries: usize,
    }
    const RUN_KEYS: [(&str, HKEY, &str); 4] = [
        (
            "HKCU",
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            "HKLM",
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            "HKCU",
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (
            "HKLM",
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    ];
    pub fn is_supported() -> bool {
        true
    }
    pub fn supports_isolation() -> bool {
        true
    }
    pub fn is_elevated() -> bool {
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut bytes = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut bytes,
            )
            .is_ok();
            let _ = CloseHandle(token);
            ok && elevation.TokenIsElevated != 0
        }
    }
    #[allow(dead_code)]
    pub fn process_exists(pid: u32) -> bool {
        unsafe {
            match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(handle) => {
                    let _ = CloseHandle(handle);
                    true
                }
                Err(_) => false,
            }
        }
    }
    pub fn snapshot_autoruns() -> Result<AutorunSnapshot, String> {
        let mut entries = Vec::new();
        for (label, hive, key_path) in RUN_KEYS {
            let root = RegKey::predef(hive);
            let key = match root.open_subkey(key_path) {
                Ok(k) => k,
                Err(_) => continue,
            };
            for item in key.enum_values() {
                let Ok((name, _value)) = item else { continue };
                let value_data = key.get_value::<String, _>(&name).unwrap_or_default();
                entries.push(AutorunEntry {
                    hive: label.to_string(),
                    key_path: key_path.to_string(),
                    value_name: name,
                    value_data,
                });
            }
        }
        entries.sort_by(|a, b| {
            (&a.hive, &a.key_path, &a.value_name).cmp(&(&b.hive, &b.key_path, &b.value_name))
        });
        Ok(AutorunSnapshot {
            captured_at_unix: unix_now(),
            entries,
        })
    }
    pub fn revert_autorun_changes(
        baseline: &[AutorunEntry],
    ) -> Result<AutorunRevertResult, String> {
        let current = snapshot_autoruns()?;
        let mut baseline_map: BTreeMap<(String, String, String), String> = BTreeMap::new();
        for entry in baseline {
            baseline_map.insert(
                (
                    entry.hive.clone(),
                    entry.key_path.clone(),
                    entry.value_name.clone(),
                ),
                entry.value_data.clone(),
            );
        }
        let mut current_map: BTreeMap<(String, String, String), String> = BTreeMap::new();
        for entry in &current.entries {
            current_map.insert(
                (
                    entry.hive.clone(),
                    entry.key_path.clone(),
                    entry.value_name.clone(),
                ),
                entry.value_data.clone(),
            );
        }
        let mut removed_additions = 0usize;
        let mut restored_entries = 0usize;
        for (label, hive, key_path) in RUN_KEYS {
            let root = RegKey::predef(hive);
            let key = match root.create_subkey(key_path) {
                Ok((k, _)) => k,
                Err(e) => {
                    return Err(format!(
                        "failed to open autorun key {}\\{}: {e}",
                        label, key_path
                    ))
                }
            };
            for ((entry_hive, entry_path, value_name), current_value) in current_map.iter() {
                if entry_hive != label || entry_path != key_path {
                    continue;
                }
                let lookup = (entry_hive.clone(), entry_path.clone(), value_name.clone());
                if !baseline_map.contains_key(&lookup) {
                    key.delete_value(value_name).map_err(|e| {
                        format!(
                            "failed to delete autorun value {}\\{}\\{}: {e}",
                            label, key_path, value_name
                        )
                    })?;
                    removed_additions += 1;
                } else if baseline_map.get(&lookup) != Some(current_value) {
                    let baseline_value = baseline_map.get(&lookup).cloned().unwrap_or_default();
                    key.set_value(value_name, &baseline_value).map_err(|e| {
                        format!(
                            "failed to restore autorun value {}\\{}\\{}: {e}",
                            label, key_path, value_name
                        )
                    })?;
                    restored_entries += 1;
                }
            }
            for ((entry_hive, entry_path, value_name), baseline_value) in baseline_map.iter() {
                if entry_hive != label || entry_path != key_path {
                    continue;
                }
                let lookup = (entry_hive.clone(), entry_path.clone(), value_name.clone());
                if !current_map.contains_key(&lookup) {
                    key.set_value(value_name, baseline_value).map_err(|e| {
                        format!(
                            "failed to restore missing autorun value {}\\{}\\{}: {e}",
                            label, key_path, value_name
                        )
                    })?;
                    restored_entries += 1;
                }
            }
        }
        Ok(AutorunRevertResult {
            removed_additions,
            restored_entries,
        })
    }
    pub fn snapshot_firewall_profiles() -> Result<FirewallSnapshot, String> {
        let output = run_powershell_json(
            "Get-NetFirewallProfile | Where-Object { $_.Name -in 'Domain','Private','Public' } | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Depth 2 -Compress",
        )?;
        parse_firewall_snapshot(&output)
    }
    pub fn apply_firewall_isolation() -> Result<(), String> {
        for profile in ["Domain", "Private", "Public"] {
            run_powershell(&format!(
                "Set-NetFirewallProfile -Profile {} -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction Stop",
                ps_quoted(profile)
            ))?;
        }
        let snapshot = snapshot_firewall_profiles()?;
        if snapshot.profiles.is_empty()
            || snapshot.profiles.iter().any(|profile| {
                !profile.enabled
                    || !profile.inbound_action.eq_ignore_ascii_case("Block")
                    || !profile.outbound_action.eq_ignore_ascii_case("Block")
            })
        {
            return Err("firewall policy is not fully enabled and blocked".into());
        }
        Ok(())
    }
    pub fn restore_firewall_profiles(snapshot: &FirewallSnapshot) -> Result<(), String> {
        for profile in &snapshot.profiles {
            run_powershell(&format!(
                "Set-NetFirewallProfile -Profile {} -Enabled {} -DefaultInboundAction {} -DefaultOutboundAction {} -ErrorAction Stop",
                ps_quoted(&profile.name),
                if profile.enabled { "True" } else { "False" },
                profile.inbound_action,
                profile.outbound_action,
            ))?;
        }
        Ok(())
    }
    pub fn isolation_controls_active(state: &State) -> Result<bool, String> {
        if firewall_rule_present(ISOLATE_RULE_IN)? || firewall_rule_present(ISOLATE_RULE_OUT)? {
            return Ok(true);
        }
        let current_profiles = snapshot_firewall_profiles()?;
        let profiles_fully_blocked = firewall_profiles_fully_blocked(&current_profiles);
        let firewall_controls_active = if let Some(snapshot) = state.firewall_snapshot.as_ref() {
            current_profiles != *snapshot && profiles_fully_blocked
        } else {
            profiles_fully_blocked
        };
        if firewall_controls_active {
            return Ok(true);
        }
        if let Some(snapshot) = state.network_snapshot.as_ref() {
            if !snapshot.adapters.is_empty() && !snapshot_adapters_are_enabled(snapshot)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn snapshot_active_adapters() -> Result<NetworkSnapshot, String> {
        let wifi_profiles = snapshot_connected_wifi_profiles();
        let output = run_powershell_json(
            "$if_indexes = @(); $if_indexes += Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -or $_.IPv6DefaultGateway -ne $null } | Select-Object -ExpandProperty InterfaceIndex; $if_indexes += Get-NetRoute -DestinationPrefix '0.0.0.0/0' -State Alive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceIndex; $if_indexes += Get-NetRoute -DestinationPrefix '::/0' -State Alive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InterfaceIndex; $if_indexes = @($if_indexes | Where-Object { $_ -ne $null } | Sort-Object -Unique); if ($if_indexes.Count -eq 0) { @() | ConvertTo-Json -Compress } else { Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne 'Loopback Pseudo-Interface 1' -and $if_indexes -contains $_.ifIndex } | Select-Object Name,InterfaceDescription,NdisPhysicalMedium | ConvertTo-Json -Compress }",
        )?;
        let adapters = parse_adapter_snapshot(&output, &wifi_profiles)?;
        Ok(NetworkSnapshot { adapters })
    }
    pub fn disable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        for adapter in &snapshot.adapters {
            run_powershell(&format!(
                "Disable-NetAdapter -Name {} -Confirm:$false -ErrorAction Stop",
                ps_quoted(&adapter.name)
            ))?;
        }
        Ok(())
    }
    pub fn enable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        let mut warnings = Vec::new();
        let mut recovered_any = false;
        for adapter in &snapshot.adapters {
            let result = run_powershell(&format!(
                "$adapter = Get-NetAdapter -Name {} -ErrorAction SilentlyContinue | Select-Object -First 1; if ($null -eq $adapter) {{ 'MISSING' }} else {{ if ($adapter.Status -ne 'Up') {{ Enable-NetAdapter -Name {} -Confirm:$false -ErrorAction Stop }}; 'READY' }}",
                ps_quoted(&adapter.name),
                ps_quoted(&adapter.name)
            ));
            let output = match result {
                Ok(output) => output,
                Err(err) => {
                    warnings.push(format!("{}: {err}", adapter.name));
                    continue;
                }
            };
            if output.trim().eq_ignore_ascii_case("MISSING") {
                warnings.push(format!(
                    "{}: adapter not found during restore",
                    adapter.name
                ));
                continue;
            }
            recovered_any = true;
            if adapter.is_wireless {
                schedule_wireless_reconnect(adapter.name.clone(), adapter.wifi_profile.clone());
            }
        }
        if recovered_any {
            return Ok(());
        }
        if !snapshot.adapters.is_empty() && snapshot_adapters_are_enabled(snapshot).unwrap_or(false)
        {
            return Ok(());
        }
        if warnings.is_empty() {
            Err("no saved adapters could be restored".into())
        } else {
            Err(warnings.join("; "))
        }
    }
    pub fn enable_all_network_adapters() -> Result<usize, String> {
        let wifi_profiles = snapshot_connected_wifi_profiles();
        let output = run_powershell_json(
            "Get-NetAdapter | Where-Object { $_.Name -ne 'Loopback Pseudo-Interface 1' -and $_.Status -ne 'Up' -and $_.HardwareInterface -eq $true } | Select-Object Name,InterfaceDescription,NdisPhysicalMedium | ConvertTo-Json -Compress",
        )?;
        let adapters = parse_adapter_snapshot(&output, &wifi_profiles)?;
        let mut enabled = 0usize;
        for adapter in adapters {
            run_powershell(&format!(
                "Enable-NetAdapter -Name {} -Confirm:$false -ErrorAction Stop",
                ps_quoted(&adapter.name)
            ))?;
            enabled += 1;
            if adapter.is_wireless {
                schedule_wireless_reconnect(adapter.name.clone(), adapter.wifi_profile.clone());
            }
        }
        Ok(enabled)
    }
    #[allow(dead_code)]
    pub fn terminate_active_tcp_connections() -> Result<usize, String> {
        let output = run_powershell_json(
            "Get-NetTCPConnection -State Established | Where-Object { $_.LocalAddress -notmatch ':' -and $_.RemoteAddress -notmatch ':' } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort | ConvertTo-Json -Compress",
        )?;
        let targets = parse_tcp_session_snapshot(&output)?;
        let mut reset = 0usize;
        for target in targets {
            let local = SocketAddr::new(
                target
                    .local_address
                    .parse()
                    .map_err(|e| format!("invalid local address {}: {e}", target.local_address))?,
                target.local_port,
            );
            let remote = SocketAddr::new(
                target.remote_address.parse().map_err(|e| {
                    format!("invalid remote address {}: {e}", target.remote_address)
                })?,
                target.remote_port,
            );
            if let Err(err) = kill_tcp_connection(&SocketKillTarget { local, remote }) {
                match err {
                    SocketKillError::OsError(msg) if msg == "317" => continue,
                    SocketKillError::UnsupportedAddressFamily => continue,
                    other => return Err(other.to_string()),
                }
            }
            reset += 1;
        }
        Ok(reset)
    }
    pub fn suspend_process(pid: u32) -> Result<(), String> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| format!("failed to snapshot threads for PID {pid}: {e}"))?
        };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!("failed to snapshot threads for PID {pid}"));
        }
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut success_count = 0usize;
        let first = unsafe { Thread32First(snapshot, &mut entry).is_ok() };
        if first {
            loop {
                if entry.th32OwnerProcessID == pid {
                    unsafe {
                        if let Ok(thread) =
                            OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                        {
                            let result = SuspendThread(thread);
                            let _ = CloseHandle(thread);
                            if result != u32::MAX {
                                success_count += 1;
                            }
                        }
                    }
                }
                if unsafe { Thread32Next(snapshot, &mut entry).is_err() } {
                    break;
                }
            }
        }
        let _ = unsafe { CloseHandle(snapshot) };
        if success_count == 0 {
            Err(format!("no suspendable threads were found for PID {pid}"))
        } else {
            Ok(())
        }
    }
    pub fn resume_process(pid: u32) -> Result<(), String> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| format!("failed to snapshot threads for PID {pid}: {e}"))?
        };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!("failed to snapshot threads for PID {pid}"));
        }
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut success_count = 0usize;
        let first = unsafe { Thread32First(snapshot, &mut entry).is_ok() };
        if first {
            loop {
                if entry.th32OwnerProcessID == pid {
                    unsafe {
                        if let Ok(thread) =
                            OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                        {
                            let result = ResumeThread(thread);
                            let _ = CloseHandle(thread);
                            if result != u32::MAX {
                                success_count += 1;
                            }
                        }
                    }
                }
                if unsafe { Thread32Next(snapshot, &mut entry).is_err() } {
                    break;
                }
            }
        }
        let _ = unsafe { CloseHandle(snapshot) };
        if success_count == 0 {
            Err(format!("no resumable threads were found for PID {pid}"))
        } else {
            Ok(())
        }
    }
    pub fn add_domain_block(domain: &str, marker: &str) -> Result<(), String> {
        let path = hosts_path()?;
        let existing = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        if existing.contains(marker) {
            return Ok(());
        }
        let addition = format!("\r\n{marker}\r\n127.0.0.1 {domain}\r\n::1 {domain}\r\n");
        fs::write(&path, format!("{existing}{addition}"))
            .map_err(|e| format!("failed to update {}: {e}", path.display()))?;
        let _ = flush_dns();
        Ok(())
    }
    pub fn remove_domain_block(domain: &str, marker: &str) -> Result<(), String> {
        let path = hosts_path()?;
        let existing = fs::read_to_string(&path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let target_v4 = format!("127.0.0.1 {domain}");
        let target_v6 = format!("::1 {domain}");
        let mut lines = Vec::new();
        let mut skipping = false;
        for line in existing.lines() {
            let trimmed = line.trim();
            if trimmed == marker {
                skipping = true;
                continue;
            }
            if skipping && (trimmed == target_v4 || trimmed == target_v6) {
                continue;
            }
            if skipping && !trimmed.is_empty() {
                skipping = false;
            }
            if !skipping || trimmed.is_empty() {
                lines.push(line);
            }
        }
        fs::write(&path, lines.join("\r\n"))
            .map_err(|e| format!("failed to update {}: {e}", path.display()))?;
        let _ = flush_dns();
        Ok(())
    }
    fn flush_dns() -> Result<(), String> {
        let status = hidden_command("ipconfig")?
            .arg("/flushdns")
            .status()
            .map_err(|e| format!("failed to spawn ipconfig: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err("ipconfig /flushdns failed".into())
        }
    }
    fn hosts_path() -> Result<PathBuf, String> {
        let windows_dir = windows_directory()
            .ok_or_else(|| "failed to resolve the Windows directory".to_string())?;
        Ok(windows_dir
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts"))
    }
    fn windows_directory() -> Option<PathBuf> {
        let mut buffer = vec![0u16; 260];
        unsafe {
            let len = GetSystemWindowsDirectoryW(Some(&mut buffer));
            if len == 0 {
                return None;
            }
            let len = len as usize;
            if len >= buffer.len() {
                buffer.resize(len + 1, 0);
                let retry_len = GetSystemWindowsDirectoryW(Some(&mut buffer));
                if retry_len == 0 {
                    return None;
                }
                return Some(PathBuf::from(String::from_utf16_lossy(
                    &buffer[..retry_len as usize],
                )));
            }
            Some(PathBuf::from(String::from_utf16_lossy(&buffer[..len])))
        }
    }
    fn hidden_command(program: &str) -> Result<Command, String> {
        let resolved = command_paths::resolve(program)?;
        let mut cmd = Command::new(resolved);
        cmd.creation_flags(CREATE_NO_WINDOW);
        Ok(cmd)
    }
    fn run_powershell(script: &str) -> Result<String, String> {
        let output = hidden_command("powershell")?
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
            .output()
            .map_err(|e| format!("failed to spawn PowerShell: {e}"))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(format!(
                "PowerShell failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
    fn run_powershell_json(script: &str) -> Result<String, String> {
        run_powershell(script)
    }
    fn ps_quoted(text: &str) -> String {
        format!("'{}'", text.replace('"', "''"))
    }
    fn parse_firewall_snapshot(json: &str) -> Result<FirewallSnapshot, String> {
        if json.trim().is_empty() || json.trim() == "null" {
            return Ok(FirewallSnapshot { profiles: vec![] });
        }
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("parse firewall JSON: {e}"))?;
        let entries = if value.is_array() {
            value.as_array().cloned().unwrap_or_default()
        } else {
            vec![value]
        };
        let profiles = entries
            .into_iter()
            .filter_map(|entry| {
                let name = entry.get("Name")?.as_str()?.to_string();
                let enabled = entry.get("Enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                let inbound_action = entry
                    .get("DefaultInboundAction")
                    .and_then(|v| v.as_str())
                    .unwrap_or("NotConfigured")
                    .to_string();
                let outbound_action = entry
                    .get("DefaultOutboundAction")
                    .and_then(|v| v.as_str())
                    .unwrap_or("NotConfigured")
                    .to_string();
                Some(FirewallProfileState {
                    name,
                    enabled,
                    inbound_action,
                    outbound_action,
                })
            })
            .collect();
        Ok(FirewallSnapshot { profiles })
    }
    fn firewall_rule_present(name: &str) -> Result<bool, String> {
        let escaped = name.replace('"', "\"");
        let output = run_powershell_json(&format!(
            "$rule = Get-NetFirewallRule -DisplayName \"{escaped}\" -ErrorAction SilentlyContinue; if ($null -eq $rule) {{ '' }} else {{ $rule.Enabled }}"
        ))?;
        Ok(output.trim().eq_ignore_ascii_case("True"))
    }
    fn firewall_profiles_fully_blocked(snapshot: &FirewallSnapshot) -> bool {
        snapshot.profiles.len() == 3
            && snapshot.profiles.iter().all(|profile| {
                profile.enabled
                    && profile.inbound_action.eq_ignore_ascii_case("Block")
                    && profile.outbound_action.eq_ignore_ascii_case("Block")
            })
    }
    fn snapshot_connected_wifi_profiles() -> std::collections::HashMap<String, Option<String>> {
        let mut profiles = std::collections::HashMap::new();
        let output = match run_powershell_json(
            "Get-NetAdapter | Where-Object { $_.PhysicalMediaType -eq 'Native 802.11' -or $_.NdisPhysicalMedium -eq 'WirelessLan' } | Select-Object Name | ConvertTo-Json -Compress",
        ) {
            Ok(output) => output,
            Err(_) => return profiles,
        };
        let value: serde_json::Value = match serde_json::from_str(&output) {
            Ok(value) => value,
            Err(_) => return profiles,
        };
        let entries = if value.is_array() {
            value.as_array().cloned().unwrap_or_default()
        } else {
            vec![value]
        };
        for entry in entries {
            let Some(name) = entry.get("Name").and_then(|v| v.as_str()) else {
                continue;
            };
            let profile = run_powershell(&format!(
                "$p = netsh wlan show interfaces | Select-String -Pattern '^\s*SSID\s*:\s*(.+)$' | Select-Object -First 1; if ($p) {{ $p.Matches[0].Groups[1].Value.Trim() }}"
            ))
            .ok()
            .filter(|text| !text.trim().is_empty());
            profiles.insert(name.to_string(), profile);
        }
        profiles
    }
    fn schedule_wireless_reconnect(_name: String, _profile: Option<String>) {}
    fn snapshot_adapters_are_enabled(snapshot: &NetworkSnapshot) -> Result<bool, String> {
        let current = snapshot_active_adapters()?;
        Ok(snapshot.adapters.iter().all(|saved| {
            current
                .adapters
                .iter()
                .any(|current| current.name == saved.name)
        }))
    }
    fn parse_adapter_snapshot(
        json: &str,
        wifi_profiles: &std::collections::HashMap<String, Option<String>>,
    ) -> Result<Vec<NetworkAdapterState>, String> {
        if json.trim().is_empty() || json.trim() == "null" {
            return Ok(vec![]);
        }
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("parse adapter JSON: {e}"))?;
        let entries = if value.is_array() {
            value.as_array().cloned().unwrap_or_default()
        } else {
            vec![value]
        };
        Ok(entries
            .into_iter()
            .filter_map(|entry| {
                let name = entry.get("Name")?.as_str()?.to_string();
                let medium = entry
                    .get("NdisPhysicalMedium")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let is_wireless = medium.eq_ignore_ascii_case("WirelessLan")
                    || medium.eq_ignore_ascii_case("Native802_11")
                    || medium.eq_ignore_ascii_case("Native 802.11");
                Some(NetworkAdapterState {
                    wifi_profile: wifi_profiles.get(&name).cloned().unwrap_or(None),
                    name,
                    is_wireless,
                })
            })
            .collect())
    }
    fn parse_tcp_session_snapshot(json: &str) -> Result<Vec<TcpSessionState>, String> {
        if json.trim().is_empty() || json.trim() == "null" {
            return Ok(vec![]);
        }
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("parse TCP JSON: {e}"))?;
        let entries = if value.is_array() {
            value.as_array().cloned().unwrap_or_default()
        } else {
            vec![value]
        };
        let mut sessions = Vec::new();
        for entry in entries {
            let local_address = entry
                .get("LocalAddress")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing LocalAddress".to_string())?
                .to_string();
            let remote_address = entry
                .get("RemoteAddress")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing RemoteAddress".to_string())?
                .to_string();
            let local_port = entry
                .get("LocalPort")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "missing LocalPort".to_string())? as u16;
            let remote_port = entry
                .get("RemotePort")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "missing RemotePort".to_string())? as u16;
            sessions.push(TcpSessionState {
                local_address,
                local_port,
                remote_address,
                remote_port,
            });
        }
        Ok(sessions)
    }
}

pub use imp::*;

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::platform::command_paths;
    use std::process::Stdio;
    pub struct AutorunRevertResult {
        pub removed_additions: usize,
        pub restored_entries: usize,
    }
    pub fn is_supported() -> bool {
        cfg!(target_os = "linux")
    }
    pub fn supports_isolation() -> bool {
        cfg!(target_os = "linux") || cfg!(target_os = "macos")
    }
    pub fn is_elevated() -> bool {
        if unsafe { libc::geteuid() == 0 } {
            return true;
        }
        check_capability(12)
    }
    #[cfg(target_os = "linux")]
    fn check_capability(bit: u8) -> bool {
        let Ok(data) = std::fs::read_to_string("/proc/self/status") else {
            return false;
        };
        for line in data.lines() {
            let Some(rest) = line.strip_prefix("CapEff:\t") else {
                continue;
            };
            let Ok(val) = u64::from_str_radix(rest.trim(), 16) else {
                return false;
            };
            return val & (1u64 << bit) != 0;
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    fn check_capability(_bit: u8) -> bool {
        false
    }
    #[allow(dead_code)]
    pub fn process_exists(pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        command_base("kill", &["-0", &pid.to_string()])
            .and_then(|mut cmd| {
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
                cmd.status()
                    .map_err(|e| format!("failed to spawn kill: {e}"))
            })
            .map(|status| status.success())
            .unwrap_or(false)
    }
    pub fn snapshot_autoruns() -> Result<AutorunSnapshot, String> {
        Err("Autorun freezing is not implemented on this platform.".into())
    }
    pub fn revert_autorun_changes(
        _baseline: &[AutorunEntry],
    ) -> Result<AutorunRevertResult, String> {
        Err("Autorun revert is not implemented on this platform.".into())
    }

    const IPTABLES_COMMENT_PREFIX: &str = "Vigil:";

    pub fn snapshot_firewall_profiles() -> Result<FirewallSnapshot, String> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(ipt_snapshot) = capture_iptables_policy_snapshot(&StdLinuxCommandRunner) {
                return Ok(iptables_snapshot_to_firewall(&ipt_snapshot));
            }
            return Ok(FirewallSnapshot { profiles: vec![] });
        }
        #[allow(unreachable_code)]
        Ok(FirewallSnapshot { profiles: vec![] })
    }

    #[cfg(target_os = "linux")]
    fn iptables_snapshot_to_firewall(snapshot: &IptablesPolicySnapshot) -> FirewallSnapshot {
        let profiles = snapshot
            .chains
            .iter()
            .map(|cp| FirewallProfileState {
                name: cp.chain.clone(),
                enabled: !cp.policy.eq_ignore_ascii_case("DROP"),
                inbound_action: cp.policy.clone(),
                outbound_action: cp.policy.clone(),
            })
            .collect();
        FirewallSnapshot { profiles }
    }
    pub fn apply_firewall_isolation() -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            execute_system_isolate_plan("apply_firewall_isolation")?;
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err("firewall backend unavailable; falling back to emergency adapter cutoff".into())
    }
    pub fn restore_firewall_profiles(_snapshot: &FirewallSnapshot) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let vigil_exists = StdLinuxCommandRunner
                .stdout(&nft_list_ruleset())
                .map(|s| s.contains("table inet vigil"))
                .unwrap_or(false);
            if vigil_exists {
                StdLinuxCommandRunner
                    .status(&nft_flush_chain(NFT_ISOL_IN_CHAIN))
                    .and_then(|()| {
                        StdLinuxCommandRunner.status(&nft_flush_chain(NFT_ISOL_FORWARD_CHAIN))
                    })
                    .and_then(|()| {
                        StdLinuxCommandRunner.status(&nft_flush_chain(NFT_ISOL_OUT_CHAIN))
                    })?;
            }
            for profile in &_snapshot.profiles {
                let policy = if profile.enabled {
                    profile.outbound_action.as_str()
                } else {
                    "DROP"
                };
                if !profile.name.is_empty() {
                    command_status("iptables", &["-P", &profile.name, policy])?;
                }
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Ok(())
    }
    pub fn isolation_controls_active(state: &State) -> Result<bool, String> {
        if let Some(snapshot) = state.firewall_snapshot.as_ref() {
            if !snapshot.profiles.is_empty() {
                let current = snapshot_firewall_profiles()?;
                let all_drop = current.profiles.iter().all(|profile| {
                    profile.enabled
                        && profile.inbound_action.eq_ignore_ascii_case("DROP")
                        && profile.outbound_action.eq_ignore_ascii_case("DROP")
                });
                if all_drop {
                    return Ok(true);
                }
            }
        }
        let Some(snapshot) = state.network_snapshot.as_ref() else {
            return Ok(false);
        };
        if snapshot.adapters.is_empty() {
            return Ok(false);
        }
        let current = snapshot_active_adapters()?;
        let any_saved_adapter_still_present = snapshot.adapters.iter().any(|adapter| {
            current
                .adapters
                .iter()
                .any(|item| item.name == adapter.name)
        });

        Ok(!any_saved_adapter_still_present)
    }
    #[allow(dead_code)]
    pub fn add_block_all_rule(rule_name: &str, dir: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let chain = match dir {
                "out" => "OUTPUT",
                "in" => "INPUT",
                _ => "OUTPUT",
            };
            let comment = format!("{IPTABLES_COMMENT_PREFIX}{rule_name}");
            command_status(
                "iptables",
                &[
                    "-I",
                    chain,
                    "1",
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "DROP",
                ],
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (rule_name, dir);
            Err("Active response is not implemented on this platform.".into())
        }
    }
    pub fn add_block_rule(rule_name: &str, target: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let comment = format!("{IPTABLES_COMMENT_PREFIX}{rule_name}");
            command_status(
                "iptables",
                &[
                    "-I",
                    "OUTPUT",
                    "1",
                    "-d",
                    target,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "DROP",
                ],
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (rule_name, target);
            Err("Active response is not implemented on this platform.".into())
        }
    }
    pub fn add_block_program_rule(
        rule_name: &str,
        pid: u32,
        _path: &str,
        dir: &str,
    ) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let chain = match dir {
                "out" => "OUTPUT",
                "in" => "INPUT",
                _ => "OUTPUT",
            };
            let comment = format!("{IPTABLES_COMMENT_PREFIX}{rule_name}");
            let mut args = vec!["-I", chain, "1"];
            if chain == "OUTPUT" {
                let uid = process_effective_uid(pid)?;
                args.extend_from_slice(&["-m", "owner", "--uid-owner"]);
                let uid_string = uid.to_string();
                args.push(uid_string.as_str());
                args.extend_from_slice(&["-m", "comment", "--comment", &comment, "-j", "DROP"]);
                return command_status("iptables", &args);
            }
            args.extend_from_slice(&["-m", "comment", "--comment", &comment, "-j", "DROP"]);
            command_status("iptables", &args)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (rule_name, _path, dir);
            Err("Active response is not implemented on this platform.".into())
        }
    }
    pub fn delete_rule(rule_name: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let comment = format!("{IPTABLES_COMMENT_PREFIX}{rule_name}");
            let mut failures = Vec::new();
            let mut deleted = 0usize;
            for chain in &["INPUT", "OUTPUT", "FORWARD"] {
                match command_status(
                    "iptables",
                    &[
                        "-D",
                        chain,
                        "-m",
                        "comment",
                        "--comment",
                        &comment,
                        "-j",
                        "DROP",
                    ],
                ) {
                    Ok(()) => deleted += 1,
                    Err(err) => failures.push(format!("{chain}: {err}")),
                }
            }
            if deleted > 0 {
                Ok(())
            } else {
                Err(format!(
                    "failed to delete firewall rule {rule_name}: {}",
                    failures.join("; ")
                ))
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = rule_name;
            Ok(())
        }
    }

    pub fn suspend_process(pid: u32) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            command_status("kill", &["-STOP", &pid.to_string()])
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            Err("Process suspension is not implemented on this platform.".into())
        }
    }
    pub fn resume_process(pid: u32) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            command_status("kill", &["-CONT", &pid.to_string()])
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            Err("Process resume is not implemented on this platform.".into())
        }
    }

    pub fn kill_tcp_connection(target: &SocketKillTarget) -> Result<(), SocketKillError> {
        #[cfg(target_os = "linux")]
        {
            let local_ip = target.local.ip().to_string();
            let local_port = target.local.port().to_string();
            let remote_ip = target.remote.ip().to_string();
            let remote_port = target.remote.port().to_string();
            let status = command_base(
                "ss",
                &[
                    "-K",
                    "dst",
                    &remote_ip,
                    "dport",
                    "=",
                    &remote_port,
                    "src",
                    &local_ip,
                    "sport",
                    "=",
                    &local_port,
                ],
            )
            .map_err(SocketKillError::OsError)?
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| SocketKillError::OsError("failed to spawn ss".into()))?;
            if status.success() {
                Ok(())
            } else {
                Err(SocketKillError::OsError("ss -K failed".into()))
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = target;
            Err(SocketKillError::PlatformUnsupported)
        }
    }
    #[allow(dead_code)]
    pub fn terminate_active_tcp_connections() -> Result<usize, String> {
        #[cfg(target_os = "linux")]
        {
            let data = std::fs::read_to_string("/proc/net/tcp")
                .map_err(|e| format!("read /proc/net/tcp: {e}"))?;
            let mut count = 0usize;
            for line in data.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                if parts[3] != "01" {
                    continue;
                }
                let Some((lip, lport)) = parse_hex_addr_port(parts[1]) else {
                    continue;
                };
                let Some((rip, rport)) = parse_hex_addr_port(parts[2]) else {
                    continue;
                };
                let status = command_base(
                    "ss",
                    &[
                        "-K",
                        "dst",
                        &rip,
                        "dport",
                        "=",
                        &rport.to_string(),
                        "src",
                        &lip,
                        "sport",
                        "=",
                        &lport.to_string(),
                    ],
                )?
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
                if status.map(|s| s.success()).unwrap_or(false) {
                    count += 1;
                }
            }
            Ok(count)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("TCP termination is not implemented on this platform.".into())
        }
    }
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn parse_hex_addr_port(s: &str) -> Option<(String, u16)> {
        let (hex_ip, hex_port) = s.split_once(':')?;
        let port = u16::from_str_radix(hex_port, 16).ok()?;
        if hex_ip.len() != 8 {
            return None;
        }
        let bytes = [
            u8::from_str_radix(&hex_ip[6..8], 16).ok()?,
            u8::from_str_radix(&hex_ip[4..6], 16).ok()?,
            u8::from_str_radix(&hex_ip[2..4], 16).ok()?,
            u8::from_str_radix(&hex_ip[0..2], 16).ok()?,
        ];
        Some((
            format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
            port,
        ))
    }

    pub fn add_domain_block(domain: &str, marker: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let entry = format!("\n{marker}\n127.0.0.1 {domain}\n::1 {domain}\n");
            std::fs::OpenOptions::new()
                .append(true)
                .open("/etc/hosts")
                .and_then(|mut f| std::io::Write::write_all(&mut f, entry.as_bytes()))
                .map_err(|e| format!("failed to update /etc/hosts: {e}"))?;
            flush_dns();
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (domain, marker);
            Err("Domain blocking is not implemented on this platform.".into())
        }
    }
    pub fn remove_domain_block(domain: &str, marker: &str) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let content = std::fs::read_to_string("/etc/hosts")
                .map_err(|e| format!("failed to read /etc/hosts: {e}"))?;
            let filtered: String = content
                .lines()
                .filter(|line| {
                    line.trim() != marker && !line.trim().ends_with(&format!(" {domain}"))
                })
                .collect::<Vec<&str>>()
                .join("\n");
            std::fs::write("/etc/hosts", filtered)
                .map_err(|e| format!("failed to write /etc/hosts: {e}"))?;
            flush_dns();
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (domain, marker);
            Err("Domain blocking is not implemented on this platform.".into())
        }
    }
    #[cfg(target_os = "linux")]
    fn flush_dns() {
        let _ = command_status("resolvectl", &["flush-caches"]);
        let _ = command_status("systemd-resolve", &["--flush-caches"]);
    }

    pub fn snapshot_active_adapters() -> Result<NetworkSnapshot, String> {
        #[cfg(target_os = "linux")]
        {
            let output = command_stdout("ip", &["-o", "link", "show", "up"])?;
            let mut adapters = Vec::new();
            for line in output.lines() {
                let mut parts = line.splitn(3, ':');
                let _ = parts.next();
                let Some(name) = parts.next().map(|p| p.trim()) else {
                    continue;
                };
                if !name.is_empty() && name != "lo" {
                    adapters.push(NetworkAdapterState {
                        name: name.to_string(),
                        is_wireless: false,
                        wifi_profile: None,
                    });
                }
            }
            return Ok(NetworkSnapshot { adapters });
        }
        #[cfg(target_os = "macos")]
        {
            let output = command_stdout("ifconfig", &["-l"])?;
            let mut adapters = Vec::new();
            for name in output.split_whitespace() {
                if name == "lo0" {
                    continue;
                }
                let details = command_stdout("ifconfig", &[name])?;
                if details.contains("status: active") {
                    adapters.push(NetworkAdapterState {
                        name: name.to_string(),
                        is_wireless: false,
                        wifi_profile: None,
                    });
                }
            }
            return Ok(NetworkSnapshot { adapters });
        }
        #[allow(unreachable_code)]
        Err("Network adapter snapshots are not implemented on this platform.".into())
    }
    pub fn disable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            for adapter in &snapshot.adapters {
                command_status("ip", &["link", "set", "dev", &adapter.name, "down"])?;
            }
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            for adapter in &snapshot.adapters {
                command_status("ifconfig", &[&adapter.name, "down"])?;
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err("Network adapter isolation is not implemented on this platform.".into())
    }
    pub fn enable_active_adapters(snapshot: &NetworkSnapshot) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            for adapter in &snapshot.adapters {
                command_status("ip", &["link", "set", "dev", &adapter.name, "up"])?;
            }
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            for adapter in &snapshot.adapters {
                command_status("ifconfig", &[&adapter.name, "up"])?;
            }
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err("Network adapter restoration is not implemented on this platform.".into())
    }
    pub fn enable_all_network_adapters() -> Result<usize, String> {
        #[cfg(target_os = "linux")]
        {
            let output = command_stdout("ip", &["-o", "link", "show"])?;
            let mut names = Vec::new();
            for line in output.lines() {
                let mut parts = line.splitn(3, ':');
                let _ = parts.next();
                let Some(name) = parts.next().map(|p| p.trim()) else {
                    continue;
                };
                if !name.is_empty() && name != "lo" {
                    names.push(name.to_string());
                }
            }
            let mut enabled = 0usize;
            for name in names {
                if command_status("ip", &["link", "set", "dev", &name, "up"]).is_ok() {
                    enabled += 1;
                }
            }
            return Ok(enabled);
        }
        #[cfg(target_os = "macos")]
        {
            let output = command_stdout("ifconfig", &["-l"])?;
            let mut enabled = 0usize;
            for name in output.split_whitespace() {
                if name == "lo0" {
                    continue;
                }
                if command_status("ifconfig", &[name, "up"]).is_ok() {
                    enabled += 1;
                }
            }
            return Ok(enabled);
        }
        #[allow(unreachable_code)]
        Ok(0)
    }

    fn command_stdout(program: &str, args: &[&str]) -> Result<String, String> {
        let output = command_base(program, args)?
            .output()
            .map_err(|e| format!("failed to spawn {program}: {e}"))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(format!(
                "{program} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
    fn command_status(program: &str, args: &[&str]) -> Result<(), String> {
        let status = command_base(program, args)?
            .status()
            .map_err(|e| format!("failed to spawn {program}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{program} failed with status {status}"))
        }
    }
    fn command_base(program: &str, args: &[&str]) -> Result<Command, String> {
        let resolved = command_paths::resolve(program)?;
        let mut cmd = Command::new(resolved);
        cmd.args(args);
        Ok(cmd)
    }

    #[cfg(target_os = "linux")]
    fn process_effective_uid(pid: u32) -> Result<u32, String> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|e| format!("read /proc/{pid}/status: {e}"))?;
        for line in status.lines() {
            let Some(rest) = line.strip_prefix("Uid:") else {
                continue;
            };
            let mut fields = rest.split_whitespace();
            let _real = fields.next();
            let Some(effective) = fields.next() else {
                return Err(format!("malformed Uid line for pid {pid}"));
            };
            return effective
                .parse::<u32>()
                .map_err(|e| format!("parse effective uid for pid {pid}: {e}"));
        }
        Err(format!("could not read effective uid for pid {pid}"))
    }
}

#[cfg(not(windows))]
pub use imp::*;

pub fn snapshot_firewall() -> Result<FirewallSnapshot, String> {
    snapshot_firewall_profiles()
}

pub fn restore_firewall(snapshot: &FirewallSnapshot) -> Result<(), String> {
    restore_firewall_profiles(snapshot)
}

#[cfg(windows)]
pub fn outbound_block_supported() -> Option<bool> {
    Some(true)
}

#[cfg(target_os = "linux")]
pub fn outbound_block_supported() -> Option<bool> {
    Some(true)
}

#[cfg(target_os = "macos")]
pub fn outbound_block_supported() -> Option<bool> {
    Some(false)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn outbound_block_supported() -> Option<bool> {
    None
}

pub fn apply_firewall_isolation_inbound_only() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        apply_firewall_isolation()
    }
}
