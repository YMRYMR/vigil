//! Registry persistence watcher (Windows only).
//!
//! Polls the four standard autorun registry keys every 30 seconds and emits a
//! synthetic `ConnEvent::Alert` when a **new** entry is detected.  The
//! synthetic `ConnInfo` uses a proc_name of `"[Registry] <value-name>"` and
//! remote_addr of `"REGISTRY"` so the alert is immediately recognisable in the
//! Alerts tab without any UI changes.
//!
//! Keys monitored:
//! - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//! - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
//! - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
//! - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

#[cfg(windows)]
pub mod win {
    use crate::types::{ConnEvent, ConnInfo};
    use chrono::Local;
    use std::collections::HashMap;
    use tokio::sync::broadcast;
    use tokio::time::{sleep, Duration};
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    const POLL_SECS: u64 = 30;

    /// Read all `(hive_label, value_name)` → `value_data` pairs from every
    /// watched autorun key.  Keys that do not exist (e.g. RunOnce when empty)
    /// are silently skipped.
    fn snapshot() -> HashMap<(String, String), String> {
        let mut map = HashMap::new();
        read_run_key(
            &mut map,
            "HKCU\\Run",
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        );
        read_run_key(
            &mut map,
            "HKLM\\Run",
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        );
        read_run_key(
            &mut map,
            "HKCU\\RunOnce",
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        );
        read_run_key(
            &mut map,
            "HKLM\\RunOnce",
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        );
        map
    }

    fn read_run_key(
        map: &mut HashMap<(String, String), String>,
        label: &str,
        hive: winreg::HKEY,
        subkey: &str,
    ) {
        let key = match RegKey::predef(hive).open_subkey(subkey) {
            Ok(k) => k,
            Err(_) => return,
        };
        for entry in key.enum_values() {
            match entry {
                Ok((name, value)) => {
                    // Most Run values are REG_SZ / REG_EXPAND_SZ; try String first.
                    if let Ok(data) = key.get_value::<String, _>(&name) {
                        map.insert((label.to_string(), name), data);
                    } else {
                        // Fallback: hex dump of raw bytes
                        let hex: String = value
                            .bytes
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        map.insert((label.to_string(), name), hex);
                    }
                }
                Err(_) => continue,
            }
        }
    }

    /// Spawn the registry watcher task.  Emits `ConnEvent::Alert` for any new
    /// autorun entry detected after the initial baseline poll.
    pub fn spawn(tx: broadcast::Sender<ConnEvent>, alert_threshold: u8) {
        tokio::spawn(async move {
            let mut baseline = snapshot();
            tracing::info!(
                "Registry persistence watcher started \
                 (polling 4 autorun keys every {}s)",
                POLL_SECS
            );

            loop {
                sleep(Duration::from_secs(POLL_SECS)).await;

                let current = snapshot();
                for ((label, name), data) in &current {
                    if baseline.contains_key(&(label.clone(), name.clone())) {
                        continue; // already known at startup
                    }

                    let reason = format!(
                        "New autorun registry entry in {}: \"{}\" = \"{}\"",
                        label, name, data
                    );
                    tracing::warn!("{}", reason);

                    let info = ConnInfo {
                        timestamp: Local::now().format("%H:%M:%S").to_string(),
                        proc_name: format!("[Registry] {}", name),
                        pid: 0,
                        proc_path: data.clone(),
                        proc_user: String::new(),
                        parent_name: label.clone(),
                        parent_pid: 0,
                        parent_user: String::new(),
                        ancestor_chain: vec![],
                        service_name: String::new(),
                        publisher: String::new(),
                        local_addr: label.clone(),
                        remote_addr: "REGISTRY".to_string(),
                        status: "AUTORUN".to_string(),
                        score: alert_threshold.max(8),
                        reasons: vec![reason],
                        pre_login: crate::session::is_pre_login(),
                        hostname: None,
                        country: None,
                        asn: None,
                        asn_org: None,
                        reputation_hit: None,
                        recently_dropped: false,
                        long_lived: false,
                        dga_like: false,
                        baseline_deviation: false,
                        script_host_suspicious: false,
                        command_line: String::new(),
                        attack_tags: Vec::new(),
                        tls_sni: None,
                        tls_ja3: None,
                    };

                    let _ = tx.send(ConnEvent::Alert(info));
                }

                baseline = current;
            }
        });
    }
}

/// Public API stub — registry monitoring is Windows-only.
#[cfg(not(windows))]
pub mod win {
    use crate::types::ConnEvent;
    use tokio::sync::broadcast;

    pub fn spawn(_tx: broadcast::Sender<ConnEvent>, _alert_threshold: u8) {
        // No-op on non-Windows platforms.
    }
}
