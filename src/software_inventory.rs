//! Minimal local software inventory foundations for advisory relevance.
//!
//! Phase 16 Task 1 starts with conservative, low-risk inventory sources:
//! currently-running processes plus Windows uninstall metadata when available.
//! This broadens advisory relevance beyond live sockets while keeping the
//! inventory explainable and cheap to collect.

use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::time::Duration;
use sysinfo::System;

const STARTUP_INVENTORY_DELAY: Duration = Duration::from_secs(15);
const STARTUP_INVENTORY_MAX_ENTRIES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledSoftware {
    pub product_key: String,
    pub display_name: String,
    pub executable_path: String,
    pub version_hint: Option<String>,
    pub publisher_hint: Option<String>,
    pub source: InventorySource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InventorySource {
    RunningProcess,
    WindowsUninstallRegistry,
}

pub fn startup_inventory_delay() -> Duration {
    STARTUP_INVENTORY_DELAY
}

pub fn collect_startup_inventory() -> Vec<InstalledSoftware> {
    collect_installed_software_limited(STARTUP_INVENTORY_MAX_ENTRIES)
}

pub fn collect_installed_software() -> Vec<InstalledSoftware> {
    collect_installed_software_limited(usize::MAX)
}

fn collect_installed_software_limited(max_entries: usize) -> Vec<InstalledSoftware> {
    let mut by_key: BTreeMap<String, InstalledSoftware> = BTreeMap::new();
    collect_running_process_inventory(max_entries, &mut by_key);

    let remaining = max_entries.saturating_sub(by_key.len());
    if remaining > 0 {
        for entry in collect_platform_installed_software(remaining) {
            if by_key.len() >= max_entries {
                break;
            }
            upsert_inventory_entry(&mut by_key, entry);
        }
    }

    by_key.into_values().collect()
}

fn collect_running_process_inventory(
    max_entries: usize,
    by_key: &mut BTreeMap<String, InstalledSoftware>,
) {
    let mut sys = System::new_all();
    sys.refresh_all();

    for process in sys.processes().values() {
        if by_key.len() >= max_entries {
            break;
        }

        let display_name = process.name().to_string_lossy().trim().to_string();
        if display_name.is_empty() {
            continue;
        }

        let executable_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let product_key = derive_product_key(&display_name, &executable_path);
        let entry = InstalledSoftware {
            product_key,
            display_name,
            executable_path,
            version_hint: None,
            publisher_hint: None,
            source: InventorySource::RunningProcess,
        };

        upsert_inventory_entry(by_key, entry);
    }
}

fn upsert_inventory_entry(
    by_key: &mut BTreeMap<String, InstalledSoftware>,
    incoming: InstalledSoftware,
) {
    match by_key.entry(incoming.product_key.clone()) {
        Entry::Vacant(slot) => {
            slot.insert(incoming);
        }
        Entry::Occupied(mut slot) => merge_inventory_entry(slot.get_mut(), incoming),
    }
}

fn merge_inventory_entry(existing: &mut InstalledSoftware, incoming: InstalledSoftware) {
    if should_prefer_display_name(
        &existing.display_name,
        &incoming.display_name,
        existing.source,
        incoming.source,
    ) {
        existing.display_name = incoming.display_name.clone();
    }

    if existing.executable_path.is_empty() && !incoming.executable_path.is_empty() {
        existing.executable_path = incoming.executable_path.clone();
    }
    if existing.version_hint.is_none() {
        existing.version_hint = incoming.version_hint.clone();
    }
    if existing.publisher_hint.is_none() {
        existing.publisher_hint = incoming.publisher_hint.clone();
    }

    if matches!(existing.source, InventorySource::RunningProcess)
        && matches!(incoming.source, InventorySource::WindowsUninstallRegistry)
    {
        existing.source = incoming.source;
    }
}

fn should_prefer_display_name(
    existing: &str,
    candidate: &str,
    existing_source: InventorySource,
    candidate_source: InventorySource,
) -> bool {
    let existing = existing.trim();
    let candidate = candidate.trim();

    if candidate.is_empty() || existing.eq_ignore_ascii_case(candidate) {
        return false;
    }
    if existing.is_empty() {
        return true;
    }

    matches!(existing_source, InventorySource::RunningProcess)
        && matches!(candidate_source, InventorySource::WindowsUninstallRegistry)
        && (existing.ends_with(".exe") || candidate.len() > existing.len())
}

#[cfg(windows)]
fn collect_platform_installed_software(limit: usize) -> Vec<InstalledSoftware> {
    collect_windows_uninstall_inventory(limit)
}

#[cfg(not(windows))]
fn collect_platform_installed_software(_limit: usize) -> Vec<InstalledSoftware> {
    Vec::new()
}

#[cfg(windows)]
fn collect_windows_uninstall_inventory(limit: usize) -> Vec<InstalledSoftware> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    const UNINSTALL_PATHS: [(winreg::enums::HKEY, &str); 4] = [
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ];

    let mut installed = Vec::new();

    for (hive, path) in UNINSTALL_PATHS {
        if installed.len() >= limit {
            break;
        }

        let root = RegKey::predef(hive);
        let Ok(uninstall) = root.open_subkey_with_flags(path, KEY_READ) else {
            continue;
        };

        for subkey_name in uninstall.enum_keys().flatten() {
            if installed.len() >= limit {
                break;
            }

            let Ok(subkey) = uninstall.open_subkey_with_flags(&subkey_name, KEY_READ) else {
                continue;
            };

            if registry_dword(&subkey, "SystemComponent") == Some(1)
                || is_windows_update_entry(&subkey)
            {
                continue;
            }

            let Some(display_name) = registry_string(&subkey, "DisplayName") else {
                continue;
            };

            let install_location = registry_string(&subkey, "InstallLocation").unwrap_or_default();
            let display_icon = registry_string(&subkey, "DisplayIcon").unwrap_or_default();
            let executable_path = preferred_inventory_path(&install_location, &display_icon);
            let product_key = derive_product_key(&display_name, &executable_path);

            installed.push(InstalledSoftware {
                product_key,
                display_name,
                executable_path,
                version_hint: registry_string(&subkey, "DisplayVersion"),
                publisher_hint: registry_string(&subkey, "Publisher"),
                source: InventorySource::WindowsUninstallRegistry,
            });
        }
    }

    installed
}

#[cfg(windows)]
fn registry_string(key: &winreg::RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name)
        .ok()
        .and_then(|value| non_empty_string(value))
}

#[cfg(windows)]
fn registry_dword(key: &winreg::RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

#[cfg(windows)]
fn is_windows_update_entry(key: &winreg::RegKey) -> bool {
    if registry_string(key, "ParentKeyName").is_some() {
        return true;
    }

    let Some(release_type) = registry_string(key, "ReleaseType") else {
        return false;
    };
    let release_type = release_type.to_ascii_lowercase();
    release_type.contains("update") || release_type.contains("hotfix")
}

#[cfg(windows)]
fn preferred_inventory_path(install_location: &str, display_icon: &str) -> String {
    let display_icon_path = parse_display_icon_path(display_icon);
    if !display_icon_path.is_empty() {
        return display_icon_path;
    }

    install_location.trim().trim_matches('"').to_string()
}

fn parse_display_icon_path(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let without_wrapping_quotes = trimmed.trim_matches('"');
    let maybe_path = match without_wrapping_quotes.rsplit_once(',') {
        Some((path, suffix))
            if suffix
                .trim()
                .chars()
                .all(|ch| ch == '-' || ch.is_ascii_digit()) =>
        {
            path
        }
        _ => without_wrapping_quotes,
    };

    maybe_path.trim().trim_matches('"').to_string()
}

fn derive_product_key(display_name: &str, executable_path: &str) -> String {
    let normalized_name = normalize_name(display_name);
    if !normalized_name.is_empty() {
        return normalized_name;
    }

    if let Some(file_name) = std::path::Path::new(executable_path).file_name() {
        let candidate = normalize_name(&file_name.to_string_lossy());
        if !candidate.is_empty() {
            return candidate;
        }
    }

    "unknown-product".to_string()
}

fn normalize_name(input: &str) -> String {
    let lower = input.trim().to_lowercase();
    let no_ext = lower.strip_suffix(".exe").unwrap_or(&lower);
    no_ext
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn non_empty_string(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_name_strips_case_and_extension() {
        assert_eq!(normalize_name("PowerShell.EXE"), "powershell");
    }

    #[test]
    fn normalize_name_preserves_unicode_letters() {
        assert_eq!(normalize_name("Программа.EXE"), "программа");
        assert_eq!(normalize_name("監視ツール.exe"), "監視ツール");
    }

    #[test]
    fn derive_product_key_prefers_display_name() {
        let key = derive_product_key("Google Chrome", "/opt/chrome/chrome");
        assert_eq!(key, "google-chrome");
    }

    #[test]
    fn derive_product_key_uses_path_when_name_missing() {
        let key = derive_product_key("", "/usr/bin/curl");
        assert_eq!(key, "curl");
    }

    #[test]
    fn merge_prefers_registry_name_and_version_when_available() {
        let mut by_key: BTreeMap<String, InstalledSoftware> = BTreeMap::new();
        upsert_inventory_entry(
            &mut by_key,
            InstalledSoftware {
                product_key: "google-chrome".into(),
                display_name: "chrome.exe".into(),
                executable_path: r"C:\Program Files\Google\Chrome\Application\chrome.exe"
                    .into(),
                version_hint: None,
                publisher_hint: None,
                source: InventorySource::RunningProcess,
            },
        );
        upsert_inventory_entry(
            &mut by_key,
            InstalledSoftware {
                product_key: "google-chrome".into(),
                display_name: "Google Chrome".into(),
                executable_path: String::new(),
                version_hint: Some("124.0.6367.60".into()),
                publisher_hint: Some("Google LLC".into()),
                source: InventorySource::WindowsUninstallRegistry,
            },
        );

        let merged = by_key.get("google-chrome").expect("merged entry exists");
        assert_eq!(merged.display_name, "Google Chrome");
        assert_eq!(
            merged.executable_path,
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        );
        assert_eq!(merged.version_hint.as_deref(), Some("124.0.6367.60"));
        assert_eq!(merged.publisher_hint.as_deref(), Some("Google LLC"));
        assert_eq!(merged.source, InventorySource::WindowsUninstallRegistry);
    }

    #[test]
    fn parse_display_icon_path_strips_resource_suffix() {
        assert_eq!(
            parse_display_icon_path(r#""C:\Program Files\App\app.exe",0"#),
            r"C:\Program Files\App\app.exe"
        );
        assert_eq!(
            parse_display_icon_path(r"C:\Program Files\App\app.exe,-42"),
            r"C:\Program Files\App\app.exe"
        );
    }

    #[test]
    fn limited_collection_respects_entry_cap() {
        let mut by_key: BTreeMap<String, InstalledSoftware> = BTreeMap::new();
        for i in 0..STARTUP_INVENTORY_MAX_ENTRIES {
            let key = format!("proc-{i}");
            by_key.insert(
                key.clone(),
                InstalledSoftware {
                    product_key: key.clone(),
                    display_name: key,
                    executable_path: String::new(),
                    version_hint: None,
                    publisher_hint: None,
                    source: InventorySource::RunningProcess,
                },
            );
        }
        assert_eq!(by_key.len(), STARTUP_INVENTORY_MAX_ENTRIES);
    }
}
