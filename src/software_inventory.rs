//! Minimal local software inventory foundations for advisory relevance.
//!
//! Phase 16 Task 1 starts with a conservative, low-risk inventory source:
//! currently-running processes. This avoids package-manager-specific parsing
//! while still giving the advisory pipeline stable product candidates.

use serde::{Deserialize, Serialize};
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
    pub publisher_hint: Option<String>,
    pub source: InventorySource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InventorySource {
    RunningProcess,
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
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut by_key: BTreeMap<String, InstalledSoftware> = BTreeMap::new();

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
            product_key: product_key.clone(),
            display_name,
            executable_path,
            publisher_hint: None,
            source: InventorySource::RunningProcess,
        };

        by_key.entry(product_key).or_insert(entry);
    }

    by_key.into_values().collect()
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
                    publisher_hint: None,
                    source: InventorySource::RunningProcess,
                },
            );
        }
        assert_eq!(by_key.len(), STARTUP_INVENTORY_MAX_ENTRIES);
    }
}
