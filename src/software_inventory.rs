//! Minimal local software inventory foundations for advisory relevance.
//!
//! Phase 16 Task 1 starts with a conservative, low-risk inventory source:
//! currently-running processes. This avoids package-manager-specific parsing
//! while still giving the advisory pipeline stable product candidates.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sysinfo::System;

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

pub fn collect_installed_software() -> Vec<InstalledSoftware> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let entries = sys.processes().values().map(|process| {
        let display_name = process.name().to_string_lossy().trim().to_string();
        let executable_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        (display_name, executable_path)
    });
    collect_from_entries(entries)
}

fn collect_from_entries<I>(entries: I) -> Vec<InstalledSoftware>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut by_key: BTreeMap<String, InstalledSoftware> = BTreeMap::new();
    for (display_name, executable_path) in entries {
        if display_name.is_empty() && executable_path.is_empty() {
            continue;
        }
        let product_key = derive_product_key(&display_name, &executable_path);
        let candidate = InstalledSoftware {
            product_key: product_key.clone(),
            display_name,
            executable_path,
            publisher_hint: None,
            source: InventorySource::RunningProcess,
        };
        by_key
            .entry(product_key)
            .and_modify(|existing| {
                if canonical_inventory_sort_key(&candidate)
                    < canonical_inventory_sort_key(existing)
                {
                    *existing = candidate.clone();
                }
            })
            .or_insert(candidate);
    }
    by_key.into_values().collect()
}

fn canonical_inventory_sort_key(entry: &InstalledSoftware) -> (bool, String, String) {
    (
        entry.display_name.trim().is_empty(),
        entry.display_name.to_lowercase(),
        entry.executable_path.to_lowercase(),
    )
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
    fn derive_product_key_unknown_when_name_and_path_missing() {
        let key = derive_product_key("", "");
        assert_eq!(key, "unknown-product");
    }

    #[test]
    fn collect_from_entries_keeps_empty_name_when_path_present() {
        let entries = vec![("".to_string(), "/opt/vendor/agentd".to_string())];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].product_key, "agentd");
    }

    #[test]
    fn collect_from_entries_prefers_stable_named_entry_for_duplicate_key() {
        let entries = vec![
            ("".to_string(), "/opt/vendor/chrome".to_string()),
            (
                "Google Chrome".to_string(),
                "/Applications/Google Chrome.app".to_string(),
            ),
            (
                "google chrome".to_string(),
                "/opt/google/chrome".to_string(),
            ),
        ];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].product_key, "google-chrome");
        assert_eq!(inventory[0].display_name, "Google Chrome");
        assert_eq!(
            inventory[0].executable_path,
            "/Applications/Google Chrome.app"
        );
    }
}
