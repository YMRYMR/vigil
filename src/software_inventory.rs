//! Minimal local software inventory foundations for advisory relevance.
//!
//! Phase 16 starts with conservative, low-risk inventory sources:
//! currently-running processes, Windows uninstall-registry entries, the
//! Debian dpkg status database on Linux, and Homebrew Cellar formula inventory
//! on macOS. This keeps inventory collection offline and low-risk while still
//! giving the advisory pipeline stable product candidates plus lightweight
//! publisher/version hints for later matching.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledSoftware {
    pub product_key: String,
    pub display_name: String,
    pub executable_path: String,
    #[serde(default)]
    pub publisher_hint: Option<String>,
    #[serde(default)]
    pub version_hint: Option<String>,
    pub source: InventorySource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InventorySource {
    RunningProcess,
    LinuxDpkgStatus,
    MacosHomebrew,
    WindowsUninstallRegistry,
    RunningService,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InventorySeed {
    display_name: String,
    executable_path: String,
    publisher_hint: Option<String>,
    version_hint: Option<String>,
    source: InventorySource,
}

pub fn collect_installed_software() -> Vec<InstalledSoftware> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let service_map = crate::process::build_services_by_pid();
    let mut entries = Vec::new();
    for process in sys.processes().values() {
        let display_name = process.name().to_string_lossy().trim().to_string();
        let executable_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let publisher_hint = inventory_hint(crate::process::publisher::get_publisher(
            &executable_path,
        ));
        let version_hint = inventory_hint(crate::process::publisher::get_file_version(
            &executable_path,
        ));
        entries.push(InventorySeed {
            display_name: display_name.clone(),
            executable_path: executable_path.clone(),
            publisher_hint: publisher_hint.clone(),
            version_hint: version_hint.clone(),
            source: InventorySource::RunningProcess,
        });
        for service_name in
            service_names_for_process(process.pid().as_u32(), &service_map, &display_name)
        {
            entries.push(InventorySeed {
                display_name: service_name,
                executable_path: executable_path.clone(),
                publisher_hint: publisher_hint.clone(),
                version_hint: version_hint.clone(),
                source: InventorySource::RunningService,
            });
        }
    }
    entries.extend(collect_windows_uninstall_entries());
    entries.extend(collect_linux_dpkg_entries());
    entries.extend(collect_macos_homebrew_entries());
    collect_from_entries(entries)
}

fn service_names_for_process(
    pid: u32,
    service_map: &std::collections::HashMap<u32, Vec<String>>,
    display_name: &str,
) -> Vec<String> {
    let Some(service_names) = service_map.get(&pid) else {
        return Vec::new();
    };

    let normalized_display_name = normalize_name(display_name);
    let mut seen = BTreeSet::new();
    let mut distinct = Vec::new();
    for service_name in service_names {
        let trimmed = service_name.trim();
        if trimmed.is_empty() {
            continue;
        }

        let normalized = normalize_name(trimmed);
        if normalized.is_empty()
            || normalized == normalized_display_name
            || !seen.insert(normalized)
        {
            continue;
        }

        distinct.push(trimmed.to_string());
    }
    distinct
}

#[cfg(windows)]
fn collect_windows_uninstall_entries() -> Vec<InventorySeed> {
    use winreg::enums::{
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    };
    use winreg::RegKey;

    let mut entries = Vec::new();
    let uninstall_roots = [
        (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            KEY_READ | KEY_WOW64_64KEY,
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            KEY_READ | KEY_WOW64_32KEY,
        ),
        (
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            KEY_READ | KEY_WOW64_64KEY,
        ),
        (
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
            KEY_READ | KEY_WOW64_32KEY,
        ),
    ];

    for (hive, path, flags) in uninstall_roots {
        let Ok(root) = RegKey::predef(hive).open_subkey_with_flags(path, flags) else {
            continue;
        };
        for child in root.enum_keys().flatten() {
            let Ok(entry_key) = root.open_subkey_with_flags(&child, flags) else {
                continue;
            };
            if let Some(entry) = inventory_seed_from_uninstall_key(&entry_key) {
                entries.push(entry);
            }
        }
    }

    entries
}

#[cfg(not(windows))]
fn collect_windows_uninstall_entries() -> Vec<InventorySeed> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn collect_linux_dpkg_entries() -> Vec<InventorySeed> {
    let Ok(status) = std::fs::read_to_string("/var/lib/dpkg/status") else {
        return Vec::new();
    };
    parse_dpkg_status(&status)
}

#[cfg(not(target_os = "linux"))]
fn collect_linux_dpkg_entries() -> Vec<InventorySeed> {
    Vec::new()
}

#[cfg(target_os = "macos")]
fn collect_macos_homebrew_entries() -> Vec<InventorySeed> {
    [
        (
            std::path::Path::new("/opt/homebrew/Cellar"),
            std::path::Path::new("/opt/homebrew/opt"),
        ),
        (
            std::path::Path::new("/usr/local/Cellar"),
            std::path::Path::new("/usr/local/opt"),
        ),
    ]
    .into_iter()
    .flat_map(|(cellar_root, opt_root)| collect_homebrew_entries_from_roots(cellar_root, opt_root))
    .collect()
}

#[cfg(not(target_os = "macos"))]
fn collect_macos_homebrew_entries() -> Vec<InventorySeed> {
    Vec::new()
}

fn collect_homebrew_entries_from_roots(
    cellar_root: &std::path::Path,
    opt_root: &std::path::Path,
) -> Vec<InventorySeed> {
    let Ok(packages) = std::fs::read_dir(cellar_root) else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    for package in packages.flatten() {
        let Ok(file_type) = package.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }

        let Some(display_name) = inventory_hint(package.file_name().to_string_lossy().to_string())
        else {
            continue;
        };
        let version_hint = homebrew_version_hint_for_package(&display_name, &package.path(), opt_root);
        entries.push(InventorySeed {
            display_name,
            executable_path: String::new(),
            publisher_hint: None,
            version_hint,
            source: InventorySource::MacosHomebrew,
        });
    }
    entries
}

fn homebrew_version_hint_for_package(
    package_name: &str,
    package_root: &std::path::Path,
    opt_root: &std::path::Path,
) -> Option<String> {
    let canonical_package_root = std::fs::canonicalize(package_root).ok()?;
    if let Some(active_version) = active_homebrew_version_from_opt(
        package_name,
        &canonical_package_root,
        opt_root,
    ) {
        return Some(active_version);
    }
    sole_child_directory_name(&canonical_package_root)
}

fn active_homebrew_version_from_opt(
    package_name: &str,
    canonical_package_root: &std::path::Path,
    opt_root: &std::path::Path,
) -> Option<String> {
    let resolved = std::fs::canonicalize(opt_root.join(package_name)).ok()?;
    if !resolved.starts_with(canonical_package_root) {
        return None;
    }
    resolved
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .and_then(inventory_hint)
}

fn sole_child_directory_name(dir: &std::path::Path) -> Option<String> {
    let mut only = None;
    for child in std::fs::read_dir(dir).ok()? {
        let child = child.ok()?;
        if !child.file_type().ok()?.is_dir() {
            continue;
        }
        let Some(name) = inventory_hint(child.file_name().to_string_lossy().to_string()) else {
            continue;
        };
        if only.is_some() {
            return None;
        }
        only = Some(name);
    }
    only
}

fn parse_dpkg_status(status: &str) -> Vec<InventorySeed> {
    let mut entries = Vec::new();
    let mut fields = BTreeMap::<String, String>::new();
    let mut current_key: Option<String> = None;

    for line in status.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if let Some(entry) = inventory_seed_from_dpkg_fields(&fields) {
                entries.push(entry);
            }
            fields.clear();
            current_key = None;
            continue;
        }

        if let Some(continuation) = line.strip_prefix(' ') {
            if let Some(key) = current_key.as_ref() {
                if let Some(value) = fields.get_mut(key) {
                    value.push('\n');
                    value.push_str(continuation.trim_end());
                }
            }
            continue;
        }

        let Some((key, value)) = line.split_once(':') else {
            current_key = None;
            continue;
        };
        let key = key.trim().to_string();
        let value = value.trim().to_string();
        fields.insert(key.clone(), value);
        current_key = Some(key);
    }

    entries
}

fn inventory_seed_from_dpkg_fields(fields: &BTreeMap<String, String>) -> Option<InventorySeed> {
    if !dpkg_status_is_installed(
        fields
            .get("Status")
            .map(String::as_str)
            .unwrap_or_default(),
    ) {
        return None;
    }

    let display_name = fields
        .get("Package")
        .map(String::as_str)
        .unwrap_or_default()
        .trim();
    if display_name.is_empty() {
        return None;
    }

    Some(InventorySeed {
        display_name: display_name.to_string(),
        executable_path: String::new(),
        publisher_hint: fields
            .get("Maintainer")
            .cloned()
            .and_then(inventory_hint),
        version_hint: fields.get("Version").cloned().and_then(inventory_hint),
        source: InventorySource::LinuxDpkgStatus,
    })
}

fn dpkg_status_is_installed(status: &str) -> bool {
    let mut parts = status.split_whitespace();
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next(),),
        (Some(_), Some("ok"), Some("installed"), None)
    )
}

#[cfg(windows)]
fn inventory_seed_from_uninstall_key(key: &winreg::RegKey) -> Option<InventorySeed> {
    let display_name = registry_string(key, "DisplayName").unwrap_or_default();
    let executable_path = preferred_registry_path(
        registry_string(key, "DisplayIcon").as_deref().unwrap_or_default(),
        registry_string(key, "InstallLocation")
            .as_deref()
            .unwrap_or_default(),
    );
    if display_name.is_empty() && executable_path.is_empty() {
        return None;
    }

    Some(InventorySeed {
        display_name,
        executable_path,
        publisher_hint: registry_string(key, "Publisher"),
        version_hint: registry_string(key, "DisplayVersion"),
        source: InventorySource::WindowsUninstallRegistry,
    })
}

#[cfg(windows)]
fn registry_string(key: &winreg::RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name)
        .ok()
        .and_then(inventory_hint)
}

fn preferred_registry_path(display_icon: &str, install_location: &str) -> String {
    let display_icon = clean_display_icon_path(display_icon);
    if !display_icon.is_empty() {
        return display_icon;
    }

    let install_location = install_location.trim();
    if registry_install_location_looks_executable(install_location) {
        return install_location.to_string();
    }

    String::new()
}

fn registry_install_location_looks_executable(value: &str) -> bool {
    let trimmed = value.trim().trim_matches('"');
    if trimmed.is_empty() {
        return false;
    }

    let Some(extension) = std::path::Path::new(trimmed)
        .extension()
        .and_then(|ext| ext.to_str())
    else {
        return false;
    };

    matches!(
        extension.to_ascii_lowercase().as_str(),
        "exe" | "com" | "bat" | "cmd" | "scr" | "pif"
    )
}

fn clean_display_icon_path(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let candidate = if let Some(rest) = trimmed.strip_prefix('"') {
        rest.split_once('"').map(|(path, _)| path).unwrap_or(rest)
    } else {
        trimmed.split_once(',').map(|(path, _)| path).unwrap_or(trimmed)
    };

    candidate.trim().trim_matches('"').to_string()
}

fn collect_from_entries<I>(entries: I) -> Vec<InstalledSoftware>
where
    I: IntoIterator<Item = InventorySeed>,
{
    let mut by_key: BTreeMap<String, InstalledSoftware> = BTreeMap::new();
    for entry in entries {
        if entry.display_name.is_empty() && entry.executable_path.is_empty() {
            continue;
        }
        let product_key = derive_product_key(&entry.display_name, &entry.executable_path);
        let candidate = InstalledSoftware {
            product_key: product_key.clone(),
            display_name: entry.display_name,
            executable_path: entry.executable_path,
            publisher_hint: entry.publisher_hint,
            version_hint: entry.version_hint,
            source: entry.source,
        };
        by_key
            .entry(product_key)
            .and_modify(|existing| {
                if canonical_inventory_sort_key(&candidate) < canonical_inventory_sort_key(existing)
                {
                    let mut preferred = candidate.clone();
                    merge_missing_inventory_fields(&mut preferred, existing);
                    *existing = preferred;
                } else {
                    merge_missing_inventory_fields(existing, &candidate);
                }
            })
            .or_insert(candidate);
    }
    by_key.into_values().collect()
}

fn canonical_inventory_sort_key(
    entry: &InstalledSoftware,
) -> (bool, bool, bool, u8, String, String) {
    (
        entry.display_name.trim().is_empty(),
        entry.publisher_hint.is_none(),
        entry.version_hint.is_none(),
        source_sort_key(entry.source),
        entry.display_name.to_lowercase(),
        entry.executable_path.to_lowercase(),
    )
}

fn source_sort_key(source: InventorySource) -> u8 {
    match source {
        InventorySource::RunningProcess => 0,
        InventorySource::LinuxDpkgStatus => 1,
        InventorySource::MacosHomebrew => 2,
        InventorySource::WindowsUninstallRegistry => 3,
        InventorySource::RunningService => 4,
    }
}

fn merge_missing_inventory_fields(target: &mut InstalledSoftware, source: &InstalledSoftware) {
    if target.display_name.trim().is_empty() {
        target.display_name = source.display_name.clone();
    }
    if target.executable_path.trim().is_empty() {
        target.executable_path = source.executable_path.clone();
    }
    if target.publisher_hint.is_none() {
        target.publisher_hint = source.publisher_hint.clone();
    }
    if target.version_hint.is_none() {
        target.version_hint = source.version_hint.clone();
    }
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

fn inventory_hint(value: String) -> Option<String> {
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
    use std::path::PathBuf;

    fn seed(
        display_name: &str,
        executable_path: &str,
        publisher_hint: Option<&str>,
        version_hint: Option<&str>,
        source: InventorySource,
    ) -> InventorySeed {
        InventorySeed {
            display_name: display_name.to_string(),
            executable_path: executable_path.to_string(),
            publisher_hint: publisher_hint.map(str::to_string),
            version_hint: version_hint.map(str::to_string),
            source,
        }
    }

    fn temp_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vigil-homebrew-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_homebrew_roots(label: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = temp_test_dir(label);
        let cellar = base.join("Cellar");
        let opt = base.join("opt");
        std::fs::create_dir_all(&cellar).unwrap();
        std::fs::create_dir_all(&opt).unwrap();
        (base, cellar, opt)
    }

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
    fn service_names_for_process_ignores_blank_duplicate_and_process_names() {
        let mut service_map = std::collections::HashMap::new();
        service_map.insert(
            42,
            vec![
                "   ".to_string(),
                "agentd".to_string(),
                "AgentD".to_string(),
                "Backup Agent".to_string(),
            ],
        );

        assert_eq!(
            service_names_for_process(42, &service_map, "AgentD.exe"),
            vec!["Backup Agent".to_string()]
        );
        assert!(service_names_for_process(44, &service_map, "agentd").is_empty());
    }

    #[test]
    fn service_names_for_process_keeps_multiple_distinct_services() {
        let mut service_map = std::collections::HashMap::new();
        service_map.insert(
            42,
            vec![
                "Dnscache".to_string(),
                "LanmanWorkstation".to_string(),
                "Dhcp".to_string(),
            ],
        );

        assert_eq!(
            service_names_for_process(42, &service_map, "svchost.exe"),
            vec![
                "Dnscache".to_string(),
                "LanmanWorkstation".to_string(),
                "Dhcp".to_string(),
            ]
        );
    }

    #[test]
    fn collect_homebrew_entries_from_roots_uses_sole_version_without_opt_link() {
        let (base, cellar, opt) = make_homebrew_roots("sole-version");
        std::fs::create_dir_all(cellar.join("ripgrep/14.1.0")).unwrap();

        let parsed = collect_homebrew_entries_from_roots(&cellar, &opt);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].display_name, "ripgrep");
        assert_eq!(parsed[0].version_hint.as_deref(), Some("14.1.0"));
        assert_eq!(parsed[0].source, InventorySource::MacosHomebrew);

        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn collect_homebrew_entries_from_roots_leaves_ambiguous_versions_unset() {
        let (base, cellar, opt) = make_homebrew_roots("ambiguous-version");
        std::fs::create_dir_all(cellar.join("wget/1.0.0")).unwrap();
        std::fs::create_dir_all(cellar.join("wget/1.2.0")).unwrap();

        let parsed = collect_homebrew_entries_from_roots(&cellar, &opt);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].display_name, "wget");
        assert_eq!(parsed[0].version_hint, None);

        std::fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn collect_homebrew_entries_from_roots_prefers_opt_link_version() {
        let (base, cellar, opt) = make_homebrew_roots("opt-version");
        let old_version = cellar.join("wget/1.0.0");
        let active_version = cellar.join("wget/1.2.0");
        std::fs::create_dir_all(&old_version).unwrap();
        std::fs::create_dir_all(&active_version).unwrap();
        std::os::unix::fs::symlink(&active_version, opt.join("wget")).unwrap();

        let parsed = collect_homebrew_entries_from_roots(&cellar, &opt);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].display_name, "wget");
        assert_eq!(parsed[0].version_hint.as_deref(), Some("1.2.0"));

        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn dpkg_status_requires_ok_installed_state() {
        assert!(dpkg_status_is_installed("install ok installed"));
        assert!(dpkg_status_is_installed("hold ok installed"));
        assert!(!dpkg_status_is_installed("deinstall ok config-files"));
        assert!(!dpkg_status_is_installed("install reinstreq half-installed"));
    }

    #[test]
    fn parse_dpkg_status_collects_installed_packages() {
        let parsed = parse_dpkg_status(
            "Package: curl\nStatus: install ok installed\nVersion: 8.8.0-1\nMaintainer: Example Maintainer <maint@example.com>\nDescription: command line tool\n installed everywhere\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n",
        );

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].display_name, "curl");
        assert_eq!(parsed[0].version_hint.as_deref(), Some("8.8.0-1"));
        assert_eq!(
            parsed[0].publisher_hint.as_deref(),
            Some("Example Maintainer <maint@example.com>")
        );
        assert_eq!(parsed[0].source, InventorySource::LinuxDpkgStatus);
    }

    #[test]
    fn preferred_registry_path_prefers_display_icon_and_strips_resource_suffix() {
        assert_eq!(
            preferred_registry_path(
                "\"C:\\Program Files\\Vendor\\agent.exe\",0",
                "C:\\Program Files\\Vendor"
            ),
            "C:\\Program Files\\Vendor\\agent.exe"
        );
    }

    #[test]
    fn preferred_registry_path_ignores_directory_install_locations() {
        assert_eq!(
            preferred_registry_path("", "C:\\Program Files\\Vendor"),
            ""
        );
    }

    #[test]
    fn preferred_registry_path_keeps_executable_install_locations() {
        assert_eq!(
            preferred_registry_path("", "C:\\Program Files\\Vendor\\agent.exe"),
            "C:\\Program Files\\Vendor\\agent.exe"
        );
    }

    #[test]
    fn collect_from_entries_keeps_empty_name_when_path_present() {
        let entries = vec![seed(
            "",
            "/opt/vendor/agentd",
            None,
            None,
            InventorySource::RunningProcess,
        )];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].product_key, "agentd");
    }

    #[test]
    fn collect_from_entries_prefers_stable_named_entry_for_duplicate_key() {
        let entries = vec![
            seed(
                "",
                "/opt/vendor/chrome",
                None,
                None,
                InventorySource::RunningProcess,
            ),
            seed(
                "Google Chrome",
                "/Applications/Google Chrome.app",
                None,
                None,
                InventorySource::RunningProcess,
            ),
            seed(
                "google chrome",
                "/opt/google/chrome",
                None,
                None,
                InventorySource::RunningProcess,
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

    #[test]
    fn collect_from_entries_prefers_richer_metadata_for_duplicate_key() {
        let entries = vec![
            seed(
                "Example Agent",
                "/opt/example/agent",
                None,
                None,
                InventorySource::RunningProcess,
            ),
            seed(
                "Example Agent",
                "/Applications/Example Agent.app",
                Some("Example Corp"),
                Some("2.4.1"),
                InventorySource::RunningProcess,
            ),
        ];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].product_key, "example-agent");
        assert_eq!(inventory[0].publisher_hint.as_deref(), Some("Example Corp"));
        assert_eq!(inventory[0].version_hint.as_deref(), Some("2.4.1"));
        assert_eq!(
            inventory[0].executable_path,
            "/Applications/Example Agent.app"
        );
    }

    #[test]
    fn collect_from_entries_merges_complementary_metadata_for_duplicate_key() {
        let entries = vec![
            seed(
                "Example Agent",
                "/opt/example/agent",
                Some("Example Corp"),
                None,
                InventorySource::RunningProcess,
            ),
            seed(
                "Example Agent",
                "/Applications/Example Agent.app",
                None,
                Some("2.4.1"),
                InventorySource::RunningProcess,
            ),
        ];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].product_key, "example-agent");
        assert_eq!(inventory[0].publisher_hint.as_deref(), Some("Example Corp"));
        assert_eq!(inventory[0].version_hint.as_deref(), Some("2.4.1"));
        assert_eq!(inventory[0].executable_path, "/opt/example/agent");
    }

    #[test]
    fn collect_from_entries_keeps_process_path_when_dpkg_metadata_wins() {
        let entries = vec![
            seed(
                "curl",
                "/usr/bin/curl",
                None,
                None,
                InventorySource::RunningProcess,
            ),
            seed(
                "curl",
                "",
                Some("Debian curl maintainers"),
                Some("8.8.0-1"),
                InventorySource::LinuxDpkgStatus,
            ),
        ];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].source, InventorySource::LinuxDpkgStatus);
        assert_eq!(
            inventory[0].publisher_hint.as_deref(),
            Some("Debian curl maintainers")
        );
        assert_eq!(inventory[0].version_hint.as_deref(), Some("8.8.0-1"));
        assert_eq!(inventory[0].executable_path, "/usr/bin/curl");
    }

    #[test]
    fn collect_from_entries_keeps_process_path_when_homebrew_metadata_wins() {
        let entries = vec![
            seed(
                "wget",
                "/opt/homebrew/bin/wget",
                None,
                None,
                InventorySource::RunningProcess,
            ),
            seed(
                "wget",
                "",
                None,
                Some("1.25.0"),
                InventorySource::MacosHomebrew,
            ),
        ];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].source, InventorySource::MacosHomebrew);
        assert_eq!(inventory[0].version_hint.as_deref(), Some("1.25.0"));
        assert_eq!(inventory[0].executable_path, "/opt/homebrew/bin/wget");
    }

    #[test]
    fn collect_from_entries_keeps_process_path_when_registry_metadata_wins() {
        let entries = vec![
            seed(
                "Example Agent",
                "C:/Program Files/Example/agent.exe",
                None,
                None,
                InventorySource::RunningProcess,
            ),
            seed(
                "Example Agent",
                "",
                Some("Example Corp"),
                Some("2.4.1"),
                InventorySource::WindowsUninstallRegistry,
            ),
        ];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].source, InventorySource::WindowsUninstallRegistry);
        assert_eq!(inventory[0].publisher_hint.as_deref(), Some("Example Corp"));
        assert_eq!(inventory[0].version_hint.as_deref(), Some("2.4.1"));
        assert_eq!(
            inventory[0].executable_path,
            "C:/Program Files/Example/agent.exe"
        );
    }

    #[test]
    fn collect_from_entries_keeps_service_identity_alongside_shared_host_process() {
        let entries = vec![
            seed(
                "svchost.exe",
                "C:/Windows/System32/svchost.exe",
                Some("Microsoft Corporation"),
                Some("10.0.0"),
                InventorySource::RunningProcess,
            ),
            seed(
                "Dnscache",
                "C:/Windows/System32/svchost.exe",
                Some("Microsoft Corporation"),
                Some("10.0.0"),
                InventorySource::RunningService,
            ),
        ];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 2);
        assert!(inventory.iter().any(|row| {
            row.product_key == "svchost" && row.source == InventorySource::RunningProcess
        }));
        assert!(inventory.iter().any(|row| {
            row.product_key == "dnscache" && row.source == InventorySource::RunningService
        }));
    }
}
