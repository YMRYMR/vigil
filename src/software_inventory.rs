//! Minimal local software inventory foundations for advisory relevance.
//!
//! Phase 16 starts with conservative, low-risk inventory sources:
//! currently-running processes, Windows uninstall-registry entries, and Linux
//! package-manager metadata (dpkg, RPM, and apk). This keeps inventory
//! collection offline and low-risk while still giving the advisory pipeline
//! stable product candidates plus lightweight publisher/version hints for
//! later matching.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use sysinfo::System;

const STARTUP_INVENTORY_DELAY: Duration = Duration::from_secs(15);
const STARTUP_INVENTORY_MAX_ENTRIES: usize = 512;
const VENDOR_SUFFIXES: &[&str] = &[
    "ab",
    "ag",
    "bv",
    "co",
    "company",
    "corp",
    "corporation",
    "gmbh",
    "inc",
    "incorporated",
    "kg",
    "kgaa",
    "limited",
    "llc",
    "ltd",
    "oy",
    "oyj",
    "plc",
    "pte",
    "sa",
    "sarl",
    "spa",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledSoftware {
    pub product_key: String,
    pub display_name: String,
    pub executable_path: String,
    #[serde(default)]
    pub publisher_hint: Option<String>,
    #[serde(default)]
    pub version_hint: Option<String>,
    #[serde(default)]
    pub product_aliases: Vec<String>,
    #[serde(default)]
    pub vendor_key: Option<String>,
    pub source: InventorySource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InventorySource {
    RunningProcess,
    LinuxDpkgStatus,
    LinuxRpmDatabase,
    LinuxApkInstalled,
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

    let service_map = crate::process::build_services_by_pid();
    let mut entries = Vec::new();
    for process in sys.processes().values() {
        if entries.len() >= max_entries {
            break;
        }

        let display_name = process.name().to_string_lossy().trim().to_string();
        let executable_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let publisher_hint =
            inventory_hint(crate::process::publisher::get_publisher(&executable_path));
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
            if entries.len() >= max_entries {
                break;
            }
            entries.push(InventorySeed {
                display_name: service_name,
                executable_path: executable_path.clone(),
                publisher_hint: publisher_hint.clone(),
                version_hint: version_hint.clone(),
                source: InventorySource::RunningService,
            });
        }
    }

    if entries.len() < max_entries {
        let remaining = max_entries - entries.len();
        append_limited_entries(&mut entries, collect_windows_uninstall_entries(), remaining);
    }
    if entries.len() < max_entries {
        let remaining = max_entries - entries.len();
        append_limited_entries(&mut entries, collect_linux_dpkg_entries(), remaining);
    }
    if entries.len() < max_entries {
        let remaining = max_entries - entries.len();
        append_limited_entries(&mut entries, collect_linux_rpm_entries(), remaining);
    }
    if entries.len() < max_entries {
        let remaining = max_entries - entries.len();
        append_limited_entries(&mut entries, collect_linux_apk_entries(), remaining);
    }

    collect_from_entries(entries)
}

fn append_limited_entries(
    entries: &mut Vec<InventorySeed>,
    additional: Vec<InventorySeed>,
    remaining: usize,
) {
    if remaining == 0 {
        return;
    }
    entries.extend(additional.into_iter().take(remaining));
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

#[cfg(target_os = "linux")]
fn collect_linux_rpm_entries() -> Vec<InventorySeed> {
    let Some(rpm) = first_existing_file(&["/usr/bin/rpm", "/bin/rpm"]) else {
        return Vec::new();
    };
    let Ok(output) = std::process::Command::new(rpm)
        .args(["-qa", "--qf", "%{NAME}\t%{EVR}\t%{VENDOR}\n"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    parse_rpm_query_output(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(target_os = "linux"))]
fn collect_linux_rpm_entries() -> Vec<InventorySeed> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn collect_linux_apk_entries() -> Vec<InventorySeed> {
    let Ok(installed) = std::fs::read_to_string("/lib/apk/db/installed") else {
        return Vec::new();
    };
    parse_apk_installed(&installed)
}

#[cfg(not(target_os = "linux"))]
fn collect_linux_apk_entries() -> Vec<InventorySeed> {
    Vec::new()
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
    if !dpkg_status_is_installed(fields.get("Status").map(String::as_str).unwrap_or_default()) {
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
        publisher_hint: fields.get("Maintainer").cloned().and_then(inventory_hint),
        version_hint: fields.get("Version").cloned().and_then(inventory_hint),
        source: InventorySource::LinuxDpkgStatus,
    })
}

fn parse_rpm_query_output(output: &str) -> Vec<InventorySeed> {
    output
        .lines()
        .filter_map(inventory_seed_from_rpm_line)
        .collect()
}

fn inventory_seed_from_rpm_line(line: &str) -> Option<InventorySeed> {
    let mut fields = line.splitn(3, '\t');
    let display_name = fields.next()?.trim();
    if display_name.is_empty() {
        return None;
    }
    Some(InventorySeed {
        display_name: display_name.to_string(),
        executable_path: String::new(),
        version_hint: fields.next().map(str::to_string).and_then(inventory_hint),
        publisher_hint: fields.next().map(str::to_string).and_then(inventory_hint),
        source: InventorySource::LinuxRpmDatabase,
    })
}

fn parse_apk_installed(installed: &str) -> Vec<InventorySeed> {
    let mut entries = Vec::new();
    let mut fields = BTreeMap::<char, String>::new();
    for line in installed.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if let Some(entry) = inventory_seed_from_apk_fields(&fields) {
                entries.push(entry);
            }
            fields.clear();
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let Some(field) = key.chars().next() else {
            continue;
        };
        fields.insert(field, value.trim().to_string());
    }
    entries
}

fn inventory_seed_from_apk_fields(fields: &BTreeMap<char, String>) -> Option<InventorySeed> {
    let display_name = fields.get(&'P')?.trim();
    if display_name.is_empty() {
        return None;
    }
    Some(InventorySeed {
        display_name: display_name.to_string(),
        executable_path: String::new(),
        version_hint: fields.get(&'V').cloned().and_then(inventory_hint),
        publisher_hint: fields
            .get(&'m')
            .cloned()
            .and_then(inventory_hint)
            .or_else(|| fields.get(&'o').cloned().and_then(inventory_hint)),
        source: InventorySource::LinuxApkInstalled,
    })
}

fn first_existing_file(paths: &[&'static str]) -> Option<&'static str> {
    paths
        .iter()
        .copied()
        .find(|path| std::path::Path::new(path).is_file())
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
        registry_string(key, "DisplayIcon")
            .as_deref()
            .unwrap_or_default(),
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
        trimmed
            .split_once(',')
            .map(|(path, _)| path)
            .unwrap_or(trimmed)
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
            product_aliases: collect_product_aliases(&entry.display_name, &entry.executable_path),
            vendor_key: entry
                .publisher_hint
                .as_deref()
                .and_then(normalize_vendor_key),
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
        InventorySource::LinuxRpmDatabase => 2,
        InventorySource::LinuxApkInstalled => 3,
        InventorySource::WindowsUninstallRegistry => 4,
        InventorySource::RunningService => 5,
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
    if target.vendor_key.is_none() {
        target.vendor_key = source.vendor_key.clone();
    }
    merge_product_aliases(&mut target.product_aliases, &source.product_aliases);
}

fn merge_product_aliases(target: &mut Vec<String>, source: &[String]) {
    let mut aliases = target.iter().cloned().collect::<BTreeSet<_>>();
    aliases.extend(source.iter().cloned());
    *target = aliases.into_iter().collect();
}

fn collect_product_aliases(display_name: &str, executable_path: &str) -> Vec<String> {
    let mut aliases = BTreeSet::new();

    let normalized_name = normalize_name(display_name);
    if !normalized_name.is_empty() {
        aliases.insert(normalized_name);
    }

    if let Some(file_name) = std::path::Path::new(executable_path).file_stem() {
        let candidate = normalize_name(&file_name.to_string_lossy());
        if !candidate.is_empty() {
            aliases.insert(candidate);
        }
    }

    aliases.into_iter().collect()
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

fn normalize_vendor_key(publisher: &str) -> Option<String> {
    let publisher = publisher.split('<').next().unwrap_or(publisher).trim();
    let mut tokens = tokenize_identity(publisher);
    while tokens
        .last()
        .is_some_and(|token| VENDOR_SUFFIXES.contains(&token.as_str()))
    {
        tokens.pop();
    }

    if tokens.is_empty() {
        let normalized = normalize_name(publisher);
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        }
    } else {
        Some(tokens.join("-"))
    }
}

fn normalize_name(input: &str) -> String {
    tokenize_identity(input).join("-")
}

fn tokenize_identity(input: &str) -> Vec<String> {
    let lower = input.trim().to_lowercase();
    let no_ext = lower.strip_suffix(".exe").unwrap_or(&lower);
    no_ext
        .chars()
        .map(|ch| if ch.is_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

fn inventory_hint(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("(none)") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn normalize_vendor_key_strips_suffixes_and_contact_details() {
        assert_eq!(
            normalize_vendor_key("Example Corporation <sec@example.com>"),
            Some("example".to_string())
        );
        assert_eq!(
            normalize_vendor_key("Microsoft Corporation"),
            Some("microsoft".to_string())
        );
    }

    #[test]
    fn collect_product_aliases_uses_display_name_and_executable_stem() {
        let aliases =
            collect_product_aliases("Google Chrome", "C:/Program Files/Google/Chrome/chrome.exe");
        assert_eq!(
            aliases,
            vec!["chrome".to_string(), "google-chrome".to_string()]
        );
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
    fn dpkg_status_requires_ok_installed_state() {
        assert!(dpkg_status_is_installed("install ok installed"));
        assert!(dpkg_status_is_installed("hold ok installed"));
        assert!(!dpkg_status_is_installed("deinstall ok config-files"));
        assert!(!dpkg_status_is_installed(
            "install reinstreq half-installed"
        ));
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
    fn parse_rpm_query_output_ignores_empty_names_and_none_vendor() {
        let parsed = parse_rpm_query_output(
            "curl\t8.8.0-1.fc40\tFedora Project\n\tbroken\tVendor\nopenssl\t3.2.2-5.fc40\t(none)\n",
        );

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].display_name, "curl");
        assert_eq!(parsed[0].publisher_hint.as_deref(), Some("Fedora Project"));
        assert_eq!(parsed[1].display_name, "openssl");
        assert_eq!(parsed[1].publisher_hint, None);
        assert_eq!(parsed[1].source, InventorySource::LinuxRpmDatabase);
    }

    #[test]
    fn parse_apk_installed_collects_maintainer_or_origin() {
        let parsed = parse_apk_installed(
            "P:busybox\nV:1.36.1-r7\nm:Example Maintainer\n\nP:musl\nV:1.2.5-r1\no:example-origin\n\n",
        );

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].display_name, "busybox");
        assert_eq!(parsed[0].version_hint.as_deref(), Some("1.36.1-r7"));
        assert_eq!(
            parsed[0].publisher_hint.as_deref(),
            Some("Example Maintainer")
        );
        assert_eq!(parsed[1].display_name, "musl");
        assert_eq!(parsed[1].publisher_hint.as_deref(), Some("example-origin"));
        assert_eq!(parsed[1].source, InventorySource::LinuxApkInstalled);
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
        assert_eq!(preferred_registry_path("", "C:\\Program Files\\Vendor"), "");
    }

    #[test]
    fn preferred_registry_path_keeps_executable_install_locations() {
        assert_eq!(
            preferred_registry_path("", "C:\\Program Files\\Vendor\\agent.exe"),
            "C:\\Program Files\\Vendor\\agent.exe"
        );
    }

    #[test]
    fn inventory_hint_drops_none_marker() {
        assert_eq!(inventory_hint("(none)".to_string()), None);
        assert_eq!(
            inventory_hint("  value  ".to_string()).as_deref(),
            Some("value")
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
        assert_eq!(inventory[0].product_aliases, vec!["agentd".to_string()]);
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
        assert_eq!(
            inventory[0].product_aliases,
            vec!["chrome".to_string(), "google-chrome".to_string()]
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
        assert_eq!(inventory[0].vendor_key.as_deref(), Some("example"));
        assert_eq!(
            inventory[0].product_aliases,
            vec!["agent".to_string(), "example-agent".to_string()]
        );
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
        assert_eq!(inventory[0].vendor_key.as_deref(), Some("example"));
        assert_eq!(
            inventory[0].product_aliases,
            vec!["agent".to_string(), "example-agent".to_string()]
        );
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
        assert_eq!(
            inventory[0].vendor_key.as_deref(),
            Some("debian-curl-maintainers")
        );
        assert_eq!(inventory[0].version_hint.as_deref(), Some("8.8.0-1"));
        assert_eq!(inventory[0].executable_path, "/usr/bin/curl");
    }

    #[test]
    fn collect_from_entries_keeps_process_path_when_rpm_metadata_wins() {
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
                Some("Fedora Project"),
                Some("8.8.0-1.fc40"),
                InventorySource::LinuxRpmDatabase,
            ),
        ];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].source, InventorySource::LinuxRpmDatabase);
        assert_eq!(
            inventory[0].publisher_hint.as_deref(),
            Some("Fedora Project")
        );
        assert_eq!(inventory[0].vendor_key.as_deref(), Some("fedora-project"));
        assert_eq!(inventory[0].version_hint.as_deref(), Some("8.8.0-1.fc40"));
        assert_eq!(inventory[0].executable_path, "/usr/bin/curl");
    }

    #[test]
    fn collect_from_entries_keeps_process_path_when_apk_metadata_wins() {
        let entries = vec![
            seed(
                "busybox",
                "/bin/busybox",
                None,
                None,
                InventorySource::RunningProcess,
            ),
            seed(
                "busybox",
                "",
                Some("alpine-baselayout"),
                Some("1.36.1-r7"),
                InventorySource::LinuxApkInstalled,
            ),
        ];
        let inventory = collect_from_entries(entries);
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].source, InventorySource::LinuxApkInstalled);
        assert_eq!(
            inventory[0].publisher_hint.as_deref(),
            Some("alpine-baselayout")
        );
        assert_eq!(
            inventory[0].vendor_key.as_deref(),
            Some("alpine-baselayout")
        );
        assert_eq!(inventory[0].version_hint.as_deref(), Some("1.36.1-r7"));
        assert_eq!(inventory[0].executable_path, "/bin/busybox");
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
        assert_eq!(
            inventory[0].source,
            InventorySource::WindowsUninstallRegistry
        );
        assert_eq!(inventory[0].publisher_hint.as_deref(), Some("Example Corp"));
        assert_eq!(inventory[0].vendor_key.as_deref(), Some("example"));
        assert_eq!(inventory[0].version_hint.as_deref(), Some("2.4.1"));
        assert_eq!(
            inventory[0].product_aliases,
            vec!["agent".to_string(), "example-agent".to_string()]
        );
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
            row.product_key == "svchost"
                && row.product_aliases == vec!["svchost".to_string()]
                && row.source == InventorySource::RunningProcess
        }));
        assert!(inventory.iter().any(|row| {
            row.product_key == "dnscache"
                && row.product_aliases == vec!["dnscache".to_string(), "svchost".to_string()]
                && row.source == InventorySource::RunningService
        }));
    }

    #[test]
    fn startup_inventory_limit_caps_seed_count_before_deduplication() {
        let mut entries = Vec::new();
        for i in 0..(STARTUP_INVENTORY_MAX_ENTRIES + 25) {
            entries.push(seed(
                &format!("proc-{i}"),
                &format!("/opt/proc-{i}"),
                None,
                None,
                InventorySource::RunningProcess,
            ));
        }
        let mut limited = Vec::new();
        append_limited_entries(&mut limited, entries, STARTUP_INVENTORY_MAX_ENTRIES);
        assert_eq!(limited.len(), STARTUP_INVENTORY_MAX_ENTRIES);
    }
}
