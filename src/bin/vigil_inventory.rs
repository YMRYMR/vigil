//! On-demand local software inventory utility for Phase 16 advisory matching.
//!
//! This binary is intentionally separate from the main Vigil startup path. It
//! performs only local/offline discovery and prints JSON so operators and later
//! advisory-matching code can inspect package-manager coverage without adding
//! new boot-time risk.
//!
//! Current target scope is Windows and Linux only.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct InventoryEntry {
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    executable_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    publisher_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    product_aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    vendor_aliases: Vec<String>,
    source: &'static str,
}

fn main() {
    let mut entries = Vec::new();
    entries.extend(collect_windows_uninstall_entries());
    entries.extend(collect_dpkg_entries());
    entries.extend(collect_rpm_entries());
    entries.extend(collect_apk_entries());

    for entry in &mut entries {
        enrich_inventory_identity(entry);
    }

    entries.sort_by(|a, b| {
        a.source
            .cmp(b.source)
            .then_with(|| a.display_name.cmp(&b.display_name))
            .then_with(|| a.version_hint.cmp(&b.version_hint))
    });

    match serde_json::to_string_pretty(&entries) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("failed to serialize software inventory: {err}");
            std::process::exit(1);
        }
    }
}

fn enrich_inventory_identity(entry: &mut InventoryEntry) {
    entry.product_aliases =
        collect_product_aliases(&entry.display_name, entry.executable_path.as_deref());
    entry.product_key = primary_product_key(&entry.display_name, entry.executable_path.as_deref());
    entry.vendor_key = entry
        .publisher_hint
        .as_deref()
        .and_then(normalize_vendor_key);
    entry.vendor_aliases = entry
        .publisher_hint
        .as_deref()
        .map(collect_vendor_aliases)
        .unwrap_or_default();
}

fn primary_product_key(display_name: &str, executable_path: Option<&str>) -> Option<String> {
    normalize_identity(display_name).or_else(|| {
        executable_path.and_then(|path| {
            Path::new(path)
                .file_stem()
                .and_then(|stem| normalize_identity(&stem.to_string_lossy()))
        })
    })
}

fn collect_product_aliases(display_name: &str, executable_path: Option<&str>) -> Vec<String> {
    let mut aliases = BTreeSet::new();
    if let Some(alias) = normalize_identity(display_name) {
        aliases.insert(alias);
    }
    if let Some(path) = executable_path {
        if let Some(stem) = Path::new(path).file_stem() {
            if let Some(alias) = normalize_identity(&stem.to_string_lossy()) {
                aliases.insert(alias);
            }
        }
    }
    aliases.into_iter().collect()
}

fn collect_vendor_aliases(publisher: &str) -> Vec<String> {
    let publisher = publisher.split('<').next().unwrap_or(publisher).trim();
    let mut aliases = BTreeSet::new();
    if let Some(alias) = normalize_vendor_key(publisher) {
        aliases.insert(alias);
    }
    if let Some(alias) = normalize_identity(publisher) {
        aliases.insert(alias);
    }
    aliases.into_iter().collect()
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
        normalize_identity(publisher)
    } else {
        Some(tokens.join("-"))
    }
}

fn normalize_identity(input: &str) -> Option<String> {
    let normalized = tokenize_identity(input).join("-");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
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

#[cfg(windows)]
fn collect_windows_uninstall_entries() -> Vec<InventoryEntry> {
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
            if let Some(entry) = inventory_entry_from_uninstall_key(&entry_key) {
                entries.push(entry);
            }
        }
    }

    entries
}

#[cfg(not(windows))]
fn collect_windows_uninstall_entries() -> Vec<InventoryEntry> {
    Vec::new()
}

#[cfg(windows)]
fn inventory_entry_from_uninstall_key(key: &winreg::RegKey) -> Option<InventoryEntry> {
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

    Some(InventoryEntry {
        display_name,
        executable_path: inventory_hint(executable_path),
        version_hint: registry_string(key, "DisplayVersion"),
        publisher_hint: registry_string(key, "Publisher"),
        product_key: None,
        product_aliases: Vec::new(),
        vendor_key: None,
        vendor_aliases: Vec::new(),
        source: "windows-uninstall-registry",
    })
}

#[cfg(windows)]
fn registry_string(key: &winreg::RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name)
        .ok()
        .and_then(inventory_hint)
}

fn collect_dpkg_entries() -> Vec<InventoryEntry> {
    let Ok(status) = std::fs::read_to_string("/var/lib/dpkg/status") else {
        return Vec::new();
    };
    parse_dpkg_status(&status)
}

fn parse_dpkg_status(status: &str) -> Vec<InventoryEntry> {
    let mut entries = Vec::new();
    let mut fields = BTreeMap::<String, String>::new();
    let mut current_key: Option<String> = None;

    for line in status.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if let Some(entry) = inventory_entry_from_dpkg_fields(&fields) {
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

fn inventory_entry_from_dpkg_fields(fields: &BTreeMap<String, String>) -> Option<InventoryEntry> {
    if !dpkg_status_is_installed(fields.get("Status").map(String::as_str).unwrap_or_default()) {
        return None;
    }
    let display_name = fields.get("Package")?.trim();
    if display_name.is_empty() {
        return None;
    }
    Some(InventoryEntry {
        display_name: display_name.to_string(),
        executable_path: None,
        version_hint: fields.get("Version").cloned().and_then(inventory_hint),
        publisher_hint: fields.get("Maintainer").cloned().and_then(inventory_hint),
        product_key: None,
        product_aliases: Vec::new(),
        vendor_key: None,
        vendor_aliases: Vec::new(),
        source: "linux-dpkg-status",
    })
}

fn dpkg_status_is_installed(status: &str) -> bool {
    let mut parts = status.split_whitespace();
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(_), Some("ok"), Some("installed"), None)
    )
}

fn collect_rpm_entries() -> Vec<InventoryEntry> {
    let Some(rpm) = first_existing_file(&["/usr/bin/rpm", "/bin/rpm"]) else {
        return Vec::new();
    };
    let Ok(output) = Command::new(rpm)
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

fn parse_rpm_query_output(output: &str) -> Vec<InventoryEntry> {
    output
        .lines()
        .filter_map(inventory_entry_from_rpm_line)
        .collect()
}

fn inventory_entry_from_rpm_line(line: &str) -> Option<InventoryEntry> {
    let mut fields = line.splitn(3, '\t');
    let display_name = fields.next()?.trim();
    if display_name.is_empty() {
        return None;
    }
    Some(InventoryEntry {
        display_name: display_name.to_string(),
        executable_path: None,
        version_hint: fields.next().map(str::to_string).and_then(inventory_hint),
        publisher_hint: fields.next().map(str::to_string).and_then(inventory_hint),
        product_key: None,
        product_aliases: Vec::new(),
        vendor_key: None,
        vendor_aliases: Vec::new(),
        source: "linux-rpm-database",
    })
}

fn collect_apk_entries() -> Vec<InventoryEntry> {
    let Ok(installed) = std::fs::read_to_string("/lib/apk/db/installed") else {
        return Vec::new();
    }
    parse_apk_installed(&installed)
}

fn parse_apk_installed(installed: &str) -> Vec<InventoryEntry> {
    let mut entries = Vec::new();
    let mut fields = BTreeMap::<char, String>::new();
    for line in installed.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if let Some(entry) = inventory_entry_from_apk_fields(&fields) {
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

fn inventory_entry_from_apk_fields(fields: &BTreeMap<char, String>) -> Option<InventoryEntry> {
    let display_name = fields.get(&'P')?.trim();
    if display_name.is_empty() {
        return None;
    }
    Some(InventoryEntry {
        display_name: display_name.to_string(),
        executable_path: None,
        version_hint: fields.get(&'V').cloned().and_then(inventory_hint),
        publisher_hint: fields
            .get(&'m')
            .cloned()
            .and_then(inventory_hint)
            .or_else(|| fields.get(&'o').cloned().and_then(inventory_hint)),
        product_key: None,
        product_aliases: Vec::new(),
        vendor_key: None,
        vendor_aliases: Vec::new(),
        source: "linux-apk-installed",
    })
}

fn first_existing_file(paths: &[&'static str]) -> Option<&'static str> {
    paths.iter().copied().find(|path| Path::new(path).is_file())
}

fn preferred_registry_path(display_icon: &str, install_location: &str) -> String {
    let display_icon = clean_display_icon_path(display_icon);
    if !display_icon.is_empty() {
        return display_icon;
    }

    let install_location = install_location.trim();
    if registry_install_location_looks_executable(install_location) {
        return install_location.trim_matches('"').to_string();
    }

    String::new()
}

fn registry_install_location_looks_executable(value: &str) -> bool {
    let trimmed = value.trim().trim_matches('"');
    if trimmed.is_empty() {
        return false;
    }

    let Some(extension) = Path::new(trimmed).extension().and_then(|ext| ext.to_str()) else {
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

    #[test]
    fn parse_dpkg_status_collects_installed_packages() {
        let parsed = parse_dpkg_status(
            "Package: curl\nStatus: install ok installed\nVersion: 8.8.0-1\nMaintainer: Example Maintainer\n\nPackage: old\nStatus: deinstall ok config-files\nVersion: 1.0\n\n",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].display_name, "curl");
        assert_eq!(parsed[0].version_hint.as_deref(), Some("8.8.0-1"));
        assert_eq!(
            parsed[0].publisher_hint.as_deref(),
            Some("Example Maintainer")
        );
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
    }

    #[test]
    fn parse_apk_installed_collects_maintainer_or_origin() {
        let parsed = parse_apk_installed(
            "P:busybox\nV:1.36.1-r7\nm:Natanael Copa <ncopa@alpinelinux.org>\n\nP:musl\nV:1.2.5-r1\no:alpine-baselayout\n\n",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].display_name, "busybox");
        assert_eq!(parsed[0].version_hint.as_deref(), Some("1.36.1-r7"));
        assert_eq!(
            parsed[0].publisher_hint.as_deref(),
            Some("Natanael Copa <ncopa@alpinelinux.org>")
        );
        assert_eq!(parsed[1].display_name, "musl");
        assert_eq!(
            parsed[1].publisher_hint.as_deref(),
            Some("alpine-baselayout")
        );
    }

    #[test]
    fn clean_display_icon_path_handles_quoted_and_comma_suffixes() {
        assert_eq!(
            clean_display_icon_path(r#""C:\\Program Files\\App\\app.exe",0"#),
            r#"C:\\Program Files\\App\\app.exe"#
        );
        assert_eq!(
            clean_display_icon_path(r#"C:\\Program Files\\App\\app.exe,1"#),
            r#"C:\\Program Files\\App\\app.exe"#
        );
    }

    #[test]
    fn preferred_registry_path_accepts_executable_install_location() {
        assert_eq!(
            preferred_registry_path("", r#""C:\\Tools\\agent.exe""#),
            r#"C:\\Tools\\agent.exe"#
        );
        assert_eq!(preferred_registry_path("", r#""C:\\Tools""#), "");
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
    fn collect_vendor_aliases_keeps_full_and_suffix_stripped_forms() {
        assert_eq!(
            collect_vendor_aliases("Example Corporation <sec@example.com>"),
            vec!["example".to_string(), "example-corporation".to_string()]
        );
        assert_eq!(
            collect_vendor_aliases("Microsoft Corporation"),
            vec!["microsoft".to_string(), "microsoft-corporation".to_string()]
        );
    }

    #[test]
    fn collect_product_aliases_uses_display_name_and_executable_stem() {
        let aliases = collect_product_aliases(
            "Google Chrome",
            Some("C:/Program Files/Google/Chrome/chrome.exe"),
        );
        assert_eq!(
            aliases,
            vec!["chrome".to_string(), "google-chrome".to_string()]
        );
    }

    #[test]
    fn enrich_inventory_identity_populates_normalized_hints() {
        let mut entry = InventoryEntry {
            display_name: "Example Agent".to_string(),
            executable_path: Some("C:/Program Files/Example/agent.exe".to_string()),
            version_hint: Some("2.4.1".to_string()),
            publisher_hint: Some("Example Corp".to_string()),
            product_key: None,
            product_aliases: Vec::new(),
            vendor_key: None,
            vendor_aliases: Vec::new(),
            source: "windows-uninstall-registry",
        };

        enrich_inventory_identity(&mut entry);

        assert_eq!(entry.product_key.as_deref(), Some("example-agent"));
        assert_eq!(entry.vendor_key.as_deref(), Some("example"));
        assert_eq!(
            entry.product_aliases,
            vec!["agent".to_string(), "example-agent".to_string()]
        );
        assert_eq!(
            entry.vendor_aliases,
            vec!["example".to_string(), "example-corp".to_string()]
        );
    }
}
