//! On-demand local software inventory utility for Phase 16 advisory matching.
//!
//! This binary is intentionally separate from the main Vigil startup path. It
//! performs only local/offline discovery and prints JSON so operators and later
//! advisory-matching code can inspect package-manager coverage without adding
//! new boot-time risk.

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct InventoryEntry {
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    publisher_hint: Option<String>,
    source: &'static str,
}

fn main() {
    let mut entries = Vec::new();
    entries.extend(collect_dpkg_entries());
    entries.extend(collect_rpm_entries());
    entries.extend(collect_apk_entries());
    entries.extend(collect_homebrew_entries());

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
        version_hint: fields.get("Version").cloned().and_then(inventory_hint),
        publisher_hint: fields.get("Maintainer").cloned().and_then(inventory_hint),
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
    output.lines().filter_map(inventory_entry_from_rpm_line).collect()
}

fn inventory_entry_from_rpm_line(line: &str) -> Option<InventoryEntry> {
    let mut fields = line.splitn(3, '\t');
    let display_name = fields.next()?.trim();
    if display_name.is_empty() {
        return None;
    }
    Some(InventoryEntry {
        display_name: display_name.to_string(),
        version_hint: fields.next().map(str::to_string).and_then(inventory_hint),
        publisher_hint: fields.next().map(str::to_string).and_then(inventory_hint),
        source: "linux-rpm-database",
    })
}

fn collect_apk_entries() -> Vec<InventoryEntry> {
    let Ok(installed) = std::fs::read_to_string("/lib/apk/db/installed") else {
        return Vec::new();
    };
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
        version_hint: fields.get(&'V').cloned().and_then(inventory_hint),
        publisher_hint: fields
            .get(&'m')
            .cloned()
            .and_then(inventory_hint)
            .or_else(|| fields.get(&'o').cloned().and_then(inventory_hint)),
        source: "linux-apk-installed",
    })
}

fn collect_homebrew_entries() -> Vec<InventoryEntry> {
    let mut entries = Vec::new();
    for root in ["/opt/homebrew/Cellar", "/usr/local/Cellar"] {
        entries.extend(collect_homebrew_formula_entries(Path::new(root)));
    }
    for root in ["/opt/homebrew/Caskroom", "/usr/local/Caskroom"] {
        entries.extend(collect_homebrew_cask_entries(Path::new(root)));
    }
    entries
}

fn collect_homebrew_formula_entries(cellar_root: &Path) -> Vec<InventoryEntry> {
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
        let Some(display_name) = package
            .file_name()
            .to_str()
            .map(str::to_string)
            .and_then(inventory_hint)
        else {
            continue;
        };
        let version_hint = sole_child_directory_name(&package.path());
        entries.push(InventoryEntry {
            display_name,
            version_hint,
            publisher_hint: None,
            source: "macos-homebrew-formula",
        });
    }
    entries
}

fn collect_homebrew_cask_entries(caskroom_root: &Path) -> Vec<InventoryEntry> {
    let Ok(casks) = std::fs::read_dir(caskroom_root) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for cask in casks.flatten() {
        let Ok(file_type) = cask.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(display_name) = cask
            .file_name()
            .to_str()
            .map(str::to_string)
            .and_then(inventory_hint)
        else {
            continue;
        };
        let version_hint = sole_child_directory_name(&cask.path());
        entries.push(InventoryEntry {
            display_name,
            version_hint,
            publisher_hint: None,
            source: "macos-homebrew-cask",
        });
    }
    entries
}

fn sole_child_directory_name(dir: &Path) -> Option<String> {
    let mut only = None;
    for child in std::fs::read_dir(dir).ok()? {
        let child = child.ok()?;
        if !child.file_type().ok()?.is_dir() {
            continue;
        }
        let candidate = child.file_name().to_str().map(str::to_string).and_then(inventory_hint)?;
        if only.is_some() {
            return None;
        }
        only = Some(candidate);
    }
    only
}

fn first_existing_file(paths: &[&'static str]) -> Option<&'static str> {
    paths.iter().copied().find(|path| Path::new(path).is_file())
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
        assert_eq!(parsed[0].publisher_hint.as_deref(), Some("Example Maintainer"));
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
        assert_eq!(parsed[1].publisher_hint.as_deref(), Some("alpine-baselayout"));
    }

    #[test]
    fn inventory_hint_drops_none_marker() {
        assert_eq!(inventory_hint("(none)".to_string()), None);
        assert_eq!(inventory_hint("  value  ".to_string()).as_deref(), Some("value"));
    }
}
