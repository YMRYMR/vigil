//! Phase 12 tamper / visibility-blind-spot heuristics.
//!
//! This module stays conservative and explainable. It does not claim kernel
//! certainty; instead it raises explicit operator-facing reasons when the host's
//! process or telemetry visibility appears degraded in ways often associated
//! with defense evasion, protected-process blind spots, or monitoring impairment.

use crate::detection_depth::DetectionAdditions;
use crate::process::ProcessInfo;

#[derive(Debug, Clone, Copy, Default)]
pub struct VisibilityContext {
    pub etw_expected: bool,
    pub etw_active: bool,
    pub elevated: bool,
    pub pre_login: bool,
}

pub fn inspect_visibility_gaps(proc: &ProcessInfo, ctx: VisibilityContext) -> DetectionAdditions {
    let mut out = DetectionAdditions::default();
    let proc_key = proc.name_key.as_str();
    let service_or_system_ancestry = matches!(
        proc.parent_name.to_ascii_lowercase().trim_end_matches(".exe"),
        "services" | "svchost" | "wininit" | "lsass" | "wmiprvse" | "taskeng" | "schtasks"
    ) || !proc.service_name.is_empty();

    if ctx.elevated && ctx.etw_expected && !ctx.etw_active {
        out.score = out.score.saturating_add(2);
        out.reasons.push(
            "Telemetry visibility gap: ETW fast-path unavailable while Vigil is elevated; real-time kernel telemetry may be impaired".into(),
        );
        out.attack_tags
            .push("T1562 Impair Defenses / Telemetry Downgrade (heuristic)".into());
    }

    if ctx.elevated && proc.name.starts_with('<') && proc.name.ends_with('>') {
        out.score = out.score.saturating_add(3);
        out.reasons.push(
            "Protected-process / blind-spot heuristic: live networking PID could not be resolved to process metadata even after retry".into(),
        );
        out.attack_tags
            .push("T1562 Impair Defenses / Protected Process Blind Spot (heuristic)".into());
    }

    if ctx.elevated && service_or_system_ancestry && proc.path.is_empty() && !proc.name.is_empty() {
        out.score = out.score.saturating_add(2);
        out.reasons.push(format!(
            "Visibility gap: service or system ancestry for {} but executable path was not readable",
            proc.name
        ));
        out.attack_tags
            .push("T1562 Impair Defenses / Metadata Access Failure (heuristic)".into());
    }

    if ctx.pre_login && service_or_system_ancestry && proc.publisher.is_empty() && !proc.path.is_empty() {
        out.score = out.score.saturating_add(2);
        out.reasons.push(format!(
            "Pre-login visibility anomaly: {} spawned from service-like ancestry without publisher metadata",
            proc.name
        ));
        out.attack_tags
            .push("T1547 Boot or Logon Autostart Execution (heuristic)".into());
    }

    if matches!(proc_key, "lsass" | "csrss" | "wininit" | "services" | "svchost")
        && proc.path.is_empty()
        && ctx.elevated
    {
        out.score = out.score.saturating_add(2);
        out.reasons.push(format!(
            "Core-system metadata gap: {} generated network activity but its executable location could not be verified",
            proc.name
        ));
        out.attack_tags
            .push("T1562 Impair Defenses / Core Process Blind Spot (heuristic)".into());
    }

    crate::detection_depth::dedup(&mut out.attack_tags);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_pid_when_elevated_triggers_blind_spot_signal() {
        let proc = ProcessInfo {
            name: "<4242>".into(),
            name_key: "<4242>".into(),
            ..Default::default()
        };
        let out = inspect_visibility_gaps(
            &proc,
            VisibilityContext {
                elevated: true,
                etw_expected: true,
                etw_active: true,
                pre_login: false,
            },
        );
        assert!(out.score >= 3);
        assert!(out.attack_tags.iter().any(|t| t.contains("T1562")));
    }

    #[test]
    fn etw_gap_when_elevated_adds_reason() {
        let proc = ProcessInfo {
            name: "svchost.exe".into(),
            name_key: "svchost".into(),
            parent_name: "services.exe".into(),
            ..Default::default()
        };
        let out = inspect_visibility_gaps(
            &proc,
            VisibilityContext {
                elevated: true,
                etw_expected: true,
                etw_active: false,
                pre_login: false,
            },
        );
        assert!(out.score >= 2);
        assert!(out.reasons.iter().any(|r| r.contains("ETW fast-path unavailable")));
    }
}
