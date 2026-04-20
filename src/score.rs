//! Connection risk scorer.
//!
//! `score()` is a pure function — no I/O, no side effects.
//! It maps a connection snapshot + config → (risk_score, reasons, attack_tags).

use crate::{
    baseline::BaselineSignal,
    config::Config,
    detection_depth::{self},
};

/// Everything the scorer needs from one connection snapshot.
pub struct ScoreInput<'a> {
    pub name: &'a str,
    pub path: &'a str,
    pub publisher: &'a str,
    pub proc_user: &'a str,
    pub parent_user: &'a str,
    pub command_line: &'a str,
    pub remote_ip: &'a str,
    pub remote_port: u16,
    pub status: &'a str,
    pub ancestors: &'a [(String, u32)],
    pub beaconing: bool,
    pub pre_login: bool,
    pub reputation_hit: Option<&'a str>,
    pub country: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub tls_sni: Option<&'a str>,
    pub tls_ja3: Option<&'a str>,
    pub recently_dropped: bool,
    pub long_lived: bool,
    pub baseline_signal: BaselineSignal,
}

const SUSPICIOUS_PARENTS: &[(&str, &[&str])] = &[
    (
        "winword",
        &[
            "cmd",
            "powershell",
            "pwsh",
            "wscript",
            "cscript",
            "mshta",
            "wmic",
            "regsvr32",
            "rundll32",
        ],
    ),
    (
        "excel",
        &[
            "cmd",
            "powershell",
            "pwsh",
            "wscript",
            "cscript",
            "mshta",
            "wmic",
            "regsvr32",
            "rundll32",
        ],
    ),
    (
        "powerpnt",
        &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta"],
    ),
    (
        "outlook",
        &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta"],
    ),
    (
        "onenote",
        &["cmd", "powershell", "pwsh", "wscript", "cscript"],
    ),
    (
        "acrord32",
        &["cmd", "powershell", "pwsh", "wscript", "cscript"],
    ),
    (
        "acrobat",
        &["cmd", "powershell", "pwsh", "wscript", "cscript"],
    ),
    ("cmd", &["powershell", "pwsh"]),
    ("powershell", &["cmd", "pwsh"]),
    (
        "wmiprvse",
        &["cmd", "powershell", "pwsh", "wscript", "cscript"],
    ),
    ("taskeng", &["cmd", "powershell", "pwsh", "wscript"]),
    ("schtasks", &["cmd", "powershell", "pwsh", "wscript"]),
];

pub fn score(input: &ScoreInput<'_>, cfg: &Config) -> (u8, Vec<String>, Vec<String>) {
    if input.remote_ip.is_empty() && input.status == "LISTEN" {
        return (0, vec![], vec![]);
    }
    const LOOPBACK: &[&str] = &["127.0.0.1", "::1", "0.0.0.0", ""];
    if LOOPBACK.contains(&input.remote_ip) {
        return (0, vec![], vec![]);
    }

    let trusted: std::collections::HashSet<String> = cfg
        .trusted_processes
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    let lolbins: std::collections::HashSet<String> =
        cfg.lolbins.iter().map(|s| s.to_lowercase()).collect();
    let common_ports: std::collections::HashSet<u16> = cfg.common_ports.iter().copied().collect();
    let malware_ports: std::collections::HashSet<u16> = cfg.malware_ports.iter().copied().collect();
    let is_trusted = trusted.contains(input.name);

    let mut s: u8 = 0;
    let mut reasons: Vec<String> = Vec::new();
    let mut attack_tags: Vec<String> = Vec::new();

    const SAFE_NO_PATH: &[&str] = &["system", "kernel", "registry"];
    let is_ghost = input.name.starts_with('<') && input.name.ends_with('>');
    if input.path.is_empty() && !SAFE_NO_PATH.contains(&input.name) && !is_ghost {
        s = s.saturating_add(3);
        reasons.push("No executable path (possible process injection / hollowing)".into());
        attack_tags.push("T1055 Process Injection (heuristic)".into());
    }

    if !input.path.is_empty() {
        let path_upper = input.path.to_uppercase();
        for frag in &cfg.suspicious_path_fragments {
            if path_upper.contains(&frag.to_uppercase()) {
                s = s.saturating_add(3);
                reasons.push(format!("Running from suspicious path: {}", input.path));
                attack_tags
                    .push("T1204 User Execution / Suspicious Drop Location (heuristic)".into());
                break;
            }
        }
    }

    if lolbins.contains(input.name) {
        s = s.saturating_add(4);
        reasons.push(format!(
            "System binary making network connection: {} (living-off-the-land)",
            input.name
        ));
        attack_tags.push("T1218 Signed Binary Proxy Execution (heuristic)".into());
    }

    for (parent_name_lc, _pid) in input.ancestors.iter() {
        let parent_key = crate::config::normalise_name(parent_name_lc);
        for (bad_parent, bad_children) in SUSPICIOUS_PARENTS {
            if parent_key == *bad_parent && bad_children.contains(&input.name) {
                s = s.saturating_add(3);
                reasons.push(format!(
                    "Suspicious parent process: {} spawned {}",
                    parent_name_lc, input.name
                ));
                attack_tags
                    .push("T1204 User Execution / Suspicious Parent Chain (heuristic)".into());
                break;
            }
        }
    }

    if input.beaconing {
        s = s.saturating_add(3);
        reasons.push("Beaconing pattern detected (regular C2 callback timing signature)".into());
        attack_tags.push("T1071 Application Layer Protocol / Beaconing (heuristic)".into());
    }

    if input.pre_login {
        s = s.saturating_add(2);
        reasons.push("Connection observed before user login (boot-time persistence)".into());
        attack_tags.push("T1547 Boot or Logon Autostart Execution (heuristic)".into());
    }

    if let Some(src) = input.reputation_hit {
        s = s.saturating_add(3);
        reasons.push(format!(
            "Reputation hit: {} is in blocklist '{}'",
            input.remote_ip, src
        ));
        attack_tags.push("T1583 / Threat Infra Reputation Hit (heuristic)".into());
    }

    if input.recently_dropped {
        s = s.saturating_add(3);
        reasons
            .push("Executable was just dropped into a watched directory (possible dropper)".into());
        attack_tags.push("T1105 Ingress Tool Transfer (heuristic)".into());
    }

    if let Some(country) = input.country {
        if !cfg.allowed_countries.is_empty()
            && !cfg
                .allowed_countries
                .iter()
                .any(|a| a.eq_ignore_ascii_case(country))
        {
            s = s.saturating_add(2);
            reasons.push(format!("Connection to unexpected country: {country}"));
        }
    }

    if input.long_lived && !is_trusted {
        s = s.saturating_add(2);
        reasons.push(format!(
            "Long-lived connection held open past {}s by untrusted process",
            cfg.long_lived_secs
        ));
        attack_tags
            .push("T1071 Application Layer Protocol / Long-Lived Channel (heuristic)".into());
    }

    let name_source = input.hostname.or(input.tls_sni);
    let dga_like = name_source
        .map(|host| {
            !host.is_empty() && crate::entropy::is_dga_like(host, cfg.dga_entropy_threshold)
        })
        .unwrap_or(false);
    if let Some(host) = name_source {
        if dga_like {
            let host_kind = if input.hostname.is_some() {
                "hostname"
            } else {
                "TLS SNI"
            };
            s = s.saturating_add(2);
            reasons.push(format!("{host_kind} looks DGA-generated: {host}"));
            attack_tags.push("T1568.002 Dynamic Resolution / DGA (heuristic)".into());
        }
    }

    const DNS_NATIVE: &[&str] = &[
        "svchost",
        "dnscache",
        "dns",
        "systemd-resolved",
        "resolved",
        "named",
        "unbound",
        "dnsmasq",
    ];
    if input.remote_port == 53 && !DNS_NATIVE.contains(&input.name) && !is_trusted {
        s = s.saturating_add(2);
        reasons.push(format!(
            "DNS query from non-DNS process: {} (possible DNS tunneling)",
            input.name
        ));
        attack_tags.push("T1071.004 DNS (heuristic)".into());
    }

    if input.remote_port > 0 {
        if malware_ports.contains(&input.remote_port) {
            s = s.saturating_add(5);
            reasons.push(format!(
                "Connection to known malware/C2 port {}",
                input.remote_port
            ));
            attack_tags.push("T1071 Application Layer Protocol / C2 Port (heuristic)".into());
        } else if !common_ports.contains(&input.remote_port) && !is_trusted {
            s = s.saturating_add(1);
            reasons.push(format!("Unusual destination port {}", input.remote_port));
        }
    }

    if !is_trusted {
        s = s.saturating_add(2);
        reasons.push(format!("Unrecognised process: {}", input.name));
        if input.publisher.is_empty() && !input.path.is_empty() {
            s = s.saturating_add(2);
            reasons.push("Unsigned binary (no publisher information)".into());
        }
    }

    let script_host_additions =
        detection_depth::inspect_script_host(input.name, input.command_line);
    let script_host_suspicious = script_host_additions.triggered();
    script_host_additions.merge_into(&mut s, &mut reasons, &mut attack_tags);

    detection_depth::inspect_behavioural_baseline(input.name, input.baseline_signal).merge_into(
        &mut s,
        &mut reasons,
        &mut attack_tags,
    );
    detection_depth::inspect_parent_token_anomaly(
        input.name,
        input.ancestors,
        input.proc_user,
        input.parent_user,
    )
    .merge_into(&mut s, &mut reasons, &mut attack_tags);
    detection_depth::inspect_signed_binary_abuse(
        input.name,
        input.publisher,
        is_trusted,
        input.reputation_hit,
        input.recently_dropped,
        input.beaconing,
        input.pre_login,
        dga_like,
        script_host_suspicious,
    )
    .merge_into(&mut s, &mut reasons, &mut attack_tags);

    if let Some(sni) = input.tls_sni {
        if input.hostname.is_none() {
            reasons.push(format!("TLS SNI observed: {sni}"));
        }
    }
    if let Some(ja3) = input.tls_ja3 {
        reasons.push(format!("TLS JA3 fingerprint observed: {ja3}"));
    }

    detection_depth::dedup(&mut attack_tags);
    let mut seen = std::collections::BTreeSet::new();
    reasons.retain(|r| seen.insert(r.to_ascii_lowercase()));

    (s, reasons, attack_tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg() -> Config {
        Config::default()
    }

    fn input<'a>(
        name: &'a str,
        path: &'a str,
        remote_ip: &'a str,
        remote_port: u16,
        status: &'a str,
    ) -> ScoreInput<'a> {
        ScoreInput {
            name,
            path,
            publisher: "",
            proc_user: "user",
            parent_user: "user",
            command_line: "",
            remote_ip,
            remote_port,
            status,
            ancestors: &[],
            beaconing: false,
            pre_login: false,
            reputation_hit: None,
            country: None,
            hostname: None,
            tls_sni: None,
            tls_ja3: None,
            recently_dropped: false,
            long_lived: false,
            baseline_signal: BaselineSignal::default(),
        }
    }

    #[test]
    fn listen_no_remote_is_zero() {
        let (s, r, tags) = score(&input("vigil", "", "", 0, "LISTEN"), &cfg());
        assert_eq!(s, 0);
        assert!(r.is_empty());
        assert!(tags.is_empty());
    }

    #[test]
    fn script_host_adds_reason_and_tag() {
        let mut inp = input(
            "powershell",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "1.2.3.4",
            443,
            "ESTABLISHED",
        );
        inp.publisher = "Microsoft Corporation";
        inp.command_line = "powershell -enc AAAA -nop -w hidden";
        let (s, reasons, tags) = score(&inp, &cfg());
        assert!(s >= 10);
        assert!(reasons.iter().any(|r| r.contains("encoded-command")));
        assert!(tags.iter().any(|t| t.contains("T1059.001")));
    }

    #[test]
    fn mature_baseline_deviation_adds_score() {
        let mut inp = input("updater", "/opt/updater", "203.0.113.5", 443, "ESTABLISHED");
        inp.baseline_signal = BaselineSignal {
            mature: true,
            new_remote: true,
            new_port: false,
            new_country: false,
            observations: 20,
        };
        let (s, reasons, _) = score(&inp, &cfg());
        assert!(s >= 4);
        assert!(reasons
            .iter()
            .any(|r| r.contains("Behavioural baseline deviation")));
    }

    #[test]
    fn tls_sni_can_drive_dga_detection_when_hostname_is_missing() {
        let mut inp = input("updater", "/opt/updater", "203.0.113.5", 443, "ESTABLISHED");
        inp.tls_sni = Some("xj3kq9z2a.example");
        let (_s, reasons, _tags) = score(&inp, &cfg());
        assert!(reasons
            .iter()
            .any(|r| r.contains("TLS SNI") || r.contains("xj3kq9z2a.example")));
    }

    #[test]
    fn scoring_1000_inputs_within_budget() {
        use std::time::Instant;
        let cfg = cfg();
        let start = Instant::now();
        for i in 0..1000u32 {
            let name = "benchmark_proc";
            let path = "/usr/bin/benchmark";
            let port = (443 + (i % 100) as u16) as u16;
            let mut inp = input(name, path, "203.0.113.5", port, "ESTABLISHED");
            if i % 3 == 0 {
                inp.beaconing = true;
            }
            if i % 5 == 0 {
                inp.reputation_hit = Some("test-list");
            }
            let _ = score(&inp, &cfg);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 50,
            "1000 scoring calls took {elapsed:?} — budget is 50ms"
        );
    }
}
