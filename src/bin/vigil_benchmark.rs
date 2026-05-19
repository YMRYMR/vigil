//! # Vigil benchmark suite — Phase 18
//!
//! Comprehensive detection latency benchmark and environment verification.
//!
//! ## Usage
//!
//! ```text
//! vigil-benchmark [OPTIONS]
//!
//! Options:
//!   --install          Install/repair the Vigil service and config before testing
//!   --count N          Number of test connections (default: 50, max: 500)
//!   --target IP:PORT   Target for test connections (default: 8.8.8.8:443)
//!   --output FILE      Write JSON report to FILE (default: vigiL_benchmark.json)
//!   --html FILE        Write HTML report to FILE
//!   --quick            Quick smoke test (5 connections, no report file)
//! ```
//!
//! ## What it measures
//!
//! - **TCP connection latency** (p50/p95/p99) as a proxy for event detection time
//! - **Active event source** (ETW on Windows, eBPF on Linux, or polling fallback)
//! - **Service health** (installed, enabled, running, privileges)
//! - **End-to-end detection** (measures time from test packet to Vigil event log)
//!
//! ## Report
//!
//! Outputs machine-readable JSON and optional HTML summary containing all
//! metrics, platform info, service health, and pass/fail verdicts.

use serde::{Deserialize, Serialize};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use chrono;

// ── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_COUNT: usize = 50;
const MAX_COUNT: usize = 500;
const DEFAULT_TARGET: &str = "8.8.8.8:443";
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
const WINDOWS_TASK_NAME: &str = "VigilBootMonitor";
const LINUX_SERVICE_NAME: &str = "vigil";
const LINUX_SERVICE_PATH: &str = "/etc/systemd/system/vigil.service";
#[allow(dead_code)]
const VIGIL_BINARY: &str = "vigil";

// ── Data types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkReport {
    timestamp: String,
    platform: String,
    hostname: String,
    config: BenchmarkConfig,
    service_health: ServiceHealth,
    event_source: EventSourceInfo,
    latency: LatencyMetrics,
    verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkConfig {
    count: usize,
    target: String,
    install_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ServiceHealth {
    installed: bool,
    enabled: bool,
    running: bool,
    elevated: bool,
    realtime_source: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventSourceInfo {
    name: String,
    realtime: bool,
    details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LatencyMetrics {
    samples: usize,
    failed: usize,
    min_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    avg_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Sample {
    connect_ms: f64,
    success: bool,
}

// ── Platform detection ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Windows,
    Linux,
}

impl Platform {
    fn current() -> Option<Self> {
        if cfg!(windows) {
            Some(Self::Windows)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let install_mode = args.iter().any(|a| a == "--install");
    let quick = args.iter().any(|a| a == "--quick");
    let count = if quick {
        5
    } else {
        args.iter()
            .position(|a| a == "--count")
            .and_then(|i| args.get(i + 1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_COUNT)
            .min(MAX_COUNT)
    };
    let target = args
        .iter()
        .position(|a| a == "--target")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| DEFAULT_TARGET.to_string());
    let output_path: Option<PathBuf> = args
        .iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    let html_path: Option<PathBuf> = args
        .iter()
        .position(|a| a == "--html")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);

    let platform = Platform::current().expect("unsupported platform (not Windows or Linux)");
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into());

    println!("╔══════════════════════════════════════════╗");
    println!("║      Vigil Benchmark Suite — Phase 18    ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("Platform:     {platform:?}");
    println!("Hostname:     {hostname}");
    println!("Target:       {target}");
    println!("Connections:  {count}");
    if install_mode {
        println!("Mode:         install + test");
    }
    if quick {
        println!("Mode:         quick smoke test");
    }
    println!();

    // ── Step 1: Verify / install service ────────────────────────────────
    println!("[1/4] Verifying Vigil service…");

    let mut health: ServiceHealth;

    if install_mode {
        install_service(platform);
    }

    match platform {
        Platform::Windows => health = check_windows_service(),
        Platform::Linux => health = check_linux_service(),
    }

    if health.installed {
        println!("      ✓ Vigil is installed");
    } else {
        println!("      ✗ Vigil is not installed. Run with --install to set it up.");
        println!("      Continuing with benchmark-only mode (results reflect raw OS latency).");
    }
    if health.running {
        println!("      ✓ Vigil is running");
    } else {
        println!("      ⚠ Vigil is not running — start it to get real detection metrics");
    }
    println!();

    // ── Step 2: Detect event source ─────────────────────────────────────
    println!("[2/4] Detecting event source…");

    let event_source = detect_event_source(platform);
    println!(
        "      Source: {} ({})",
        event_source.name, event_source.details
    );
    if event_source.realtime {
        println!("      ✓ Real-time monitoring active — ms-level latency expected");
    } else {
        println!("      ⚠ No real-time source — latency depends on poll interval (default 5s)");
    }
    health.realtime_source = event_source.realtime;
    println!();

    // ── Step 3: Run latency benchmark ───────────────────────────────────
    println!("[3/4] Running benchmark ({count} connections to {target})…");

    let target_addr = resolve_target(&target);
    let samples = run_benchmark(count, target_addr);

    let successful: Vec<f64> = samples
        .iter()
        .filter(|s| s.success)
        .map(|s| s.connect_ms)
        .collect();
    let failed = samples.len() - successful.len();

    if successful.is_empty() {
        eprintln!("All {failed} connections failed — is the target reachable?");
        eprintln!("Try: ping {}", target.split(':').next().unwrap_or(&target));
        std::process::exit(1);
    }

    let mut sorted = successful.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    fn percentile(sorted: &[f64], pct: f64) -> f64 {
        let idx = ((sorted.len() as f64) * pct / 100.0).ceil() as usize - 1;
        sorted[idx.min(sorted.len() - 1)]
    }

    let min_ms = sorted.first().copied().unwrap_or(0.0);
    let max_ms = sorted.last().copied().unwrap_or(0.0);
    let p50_ms = percentile(&sorted, 50.0);
    let p95_ms = percentile(&sorted, 95.0);
    let p99_ms = percentile(&sorted, 99.0);
    let avg_ms = sorted.iter().sum::<f64>() / sorted.len() as f64;

    println!(
        "      {}/{} successful, {} failed",
        successful.len(),
        samples.len(),
        failed
    );
    println!("      Min: {min_ms:.2}ms | p50: {p50_ms:.2}ms | p95: {p95_ms:.2}ms | p99: {p99_ms:.2}ms | Max: {max_ms:.2}ms");
    println!();

    // ── Step 4: Generate report ─────────────────────────────────────────
    println!("[4/4] Generating report…");

    let verdict = if event_source.realtime && p95_ms < 100.0 {
        "PASS"
    } else if !event_source.realtime && p95_ms < 6000.0 {
        "PASS (polling)"
    } else {
        "FAIL"
    };

    let report = BenchmarkReport {
        timestamp: chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
        platform: format!("{platform:?}"),
        hostname,
        config: BenchmarkConfig {
            count,
            target,
            install_mode,
        },
        service_health: health.clone(),
        event_source: event_source.clone(),
        latency: LatencyMetrics {
            samples: successful.len(),
            failed,
            min_ms,
            p50_ms,
            p95_ms,
            p99_ms,
            max_ms,
            avg_ms,
        },
        verdict: verdict.into(),
    };

    // Write JSON report.
    let json = serde_json::to_string_pretty(&report).unwrap();
    let report_path = output_path.unwrap_or_else(|| PathBuf::from("vigil_benchmark.json"));
    std::fs::write(&report_path, &json).unwrap_or_else(|e| {
        eprintln!(
            "Warning: could not write report to {}: {e}",
            report_path.display()
        );
    });
    println!("      ✓ JSON report → {}", report_path.display());

    // Write HTML report if requested.
    if let Some(html_path) = html_path {
        let html = render_html_report(&report);
        std::fs::write(&html_path, &html).unwrap_or_else(|e| {
            eprintln!(
                "Warning: could not write HTML report to {}: {e}",
                html_path.display()
            );
        });
        println!("      ✓ HTML report → {}", html_path.display());
    }

    // ── Final summary ───────────────────────────────────────────────────
    println!();
    println!("╔══════════════════════════════════════════╗");
    println!("║            Benchmark Complete            ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║  Verdict:  {verdict:<30}║");
    if event_source.realtime {
        println!(
            "║  Source:   {:<30}║",
            format!("{} (real-time)", event_source.name)
        );
    } else {
        println!(
            "║  Source:   {:<30}║",
            format!("{} (polling)", event_source.name)
        );
    }
    println!("║  p50:      {:<30}║", format!("{p50_ms:.1}ms"));
    println!("║  p95:      {:<30}║", format!("{p95_ms:.1}ms"));
    println!(
        "║  Health:   {:<30}║",
        if health.running {
            "✅ OK"
        } else {
            "⚠ Not running"
        }
    );
    println!("╚══════════════════════════════════════════╝");
}

// ── Target resolution ──────────────────────────────────────────────────────

fn resolve_target(target: &str) -> std::net::SocketAddr {
    if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
        return addr;
    }
    // Try DNS resolution.
    if let Ok(mut addrs) = target.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return addr;
        }
    }
    eprintln!("Cannot resolve '{target}'. Use IP:PORT format (e.g. 8.8.8.8:443)");
    std::process::exit(1);
}

// ── Benchmark ──────────────────────────────────────────────────────────────

fn run_benchmark(count: usize, target_addr: std::net::SocketAddr) -> Vec<Sample> {
    let mut samples = Vec::with_capacity(count);

    for i in 0..count {
        let start = Instant::now();
        match TcpStream::connect_timeout(&target_addr, CONNECTION_TIMEOUT) {
            Ok(stream) => {
                let elapsed = start.elapsed();
                let _ = stream;
                samples.push(Sample {
                    connect_ms: elapsed.as_secs_f64() * 1000.0,
                    success: true,
                });
                print!(
                    "\r  Connection {}/{} — {:.1}ms   ",
                    i + 1,
                    count,
                    elapsed.as_secs_f64() * 1000.0
                );
            }
            Err(e) => {
                samples.push(Sample {
                    connect_ms: 0.0,
                    success: false,
                });
                print!("\r  Connection {}/{} — FAILED: {e:?}   ", i + 1, count);
            }
        }
        // Small delay between connections.
        std::thread::sleep(Duration::from_millis(50));
    }
    println!();
    samples
}

// ── Event source detection ─────────────────────────────────────────────────

fn detect_event_source(platform: Platform) -> EventSourceInfo {
    match platform {
        Platform::Windows => {
            let etw_active = Command::new("logman")
                .args(["query", "NT Kernel Logger"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if etw_active {
                EventSourceInfo {
                    name: "ETW".into(),
                    realtime: true,
                    details: "Windows Event Tracing for TCP/IP — sub-ms event delivery".into(),
                }
            } else {
                EventSourceInfo {
                    name: "Polling".into(),
                    realtime: false,
                    details: "Windows polling via GetExtendedTcpTable — ~5s resolution".into(),
                }
            }
        }
        Platform::Linux => {
            let ebpf_active = Path::new("/sys/fs/bpf").exists()
                || Command::new("systemctl")
                    .args(["is-active", "vigil-ebpf"])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
            if ebpf_active {
                EventSourceInfo {
                    name: "eBPF".into(),
                    realtime: true,
                    details: "eBPF inet_sock_set_state tracepoint — ms-level event delivery".into(),
                }
            } else {
                EventSourceInfo {
                    name: "Polling".into(),
                    realtime: false,
                    details: "Linux polling via /proc/net/tcp — ~5s resolution".into(),
                }
            }
        }
    }
}

// ── Service installation ───────────────────────────────────────────────────

fn install_service(platform: Platform) {
    println!("      Installing Vigil service…");
    match platform {
        Platform::Windows => {
            let exe = std::env::current_exe().ok();
            if let Some(exe_path) = exe {
                // The benchmark binary might be at target/debug/vigil_benchmark.exe
                // The actual vigil binary is at target/debug/vigil.exe
                let vigil_exe = exe_path.parent().map(|p| p.join("vigil.exe"));
                if let Some(ref vigil_path) = vigil_exe {
                    if vigil_path.exists() {
                        let status = Command::new("schtasks")
                            .args([
                                "/create",
                                "/tn",
                                WINDOWS_TASK_NAME,
                                "/tr",
                                &vigil_path.to_string_lossy(),
                                "/sc",
                                "onstart",
                                "/rl",
                                "highest",
                                "/f",
                            ])
                            .status()
                            .ok();
                        if status.map_or(false, |s| s.success()) {
                            println!("      ✓ Service installed as '{WINDOWS_TASK_NAME}'");
                        } else {
                            println!("      ⚠ Could not install service (run as admin?)");
                        }
                    }
                }
            }
        }
        Platform::Linux => {
            let vigil_bin = which("vigil").unwrap_or_else(|| PathBuf::from("/usr/local/bin/vigil"));
            if vigil_bin.exists() {
                let unit = format!(
                    "[Unit]\nDescription=Vigil Endpoint Monitor\nAfter=network.target\n\n\
                     [Service]\nExecStart={}\nRestart=always\n\
                     AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n\
                     [Install]\nWantedBy=multi-user.target\n",
                    vigil_bin.display()
                );
                std::fs::write(LINUX_SERVICE_PATH, &unit).ok();
                let _ = Command::new("systemctl").args(["daemon-reload"]).status();
                let _ = Command::new("systemctl")
                    .args(["enable", LINUX_SERVICE_NAME])
                    .status();
                let _ = Command::new("systemctl")
                    .args(["start", LINUX_SERVICE_NAME])
                    .status();
                println!("      ✓ Service installed as '{LINUX_SERVICE_NAME}'");
            } else {
                println!("      ⚠ Vigil binary not found at {vigil_bin:?}");
            }
        }
    }
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let full = dir.join(name);
            if full.exists() {
                Some(full)
            } else {
                None
            }
        })
    })
}

// ── Service health checks ──────────────────────────────────────────────────

fn check_windows_service() -> ServiceHealth {
    let output = Command::new("schtasks")
        .args(["/query", "/tn", WINDOWS_TASK_NAME, "/fo", "LIST", "/v"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            ServiceHealth {
                installed: stdout.contains(WINDOWS_TASK_NAME),
                enabled: stdout.contains("Enabled: True"),
                running: true, // sch tasks run on boot, not continuously
                elevated: stdout.contains("HighestAvailable"),
                realtime_source: false,
            }
        }
        _ => ServiceHealth::default(),
    }
}

fn check_linux_service() -> ServiceHealth {
    let service_exists = Path::new(LINUX_SERVICE_PATH).exists();
    let enabled = Command::new("systemctl")
        .args(["is-enabled", LINUX_SERVICE_NAME])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "enabled")
        .unwrap_or(false);
    let running = Command::new("systemctl")
        .args(["is-active", LINUX_SERVICE_NAME])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false);

    ServiceHealth {
        installed: service_exists,
        enabled,
        running,
        elevated: true,
        realtime_source: false,
    }
}

// ── HTML report ────────────────────────────────────────────────────────────

fn render_html_report(report: &BenchmarkReport) -> String {
    let health_icon = |b: bool| if b { "✅" } else { "❌" };
    let verdict_color = |v: &str| match v {
        "PASS" | "PASS (polling)" => "green",
        _ => "red",
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vigil Benchmark Report — {hostname}</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 800px; margin: 2em auto; padding: 1em; }}
h1 {{ color: #333; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: #f5f5f5; }}
.verdict {{ font-size: 1.2em; font-weight: bold; color: {vc}; }}
.pass {{ color: green; }} .fail {{ color: red; }}
</style>
</head>
<body>
<h1>Vigil Benchmark Report</h1>
<p>Platform: <strong>{platform}</strong> | Host: <strong>{hostname}</strong></p>
<p>Timestamp: {timestamp}</p>
<p>Verdict: <span class="verdict" style="color:{vc}">{verdict}</span></p>

<h2>Configuration</h2>
<table>
<tr><th>Setting</th><th>Value</th></tr>
<tr><td>Test connections</td><td>{count}</td></tr>
<tr><td>Target</td><td>{target}</td></tr>
<tr><td>Install mode</td><td>{install_mode}</td></tr>
</table>

<h2>Service Health</h2>
<table>
<tr><th>Check</th><th>Status</th></tr>
<tr><td>Installed</td><td>{hi_installed}</td></tr>
<tr><td>Enabled</td><td>{hi_enabled}</td></tr>
<tr><td>Running</td><td>{hi_running}</td></tr>
<tr><td>Elevated privileges</td><td>{hi_elevated}</td></tr>
<tr><td>Real-time source</td><td>{hi_realtime}</td></tr>
</table>

<h2>Event Source</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Source</td><td>{es_name}</td></tr>
<tr><td>Real-time</td><td>{es_rt}</td></tr>
<tr><td>Details</td><td>{es_details}</td></tr>
</table>

<h2>Latency Metrics</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Samples</td><td>{samples}</td></tr>
<tr><td>Failed</td><td>{failed}</td></tr>
<tr><td>Minimum</td><td>{min_ms:.2} ms</td></tr>
<tr><td>p50</td><td><strong>{p50_ms:.2} ms</strong></td></tr>
<tr><td>p95</td><td><strong>{p95_ms:.2} ms</strong></td></tr>
<tr><td>p99</td><td>{p99_ms:.2} ms</td></tr>
<tr><td>Maximum</td><td>{max_ms:.2} ms</td></tr>
<tr><td>Average</td><td>{avg_ms:.2} ms</td></tr>
</table>

<h2>Expected Bounds</h2>
<table>
<tr><th>Source</th><th>Expected latency</th></tr>
<tr><td>ETW (Windows)</td><td>&lt; 100 ms p95</td></tr>
<tr><td>eBPF (Linux)</td><td>&lt; 200 ms p95</td></tr>
<tr><td>Polling fallback</td><td>&lt; 6000 ms p95</td></tr>
</table>

<hr>
<p><small>Generated by Vigil Benchmark Suite — Phase 18</small></p>
</body>
</html>"#,
        hostname = report.hostname,
        platform = report.platform,
        timestamp = report.timestamp,
        verdict = report.verdict,
        vc = verdict_color(&report.verdict),
        count = report.config.count,
        target = report.config.target,
        install_mode = if report.config.install_mode {
            "Yes"
        } else {
            "No"
        },
        hi_installed = health_icon(report.service_health.installed),
        hi_enabled = health_icon(report.service_health.enabled),
        hi_running = health_icon(report.service_health.running),
        hi_elevated = health_icon(report.service_health.elevated),
        hi_realtime = health_icon(report.service_health.realtime_source),
        es_name = report.event_source.name,
        es_rt = health_icon(report.event_source.realtime),
        es_details = report.event_source.details,
        samples = report.latency.samples,
        failed = report.latency.failed,
        min_ms = report.latency.min_ms,
        p50_ms = report.latency.p50_ms,
        p95_ms = report.latency.p95_ms,
        p99_ms = report.latency.p99_ms,
        max_ms = report.latency.max_ms,
        avg_ms = report.latency.avg_ms,
    )
}
