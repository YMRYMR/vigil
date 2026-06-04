//! Standalone Vigil protection-status report.
//!
//! This first slice is intentionally conservative: it reports only facts that a
//! CLI process can check without attaching to the live GUI/service runtime. Live
//! runtime health will be layered on top of the same JSON contract later.

#![allow(dead_code)]
#![allow(clippy::needless_return)]

#[path = "../status_report.rs"]
mod status_report;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "vigil_status v{}\n\nUsage: vigil_status [--json]\n\nPrints a conservative JSON health report for local Vigil state. Runtime-only\nfacts remain unknown until the GUI/service publishes live health.",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }

    status_report::print_json_or_exit();
}
