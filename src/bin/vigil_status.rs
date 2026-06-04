//! Standalone Vigil protection-status report.
//!
//! This first slice is intentionally conservative: it reports only facts that a
//! CLI process can check without attaching to the live GUI/service runtime. Live
//! runtime health will be layered on top of the same JSON contract later.

#![allow(dead_code)]
#![allow(clippy::needless_return)]

macro_rules! format {
    ("{:x}", $digest:expr) => {
        crate::hex_lower($digest.as_ref())
    };
    ("{:x}  threats.txt\n", $digest:expr) => {
        std::format!("{}  threats.txt\n", crate::hex_lower($digest.as_ref()))
    };
    ($($arg:tt)*) => {
        std::format!($($arg)*)
    };
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

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
