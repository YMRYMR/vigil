//! Standalone Vigil protection-status report.
//!
//! This first slice is intentionally conservative: it reports only facts that a
//! CLI process can check without attaching to the live GUI/service runtime. Live
//! runtime health will be layered on top of the same JSON contract later.

#![allow(dead_code)]
#![allow(clippy::needless_return)]

extern crate sha2 as sha2_crate;

mod sha2 {
    use std::fmt;

    pub trait Digest {
        fn digest(data: impl AsRef<[u8]>) -> HexDigest;
    }

    pub struct Sha256;

    pub struct HexDigest([u8; 32]);

    impl Digest for Sha256 {
        fn digest(data: impl AsRef<[u8]>) -> HexDigest {
            use crate::sha2_crate::Digest as _;

            let digest = crate::sha2_crate::Sha256::digest(data.as_ref());
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(digest.as_ref());
            HexDigest(bytes)
        }
    }

    impl fmt::LowerHex for HexDigest {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            for byte in &self.0 {
                write!(formatter, "{byte:02x}")?;
            }
            Ok(())
        }
    }
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
