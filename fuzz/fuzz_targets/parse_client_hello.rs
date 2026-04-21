#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/tls.rs"]
mod tls;

fuzz_target!(|data: &[u8]| {
    let _ = tls::parse_client_hello(data);
});
