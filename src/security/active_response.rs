#[path = "active_response_impl.rs"]
mod imp;

const ISOLATE_RULE_IN: &str = "Vigil Isolate In";
const ISOLATE_RULE_OUT: &str = "Vigil Isolate Out";

pub use imp::*;

pub fn restore_network() -> Result<String, String> {
    imp::restore_machine()
}
