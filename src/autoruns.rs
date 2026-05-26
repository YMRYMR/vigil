//! Compatibility wrappers for autorun freeze and restore actions.
//!
//! The UI still routes these actions through `crate::autoruns`, while the
//! underlying implementation now lives in `active_response`.

use crate::active_response;

pub fn freeze() -> Result<String, String> {
    active_response::freeze_autoruns()
}

pub fn revert() -> Result<String, String> {
    active_response::revert_frozen_autoruns()
}
