//! Activity tab wrapper around the process-grouped list.

use crate::types::ConnInfo;
use crate::ui::process_list_fast::CachedGroupView;
use crate::ui::{process_list_fast, ProcessSelection, TableState};
use std::collections::VecDeque;

pub fn show(
    ui: &mut egui::Ui,
    rows: &VecDeque<ConnInfo>,
    selected: &mut Option<ProcessSelection>,
    state: &mut TableState,
    data_version: u64,
    cache: &mut Option<CachedGroupView>,
) -> bool {
    process_list_fast::show(
        ui,
        rows,
        selected,
        state,
        process_list_fast::Kind::Activity,
        data_version,
        cache,
    )
}
