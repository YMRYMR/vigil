//! Activity tab wrapper around the process-grouped list.

use crate::types::ConnInfo;
use crate::ui::process_list::CachedGroupView;
use crate::ui::{process_list, ProcessSelection, TableState};
use std::collections::VecDeque;

pub fn show(
    ui: &mut egui::Ui,
    rows: &VecDeque<ConnInfo>,
    selected: &mut Option<ProcessSelection>,
    state: &mut TableState,
    data_version: u64,
    cache: &mut Option<CachedGroupView>,
) -> bool {
    process_list::show(
        ui,
        rows,
        selected,
        state,
        process_list::Kind::Activity,
        data_version,
        cache,
    )
}
