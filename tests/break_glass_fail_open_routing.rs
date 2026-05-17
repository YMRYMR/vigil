#[test]
fn missing_protected_break_glass_state_fails_closed_when_isolated() {
    let source = include_str!("../src/platform/break_glass.rs");
    let missing_state_arm = source
        .find("Ok(None) =>")
        .expect("recover_if_stale should handle missing protected state");
    let missing_state_block = &source[missing_state_arm..];

    assert!(
        missing_state_block.contains("let isolated = active_response::status().isolated;"),
        "missing protected state should check whether the machine is isolated"
    );
    assert!(
        missing_state_block.contains("protected break-glass state is missing"),
        "missing-state path should keep a clear audit reason"
    );
    assert!(
        missing_state_block.contains("return if isolated { 1 } else { 0 }"),
        "missing protected state while isolated should now fail closed"
    );
    assert!(
        !missing_state_block.contains("attempt_fail_open_recovery"),
        "missing-state path should not use fail-open recovery anymore"
    );
}

#[test]
fn unreadable_protected_break_glass_state_fails_closed_when_isolated() {
    let source = include_str!("../src/platform/break_glass.rs");
    let load_error_arm = source
        .find("Err(err) =>")
        .expect("recover_if_stale should handle protected-state load errors");
    let load_error_block = &source[load_error_arm..];

    assert!(
        load_error_block.contains("let isolated = active_response::status().isolated;"),
        "protected-state load errors should check whether the machine is isolated"
    );
    assert!(
        load_error_block.contains("failed to load protected break-glass state"),
        "load-error path should keep a clear audit reason"
    );
    assert!(
        load_error_block.contains("return if isolated { 1 } else { 0 }"),
        "protected-state load errors while isolated should now fail closed"
    );
    assert!(
        !load_error_block.contains("attempt_fail_open_recovery"),
        "load-error path should not use fail-open recovery anymore"
    );
}

#[test]
fn fail_open_recovery_helper_is_removed_after_fail_closed_hardening() {
    let source = include_str!("../src/platform/break_glass.rs");

    assert!(
        !source.contains("fn attempt_fail_open_recovery"),
        "fail-open recovery helper should be removed after hardening"
    );
    assert!(
        source.contains("match active_response::restore_machine()"),
        "stale-heartbeat recovery should still restore connectivity when protected state is valid"
    );
    assert!(
        source.contains("let _ = disarm();"),
        "successful stale-heartbeat recovery should still disarm the watchdog"
    );
}
