#[test]
fn missing_protected_break_glass_state_routes_to_fail_open_recovery() {
    let source = include_str!("../src/platform/break_glass.rs");
    let missing_state_arm = source
        .find("Ok(None) =>")
        .expect("recover_if_stale should handle missing protected state");
    let missing_state_block = &source[missing_state_arm..];

    assert!(
        missing_state_block.contains("active_response::status().isolated"),
        "missing protected state should check whether the machine is isolated"
    );
    assert!(
        missing_state_block.contains("return attempt_fail_open_recovery("),
        "missing protected state while isolated should try fail-open recovery"
    );
    assert!(
        missing_state_block
            .contains("missing protected break-glass state while machine is isolated"),
        "missing-state fail-open path should keep a clear audit reason"
    );
}

#[test]
fn unreadable_protected_break_glass_state_routes_to_fail_open_recovery() {
    let source = include_str!("../src/platform/break_glass.rs");
    let load_error_arm = source
        .find("Err(err) =>")
        .expect("recover_if_stale should handle protected-state load errors");
    let load_error_block = &source[load_error_arm..];

    assert!(
        load_error_block.contains("active_response::status().isolated"),
        "protected-state load errors should check whether the machine is isolated"
    );
    assert!(
        load_error_block.contains("return attempt_fail_open_recovery("),
        "protected-state load errors while isolated should try fail-open recovery"
    );
    assert!(
        load_error_block.contains("failed to load protected break-glass state"),
        "load-error fail-open path should keep a clear audit reason"
    );
}

#[test]
fn fail_open_recovery_attempts_restore_and_disarms_only_after_success() {
    let source = include_str!("../src/platform/break_glass.rs");
    let helper_arm = source
        .find("fn attempt_fail_open_recovery")
        .expect("fail-open recovery helper should exist");
    let helper = &source[helper_arm..];

    assert!(
        helper.contains("active_response::restore_machine()"),
        "fail-open recovery must attempt to restore machine connectivity"
    );
    assert!(
        helper.contains("\"fail_open_path\": true"),
        "fail-open recovery should be explicit in audit payloads"
    );
    assert!(
        helper.contains("let _ = disarm();"),
        "successful fail-open recovery should disarm the watchdog"
    );
    assert!(
        helper.find("Ok(message) =>").unwrap() < helper.find("let _ = disarm();").unwrap(),
        "watchdog disarm should be in the success path"
    );
}
