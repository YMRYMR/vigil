# Supported Platforms

Vigil's active product scope is **Windows and Linux only**.

This document is the project-level support contract for new development. When roadmap text, older docs, or legacy code mention macOS, treat that macOS material as historical or deprecated unless a later support-policy change explicitly re-adds it.

## Tier 1: Windows

Windows remains a first-class target for detection, response, service mode, packaging, and operator UX.

Current Windows-specific priorities:

- ETW-backed real-time network visibility.
- Windows service / scheduled-task boot monitoring with fail-open guardrails.
- Windows uninstall-registry software inventory.
- Reversible active-response actions through Windows-native controls.
- Safe startup behavior: Vigil must never be able to repeatedly block the user from logging in.

## Tier 1: Linux

Linux remains a first-class target for detection, response, service mode, packaging, and operator UX.

Current Linux-specific priorities:

- eBPF-backed real-time network visibility where available, with polling fallback.
- systemd service mode with fail-open guardrails.
- Package inventory through dpkg, RPM, and Alpine apk sources.
- Reversible active-response actions through Linux-native controls.
- Clear privilege UX around root and Linux capabilities.

## Deprecated: macOS

macOS is not an active support target right now.

Practical consequences:

- Do not add new macOS-only features.
- Do not spend roadmap effort on macOS parity.
- Do not expand macOS packaging, launchd, DTrace, Endpoint Security, or Network Extension work.
- When touching shared code, avoid making macOS behavior worse accidentally, but do not block Windows/Linux work on macOS parity.
- Existing macOS code can be removed gradually when doing so reduces maintenance burden and does not destabilize Windows/Linux builds.

## Development rule

New functionality should answer two questions before implementation:

1. What is the Windows behavior?
2. What is the Linux behavior?

If one platform cannot support the feature yet, the code and UI should say so explicitly rather than pretending parity exists.

## Startup safety rule

Across supported platforms, Vigil must fail open at OS startup. A Vigil bug, hang, network failure, advisory-cache failure, package-inventory failure, or service-mode error must not repeatedly prevent the machine from reaching a usable login/session state.
