# Vigil resilience lab tests

This directory is reserved for harmless local simulator scripts used by the Vigil
resilience lab.

Read [`docs/ADVERSARIAL-LAB.md`](../../docs/ADVERSARIAL-LAB.md) before adding or
running anything here.

## Rules for scripts

Scripts in this directory must:

- run only against local VM or host-only-network targets;
- avoid dangerous samples, credential access, persistence, and destructive actions;
- be clearly labeled as benign simulators;
- have bounded runtime and resource usage by default;
- print what they are doing;
- include cleanup instructions when they create files, listeners, or background
  processes;
- document expected Vigil observations and acceptable limitations.

## Suggested future layout

```text
scripts/
  connection_churn.py
  benign_beacon_sim.py
  process_tree_sim.py
  file_tamper_sim.py
  resource_stress.py
expected-results/
  linux-baseline.md
  windows-baseline.md
```
