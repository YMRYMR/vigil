# OpenSSF Best Practices Controls

This document records the repository evidence and maintainer settings used to satisfy the OpenSSF Best Practices / OSPS controls that are not fully visible from source code alone.

## Repository access control

### OSPS-AC-02.01 — collaborator permissions

Vigil is maintained as a personal GitHub repository. New collaborators must be added manually by a repository administrator, and permissions must be assigned intentionally.

Required maintainer setting:

1. Go to **Settings → Collaborators and teams**.
2. Add collaborators only when needed.
3. Assign the lowest permission that can do the work, normally **Read** or **Triage** first.
4. Elevate to **Write**, **Maintain**, or **Admin** only when required.
5. Remove access when it is no longer needed.

Evidence to keep current:

- repository owner/admin review of collaborator list before releases
- no broad default write access for new collaborators

### OSPS-AC-03.01 — no direct commits to primary branch

The primary branch is `master`. Direct pushes to `master` must be blocked through GitHub branch protection or rulesets.

Required GitHub ruleset / branch protection settings for `master`:

- require pull requests before merging
- require at least one approval before merge
- require status checks to pass before merge
- include administrators when possible
- block force pushes
- block direct pushes

Suggested required status checks:

- CI / Format & lint
- CI / Build & test (x86_64-pc-windows-msvc)
- CI / Build & test (aarch64-apple-darwin)
- CI / Build & test (x86_64-unknown-linux-gnu)
- Artifact hygiene / Check for generated executables and large binaries
- Secret scan / Scan for common plaintext secret patterns
- Dependency Review
- CodeQL

### OSPS-AC-03.02 — primary branch deletion is sensitive

GitHub repository rulesets / branch protection must prevent deleting `master` or require explicit administrator action outside ordinary development flow.

Required GitHub ruleset / branch protection settings for `master`:

- block branch deletion
- block force pushes
- restrict bypass permissions to repository administrators only

## Build and release hardening

### OSPS-BR-01.01 / OSPS-BR-01.02 — validate untrusted CI metadata

GitHub Actions metadata such as `github.ref_name`, branch names, tag names, PR titles, and artifact names are untrusted input. Workflows must either avoid using them in shell commands or validate them before use.

Repository controls:

- workflows use pinned third-party actions where practical
- release tag metadata is validated before it is used in shell, filenames, manifests, or release assets
- branch-name use in workflow commands must be sanitized or avoided
- release filenames are built only from a normalized version string produced by the `validate-release-metadata` job

### OSPS-BR-01.03 — untrusted code snapshots cannot access privileged credentials

Pull-request workflows run with read-only repository permissions and must not receive release signing keys or publishing credentials.

Repository controls:

- `pull_request` CI uses `permissions: contents: read`
- release signing and publishing only run on trusted tag pushes in `release.yml`
- release jobs require repository secrets only in the release workflow, not PR validation workflows
- workflows must not use `pull_request_target` for untrusted code checkout or build execution

### OSPS-BR-07.01 — avoid storing secrets in version control

Repository controls:

- `.gitignore` excludes local env files, private keys, signing keys, generated installers, and build artifacts
- CI includes a secret-pattern scan for common plaintext credential formats
- release signing keys live in GitHub Actions secrets, never in the repository

## Documentation and repository inventory

### OSPS-DO-01.01 — user guides for released functionality

The README and `docs/USER-GUIDE.md` document basic functionality for released builds: install, launch, Settings, Activity, Alerts, Inspector, Help, active response, logs, service mode, and uninstall.

### OSPS-QA-02.01 — dependency list

Rust direct dependencies are declared in `Cargo.toml`. Exact resolved dependencies are tracked in `Cargo.lock` for reproducible application builds. `docs/DEPENDENCIES.md` summarizes the direct dependency inventory for human review.

### OSPS-QA-04.01 — codebase inventory

Vigil currently has a single code repository:

| Codebase | Purpose |
|---|---|
| `github.com/YMRYMR/vigil` | Vigil desktop agent, UI, installers, CI, and release automation |

If additional repositories are added, list them here and in the README.

### OSPS-QA-05.01 / OSPS-QA-05.02 — no generated executables or unreviewable binaries

Repository policy:

- do not commit generated installers, release archives, compiled executables, DMGs, AppImages, object files, or build output
- avoid unreviewable binary blobs unless they are small source assets required for the UI and documented
- generated release artifacts must be produced by CI and attached to GitHub Releases, not committed to the repository

The `artifact-hygiene` CI workflow checks for common generated executable artifacts and large binary blobs.

## Vulnerability management

### OSPS-VM-02.01 — security contact

Security contacts and private reporting instructions are documented in `SECURITY.md`.
