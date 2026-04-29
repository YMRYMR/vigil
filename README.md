# Vigil

[![CI](https://github.com/YMRYMR/vigil/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/YMRYMR/vigil/actions/workflows/ci.yml)
[![CodeQL](https://github.com/YMRYMR/vigil/actions/workflows/codeql.yml/badge.svg?branch=master&event=push)](https://github.com/YMRYMR/vigil/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/YMRYMR/vigil/badge)](https://securityscorecards.dev/viewer/?uri=github.com/YMRYMR/vigil)
[![Snyk](https://github.com/YMRYMR/vigil/actions/workflows/snyk-open-source.yml/badge.svg?branch=master&event=push)](https://github.com/YMRYMR/vigil/actions/workflows/snyk-open-source.yml)
[![Dependency Review](https://github.com/YMRYMR/vigil/actions/workflows/dependency-review.yml/badge.svg?event=pull_request)](https://github.com/YMRYMR/vigil/actions/workflows/dependency-review.yml)
[![Artifact hygiene](https://github.com/YMRYMR/vigil/actions/workflows/artifact-hygiene.yml/badge.svg?branch=master)](https://github.com/YMRYMR/vigil/actions/workflows/artifact-hygiene.yml)
[![Secret scan](https://github.com/YMRYMR/vigil/actions/workflows/secret-scan.yml/badge.svg?branch=master)](https://github.com/YMRYMR/vigil/actions/workflows/secret-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/YMRYMR/vigil?label=release)](https://github.com/YMRYMR/vigil/releases/latest)

Cross-platform endpoint defense for Windows, macOS, and Linux.

Vigil watches live network and process activity on your machine, scores suspicious
behaviour, shows you the process and connection context behind each alert, and
can take reversible containment actions when something needs to be stopped.

It is designed for local machine protection first: detect suspicious outbound
activity quickly, help the operator understand what is happening, preserve
evidence when needed, and contain the machine or process without turning every
high-noise event into a destructive action.

![Vigil current UI](docs/images/vigil-current.png)

---

## Documentation

- [User guide](docs/USER-GUIDE.md) — released functionality, operator workflows, and day-to-day use
- [Security policy](SECURITY.md) — vulnerability reporting and security contacts
- [OpenSSF Best Practices controls](docs/OPENSSF-BEST-PRACTICES.md) — repository controls and maintainer settings
- [Codebase inventory](docs/CODEBASES.md) — repositories that are part of Vigil

---

## Download the latest build

- [Windows installer](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-windows-x86_64.exe)
- [macOS DMG](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-macos-aarch64.dmg)
- [Linux AppImage](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-linux-x86_64.AppImage)
- [All supported OSs bundle](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-all-supported-os.zip)
- [Signed update manifest](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-update-manifest.json)
- [Manifest signature](https://github.com/YMRYMR/vigil/releases/latest/download/Vigil-latest-update-manifest.json.sig)
- GHCR Linux package image: `ghcr.io/YMRYMR/vigil`

The latest-release links above are refreshed by the release pipeline after a
merged `master` change finishes CI and the tag-driven publishing workflow
completes.

The GHCR image tracks the latest released Linux AppImage as a container package
so it is easy to mirror, automate, or consume in CI environments:

```bash
docker pull ghcr.io/YMRYMR/vigil:latest
```

Each release asset is published with a GitHub artifact attestation. Verify a
downloaded file with:

```bash
gh attestation verify PATH/TO/FILE -R YMRYMR/vigil
```

The release workflow also emits SLSA3 provenance for the published assets via
the GitHub Actions SLSA generator. That provenance is attached to the release
for users who prefer `slsa-verifier`-style supply-chain checks.

Merged pull requests to `master` now cut the next patch release automatically
after the `CI` workflow succeeds. That automated version bump creates the tag
that feeds the existing signed release pipeline, so `releases/latest` and the
signed update manifest stay in sync with merged code.

The signed update manifest is the trust anchor for Vigil's update channel. It
lists the release assets and their SHA-256 digests, then gets signed with an
embedded Ed25519 public key in the app. You can verify it offline with:

```bash
vigil --verify-update-manifest Vigil-latest-update-manifest.json Vigil-latest-update-manifest.json.sig
```

Vigil's offline advisory importer also accepts one or more local NVD CVE JSON
files in a single run, which is useful when the export is split into pages or
incremental batches:

```bash
vigil --import-nvd-snapshot nvdcve-page-1.json nvdcve-page-2.json
```

Vigil can also pull the live NVD CVE API directly into the same protected
cache. The sync path uses incremental `lastModStartDate` / `lastModEndDate`
windows after the first fetch, respects the NVD's 2-hour automated polling
guidance, and keeps the last trusted cache if refresh fails:
