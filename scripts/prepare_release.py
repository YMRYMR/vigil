#!/usr/bin/env python3
"""Prepare the next Vigil release version.

This helper keeps the app version embedded in the binaries aligned with the
GitHub release tag that the existing release workflow publishes.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def bump_patch(version: str) -> str:
    match = SEMVER_RE.fullmatch(version.strip())
    if not match:
        raise ValueError(
            f"expected a stable MAJOR.MINOR.PATCH version, got {version!r}"
        )
    major, minor, patch = (int(part) for part in match.groups())
    return f"{major}.{minor}.{patch + 1}"


def current_version_from_cargo_toml(text: str) -> str:
    lines = text.splitlines(keepends=True)
    in_package = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
            continue
        if not in_package:
            continue
        if not stripped.startswith("version"):
            continue
        match = re.match(r'(\s*version\s*=\s*")([^"]+)(".*)', line)
        if not match:
            raise ValueError("found package version line in Cargo.toml but could not parse it")
        return match.group(2)

    raise ValueError("could not find [package] version in Cargo.toml")


def current_version_from_cargo_lock(text: str) -> str:
    lines = text.splitlines(keepends=True)
    in_package = False
    package_name = None

    for line in lines:
        stripped = line.strip()
        if stripped == "[[package]]":
            in_package = True
            package_name = None
            continue
        if stripped.startswith("[") and stripped != "[[package]]":
            in_package = False
            package_name = None
            continue
        if not in_package:
            continue
        if stripped.startswith('name = "'):
            match = re.match(r'\s*name\s*=\s*"([^"]+)"', line)
            if match:
                package_name = match.group(1)
            continue
        if package_name != "vigil" or not stripped.startswith("version"):
            continue
        match = re.match(r'(\s*version\s*=\s*")([^"]+)(".*)', line)
        if not match:
            raise ValueError("found vigil package version line in Cargo.lock but could not parse it")
        return match.group(2)

    raise ValueError('could not find package "vigil" version in Cargo.lock')


def update_cargo_toml(text: str, next_version: str) -> tuple[str, str]:
    lines = text.splitlines(keepends=True)
    in_package = False

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
            continue
        if not in_package:
            continue
        if not stripped.startswith("version"):
            continue
        match = re.match(r'(\s*version\s*=\s*")([^"]+)(".*)', line)
        if not match:
            raise ValueError("found package version line in Cargo.toml but could not parse it")
        current_version = match.group(2)
        lines[idx] = f"{match.group(1)}{next_version}{match.group(3)}"
        return "".join(lines), current_version

    raise ValueError("could not find [package] version in Cargo.toml")


def update_cargo_lock(text: str, next_version: str) -> tuple[str, str]:
    lines = text.splitlines(keepends=True)
    in_package = False
    package_name = None

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[[package]]":
            in_package = True
            package_name = None
            continue
        if stripped.startswith("[") and stripped != "[[package]]":
            in_package = False
            package_name = None
            continue
        if not in_package:
            continue
        if stripped.startswith('name = "'):
            match = re.match(r'\s*name\s*=\s*"([^"]+)"', line)
            if match:
                package_name = match.group(1)
            continue
        if package_name != "vigil" or not stripped.startswith("version"):
            continue
        match = re.match(r'(\s*version\s*=\s*")([^"]+)(".*)', line)
        if not match:
            raise ValueError("found vigil package version line in Cargo.lock but could not parse it")
        current_version = match.group(2)
        lines[idx] = f"{match.group(1)}{next_version}{match.group(3)}"
        return "".join(lines), current_version

    raise ValueError('could not find package "vigil" version in Cargo.lock')


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bump Vigil's stable patch version in Cargo.toml and Cargo.lock."
    )
    parser.add_argument("--cargo-toml", required=True, type=pathlib.Path)
    parser.add_argument("--cargo-lock", required=True, type=pathlib.Path)
    parser.add_argument(
        "--print-current",
        action="store_true",
        help="Validate the current version and print it without modifying files.",
    )
    parser.add_argument(
        "--next-version",
        help="Explicit version to write. Defaults to the next stable patch version.",
    )
    parser.add_argument(
        "--github-output",
        type=pathlib.Path,
        help="Optional path to the GitHub Actions output file.",
    )
    args = parser.parse_args()

    cargo_toml_text = args.cargo_toml.read_text(encoding="utf-8")
    cargo_lock_text = args.cargo_lock.read_text(encoding="utf-8")

    current_toml_version = current_version_from_cargo_toml(cargo_toml_text)
    current_lock_version = current_version_from_cargo_lock(cargo_lock_text)
    if current_toml_version != current_lock_version:
        raise ValueError(
            "Cargo.toml and Cargo.lock disagree on the current Vigil version "
            f"({current_toml_version} vs {current_lock_version})"
        )

    if args.print_current:
        print(f"current_version={current_toml_version}")
        if args.github_output is not None:
            with args.github_output.open("a", encoding="utf-8") as handle:
                handle.write(f"current_version={current_toml_version}\n")
        return 0

    next_version = args.next_version or bump_patch(current_toml_version)

    updated_toml, toml_version = update_cargo_toml(cargo_toml_text, next_version)
    updated_lock, lock_version = update_cargo_lock(cargo_lock_text, next_version)

    if toml_version != lock_version:
        raise ValueError(
            "Cargo.toml and Cargo.lock disagree on the current Vigil version "
            f"({toml_version} vs {lock_version})"
        )

    args.cargo_toml.write_text(updated_toml, encoding="utf-8")
    args.cargo_lock.write_text(updated_lock, encoding="utf-8")

    print(f"current_version={current_toml_version}")
    print(f"next_version={next_version}")
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"current_version={current_toml_version}\n")
            handle.write(f"next_version={next_version}\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
