#!/usr/bin/env python3
"""Build focused release notes for a single Vigil release."""

from __future__ import annotations

import argparse
import pathlib
import re


SECTION_PRIORITIES = (
    "what changed",
    "what's changed",
    "summary",
    "changes",
    "included",
    "scope",
    "highlights",
)


def normalize_heading(text: str) -> str:
    normalized = text.strip().lower()
    normalized = normalized.replace("’", "'")
    normalized = re.sub(r"[^\w\s']+", "", normalized)
    return " ".join(normalized.split())


def split_sections(body: str) -> list[tuple[str | None, list[str]]]:
    sections: list[tuple[str | None, list[str]]] = []
    current_heading: str | None = None
    current_lines: list[str] = []

    for line in body.splitlines():
        heading_match = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", line)
        if heading_match:
            if current_lines:
                sections.append((current_heading, current_lines))
            current_heading = heading_match.group(1).strip()
            current_lines = []
            continue
        current_lines.append(line)

    if current_lines:
        sections.append((current_heading, current_lines))

    return sections


def normalize_bullet(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^\s*[-*+]\s+", "", text)
    text = re.sub(r"^\s*\d+\.\s+", "", text)
    return " ".join(part.strip() for part in text.splitlines() if part.strip())


def section_bullets(lines: list[str]) -> list[str]:
    bullets: list[str] = []
    current_list_item: list[str] = []
    paragraph: list[str] = []

    def flush_list_item() -> None:
        nonlocal current_list_item
        if not current_list_item:
            return
        bullet = normalize_bullet("\n".join(current_list_item))
        if bullet:
            bullets.append(bullet)
        current_list_item = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if not paragraph:
            return
        text = " ".join(part.strip() for part in paragraph if part.strip())
        if text:
            bullets.append(text)
        paragraph = []

    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            flush_list_item()
            flush_paragraph()
            continue
        if re.match(r"^\s*[-*+]\s+", line) or re.match(r"^\s*\d+\.\s+", line):
            flush_list_item()
            flush_paragraph()
            current_list_item = [line]
            continue
        if current_list_item:
            current_list_item.append(line)
        else:
            paragraph.append(line)

    flush_list_item()
    flush_paragraph()
    return bullets


def extract_release_bullets(body: str) -> list[str]:
    if not body.strip():
        return []

    sections = split_sections(body)
    prioritized: list[str] = []
    fallback: list[str] = []

    for heading, lines in sections:
        bullets = section_bullets(lines)
        if not bullets:
            continue
        if heading is None:
            fallback.extend(bullets)
            continue
        normalized = normalize_heading(heading)
        if normalized in SECTION_PRIORITIES:
            prioritized.extend(bullets)

    chosen = prioritized or fallback
    deduped: list[str] = []
    seen: set[str] = set()
    for bullet in chosen:
        normalized = " ".join(bullet.split()).lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(bullet)
    return deduped[:6]


def build_release_notes(
    *,
    tag: str,
    pr_title: str,
    pr_body: str,
    pr_url: str,
    fallback_subject: str,
) -> str:
    bullets = extract_release_bullets(pr_body)
    if not bullets:
        title = pr_title.strip() or fallback_subject.strip() or f"Release {tag}"
        bullets = [title]

    lines = ["## What's changed"]
    lines.extend(f"- {bullet}" for bullet in bullets)

    reference_url = pr_url.strip()
    if reference_url:
        lines.extend(
            [
                "",
                "## Reference",
                f"- Source PR: {reference_url}",
            ]
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate release notes from a release PR summary."
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--pr-title", default="")
    parser.add_argument("--pr-body", default="")
    parser.add_argument("--pr-url", default="")
    parser.add_argument("--fallback-subject", default="")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    notes = build_release_notes(
        tag=args.tag,
        pr_title=args.pr_title,
        pr_body=args.pr_body,
        pr_url=args.pr_url,
        fallback_subject=args.fallback_subject,
    )
    args.output.write_text(notes, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
