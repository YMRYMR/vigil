#!/usr/bin/env python3

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from generate_release_notes import build_release_notes, extract_release_bullets


class ReleaseNotesTests(unittest.TestCase):
    def test_extracts_bullets_from_summary_section(self) -> None:
        body = """## Summary
- remove the unnecessary Actions write permission from `auto-release.yml`
- pin the remaining tag-based workflow dependencies to immutable commit SHAs

## Why
This should not be included.
"""
        self.assertEqual(
            extract_release_bullets(body),
            [
                "remove the unnecessary Actions write permission from `auto-release.yml`",
                "pin the remaining tag-based workflow dependencies to immutable commit SHAs",
            ],
        )

    def test_extracts_paragraphs_from_what_changed_section(self) -> None:
        body = """## What changed

This updates the active-response query path used by the inspector so selection does not repeatedly reload the protected state file on every repaint.

It adds a short in-memory cache for read-only query calls and refreshes that cache when the state is written.

## Impact

Selecting an item should no longer drag the whole UI down.
"""
        self.assertEqual(
            extract_release_bullets(body),
            [
                "This updates the active-response query path used by the inspector so selection does not repeatedly reload the protected state file on every repaint.",
                "It adds a short in-memory cache for read-only query calls and refreshes that cache when the state is written.",
            ],
        )

    def test_falls_back_to_title_when_body_has_no_release_summary(self) -> None:
        notes = build_release_notes(
            tag="v1.3.14",
            pr_title="[codex] Fix inspector selection responsiveness",
            pr_body="## Why\nBecause it was needed.\n",
            pr_url="https://github.com/YMRYMR/vigil/pull/118",
            fallback_subject="release subject",
        )
        self.assertIn(
            "- [codex] Fix inspector selection responsiveness",
            notes,
        )
        self.assertIn(
            "- Source PR: https://github.com/YMRYMR/vigil/pull/118",
            notes,
        )


if __name__ == "__main__":
    unittest.main()
