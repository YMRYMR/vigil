import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from prepare_release import (
    bump_patch,
    current_version_from_cargo_lock,
    current_version_from_cargo_toml,
    update_cargo_lock,
    update_cargo_toml,
)


class PrepareReleaseTests(unittest.TestCase):
    def test_bump_patch_accepts_stable_semver(self) -> None:
        self.assertEqual(bump_patch("1.3.5"), "1.3.6")

    def test_bump_patch_rejects_prerelease(self) -> None:
        with self.assertRaises(ValueError):
            bump_patch("1.3.5-rc.1")

    def test_update_cargo_toml_updates_package_version_only(self) -> None:
        text = """[package]
name = "vigil"
version = "1.3.5"

[workspace.metadata.dist]
cargo-dist-version = "0.22.1"
"""
        updated, current = update_cargo_toml(text, "1.3.6")
        self.assertEqual(current, "1.3.5")
        self.assertIn('version = "1.3.6"\n', updated)
        self.assertIn('cargo-dist-version = "0.22.1"\n', updated)
        self.assertEqual(current_version_from_cargo_toml(text), "1.3.5")
        self.assertIn('version = "1.3.6"\n\n[workspace.metadata.dist]\n', updated)

    def test_update_cargo_lock_updates_root_package_only(self) -> None:
        text = """version = 4

[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "vigil"
version = "1.3.5"
"""
        updated, current = update_cargo_lock(text, "1.3.6")
        self.assertEqual(current, "1.3.5")
        self.assertIn('name = "serde"\nversion = "1.0.0"\n', updated)
        self.assertIn('name = "vigil"\nversion = "1.3.6"\n', updated)
        self.assertEqual(current_version_from_cargo_lock(text), "1.3.5")

    def test_update_cargo_lock_preserves_windows_line_endings(self) -> None:
        text = (
            'version = 4\r\n\r\n[[package]]\r\nname = "vigil"\r\nversion = "1.3.5"\r\n'
        )
        updated, current = update_cargo_lock(text, "1.3.6")
        self.assertEqual(current, "1.3.5")
        self.assertIn('name = "vigil"\r\nversion = "1.3.6"\r\n', updated)


if __name__ == "__main__":
    unittest.main()
