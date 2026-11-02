"""Ensure the isolated negative control reuses the caller's Cargo cache."""

from pathlib import Path
import unittest

from context_binding_control import child_environment


class CargoTargetEnvironment(unittest.TestCase):
    def test_unset_uses_original_workspace_target(self):
        self.assertEqual(child_environment(Path("/workspace/source"), {})["CARGO_TARGET_DIR"],
                         "/workspace/source/target")

    def test_relative_override_is_resolved_before_changing_directory(self):
        inherited = {"CARGO_TARGET_DIR": "../cache", "CARGO_BUILD_JOBS": "2"}
        child = child_environment(Path("/workspace/source"), inherited)
        self.assertEqual(child["CARGO_TARGET_DIR"], "/workspace/cache")
        self.assertEqual(child["CARGO_BUILD_JOBS"], "2")
        self.assertEqual(inherited["CARGO_TARGET_DIR"], "../cache")

    def test_absolute_override_is_preserved(self):
        self.assertEqual(child_environment(Path("/workspace/source"),
                         {"CARGO_TARGET_DIR": "/cache/native"})["CARGO_TARGET_DIR"], "/cache/native")


if __name__ == "__main__":
    unittest.main()
