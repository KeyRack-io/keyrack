#!/usr/bin/env python3
# Copyright 2026 KeyRack Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Test gate selection only; these tests are not OS-isolation evidence."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("worker_fixture", Path(__file__).with_name("prepare-worker-vault-fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FixtureGate(unittest.TestCase):
    def test_required_refuses_every_unsupported_platform(self):
        for platform in ["darwin", "win32", "", "Linux"]:
            with self.subTest(platform=platform), self.assertRaises(RuntimeError):
                fixture.isolation_requested("required", platform)

    def test_required_linux_cannot_skip(self):
        self.assertTrue(fixture.isolation_requested("required", "linux"))

    def test_optional_and_disabled_are_explicit(self):
        self.assertFalse(fixture.isolation_requested("off", "linux"))
        self.assertFalse(fixture.isolation_requested("auto", "darwin"))
        self.assertTrue(fixture.isolation_requested("auto", "linux"))

    def test_invalid_mode_fails_closed(self):
        for mode in ["", "false", "skip", "REQUIRED"]:
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                fixture.isolation_requested(mode, "linux")


if __name__ == "__main__":
    unittest.main()
