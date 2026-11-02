"""Ensure the isolated negative control reuses the caller's Cargo cache."""

from pathlib import Path
import unittest

from context_binding_control import child_environment, counterfactual_sources


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

    def test_warning_policy_is_preserved_with_mutation_local_allowances(self):
        inherited = {"RUSTFLAGS": "-D warnings", "CARGO_ENCODED_RUSTFLAGS": "-D\x1fwarnings"}
        child = child_environment(Path("/workspace/source"), inherited)
        for name, value in inherited.items():
            self.assertEqual(child[name], value)
        root = Path(__file__).resolve().parents[4]
        native_path = root / "crates/keyrack-pkcs11/src/provider/context_wrapping/native.rs"
        engine_path = root / "crates/keyrack-pkcs11/src/provider/context_wrapping.rs"
        native, engine = native_path.read_text(), engine_path.read_text()
        changed_native, changed_engine = counterfactual_sources(native, engine)
        self.assertEqual(native_path.read_text(), native)
        self.assertEqual(engine_path.read_text(), engine)
        self.assertEqual(changed_native.count("#[allow(dead_code)]") - native.count("#[allow(dead_code)]"), 5)
        self.assertEqual(changed_native.count("#[allow(unused_imports)]") - native.count("#[allow(unused_imports)]"), 1)
        self.assertEqual(changed_engine.count("#[allow(dead_code)]") - engine.count("#[allow(dead_code)]"), 1)
        self.assertNotIn("#![allow", changed_native)
        self.assertNotIn("#![allow", changed_engine)
        self.assertIn("    #[allow(dead_code)]\n    Kek,", changed_native)
        self.assertNotIn("native::self_test(provider, &profile)?;", changed_engine)
        derive = changed_native.split("fn derive(", 1)[1].split("fn unwrapped_policy(", 1)[0]
        self.assertIn("Ok(parent)", derive)
        self.assertNotIn("derive_key", derive)


if __name__ == "__main__":
    unittest.main()
