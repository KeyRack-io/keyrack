#!/usr/bin/env python3
"""Prove the service swap assertion fails for direct-parent AES-KW.

Only an isolated source copy is changed. The counterfactual must bypass startup
qualification and provision wrap/unwrap-capable parents, or it would fail before
the headline assertion and prove nothing about that assertion. No runtime
configuration or production fallback enables this construction.
"""

import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise RuntimeError(f"counterfactual anchor must occur exactly once: {old!r}")
    return source.replace(old, new, 1)


def child_environment(root: Path, inherited: dict[str, str]) -> dict[str, str]:
    environment = dict(inherited)
    target = Path(environment.get("CARGO_TARGET_DIR") or "target")
    # A copied working directory must still reuse the original dependency cache.
    if not target.is_absolute():
        target = (root / target).resolve()
    environment["CARGO_TARGET_DIR"] = str(target)
    return environment


def counterfactual_sources(native: str, engine: str) -> tuple[str, str]:
    native = replace_once(native, "Attribute::Wrap(matches!(role, Role::Kek)),",
                          "Attribute::Wrap(matches!(role, Role::Kek | Role::Parent)),")
    native = replace_once(native, "Attribute::Unwrap(matches!(role, Role::Kek)),",
                          "Attribute::Unwrap(matches!(role, Role::Kek | Role::Parent)),")
    derive_start = "    fn derive(\n"
    derive_end = "    pub(super) fn new(provider: &Pkcs11Provider) -> Result<Self> {"
    if native.count(derive_start) != 1 or native.count(derive_end) != 1:
        raise RuntimeError("counterfactual requires exactly one owned derivation method")
    start = native.index(derive_start)
    end = native.index(derive_end, start)
    native = native[:start] + """    fn derive(
        &self, parent: ObjectHandle, _context: &WrappingContext, _label: &str,
    ) -> Result<ObjectHandle> {
        Ok(parent)
    }

""" + native[end:]
    # Derivation now returns the resident parent, not a temporary session KEK.
    # Preserve explicit cleanup of temporary children but never destroy this
    # borrowed parent in the isolated counterfactual. Both open and the
    # generation/rewrap cleanup scopes use this same destruction helper.
    native = replace_once(native, "        for key in keys {", """        for key in keys {
            if session
                .get_attributes(*key, &[AttributeType::Token])
                .map_err(|e| map_pkcs11_error("counterfactual resident readback", &e))?
                == [Attribute::Token(true)]
            {
                continue; // Counterfactual source only: borrowed resident parent.
            }""")
    engine = replace_once(engine, "native::self_test(provider, &profile)?;",
                          "let _ = provider; // Counterfactual source only: bypass admission.")
    # Removing derivation and startup admission makes these exact items unused.
    # Keep CI's -D warnings intact; allow only mutation-induced warnings in the
    # isolated copy, never in production source or global compiler flags.
    for anchor, lint in [
        ("use cryptoki::mechanism::ekdf::AesCbcDeriveParams;", "unused_imports"),
        ("    Kek,", "dead_code"),
        ("fn context_digest(", "dead_code"),
        ("    fn known_answer(", "dead_code"),
        ("pub(super) fn self_test(", "dead_code"),
        ("fn self_test_observed(", "dead_code"),
    ]:
        indent = anchor[:len(anchor) - len(anchor.lstrip())]
        native = replace_once(native, anchor, f"{indent}#[allow({lint})]\n" + anchor)
    engine = replace_once(engine, "    fn self_test_context(",
                          "    #[allow(dead_code)]\n    fn self_test_context(")
    return native, engine


def main() -> None:
    root = Path(__file__).resolve().parents[4]
    native_path = Path("crates/keyrack-pkcs11/src/provider/context_wrapping/native.rs")
    engine_path = Path("crates/keyrack-pkcs11/src/provider/context_wrapping.rs")
    originals = {path: (root / path).read_bytes() for path in [native_path, engine_path]}
    with tempfile.TemporaryDirectory(prefix="keyrack-context-control-") as temporary:
        copied = Path(temporary) / "source"
        shutil.copytree(root, copied, ignore=shutil.ignore_patterns(".git", "target", "__pycache__"))
        native, engine = counterfactual_sources(originals[native_path].decode(),
                                               originals[engine_path].decode())
        (copied / native_path).write_text(native)
        (copied / engine_path).write_text(engine)
        command = ["cargo", "test", "--locked", "-p", "keyrack-service", "--test", "softhsm_wrapped_service",
                   "native_wrapped_grpc_rest_roundtrip_and_envelope_swap_refusal", "--", "--ignored", "--exact",
                   "--nocapture", "--test-threads=1"]
        process = subprocess.Popen(command, cwd=copied, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, start_new_session=True, env=child_environment(root, os.environ))
        try:
            output, _ = process.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
            print(output, end="")
            raise RuntimeError("counterfactual exceeded 180 seconds; no control evidence") from None
        print(output, end="")
        if process.returncode != 101 or "swapped child must not open: " not in output or "1 failed" not in output:
            raise RuntimeError("direct-parent control did not reach the exact service swap assertion")
        for path, original in originals.items():
            if (root / path).read_bytes() != original:
                raise RuntimeError(f"original source changed during isolated control: {path}")
        print("CONTEXT_BINDING_CONTROL_PASS direct_parent_kw=true exact_service_swap_assertion_failed=true "
              "production_source_unchanged=true "
              f"native_input_sha256={hashlib.sha256(originals[native_path]).hexdigest()}")


if __name__ == "__main__":
    main()
