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


def main() -> None:
    root = Path(__file__).resolve().parents[4]
    native_path = Path("crates/keyrack-pkcs11/src/provider/context_wrapping/native.rs")
    engine_path = Path("crates/keyrack-pkcs11/src/provider/context_wrapping.rs")
    originals = {path: (root / path).read_bytes() for path in [native_path, engine_path]}
    with tempfile.TemporaryDirectory(prefix="keyrack-context-control-") as temporary:
        copied = Path(temporary) / "source"
        shutil.copytree(root, copied, ignore=shutil.ignore_patterns(".git", "target", "__pycache__"))
        native = originals[native_path].decode()
        native = replace_once(native, "Attribute::Wrap(matches!(role, Role::Kek)),",
                              "Attribute::Wrap(matches!(role, Role::Kek | Role::Parent)),")
        native = replace_once(native, "Attribute::Unwrap(matches!(role, Role::Kek)),",
                              "Attribute::Unwrap(matches!(role, Role::Kek | Role::Parent)),")
        start = native.index("fn derive(")
        end = native.index("fn unwrapped_policy(", start)
        native = native[:start] + """fn derive(
    _session: &Session, parent: ObjectHandle, _context: &WrappingContext, _label: &str,
) -> Result<ObjectHandle> {
    Ok(parent)
}

""" + native[end:]
        native = replace_once(native, "for key in [child, kek] {", "for key in [child] {")
        native = replace_once(native, "let destroyed = session.destroy_object(kek);",
                              "let destroyed: cryptoki::error::Result<()> = Ok(());")
        engine = replace_once(originals[engine_path].decode(), "native::self_test(provider, &profile)?;",
                              "let _ = provider; // Counterfactual source only: bypass admission.")
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
