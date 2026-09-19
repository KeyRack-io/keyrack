#!/usr/bin/env python3
"""Revert each A2 wrapping check on its own and record the failure it owes.

A check that no test can make fail is not proven, and a gate that still passes
with the gate removed is not a gate. Each control edits exactly one guard,
verifies the edit actually changed the file (so a stale pattern cannot pass as
a proof), runs the test that is supposed to notice, and reverts.

Usage: python3 scripts/a2-wrapping-controls.py [--filter SUBSTRING]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = "crates/keyrack-core/src/provider/software.rs"
DRIVER = "crates/keyrack-core/src/creation_driver.rs"
CORE_TEST = ("keyrack-core", "software_wrapping")
SQLITE_TEST = ("keyrack-sqlite", "software_wrapping_creation")


@dataclass
class Control:
    name: str
    guard: str
    file: str
    before: str
    after: str
    suite: tuple[str, str]
    test: str
    # Further edits reverted together with the first. A layered check is only
    # provable by removing every layer that covers the same fact.
    also: tuple[tuple[str, str, str], ...] = ()
    # "fails": the watched test must fail with this check gone.
    # "layered": it must still pass, because a deeper check owns the outcome.
    # Recording the second honestly is the point; a control that cannot fail
    # is not evidence of a guard, and pretending otherwise is how eight green
    # controls come to imply eight independent guards.
    expect: str = "fails"

    def edits(self) -> tuple[tuple[str, str, str], ...]:
        return ((self.file, self.before, self.after),) + self.also


CONTROLS = [
    Control(
        name="provider-capability-gate",
        guard="the provider refuses a tuple it does not declare",
        file=CORE,
        before="""        self.wrapping_capabilities()
            .require(&WrappingCapability::requested(
                context,
                operation,
                WrappedKeyLifecycle::SessionObject,
            ))
            .map_err(|e| KeyRackError::Provider(format!("software wrapping refused: {e}")))?;""",
        after="""        let _ = operation;""",
        suite=CORE_TEST,
        test="an_undeclared_tuple_is_refused_for_every_operation",
    ),
    Control(
        name="context-as-aad",
        guard="the canonical context authenticates the wrapping",
        file=CORE,
        before="""        context
            .canonical_bytes()
            .map_err(|e| KeyRackError::Provider(format!("software wrapping refused: {e}")))
    }""",
        after="""        Ok(Vec::new())
    }""",
        suite=CORE_TEST,
        test="the_authenticated_context_refuses_every_other_binding",
    ),
    Control(
        name="provider-scope",
        guard="a scoped provider refuses a context naming another backend",
        file=CORE,
        before="""            if scope.provider_ref != context.provider_ref
                || scope.security_domain != context.security_domain
            {""",
        after="""            if false {""",
        suite=CORE_TEST,
        test="a_scoped_provider_refuses_a_context_naming_another_backend",
    ),
    Control(
        name="parent-handle-spec",
        guard="the parent handle must be the spec the context binds",
        file=CORE,
        before="""        if parent.key_spec != context.parent_spec {""",
        after="""        if false {""",
        suite=CORE_TEST,
        test="a_parent_handle_that_is_not_the_bound_spec_is_refused",
    ),
    Control(
        name="envelope-length",
        guard="an envelope of the wrong length is refused, not parsed",
        file=CORE,
        before="""        if envelope.len() != SOFTWARE_ENVELOPE_BYTES {""",
        after="""        if false {""",
        suite=CORE_TEST,
        test="the_authenticated_context_refuses_every_other_binding",
    ),
    Control(
        name="close-binds-open-object",
        guard="closing an open object requires the lease to describe it",
        file=CORE,
        before="""                if open.context_sha256 != lease.context_sha256() {""",
        after="""                if false {""",
        suite=CORE_TEST,
        test="closing_under_another_context_is_refused_and_destroys_nothing",
    ),
    Control(
        name="close-binds-closed-object",
        guard="a repeated close requires the lease to describe the closed object",
        file=CORE,
        before="""                if recorded.context_sha256 != lease.context_sha256() {""",
        after="""                if false {""",
        suite=CORE_TEST,
        test="closing_under_another_context_is_refused_and_destroys_nothing",
    ),
    Control(
        name="verifier-incarnation",
        guard="closure evidence is limited to objects this incarnation issued",
        file=CORE,
        before="""        if !object.starts_with(&format!("kr-sw-a2-{}-", self.incarnation)) {""",
        after="""        if false {""",
        suite=SQLITE_TEST,
        test="closure_evidence_is_refused_for_anything_but_this_creation_object",
    ),
    Control(
        name="verifier-origin",
        guard="closing an opened object is not evidence about a creation object",
        file=CORE,
        before="""        if binding.origin != ObjectOrigin::Generated {""",
        after="""        if false {""",
        suite=SQLITE_TEST,
        test="closure_evidence_is_refused_for_anything_but_this_creation_object",
    ),
    Control(
        name="verifier-envelope-digest",
        guard="closure evidence must bind the staged envelope",
        file=CORE,
        before="""        if binding.envelope_blake3 != claim.envelope_digest {""",
        after="""        if false {""",
        suite=SQLITE_TEST,
        test="closure_evidence_is_refused_for_anything_but_this_creation_object",
    ),
    Control(
        name="verifier-creation-context",
        guard="closure evidence must bind the creation context",
        file=CORE,
        before="""        if binding.context_sha256 != expected {""",
        after="""        if false {""",
        suite=SQLITE_TEST,
        test="closure_evidence_is_refused_for_anything_but_this_creation_object",
    ),
    Control(
        name="preflight-requires-open",
        guard="a child that could not be opened again is never created",
        file=DRIVER,
        before="""        for operation in [
            WrappingOperation::Generate,
            WrappingOperation::Open,
            WrappingOperation::Close,
        ] {""",
        after="""        for operation in [WrappingOperation::Generate, WrappingOperation::Close] {""",
        suite=SQLITE_TEST,
        test="a_child_that_could_not_be_opened_again_is_never_created",
    ),
    Control(
        name="adapter-lease-binding",
        guard="a lease must bind the creation context it was generated for",
        file=DRIVER,
        before="""        let bound = generated.lease.context_sha256()
            == context
                .context_sha256()
                .map_err(|_| invalid("invalid creation context"))?;""",
        after="""        let bound = true;""",
        suite=SQLITE_TEST,
        test="a_lease_bound_to_another_context_never_reaches_publication",
    ),
    Control(
        name="adapter-closure-binding",
        guard="a closure must bind the context of the object it closed",
        file=DRIVER,
        before="""        if closure.context_sha256 != lease.context_sha256() {""",
        after="""        if false {""",
        suite=SQLITE_TEST,
        test="a_closure_reported_under_another_context_never_reaches_publication",
    ),
    # The five below are the A2 review's two defects. Each watches the exact
    # regression from that review, so what fails when a binding is removed is
    # the reviewer's test rather than one of ours agreeing with itself.
    Control(
        name="adapter-reserves-owner-before-generate",
        guard="the owner of a cleanup exists before there is anything to clean up",
        file=DRIVER,
        before="""        self.reserve(&binding)?;""",
        after="""""",
        suite=SQLITE_TEST,
        test="review_one_attempt_adapter_must_not_replace_cleanup_owner",
    ),
    Control(
        name="adapter-retains-unusable-lease",
        guard="a lease for the wrong context is kept, because it is the only way to close that object",
        file=DRIVER,
        before="""        self.retain(&binding, generated.lease, &generated.envelope)?;
        if !bound {
            return Err(invalid("provider lease does not bind the creation context"));
        }""",
        after="""        if !bound {
            return Err(invalid("provider lease does not bind the creation context"));
        }
        self.retain(&binding, generated.lease, &generated.envelope)?;""",
        suite=SQLITE_TEST,
        test="a_generation_that_answers_badly_keeps_its_cleanup_ownership",
    ),
    Control(
        name="provider-records-creation",
        guard="the provider keeps the creation its object was generated for",
        file=CORE,
        before="""            Some(creation.clone()),""",
        after="""            None,""",
        suite=SQLITE_TEST,
        test="a_journaled_creation_publishes_a_wrapped_child_that_still_opens",
    ),
    Control(
        name="verifier-creation-binding",
        guard="a closure is evidence for the creation it came from and no other",
        file=CORE,
        before="""        binding
            .creation
            .as_ref()
            .ok_or(invalid("closure names an object with no creation binding"))?
            .require(request)?;""",
        after="""""",
        suite=SQLITE_TEST,
        test="closure_evidence_is_refused_for_anything_but_this_creation_object",
    ),
    Control(
        name="adapter-closure-owner",
        guard="the adapter refuses to close for a creation other than the one it holds",
        file=DRIVER,
        before="""                Some(held) if held.binding() != &binding => {""",
        after="""                Some(held) if held.binding() != &binding && false => {""",
        suite=SQLITE_TEST,
        test="review_creation_closure_must_not_rebind_owner",
        expect="layered",
    ),
    Control(
        name="adapter-and-provider-closure-owner",
        guard="both layers of the same fact, removed together",
        file=DRIVER,
        before="""                Some(held) if held.binding() != &binding => {""",
        after="""                Some(held) if held.binding() != &binding && false => {""",
        also=(
            (
                CORE,
                """        binding
            .creation
            .as_ref()
            .ok_or(invalid("closure names an object with no creation binding"))?
            .require(request)?;""",
                """""",
            ),
        ),
        suite=SQLITE_TEST,
        test="review_creation_closure_must_not_rebind_owner",
    ),
    Control(
        name="adapter-claim-fingerprint",
        guard="the claim carries the fingerprint reserved before the effect",
        file=DRIVER,
        before="""            intent_fingerprint: binding.fingerprint(),""",
        after="""            intent_fingerprint: request.fingerprint()?,""",
        suite=SQLITE_TEST,
        test="review_creation_closure_must_not_rebind_operation_and_attempt",
        expect="layered",
    ),
    Control(
        name="adapter-requires-verifier",
        guard="a provider that cannot evidence closure cannot be installed",
        file=DRIVER,
        before="""        let verifier = provider
            .wrapping_closure_verifier()
            .ok_or(invalid("provider cannot evidence wrapped-key closure"))?;""",
        after="""        let verifier: Arc<dyn A2ClosureVerifier> = provider
            .wrapping_closure_verifier()
            .unwrap_or_else(|| Arc::new(AcceptAll));""",
        suite=SQLITE_TEST,
        test="a_provider_that_cannot_evidence_closure_cannot_be_installed",
    ),
]

# The accept-all verifier the design refuses to ship. It exists only inside the
# control that removes the requirement, to show what that requirement prevents.
ACCEPT_ALL = """
struct AcceptAll;
impl A2ClosureVerifier for AcceptAll {
    fn verify(&self, _: &CreationRequest, _: &A2ClosureClaim) -> Result<()> {
        Ok(())
    }
}
"""


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True)


def revert(paths: set[str]) -> None:
    run(["git", "checkout", "--"] + sorted(paths))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--filter", default="")
    args = parser.parse_args()

    dirty = run(["git", "status", "--porcelain", CORE, DRIVER]).stdout.strip()
    if dirty:
        print(f"refusing to run with uncommitted changes to the files under control:\n{dirty}")
        return 2

    results = []
    for control in CONTROLS:
        if args.filter and args.filter not in control.name:
            continue
        edits = control.edits()
        missing = [
            file
            for file, before, _ in edits
            if before not in (ROOT / file).read_text()
        ]
        if missing:
            print(f"[{control.name}] PATTERN NOT FOUND in {missing} — control cannot run")
            results.append((control, "pattern-not-found", ""))
            continue
        for file, before, after in edits:
            path = ROOT / file
            patched = path.read_text().replace(before, after, 1)
            if control.name == "adapter-requires-verifier":
                patched += ACCEPT_ALL
            path.write_text(patched)
        package, suite = control.suite
        outcome = run(
            [
                "cargo", "test", "-p", package, "--test", suite,
                "--target-dir", "./target", control.test, "--", "--exact",
            ]
        )
        revert({file for file, _, _ in edits})
        stdout = outcome.stdout
        passed = outcome.returncode == 0 and "1 passed" in stdout
        failed = "FAILED" in stdout or outcome.returncode != 0
        if control.expect == "layered":
            if passed:
                verdict = "still passes as expected — a deeper check owns the outcome"
            elif failed:
                verdict = "FAILS — it owns the outcome after all; reclassify it"
            else:
                verdict = "inconclusive"
        elif passed:
            verdict = "STILL PASSES — check is unproven"
        elif failed:
            verdict = "fails as expected"
        else:
            verdict = "inconclusive"
        detail = ""
        for line in stdout.splitlines():
            if "panicked at" in line or line.startswith("thread "):
                detail = line.strip()
                break
        if not detail:
            for line in outcome.stderr.splitlines():
                if line.startswith("error"):
                    detail = line.strip()
                    break
        results.append((control, verdict, detail))
        print(f"[{control.name}] {verdict}")
        if detail:
            print(f"    {detail}")

    print("\n=== controls ===")
    unproven = 0
    for control, verdict, detail in results:
        if not verdict.startswith(("fails as expected", "still passes as expected")):
            unproven += 1
        print(f"{control.name}: {verdict}")
        print(f"    guard: {control.guard}")
        print(f"    watched: {control.suite[0]}::{control.test}")
        if detail:
            print(f"    observed: {detail}")
    return 1 if unproven else 0


if __name__ == "__main__":
    sys.exit(main())
