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
SERVICE = "crates/keyrack-service/src/hierarchy.rs"
CORE_TEST = ("keyrack-core", "software_wrapping")
SQLITE_TEST = ("keyrack-sqlite", "software_wrapping_creation")
SERVICE_TEST = ("keyrack-service", "wrapped_child_creation")


@dataclass
class Control:
    name: str
    guard: str
    file: str
    before: str
    after: str
    suite: tuple[str, str]
    test: str


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
        before="""        if generated.lease.context_sha256()
            != context
                .context_sha256()
                .map_err(|_| invalid("invalid creation context"))?
        {""",
        after="""        if false {""",
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
    # ── the service half: what CreateKey with a parent refuses ──
    #
    # Several of these sit in front of an invariant the creation journal
    # rechecks inside its own transaction. Removing one can therefore leave the
    # outcome refused while changing what the caller is told; the run prints the
    # observed failure so the two cases stay distinguishable.
    Control(
        name="service-profile-required",
        guard="a provider with no configured wrapping profile cannot wrap",
        file=SERVICE,
        before="""    let profile = state.wrapping.require(provider_name)?;""",
        after="""    let profile: &WrappingProfile = Box::leak(Box::new(WrappingProfile {
        mechanism: WrappingIdentifier::new("software:aes-256-gcm:v1").unwrap(),
        security_domain: WrappingIdentifier::new("test-single-process").unwrap(),
    }));""",
        suite=SERVICE_TEST,
        test="a_provider_without_a_configured_profile_refuses_child_creation",
    ),
    Control(
        name="service-same-domain",
        guard="parent and child must be in one security domain",
        file=SERVICE,
        before="""    if child != parent {""",
        after="""    if false {""",
        suite=SERVICE_TEST,
        test="a_child_must_be_in_the_same_security_domain_as_its_parent",
    ),
    Control(
        name="service-child-spec",
        guard="only a symmetric encryption key can be a wrapped child",
        file=SERVICE,
        before="""    if !matches!(record.key_spec, KeySpec::Aes128 | KeySpec::Aes256) {""",
        after="""    if false {""",
        suite=SERVICE_TEST,
        test="only_symmetric_encryption_keys_can_be_children",
    ),
    Control(
        name="service-exportable-child",
        guard="a wrapped child cannot be exportable",
        file=SERVICE,
        before="""    if record.exportability != Exportability::NonExportable {""",
        after="""    if false {""",
        suite=SERVICE_TEST,
        test="a_child_cannot_be_exportable",
    ),
    Control(
        name="service-exportable-parent",
        guard="an exportable parent protects nothing it wraps",
        file=SERVICE,
        before="""    if parent.exportability != Exportability::NonExportable || parent.first_exported_at.is_some() {""",
        after="""    if false {""",
        suite=SERVICE_TEST,
        test="an_exportable_parent_cannot_wrap_children",
    ),
    Control(
        name="service-legacy-parent",
        guard="a parent whose binding predates 0.5.0 is refused by name",
        file=SERVICE,
        before="""    if parent.has_legacy_parent_semantics() {""",
        after="""    if false {""",
        suite=SERVICE_TEST,
        test="a_parent_created_before_0_5_0_is_refused_by_name",
    ),
    Control(
        name="service-parent-state",
        guard="a disabled or compromised parent cannot wrap children",
        file=SERVICE,
        before="""    if parent.state != KeyState::Enabled || parent.has_compromise_history() {""",
        after="""    if false {""",
        suite=SERVICE_TEST,
        test="a_disabled_or_compromised_parent_cannot_wrap_children",
    ),
    Control(
        name="service-resident-parent",
        guard="a wrapped key cannot itself wrap children",
        file=SERVICE,
        before="""    if !parent
        .primary_version()
        .is_some_and(|v| matches!(v.material, KeyMaterial::ProviderResident { .. }))
    {""",
        after="""    if false {""",
        suite=SERVICE_TEST,
        test="a_wrapped_key_cannot_itself_wrap_children",
    ),
    Control(
        name="startup-mechanism-declared",
        guard="a provider must declare the mechanism it is activated with",
        file=SERVICE,
        before="""        if !declared
            .tuples()
            .iter()
            .any(|tuple| tuple.mechanism == profile.mechanism && tuple.operation == operation)
        {""",
        after="""        if false {""",
        suite=SERVICE_TEST,
        test="a_declared_profile_the_provider_does_not_implement_refuses_at_startup",
    ),
    Control(
        name="startup-closure-evidence",
        guard="a provider that cannot evidence closure must not start activated",
        file=SERVICE,
        before="""    if provider.wrapping_closure_verifier().is_none() {""",
        after="""    if false {""",
        suite=SERVICE_TEST,
        test="a_declared_profile_the_provider_does_not_implement_refuses_at_startup",
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

    dirty = run(["git", "status", "--porcelain", CORE, DRIVER, SERVICE]).stdout.strip()
    if dirty:
        print(f"refusing to run with uncommitted changes to the files under control:\n{dirty}")
        return 2

    results = []
    for control in CONTROLS:
        if args.filter and args.filter not in control.name:
            continue
        path = ROOT / control.file
        original = path.read_text()
        if control.before not in original:
            print(f"[{control.name}] PATTERN NOT FOUND — control cannot run")
            results.append((control, "pattern-not-found", ""))
            continue
        patched = original.replace(control.before, control.after, 1)
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
        revert({control.file})
        stdout = outcome.stdout
        if outcome.returncode == 0 and "1 passed" in stdout:
            verdict = "STILL PASSES — check is unproven"
        elif "FAILED" in stdout or outcome.returncode != 0:
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
        if verdict != "fails as expected":
            unproven += 1
        print(f"{control.name}: {verdict}")
        print(f"    guard: {control.guard}")
        print(f"    watched: {control.suite[0]}::{control.test}")
        if detail:
            print(f"    observed: {detail}")
    return 1 if unproven else 0


if __name__ == "__main__":
    sys.exit(main())
