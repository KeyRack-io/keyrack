# API availability contract

`contract.json` explicitly binds each KeyService RPC to its Rust gRPC method and
REST method/path/handler, or records why it has no REST operation. The three
0.4.0 export RPCs are intentional gRPC-only APIs. Other existing missing REST
operations are recorded as `existing_gap`, and the three incomplete namespace
handlers are `stub`; these labels do not establish deliberate product intent
or claim that a namespace registry exists. REST-only operational endpoints and
the external PDP protocol are also enumerated with reasons.

The checker invokes **protoc**, decodes its service descriptors and compares them
with **syn**'s Rust syntax tree. RPC bindings use actual request/response types,
not a guessed RPC-to-route naming convention. REST method, path, handler,
feature gate and listener wiring must match. Unrecognized router construction
fails closed for review. Namespace stub bodies have normalized AST hashes so
an implementation change requires reviewing their status in the published table.

Run from the repository root with Rust and protoc installed:

```sh
cargo run --locked -p keyrack-surface-contract -- --check
cargo test --locked -p keyrack-surface-contract
python3 conformance/api-surface/controls.py --output-dir target/proofs/api-surface
```

After an intentional interface change, update the explicit binding or gap
classification and reason, then regenerate both artifacts:

```sh
cargo run --locked -p keyrack-surface-contract -- --write
```

Review the diff in `docs/generated/api-surface-parity.md` and its JSON companion.
The named `grpc_rest_surface_parity_matches_allowlist` test is part of the
workspace Test job. A separate CI job retains negative-control evidence. The
website consumes these artifacts from a pinned source commit, reruns this same
checker and labels its table with that revision; it has no second operation list.

This is an availability gate. It does not prove that matching endpoints have
identical payloads, authorization decisions, error mappings or side effects.
Existing integration tests for cascading disable, descendant rotation counts
and other cross-interface behavior remain necessary. The table also distinguishes
feature-disabled crypto operations and deployment-dependent REST authentication.
