#!/usr/bin/env python3
"""Cross-check every KMIP constant in keyrack-kmip against a neutral table.

The constants in `crates/keyrack-kmip/src/ttlv.rs` are the client's entire
understanding of the wire format, and a wrong one is invisible to unit tests
that both encode and decode with the same value. This compares them against
PyKMIP's enumerations — a third-party implementation of the same
specification — so a misreading has to be shared by two independent codebases
to survive.

Exits non-zero if any constant disagrees. Run it from the fixture directory
with a Python that has PyKMIP installed.
"""
import pathlib
import re
import sys

from kmip.core import enums

RUST = (
    pathlib.Path(__file__).resolve().parents[2]
    / "crates"
    / "keyrack-kmip"
    / "src"
    / "ttlv.rs"
)

# Rust module -> (PyKMIP enum, name overrides where the two spell it differently)
MODULES = {
    "tag": (
        enums.Tags,
        {
            "UNIQUE_ID": "UNIQUE_IDENTIFIER",
            "IV_COUNTER_NONCE": "IV_COUNTER_NONCE",
            "MAC_DATA": "MAC_DATA",
        },
    ),
    "operation": (enums.Operation, {"RNG_RETRIEVE": "RNG_RETRIEVE"}),
    "result_status": (enums.ResultStatus, {}),
    "object_type": (enums.ObjectType, {}),
    "crypto_algorithm": (
        enums.CryptographicAlgorithm,
        {"ED25519": "ED25519"},
    ),
    "block_cipher_mode": (enums.BlockCipherMode, {}),
}


def rust_constants():
    """Parse `pub mod <name> { pub const NAME: u32 = 0x..; }` blocks."""
    text = RUST.read_text()
    out = {}
    for mod in MODULES:
        m = re.search(rf"pub mod {mod} \{{(.*?)\n\}}", text, re.S)
        if not m:
            continue
        consts = {}
        for name, value in re.findall(
            r"pub const (\w+): u32 = (0x[0-9A-Fa-f_]+);", m.group(1)
        ):
            consts[name] = int(value.replace("_", ""), 16)
        out[mod] = consts
    return out


def main():
    mismatches = []
    unknown = []
    checked = 0

    for mod, consts in rust_constants().items():
        py_enum, overrides = MODULES[mod]
        for name, ours in consts.items():
            py_name = overrides.get(name, name)
            member = getattr(py_enum, py_name, None)
            if member is None:
                unknown.append((mod, name, ours))
                continue
            checked += 1
            if member.value != ours:
                mismatches.append((mod, name, ours, member.value, py_enum.__name__))

    for mod, name, ours, theirs, enum_name in mismatches:
        # Name the value we are actually sending, which is the part that makes
        # the defect concrete rather than a number mismatch.
        try:
            collision = getattr(enums, enum_name)(ours).name
        except (ValueError, AttributeError):
            collision = "not a defined value"
        print(
            f"MISMATCH {mod}::{name}\n"
            f"    ours   0x{ours:02X}  ({collision})\n"
            f"    neutral 0x{theirs:02X}  ({name})"
        )

    for mod, name, ours in unknown:
        print(f"UNCHECKED {mod}::{name} = 0x{ours:02X} (no counterpart to compare)")

    print(
        f"\n{checked} constants compared, {len(mismatches)} mismatched, "
        f"{len(unknown)} not comparable"
    )
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
