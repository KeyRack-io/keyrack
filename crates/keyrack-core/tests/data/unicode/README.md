# Independent Unicode NFC oracle

These unmodified files were downloaded from Unicode, Inc. on 2026-09-07:

| File | Source | SHA-256 |
| --- | --- | --- |
| `NormalizationTest-17.0.0.txt` | https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt | `5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db` |
| `LICENSE.txt` | https://www.unicode.org/license.txt | `e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96` |

The data file's header identifies version 17.0.0 and date 2025-06-30. This
matches `unicode-normalization` 0.1.25's `UNICODE_VERSION = (17, 0, 0)`;
Cargo.lock package checksum is
`5fd4f6878c9cb28d874b009da9e8d183b5abc80117c40bbd187a1fde336be6e8`.
The accompanying Unicode License V3 applies to the reference data.

`canonical_identity.rs` verifies both hashes and all 20,034 reference rows.
Expected NFC strings come from the published second/fourth columns, never from
the implementation under test. It checks all five NFC column relations through
the product text normalizer, flat-map normalizer, and actual V2 canonicalizer.
Expected canonical bytes are hand-framed from the reference strings, independent
of the product encoder. Each reference source also exercises list-value and
nested-record canonicalization against its published NFC result. It also checks
NFC identity for every Unicode scalar not
listed as a source in Part 1 (a superset of the assigned scalars required by the
reference's second conformance condition).

The generated `canonical_bytes_equal_iff_rule_observations_equal` property is
over accepted flat string maps. Its complete separating observations contain
presence and captured values for every normalized key in the union of the maps.
A single boolean rule is not a complete observation: unrelated maps can both
fail, and `$`-prefixed patterns denote variables. Rules receive the original raw
maps, so the test cannot mask a missing normalization boundary. Other generated
tests exercise arbitrary-rule forward congruence, Unicode-equivalent spellings,
different and independent maps, and duplicate normalized keys. These are bounded
generated tests, not a proof of injectivity over unbounded inputs.

All fixtures are public test data. Software AEAD tests establish identity/AAD
semantics only; they do not qualify provider-native wrapping or key custody.
