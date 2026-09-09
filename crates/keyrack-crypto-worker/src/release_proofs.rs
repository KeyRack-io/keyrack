// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

fn window() -> Window {
    Window {
        incarnation_matches: kani::any(),
        generation: kani::any(),
        not_before: kani::any(),
        expires: kani::any(),
    }
}

// Arbitrary symbolic choices enumerate bounded serializations of mutex-held
// transitions. OS mutex correctness and atomic pipe writes are assumptions.
#[kani::proof]
#[kani::unwind(9)]
fn worker_fence_release_interleavings() {
    let mut policy = Policy::default();
    let mut phase = Phase::Pending;
    let w = window();
    let mut fenced = false;
    let mut commits = 0u8;
    for _ in 0..8 {
        let now: u64 = kani::any();
        match kani::any::<u8>() % 4 {
            0 => {
                policy.admit(w, now);
            }
            1 => {
                let valid: bool = kani::any();
                let before = policy;
                policy.fence(valid);
                if valid {
                    fenced = true;
                } else {
                    assert_eq!(policy, before);
                }
            }
            2 => {
                let previous = phase;
                let outcome: u8 = kani::any::<u8>() % 3;
                let _ = policy.release::<()>(&mut phase, w, now, || {
                    assert!(!fenced);
                    assert_eq!(previous, Phase::Pending);
                    match outcome {
                        0 => Ok(false),
                        1 => {
                            commits += 1;
                            Ok(true)
                        }
                        _ => Err(()),
                    }
                });
                if previous != Phase::Pending {
                    assert_eq!(phase, previous);
                }
                if previous == Phase::Pending && policy.allows(w, now) && outcome == 2 {
                    assert_eq!(phase, Phase::Indeterminate);
                }
                assert!(commits <= 1);
            }
            _ => {
                policy.stop();
                fenced = true;
            }
        }
        if fenced {
            assert!(!policy.allows(w, now));
        }
    }
}

#[kani::proof]
fn worker_release_checks_every_retry() {
    let mut policy = Policy::default();
    let first = window();
    let first_now: u64 = kani::any();
    kani::assume(policy.admit(first, first_now));
    let mut phase = Phase::Pending;
    assert_eq!(
        policy.release::<()>(&mut phase, first, first_now, || Ok(false)),
        Ok(Phase::Pending)
    );
    let retry = window();
    let now: u64 = kani::any();
    let invalid = !retry.incarnation_matches
        || retry.generation == 0
        || retry.generation != first.generation
        || now < retry.not_before
        || now >= retry.expires;
    let mut called = false;
    let result = policy.release::<()>(&mut phase, retry, now, || {
        called = true;
        Ok(true)
    });
    if invalid {
        assert!(!called);
        assert_eq!(result, Ok(Phase::Suppressed));
    } else {
        assert!(called);
        assert_eq!(result, Ok(Phase::Committed));
    }
}

#[kani::proof]
fn worker_invalid_fence_preserves_admission() {
    let mut policy = Policy::default();
    let w = window();
    let now: u64 = kani::any();
    policy.admit(w, now);
    let before = policy;
    assert!(!policy.fence(false));
    assert_eq!(policy, before);
    assert_eq!(policy.allows(w, now), before.allows(w, now));
}
