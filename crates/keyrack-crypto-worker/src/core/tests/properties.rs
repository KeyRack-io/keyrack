// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use proptest::prelude::*;
use std::collections::BTreeMap;

#[derive(Default)]
struct Source {
    calls: usize,
    fail: bool,
}
impl MaterialSource for Source {
    fn open(&mut self, _: &WrappingContext) -> Result<Secret, Error> {
        self.calls += 1;
        if self.fail {
            Err(Error::Material)
        } else {
            Ok(Secret(Zeroizing::new(vec![7; 32])))
        }
    }
}
fn new_worker(key: &SigningKey, clock: &TestClock, capacity: usize) -> Worker<Source, TestClock> {
    Worker::new(
        key.verifying_key(),
        "development-only".into(),
        Source::default(),
        clock.clone(),
        Limits {
            resident_keys: capacity,
            residence_ms: 30,
            uses_per_residency: 3,
            authority_horizon_ms: 1000,
        },
    )
    .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]
    #[test]
    fn cache_residency_fence_restart_sequences(capacity in 1usize..4,
        operations in prop::collection::vec((0u8..9, 0u8..5, 0u16..60), 1..96)) {
        let key = SigningKey::from_bytes(&[31;32]);
        let clock = TestClock(Rc::new(Cell::new(0)));
        let mut worker = new_worker(&key, &clock, capacity);
        // Independent expected residency: context -> (absolute deadline, lease, uses).
        let mut model: BTreeMap<[u8;32], (u64,u64,u64)> = BTreeMap::new();
        let mut sequence = 0u64;
        let mut lease = 0u64;
        let mut calls = 0usize;
        let mut fenced = false;
        let mut previous: Option<(Signed, WrappingContext)> = None;
        for (action, child, delta) in operations {
            let mut ctx = context();
            ctx.child = keyrack_core::wrapping::VersionedKeyId::new(keyrack_core::lid::Lid::from_bytes([child+1;32]),1).unwrap();
            let binding = context_digest(&ctx).unwrap();
            let now = clock.millis();
            match action {
                0 | 1 | 7 => {
                    // Fresh permission does not refresh an existing residency.
                    model.retain(|_, v| v.0 > now);
                    sequence += 1;
                    let mut g = grant(&worker, sequence, Operation::Encrypt, b"message");
                    g.context_sha256 = binding;
                    g.not_before_ms = now;
                    g.expires_ms = now + 100;
                    g.ancestor_expires_ms = now + 90;
                    g.residency_until_ms = now + u64::from(delta) + 1;
                    if action == 7 { g.expires_ms = now; }
                    let signed = sign(&key, &AuthorityMessage::Grant(g));
                    let expected = if action == 7 { Err(Error::Expired) }
                        else if fenced { Err(Error::Replay) }
                        else {
                            let open = if model.contains_key(&binding) { Ok(()) }
                            else if model.len() == capacity { Err(Error::Limit) }
                            else {
                                calls += 1;
                                if worker.source.fail { Err(Error::Material) }
                                else {
                                    lease += 1;
                                    model.insert(binding, (now + (u64::from(delta)+1).min(30), lease, 0));
                                    Ok(())
                                }
                            };
                            open.and_then(|()| {
                                let resident = model.get_mut(&binding).unwrap();
                                if resident.2 == 3 { Err(Error::Limit) }
                                else { resident.2 += 1; Ok(()) }
                            })
                        };
                    let actual = worker.execute(&signed,"alice",&ctx,Operation::Encrypt,b"message").map(|_| ());
                    prop_assert_eq!(actual, expected);
                    previous = Some((signed,ctx));
                },
                2 => {
                    // Model idle timer sweeps, biased to before/equal/after a
                    // live deadline as well as arbitrary monotonic advances.
                    let target = model.values().map(|v|v.0).min().unwrap_or(now + u64::from(delta));
                    let next = match child % 3 { 0 => target.saturating_sub(1), 1 => target, _ => target+1 }.max(now);
                    clock.0.set(next);
                    let expired: BTreeMap<_,_> = model.iter().filter(|(_,v)|v.0 <= next).map(|(k,v)|(*k,v.1)).collect();
                    let dropped = worker.expire();
                    prop_assert_eq!(dropped.len(), expired.len());
                    let reported: BTreeMap<_,_> = dropped.iter().map(|r|(r.context_sha256,r.lease)).collect();
                    prop_assert_eq!(reported,expired);
                    model.retain(|_,v|v.0 > next);
                    prop_assert!(worker.expire().is_empty());
                },
                3 | 4 => {
                    let mut signed = sign(&key,&AuthorityMessage::Fence(Fence {
                        worker: worker.instance.clone(), security_domain: "development-only".into(),
                        generation: 2, expires_ms: now+1,
                    }));
                    if action == 4 { signed.signature[0] ^= 1; }
                    let result = worker.fence(&signed);
                    if action == 4 { prop_assert!(result.is_err()); }
                    else if fenced { prop_assert_eq!(result.err(),Some(Error::Replay)); }
                    else {
                        let receipt=result.unwrap();
                        prop_assert_eq!(receipt.purged.len(),model.len());
                        let actual: BTreeMap<_,_> = receipt.purged.iter().map(|r|(r.context_sha256,r.lease)).collect();
                        let expected: BTreeMap<_,_> = model.iter().map(|(k,v)|(*k,v.1)).collect();
                        prop_assert_eq!(actual, expected);
                        model.clear(); fenced=true;
                    }
                },
                5 => {
                    let old_instance=worker.instance.clone();
                    worker=new_worker(&key,&clock,capacity);
                    prop_assert_ne!(&worker.instance,&old_instance);
                    model.clear(); sequence=0; lease=0; calls=0; fenced=false;
                    if let Some((ref signed,ref old_ctx))=previous {
                        prop_assert!(worker.execute(signed,"alice",old_ctx,Operation::Encrypt,b"message").is_err());
                        prop_assert_eq!(worker.source.calls,0);
                    }
                    previous=None;
                },
                6 => { worker.source.fail = child % 2 == 0; },
                _ => {
                    if let Some((ref signed,ref old_ctx))=previous {
                        model.retain(|_,v|v.0 > now);
                        prop_assert!(worker.execute(signed,"alice",old_ctx,Operation::Encrypt,b"message").is_err());
                    }
                },
            }
            prop_assert_eq!(worker.source.calls,calls);
            prop_assert_eq!(worker.next_lease,lease);
            prop_assert!(worker.resident.len() <= capacity);
            let actual: BTreeMap<_,_> = worker.resident.iter().map(|(k,v)|(*k,(v.until,v.lease,v.uses))).collect();
            prop_assert_eq!(&actual,&model);
            prop_assert!(actual.values().all(|v|v.2 <= 3));
        }
    }
}
