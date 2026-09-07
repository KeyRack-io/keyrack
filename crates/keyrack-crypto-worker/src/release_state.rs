// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Runtime transition kernel. Its caller holds the release/fence mutex through
//! the write callback. No authorization ticket can escape that critical section.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Policy {
    pub generation: Option<u64>,
    fenced: bool,
    stopped: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct Window {
    // Computed from exact runtime incarnation equality, not IPC-supplied.
    pub incarnation_matches: bool,
    pub generation: u64,
    pub not_before: u64,
    pub expires: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Pending,
    Committed,
    Suppressed,
}
impl Policy {
    pub fn allows(&self, w: Window, now: u64) -> bool {
        !self.stopped
            && !self.fenced
            && w.incarnation_matches
            && w.generation != 0
            && self.generation.map_or(true, |g| g == w.generation)
            && now >= w.not_before
            && now < w.expires
    }
    pub fn admit(&mut self, w: Window, now: u64) -> bool {
        if !self.allows(w, now) {
            return false;
        }
        self.generation = Some(w.generation);
        true
    }
    pub fn fence(&mut self, validated: bool) -> bool {
        if !validated {
            return false;
        }
        self.fenced = true;
        true
    }
    pub fn stop(&mut self) {
        self.stopped = true;
    }
    pub fn stopped(&self) -> bool {
        self.stopped
    }
    pub fn release<E>(
        &self,
        phase: &mut Phase,
        w: Window,
        now: u64,
        write: impl FnOnce() -> Result<bool, E>,
    ) -> Result<Phase, E> {
        if *phase != Phase::Pending {
            return Ok(*phase);
        }
        if self.allows(w, now) {
            match write() {
                Ok(true) => *phase = Phase::Committed,
                Ok(false) => {} // Retry must pass allows() again.
                Err(error) => {
                    *phase = Phase::Suppressed;
                    return Err(error);
                }
            }
        } else {
            *phase = Phase::Suppressed;
        }
        Ok(*phase)
    }
}

#[cfg(kani)]
#[path = "release_proofs.rs"]
mod proofs;
