// Copyright 2026 KeyRack Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! One authenticated, whole-domain local observation. Never all-holder completion.
use super::{Clock, Error, MaterialSource, Worker};
use crate::delivery::Delivery;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::Signer;
use keyrack_core::custody::{
    AuthorityScope, Canonical, ClockDomain, ClockReading, Evidence, ExecutorIncarnation,
    RevocationCommand, RevocationResult, WrappingIdentifier, MAX_RECEIPT_LEASES,
};

impl<S: MaterialSource, C: Clock> Worker<S, C> {
    pub(crate) fn executor(&self) -> Result<ExecutorIncarnation, Error> {
        ExecutorIncarnation::new(
            STANDARD
                .decode(&self.instance)
                .map_err(|_| Error::Context)?
                .try_into()
                .map_err(|_| Error::Context)?,
        )
        .map_err(|_| Error::Context)
    }

    fn check_revocation(&self, command: &RevocationCommand) -> Result<(), Error> {
        // Trusted private runtime policy: the launcher's authority key owns
        // one exact provider/domain. Neither scope nor clock comes from IPC.
        let expected_scope = AuthorityScope::SecurityDomain {
            provider_ref: self.provider_ref.clone(),
            security_domain: WrappingIdentifier::new(&self.domain).map_err(|_| Error::Context)?,
        };
        let executor = self.executor()?;
        if command.executor != executor
            || command.authority.issuer != self.trust.authority.issuer
            || command.authority.scope != expected_scope
        {
            return Err(Error::Authority);
        }
        let now = self.clock.millis();
        command
            .validity
            .check_at(ClockReading {
                domain: ClockDomain::ExecutorMonotonicMilliseconds(executor),
                milliseconds: now,
            })
            .map_err(|_| Error::Expired)?;
        if command.validity.not_after > now.saturating_add(self.limits.authority_horizon_ms) {
            return Err(Error::Expired);
        }
        // The initial generation is trusted launcher policy, shared with use/creation.
        // A terminal incarnation cannot issue a second completion observation.
        if self.fenced || command.authority.generation <= self.generation {
            return Err(Error::Replay);
        }
        Ok(())
    }

    pub(crate) fn revoke<D: Clock>(
        &mut self,
        bytes: &[u8],
        delivery: &Delivery<D>,
    ) -> Result<Evidence<RevocationResult>, Error> {
        let evidence = Evidence::<RevocationCommand>::from_canonical_bytes(bytes)
            .map_err(|_| Error::Authority)?;
        let authenticated = evidence
            .authenticate(&self.trust.authority)
            .map_err(|_| Error::Authority)?;
        let command = authenticated.claims();
        let instance = self.instance.clone();
        let (observed_leases, in_flight) =
            delivery.fence(&instance, command.authority.generation.get(), || {
                // Currentness/time are checked after obtaining the release lock.
                self.check_revocation(command)?;
                let mut leases: Vec<_> = self
                    .resident
                    .values()
                    .map(|resident| resident.lease)
                    .collect();
                leases.sort_unstable_by_key(|lease| lease.counter);
                leases.truncate(MAX_RECEIPT_LEASES);
                self.generation = command.authority.generation;
                self.fenced = true;
                // Purge the entire scope, never just the bounded diagnostic set.
                self.resident.clear();
                Ok(leases)
            })?;
        // The mutable worker borrow excludes ongoing provider work. After F the
        // terminal gate forbids late admission/release, including prepared data.
        let claims = RevocationResult {
            fence: command.fence,
            executor: self.executor()?,
            authority: command.authority.clone(),
            command_sha256: command.sha256().map_err(|_| Error::Authority)?,
            in_flight,
            observed_leases,
        };
        claims.check_command(command).map_err(|_| Error::Material)?;
        let signer = self.observation_key();
        let mut result = Evidence {
            issuer: signer.issuer,
            key_id: signer.key_id,
            claims,
            signature: [0; 64],
        };
        result.signature = self
            .observer
            .sign(&result.signing_bytes().map_err(|_| Error::Material)?)
            .to_bytes();
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
