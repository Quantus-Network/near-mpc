//! Dilithium key registration (derived key DKG) implementation.
//!
//! This module handles the registration of derived Dilithium keys. Unlike ECC schemes
//! where derived keys can be computed on-the-fly using linear derivation, Dilithium
//! requires a full DKG protocol for each derived key.
//!
//! The DKG is seeded deterministically using contributions from each party's master
//! share combined with the tweak, ensuring:
//! 1. The derived key is bound to the master key
//! 2. The same (master_key, tweak) always produces the same derived key
//! 3. Only parties with valid master shares can participate

use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use crate::providers::dilithium::{
    DilithiumKeygenOutput, DilithiumPublicKey, DilithiumSignatureProvider, DilithiumTaskId,
    KeyRegistrationId, PrivateKeyShare,
};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::signature::Tweak;
use std::time::Duration;
use threshold_signatures::participants::Participant;
use threshold_signatures::protocol::{Action, Protocol};

// Import types from qp-rusty-crystals-threshold
use qp_rusty_crystals_threshold::derivation::derive_dkg_contribution;
use qp_rusty_crystals_threshold::keygen::dkg::{
    Action as DkgAction, DilithiumDkg, DkgConfig, DkgOutput,
};
use qp_rusty_crystals_threshold::ThresholdConfig;

/// Identifier for a derived key, used for storage lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DerivedKeyId {
    /// The domain ID (identifies the master key)
    pub domain_id: DomainId,
    /// The derivation tweak
    pub tweak: [u8; 32],
}

impl DerivedKeyId {
    pub fn new(domain_id: DomainId, tweak: Tweak) -> Self {
        Self {
            domain_id,
            tweak: tweak.as_bytes(),
        }
    }
}

impl DilithiumSignatureProvider {
    /// Run key registration as the leader node.
    ///
    /// This is called when the contract emits a `register_dilithium_key` event.
    /// The leader selects participants, creates a channel, and coordinates DKG.
    /// All participating nodes run a full DKG protocol, with randomness seeded
    /// by their master share + the tweak to ensure determinism.
    ///
    /// Returns the derived public key on success.
    pub async fn run_key_registration_as_leader(
        &self,
        domain_id: DomainId,
        tweak: Tweak,
    ) -> anyhow::Result<DilithiumPublicKey> {
        // Get the master keyshare for this domain
        let master_keygen_output = self
            .keyshares
            .get(&domain_id)
            .ok_or_else(|| anyhow::anyhow!("No master keyshare for domain {:?}", domain_id))?;

        let threshold = master_keygen_output.private_share.threshold() as usize;

        // For derived key DKG, we include ALL participants (not just threshold).
        // This ensures every node has the derived share and can participate in signing.
        // Unlike ECC where derivation is linear, Dilithium requires each node to have
        // the derived share - there's no way to compute it on-the-fly from the master.
        let participants: Vec<_> = self
            .mpc_config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .collect();

        // Create a channel for this key registration task
        let task_id = DilithiumTaskId::KeyRegistration {
            id: KeyRegistrationId::new(domain_id, &tweak),
        };
        let channel = self
            .client
            .new_channel_for_task(task_id, participants.clone())?;

        tracing::info!(
            "Starting Dilithium key registration DKG for domain {:?} with {} participants",
            domain_id,
            participants.len()
        );

        // Run the derived key DKG
        let derived_output = DilithiumDerivedKeyComputation {
            master_share: master_keygen_output.private_share.clone(),
            tweak: tweak.as_bytes(),
            threshold,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(120), // DKG may take longer than signing
        )
        .await?;

        // Store the derived share for future signing
        let derived_key_id = DerivedKeyId::new(domain_id, tweak);
        self.store_derived_share(derived_key_id, derived_output.clone());

        tracing::info!(
            "Dilithium derived key generation completed for domain {:?}",
            domain_id
        );

        Ok(derived_output.public_key)
    }

    /// Handle key registration as a follower when receiving a task from the network.
    ///
    /// This is called via `process_channel` when another node initiates key registration.
    /// We extract the domain_id and tweak from the KeyRegistrationId, run DKG, and store
    /// the derived share.
    ///
    /// The KeyRegistrationId contains the full 32-byte tweak, so we don't need to look
    /// anything up - we have all the information needed to participate in the DKG.
    pub async fn handle_key_registration_as_follower(
        &self,
        channel: NetworkTaskChannel,
        reg_id: super::KeyRegistrationId,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Handling key registration as follower for domain {:?}",
            reg_id.domain_id
        );

        // The KeyRegistrationId contains the full tweak, so we can use it directly
        let tweak_bytes = reg_id.tweak;

        // Get the master keyshare for this domain
        let master_keygen_output = self.keyshares.get(&reg_id.domain_id).ok_or_else(|| {
            anyhow::anyhow!("No master keyshare for domain {:?}", reg_id.domain_id)
        })?;

        let threshold = master_keygen_output.private_share.threshold() as usize;

        // Run the derived key DKG with the actual tweak from the registration request
        let derived_output = DilithiumDerivedKeyComputation {
            master_share: master_keygen_output.private_share.clone(),
            tweak: tweak_bytes,
            threshold,
        }
        .perform_leader_centric_computation(channel, Duration::from_secs(120))
        .await?;

        // Store the derived share with the correct tweak
        let derived_key_id = DerivedKeyId {
            domain_id: reg_id.domain_id,
            tweak: tweak_bytes,
        };
        self.store_derived_share(derived_key_id, derived_output);

        tracing::info!("Stored derived key share for domain {:?}", reg_id.domain_id);

        Ok(())
    }
}

/// Computation wrapper for derived key DKG that implements MpcLeaderCentricComputation.
pub struct DilithiumDerivedKeyComputation {
    /// This party's master private key share
    pub master_share: PrivateKeyShare,
    /// The derivation tweak (from account_id + path)
    pub tweak: [u8; 32],
    /// Threshold for the derived key (same as master key)
    pub threshold: usize,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<DilithiumKeygenOutput> for DilithiumDerivedKeyComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<DilithiumKeygenOutput> {
        // Get all participants from the channel
        let near_participants: Vec<ParticipantId> = channel.participants().to_vec();
        let my_near_id: ParticipantId = channel.my_participant_id();
        let total_parties = near_participants.len();

        // Convert NEAR ParticipantIds to raw u32 values
        let participant_ids: Vec<u32> = near_participants.iter().map(|p| p.raw()).collect();
        let my_id = my_near_id.raw();

        tracing::debug!(
            "Dilithium derived key DKG: my_id={}, total_parties={}, threshold={}, participants={:?}",
            my_id,
            total_parties,
            self.threshold,
            participant_ids
        );

        // Create threshold config
        let threshold_config = ThresholdConfig::new(self.threshold as u32, total_parties as u32)
            .map_err(|e| anyhow::anyhow!("Failed to create threshold config: {:?}", e))?;

        // Create DKG config
        let dkg_config = DkgConfig::new(threshold_config, my_id, participant_ids)
            .map_err(|e| anyhow::anyhow!("Failed to create DKG config: {}", e))?;

        // Derive the DKG seed from the master share and tweak.
        // This ensures:
        // 1. Determinism: same (master_share, tweak) → same contribution
        // 2. Security: outsiders can't compute contributions without master shares
        // 3. Binding: derived key is cryptographically bound to master key
        let seed = derive_dkg_contribution(&self.master_share, &self.tweak);

        tracing::debug!(
            "Derived DKG seed from master share (party_id={}) and tweak",
            self.master_share.party_id()
        );

        // Create the DKG protocol with the derived seed
        let dkg = DilithiumDkg::new(dkg_config, seed);

        // Wrap in cait-sith compatible adapter
        let adapter = DilithiumDerivedDkgAdapter::new(dkg);

        // Run the protocol
        let output: DkgOutput =
            run_protocol("dilithium derived key generation", channel, adapter).await?;

        Ok(DilithiumKeygenOutput {
            public_key: output.public_key,
            private_share: output.private_share,
        })
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Adapter that wraps DilithiumDkg for derived key generation.
///
/// This is identical to the regular DKG adapter, but used for derived keys
/// where the seed is deterministically derived from master share + tweak.
pub struct DilithiumDerivedDkgAdapter {
    inner: DilithiumDkg,
}

impl DilithiumDerivedDkgAdapter {
    pub fn new(dkg: DilithiumDkg) -> Self {
        Self { inner: dkg }
    }
}

impl Protocol for DilithiumDerivedDkgAdapter {
    type Output = DkgOutput;

    fn poke(
        &mut self,
    ) -> Result<Action<Self::Output>, threshold_signatures::errors::ProtocolError> {
        match self.inner.poke() {
            Ok(action) => match action {
                DkgAction::Wait => Ok(Action::Wait),
                DkgAction::SendMany(data) => Ok(Action::SendMany(data)),
                DkgAction::SendPrivate(to_id, data) => {
                    let participant: Participant = Participant::from(to_id);
                    Ok(Action::SendPrivate(participant, data))
                }
                DkgAction::Return(output) => Ok(Action::Return(output)),
            },
            Err(e) => Err(threshold_signatures::errors::ProtocolError::Other(
                e.to_string(),
            )),
        }
    }

    fn message(&mut self, from: Participant, data: threshold_signatures::protocol::MessageData) {
        let from_id: u32 = from.into();
        self.inner.message(from_id, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derived_key_id_creation() {
        let domain_id = DomainId(5);
        let tweak_bytes = [42u8; 32];
        let tweak = Tweak::new(tweak_bytes);

        let id = DerivedKeyId::new(domain_id, tweak);

        assert_eq!(id.domain_id, domain_id);
        assert_eq!(id.tweak, tweak_bytes);
    }

    #[test]
    fn test_derived_key_id_equality() {
        let id1 = DerivedKeyId {
            domain_id: DomainId(5),
            tweak: [1u8; 32],
        };
        let id2 = DerivedKeyId {
            domain_id: DomainId(5),
            tweak: [1u8; 32],
        };
        let id3 = DerivedKeyId {
            domain_id: DomainId(5),
            tweak: [2u8; 32],
        };
        let id4 = DerivedKeyId {
            domain_id: DomainId(6),
            tweak: [1u8; 32],
        };

        assert_eq!(id1, id2);
        assert_ne!(id1, id3); // different tweak
        assert_ne!(id1, id4); // different domain
    }

    #[test]
    fn test_derived_key_id_hash() {
        use std::collections::HashMap;

        let mut map: HashMap<DerivedKeyId, String> = HashMap::new();

        let id1 = DerivedKeyId {
            domain_id: DomainId(5),
            tweak: [1u8; 32],
        };
        let id2 = DerivedKeyId {
            domain_id: DomainId(6),
            tweak: [1u8; 32],
        };

        map.insert(id1.clone(), "key1".to_string());
        map.insert(id2.clone(), "key2".to_string());

        assert_eq!(map.get(&id1), Some(&"key1".to_string()));
        assert_eq!(map.get(&id2), Some(&"key2".to_string()));

        // Lookup with freshly created ID should work
        let id1_fresh = DerivedKeyId {
            domain_id: DomainId(5),
            tweak: [1u8; 32],
        };
        assert_eq!(map.get(&id1_fresh), Some(&"key1".to_string()));
    }
}
