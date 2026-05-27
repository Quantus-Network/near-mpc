//! Dilithium threshold signing implementation.
//!
//! This module provides the signing functionality for threshold Dilithium (ML-DSA-87)
//! signatures, wrapping the `qp-rusty-crystals-threshold` signing protocol in a
//! cait-sith compatible Protocol trait implementation.
//!
//! The threshold library now handles arbitrary participant IDs internally via
//! ParticipantList, so this adapter simply converts between NEAR's Participant
//! type and our ParticipantId (u32).
//!
//! ## Derived Keys
//!
//! For Dilithium, users MUST register derived keys via `register_dilithium_key`
//! before signing. Unlike ECC schemes where derivation is linear and can be done
//! on-the-fly (derived_share = master_share + tweak), Dilithium derivation is NOT
//! linear and requires a full DKG for each derived key.
//!
//! This means:
//! - ECC: Tweak can be applied during signing; no pre-registration needed
//! - Dilithium: Derived share must be pre-generated via DKG; signing fails without it

use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use crate::providers::dilithium::{
    DerivedKeyId, DilithiumKeygenOutput, DilithiumPublicKey, DilithiumSignature,
    DilithiumSignatureProvider, DilithiumTaskId,
};
use crate::types::SignatureId;
use anyhow::Context;

use std::time::Duration;
use threshold_signatures::participants::Participant;
use threshold_signatures::protocol::{Action, Protocol};
use tokio::time::timeout;

// Import types from qp-rusty-crystals-threshold
use qp_rusty_crystals_threshold::signing_protocol::{
    Action as DilithiumAction, DilithiumSignProtocol,
};
use qp_rusty_crystals_threshold::{ThresholdConfig, ThresholdSigner};

impl DilithiumSignatureProvider {
    /// Leader-side signature computation.
    pub(super) async fn make_signature_leader(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(DilithiumSignature, DilithiumPublicKey)> {
        let sign_request = self.sign_request_store.get(id).await?;

        // Select threshold number of parties for signing (subset signing is supported)
        let threshold = self.mpc_config.participants.threshold as usize;
        let running_participants: Vec<_> = self
            .mpc_config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .collect();

        let participants = self
            .client
            .select_random_active_participants_including_me(threshold, &running_participants)
            .context("Can't choose active participants for a dilithium signature")?;

        let channel = self
            .client
            .new_channel_for_task(DilithiumTaskId::Signature { id }, participants.clone())?;

        // Check if we have a derived share for this (domain, tweak) combination.
        // Derived shares are created when users call register_dilithium_key.
        //
        // IMPORTANT: Unlike ECC schemes where derivation is linear (derived_share = master_share + tweak),
        // Dilithium requires a full DKG for each derived key. There is no algebraic relationship
        // that allows us to derive a share on-the-fly from the master share.
        //
        // Therefore, if no derived share exists, we MUST fail rather than falling back to
        // the master share. Using the master share would produce a signature that doesn't
        // match the expected derived public key.
        let derived_key_id = DerivedKeyId {
            domain_id: sign_request.domain,
            tweak: sign_request.tweak.as_bytes(),
        };

        let keygen_output = self.get_derived_share(&derived_key_id).ok_or_else(|| {
            anyhow::anyhow!(
                "Dilithium derived share not found for domain {:?}. \
                 Dilithium keys must be registered via register_dilithium_key before signing. \
                 Unlike ECC, Dilithium derivation requires a full DKG and cannot be computed on-the-fly.",
                sign_request.domain
            )
        })?;

        tracing::debug!(
            "Using derived share for domain {:?} with tweak",
            sign_request.domain
        );

        // Get message from payload (Dilithium uses EdDSA-style raw message payload)
        let message = sign_request
            .payload
            .as_eddsa()
            .ok_or_else(|| {
                anyhow::anyhow!("Signature request payload is not an EdDSA/Dilithium payload")
            })?
            .to_vec();

        let result = DilithiumSignComputation {
            keygen_output: keygen_output.clone(),
            message,
            context: vec![], // Empty context for now
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.signature.timeout_sec),
        )
        .await?;

        let Some(signature) = result else {
            anyhow::bail!("Dilithium resulting signature doesn't contain value for the leader!");
        };

        Ok((signature, keygen_output.public_key))
    }

    /// Follower-side signature computation.
    pub(super) async fn make_signature_follower(
        &self,
        channel: NetworkTaskChannel,
        id: SignatureId,
    ) -> anyhow::Result<()> {
        let sign_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.sign_request_store.get(id),
        )
        .await??;

        // Check for derived share - same logic as leader.
        //
        // IMPORTANT: Unlike ECC schemes where derivation is linear, Dilithium requires
        // a full DKG for each derived key. We MUST fail if no derived share exists
        // rather than falling back to the master share.
        let derived_key_id = DerivedKeyId {
            domain_id: sign_request.domain,
            tweak: sign_request.tweak.as_bytes(),
        };

        let keygen_output = self.get_derived_share(&derived_key_id).ok_or_else(|| {
            anyhow::anyhow!(
                "Follower: Dilithium derived share not found for domain {:?}. \
                 Dilithium keys must be registered via register_dilithium_key before signing.",
                sign_request.domain
            )
        })?;

        tracing::debug!(
            "Follower using derived share for domain {:?}",
            sign_request.domain
        );

        let message = sign_request
            .payload
            .as_eddsa()
            .ok_or_else(|| {
                anyhow::anyhow!("Signature request payload is not an EdDSA/Dilithium payload")
            })?
            .to_vec();

        let _ = DilithiumSignComputation {
            keygen_output,
            message,
            context: vec![],
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.signature.timeout_sec),
        )
        .await?;

        Ok(())
    }
}

/// Computation wrapper for Dilithium signing that implements MpcLeaderCentricComputation.
pub struct DilithiumSignComputation {
    pub keygen_output: DilithiumKeygenOutput,
    pub message: Vec<u8>,
    pub context: Vec<u8>,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<Option<DilithiumSignature>> for DilithiumSignComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<Option<DilithiumSignature>> {
        // Get participants from the channel - use raw NEAR IDs directly
        // The threshold library now handles arbitrary IDs via ParticipantList
        let near_participants: Vec<ParticipantId> = channel.participants().to_vec();
        let my_near_id: ParticipantId = channel.my_participant_id();
        let signing_party_count = near_participants.len();

        // Get DKG parameters from the keyshare
        let dkg_threshold = self.keygen_output.private_share.threshold();

        // Convert NEAR ParticipantIds to raw u32 values for the threshold library
        let participant_ids: Vec<u32> = near_participants.iter().map(|p| p.raw()).collect();
        let my_id = my_near_id.raw();

        tracing::debug!(
            "Dilithium signing: my_id={}, my_dkg_party_id={}, signing_parties={}, threshold={}, participants={:?}",
            my_id,
            self.keygen_output.private_share.party_id(),
            signing_party_count,
            dkg_threshold,
            participant_ids
        );

        // Create threshold config for the signing session.
        // With subset signing support, total_parties can be less than DKG total
        // as long as it's >= threshold.
        let config = ThresholdConfig::new(dkg_threshold, signing_party_count as u32)
            .map_err(|e| anyhow::anyhow!("Failed to create threshold config: {:?}", e))?;

        // Create the threshold signer using the keyshare from DKG
        let signer = ThresholdSigner::new(
            self.keygen_output.private_share.clone(),
            self.keygen_output.public_key.clone(),
            config,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create threshold signer: {:?}", e))?;

        // Get the leader ID from the channel
        let leader_id = channel.sender().get_leader().raw();

        // Generate a unique seed for this signing session
        // This must be cryptographically random and unique per session
        let round1_seed: [u8; 32] = rand::random();

        // Generate attempt nonce for SSID computation
        // This must be agreed upon by all participants - derived from channel's unique ID
        // The channel ID is unique per signing attempt, providing session isolation
        let attempt_nonce: [u8; 32] = channel.derive_attempt_nonce();

        // Create the signing protocol with NEAR participant IDs directly
        // The threshold library handles ID-to-index mapping internally via ParticipantList
        // The leader is responsible for combine/retry decisions in the 4-round protocol
        let protocol = DilithiumSignProtocol::new(
            signer,
            self.message,
            self.context,
            participant_ids,
            my_id,
            leader_id,
            round1_seed,
            attempt_nonce,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create signing protocol: {:?}", e))?;

        // Wrap in cait-sith compatible adapter
        // The adapter only converts between NEAR's Participant type and our u32 IDs
        let adapter = DilithiumProtocolAdapter::new(protocol);

        // Run the protocol
        let signature: DilithiumSignature =
            run_protocol("sign dilithium", channel, adapter).await?;

        // All parties now get the signature (leader broadcasts it in Round 4)
        Ok(Some(signature))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Adapter that wraps DilithiumSignProtocol to implement the cait-sith Protocol trait.
///
/// This adapter converts between NEAR's cait-sith Participant type and our
/// ParticipantId (u32). The threshold library handles arbitrary participant IDs
/// internally via ParticipantList, so no ID-to-index mapping is needed here.
pub struct DilithiumProtocolAdapter {
    inner: DilithiumSignProtocol,
}

impl DilithiumProtocolAdapter {
    pub fn new(protocol: DilithiumSignProtocol) -> Self {
        Self { inner: protocol }
    }
}

impl Protocol for DilithiumProtocolAdapter {
    type Output = DilithiumSignature;

    fn poke(
        &mut self,
    ) -> Result<Action<Self::Output>, threshold_signatures::errors::ProtocolError> {
        match self.inner.poke() {
            Ok(action) => match action {
                DilithiumAction::Wait => Ok(Action::Wait),
                DilithiumAction::SendMany(data) => Ok(Action::SendMany(data)),
                DilithiumAction::Return(sig) => Ok(Action::Return(sig)),
            },
            Err(e) => Err(threshold_signatures::errors::ProtocolError::Other(
                e.to_string(),
            )),
        }
    }

    fn message(&mut self, from: Participant, data: threshold_signatures::protocol::MessageData) {
        // Convert cait-sith Participant to our ParticipantId (u32)
        let from_id: u32 = from.into();
        // The cait-sith Protocol trait's `message` is infallible, so we have to
        // absorb deserialization / malformed-message errors here. We log them
        // rather than propagating, because a single bad frame from a peer
        // should not tear down the whole signing instance — the protocol will
        // simply time out waiting for that peer and the outer mpc-node retry
        // machinery (a fresh ChannelId, a fresh DilithiumSignProtocol) will
        // take over on the next tick.
        if let Err(e) = self.inner.message(from_id, data) {
            tracing::warn!(target: "dilithium", "Discarding malformed message from {}: {}", from_id, e);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_arbitrary_participant_ids() {
        // Test that large NEAR-style IDs work directly without mapping
        let near_ids: Vec<u32> = vec![524342676, 1313390130, 3526595269, 3731869668];

        // The threshold library's ParticipantList handles these directly
        let participant_list =
            qp_rusty_crystals_threshold::ParticipantList::new(&near_ids).unwrap();

        // Verify the list contains all IDs
        assert_eq!(participant_list.len(), 4);
        for &id in &near_ids {
            assert!(participant_list.contains(id));
        }

        // Indices are assigned based on sorted order
        assert_eq!(participant_list.index_of(524342676), Some(0)); // smallest
        assert_eq!(participant_list.index_of(3731869668), Some(3)); // largest
    }

    #[test]
    fn test_subset_signing_with_arbitrary_ids() {
        // Test subset signing with arbitrary NEAR-style IDs
        // Original DKG had NEAR IDs: [100, 200, 300, 400]
        // Signing with subset: [100, 200, 400] (skipping 300)

        let signing_ids: Vec<u32> = vec![100, 200, 400];

        // The threshold library handles these directly via ParticipantList
        let participant_list =
            qp_rusty_crystals_threshold::ParticipantList::new(&signing_ids).unwrap();

        // Verify subset is properly handled
        assert_eq!(participant_list.len(), 3);
        assert!(participant_list.contains(100));
        assert!(participant_list.contains(200));
        assert!(participant_list.contains(400));
        assert!(!participant_list.contains(300)); // not in signing set
    }
}
