//! Dilithium distributed key generation implementation.
//!
//! This module provides the DKG functionality for threshold Dilithium (ML-DSA-87)
//! keys, wrapping the `qp-rusty-crystals-threshold` DKG protocol in a
//! cait-sith compatible Protocol trait implementation.
//!
//! The threshold library now handles arbitrary participant IDs internally via
//! ParticipantList, so this adapter simply converts between NEAR's Participant
//! type and our ParticipantId (u32).

use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use crate::providers::dilithium::{DilithiumKeygenOutput, DilithiumSignatureProvider};
use threshold_signatures::errors::MessageError;
use threshold_signatures::participants::Participant;
use threshold_signatures::protocol::{Action, Protocol};

// Import types from qp-rusty-crystals-threshold
use qp_rusty_crystals_threshold::keygen::dkg::{
    Action as DkgAction, DilithiumDkg, DkgConfig, DkgOutput,
};
use qp_rusty_crystals_threshold::ThresholdConfig;

impl DilithiumSignatureProvider {
    /// Run key generation as a client (both leader and follower).
    pub(super) async fn run_key_generation_client_internal(
        threshold: usize,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<DilithiumKeygenOutput> {
        let key = DilithiumKeyGenerationComputation { threshold }
            .perform_leader_centric_computation(
                channel,
                // TODO: Move timeout to config
                std::time::Duration::from_secs(120),
            )
            .await?;
        tracing::info!("Dilithium key generation completed");

        Ok(key)
    }
}

/// Computation wrapper for Dilithium DKG that implements MpcLeaderCentricComputation.
pub struct DilithiumKeyGenerationComputation {
    pub threshold: usize,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<DilithiumKeygenOutput> for DilithiumKeyGenerationComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<DilithiumKeygenOutput> {
        // Get all participants from the channel - use raw NEAR IDs directly
        // The threshold library now handles arbitrary IDs via ParticipantList
        let near_participants: Vec<ParticipantId> = channel.participants().to_vec();
        let my_near_id: ParticipantId = channel.my_participant_id();
        let total_parties = near_participants.len();

        // Convert NEAR ParticipantIds to raw u32 values for the threshold library
        let participant_ids: Vec<u32> = near_participants.iter().map(|p| p.raw()).collect();
        let my_id = my_near_id.raw();

        tracing::debug!(
            "Dilithium DKG: my_id={}, total_parties={}, threshold={}, participants={:?}",
            my_id,
            total_parties,
            self.threshold,
            participant_ids
        );

        // Create threshold config
        let threshold_config = ThresholdConfig::new(self.threshold as u32, total_parties as u32)
            .map_err(|e| anyhow::anyhow!("Failed to create threshold config: {:?}", e))?;

        // Create DKG config with NEAR participant IDs directly
        // The threshold library handles ID-to-index mapping internally via ParticipantList
        let dkg_config = DkgConfig::new(threshold_config, my_id, participant_ids)
            .map_err(|e| anyhow::anyhow!("Failed to create DKG config: {}", e))?;

        // Generate random seed for this party
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| anyhow::anyhow!("Failed to generate random seed: {}", e))?;

        // Create the DKG protocol
        let dkg = DilithiumDkg::new(dkg_config, seed);

        // Wrap in cait-sith compatible adapter
        // The adapter only converts between NEAR's Participant type and our u32 IDs
        let adapter = DilithiumDkgAdapter::new(dkg);

        // Run the protocol
        let output: DkgOutput = run_protocol("dilithium key generation", channel, adapter).await?;

        Ok(DilithiumKeygenOutput {
            public_key: output.public_key,
            private_share: output.private_share,
        })
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Adapter that wraps DilithiumDkg to implement the cait-sith Protocol trait.
///
/// This adapter converts between NEAR's cait-sith Participant type and our
/// ParticipantId (u32). The threshold library handles arbitrary participant IDs
/// internally via ParticipantList, so no ID-to-index mapping is needed here.
pub struct DilithiumDkgAdapter {
    inner: DilithiumDkg,
}

impl DilithiumDkgAdapter {
    pub fn new(dkg: DilithiumDkg) -> Self {
        Self { inner: dkg }
    }
}

impl Protocol for DilithiumDkgAdapter {
    type Output = DkgOutput;

    fn poke(
        &mut self,
    ) -> Result<Action<Self::Output>, threshold_signatures::errors::ProtocolError> {
        match self.inner.poke() {
            Ok(action) => match action {
                DkgAction::Wait => Ok(Action::Wait),
                DkgAction::SendMany(data) => Ok(Action::SendMany(data)),
                DkgAction::SendPrivate(to_id, data) => {
                    // Convert our ParticipantId (u32) to cait-sith Participant
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

    fn message(
        &mut self,
        from: Participant,
        data: threshold_signatures::protocol::MessageData,
    ) -> Result<(), MessageError> {
        // Convert cait-sith Participant to our ParticipantId (u32)
        let from_id: u32 = from.into();
        self.inner.message(from_id, data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_dkg_adapter_creation() {
        // This test verifies the basic setup works with arbitrary NEAR-style IDs
        // The threshold library handles ID-to-index mapping internally
        let threshold_config = ThresholdConfig::new(2, 3).unwrap();
        // Use arbitrary IDs like NEAR would
        let dkg_config = DkgConfig::new(
            threshold_config,
            524342676,
            vec![524342676, 1313390130, 3526595269],
        )
        .unwrap();
        let seed = [42u8; 32];
        let dkg = DilithiumDkg::new(dkg_config, seed);

        let _adapter = DilithiumDkgAdapter::new(dkg);
    }

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
}
