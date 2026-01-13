//! Dilithium distributed key generation implementation.
//!
//! This module provides the DKG functionality for threshold Dilithium (ML-DSA-87)
//! keys, wrapping the `qp-rusty-crystals-threshold` DKG protocol in a
//! cait-sith compatible Protocol trait implementation.

use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::protocol::run_protocol;
use crate::providers::dilithium::{DilithiumKeygenOutput, DilithiumSignatureProvider};
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
        let participants: Vec<u8> = channel
            .participants()
            .iter()
            .map(|p| p.raw() as u8)
            .collect();

        let my_participant_id = channel.my_participant_id().raw() as u8;
        let total_parties = participants.len() as u8;

        // Create threshold config
        let threshold_config = ThresholdConfig::new(self.threshold as u8, total_parties)
            .map_err(|e| anyhow::anyhow!("Failed to create threshold config: {:?}", e))?;

        // Create DKG config
        let dkg_config = DkgConfig::new(threshold_config, my_participant_id, participants.clone())
            .map_err(|e| anyhow::anyhow!("Failed to create DKG config: {}", e))?;

        // Generate random seed for this party
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| anyhow::anyhow!("Failed to generate random seed: {}", e))?;

        // Create the DKG protocol
        let dkg = DilithiumDkg::new(dkg_config, seed);

        // Wrap in cait-sith compatible adapter
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

    fn poke(&mut self) -> Result<Action<Self::Output>, threshold_signatures::errors::ProtocolError> {
        match self.inner.poke() {
            Ok(action) => match action {
                DkgAction::Wait => Ok(Action::Wait),
                DkgAction::SendMany(data) => Ok(Action::SendMany(data)),
                DkgAction::SendPrivate(to, data) => {
                    Ok(Action::SendPrivate(Participant::from(to as u32), data))
                }
                DkgAction::Return(output) => Ok(Action::Return(output)),
            },
            Err(e) => Err(threshold_signatures::errors::ProtocolError::Other(
                e.to_string().into(),
            )),
        }
    }

    fn message(&mut self, from: Participant, data: threshold_signatures::protocol::MessageData) {
        // Convert cait-sith Participant to our u8 participant ID
        let from_id: u32 = from.into();
        self.inner.message(from_id as u8, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_dkg_adapter_creation() {
        // This test verifies the basic setup works
        // Full integration tests would require the complete MPC infrastructure
        let threshold_config = ThresholdConfig::new(2, 3).unwrap();
        let dkg_config = DkgConfig::new(threshold_config, 0, vec![0, 1, 2]).unwrap();
        let seed = [42u8; 32];
        let dkg = DilithiumDkg::new(dkg_config, seed);
        let _adapter = DilithiumDkgAdapter::new(dkg);
    }
}
