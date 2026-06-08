//! Dilithium key resharing implementation.
//!
//! This module provides the key resharing (committee handoff) functionality for
//! threshold Dilithium (ML-DSA-87) keys, wrapping the `qp-rusty-crystals-threshold`
//! resharing protocol in a cait-sith compatible Protocol trait implementation.
//!
//! Key resharing allows changing the participant set while preserving the same
//! public key. This is essential for:
//! - Adding new nodes to the committee
//! - Removing nodes from the committee
//! - Replacing compromised or failed nodes
//! - Proactive security (periodic key refresh)

use crate::config::ParticipantsConfig;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use crate::providers::dilithium::DilithiumSignatureProvider;
use crate::providers::dilithium::{DilithiumKeygenOutput, DilithiumPublicKey, PrivateKeyShare};
use threshold_signatures::participants::Participant;
use threshold_signatures::protocol::{Action, Protocol};

// Import types from qp-rusty-crystals-threshold resharing module
use qp_rusty_crystals_threshold::resharing::{
    Action as ResharingAction, ResharingConfig, ResharingOutput, ResharingProtocol,
};

impl DilithiumSignatureProvider {
    /// Run key resharing as a client (both leader and follower).
    ///
    /// This function handles the committee handoff protocol, allowing the set of
    /// participants to change while preserving the same public key.
    ///
    /// # Arguments
    ///
    /// * `new_threshold` - The threshold for the new committee
    /// * `key_share` - The existing private key share (None if joining as a new party)
    /// * `public_key` - The public key being reshared
    /// * `old_participants` - Configuration of the old committee
    /// * `channel` - Network channel for communication
    ///
    /// # Returns
    ///
    /// A new `DilithiumKeygenOutput` containing the reshared private key share
    /// and the (unchanged) public key.
    pub(super) async fn run_key_resharing_client_internal(
        new_threshold: usize,
        key_share: Option<PrivateKeyShare>,
        public_key: DilithiumPublicKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<DilithiumKeygenOutput> {
        let new_keyshare = KeyResharingComputation {
            new_threshold,
            old_participants: old_participants.participants.iter().map(|p| p.id).collect(),
            old_threshold: old_participants.threshold as usize,
            my_share: key_share,
            public_key: public_key.clone(),
        }
        .perform_leader_centric_computation(
            channel,
            // Resharing may take longer than signing due to multiple rounds
            std::time::Duration::from_secs(120),
        )
        .await?;

        tracing::info!("Dilithium key resharing completed");

        // Verify the public key hasn't changed
        anyhow::ensure!(
            new_keyshare.public_key == public_key,
            "Public key should not change after key resharing"
        );

        Ok(new_keyshare)
    }
}

/// Runs the key resharing protocol for Dilithium.
///
/// This protocol is identical for the leader and the followers.
/// When the set of old participants is the same as the set of new participants
/// then this is equivalent to "key refreshing" (proactive security).
///
/// This function would not succeed if:
///     - the number of participants common between old and new is smaller than
///       the old threshold; or
///     - the threshold is larger than the number of participants.
pub struct KeyResharingComputation {
    /// Threshold for the new committee.
    new_threshold: usize,
    /// Participant IDs of the old committee.
    old_participants: Vec<ParticipantId>,
    /// Threshold of the old committee.
    old_threshold: usize,
    /// Our existing private key share (None if we're a new party joining).
    my_share: Option<PrivateKeyShare>,
    /// The public key being reshared.
    public_key: DilithiumPublicKey,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<DilithiumKeygenOutput> for KeyResharingComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<DilithiumKeygenOutput> {
        let me = channel.my_participant_id();
        let my_id = me.raw();

        // Get new participants from the channel
        let new_participants: Vec<ParticipantId> = channel.participants().to_vec();
        let new_participant_ids: Vec<u32> = new_participants.iter().map(|p| p.raw()).collect();

        // Convert old participants to raw u32 IDs
        let old_participant_ids: Vec<u32> = self.old_participants.iter().map(|p| p.raw()).collect();

        tracing::debug!(
            "Dilithium key resharing: my_id={}, old_threshold={}, old_participants={:?}, \
             new_threshold={}, new_participants={:?}",
            my_id,
            self.old_threshold,
            old_participant_ids,
            self.new_threshold,
            new_participant_ids
        );

        // Create resharing configuration
        let resharing_config = ResharingConfig::new(
            self.my_share,
            self.old_threshold as u32,
            old_participant_ids,
            self.new_threshold as u32,
            new_participant_ids,
            my_id,
            self.public_key.clone(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create resharing config: {}", e))?;

        // Generate fresh entropy for this party's contribution to the session seed.
        // The Mithril resharing protocol requires each old-committee member to contribute
        // independent randomness so that resharing achieves forward secrecy: even if old
        // shares leak later, the per-session randomness used to derive the new shares
        // cannot be reconstructed without this fresh entropy.
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| anyhow::anyhow!("Failed to generate resharing seed: {}", e))?;

        // Derive session nonce from channel ID for SSID computation
        // All participants in the same channel will derive the same nonce
        let session_nonce = channel.derive_attempt_nonce();

        // Create the resharing protocol
        let resharing = ResharingProtocol::new(resharing_config, seed, &session_nonce);

        // Wrap in cait-sith compatible adapter
        let adapter = DilithiumResharingAdapter::new(resharing);

        // Run the protocol
        let output: ResharingOutput =
            run_protocol("dilithium key resharing", channel, adapter).await?;

        // Extract the new private share (will be Some if we're in the new committee)
        let private_share = output
            .private_share
            .ok_or_else(|| anyhow::anyhow!("No private share in resharing output"))?;

        Ok(DilithiumKeygenOutput {
            public_key: output.public_key,
            private_share,
        })
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Adapter that wraps ResharingProtocol to implement the cait-sith Protocol trait.
///
/// This adapter converts between NEAR's cait-sith Participant type and our
/// ParticipantId (u32). The threshold library handles arbitrary participant IDs
/// internally via ParticipantList, so no ID-to-index mapping is needed here.
pub struct DilithiumResharingAdapter {
    inner: ResharingProtocol,
}

impl DilithiumResharingAdapter {
    /// Create a new adapter wrapping a ResharingProtocol.
    pub fn new(resharing: ResharingProtocol) -> Self {
        Self { inner: resharing }
    }
}

impl Protocol for DilithiumResharingAdapter {
    type Output = ResharingOutput;

    fn poke(
        &mut self,
    ) -> Result<Action<Self::Output>, threshold_signatures::errors::ProtocolError> {
        match self.inner.poke() {
            Ok(action) => match action {
                ResharingAction::Wait => Ok(Action::Wait),
                ResharingAction::SendMany(data) => Ok(Action::SendMany(data)),
                ResharingAction::SendPrivate(to_id, data) => {
                    // Convert our ParticipantId (u32) to cait-sith Participant
                    let participant: Participant = Participant::from(to_id);
                    Ok(Action::SendPrivate(participant, data))
                }
                ResharingAction::Return(output) => Ok(Action::Return(output)),
            },
            Err(e) => Err(threshold_signatures::errors::ProtocolError::Other(
                e.to_string(),
            )),
        }
    }

    fn message(&mut self, from: Participant, data: threshold_signatures::protocol::MessageData) {
        // Convert cait-sith Participant to our ParticipantId (u32)
        let from_id: u32 = from.into();
        // The cait-sith Protocol trait's `message` is infallible, so we absorb any
        // deserialization errors here. The protocol will simply timeout waiting for
        // that peer if the message was malformed.
        if let Err(e) = self.inner.message(from_id, data) {
            tracing::warn!(target: "dilithium", "Discarding malformed resharing message from {}: {}", from_id, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::computation::MpcLeaderCentricComputation;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::providers::dilithium::DilithiumTaskId;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use mpc_contract::primitives::domain::DomainId;
    use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};
    use qp_rusty_crystals_threshold::{generate_with_dealer, ThresholdConfig};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[test]
    fn test_dilithium_resharing_adapter_creation() {
        // Test that we can create a resharing adapter with arbitrary NEAR-style IDs
        let threshold_config = ThresholdConfig::new(2, 3).unwrap();
        let seed = [42u8; 32];
        let (public_key, shares) = generate_with_dealer(&seed, threshold_config).unwrap();

        // Use arbitrary IDs like NEAR would
        let old_participants = vec![524342676u32, 1313390130, 3526595269];
        let new_participants = vec![524342676u32, 1313390130, 3526595269]; // Same committee

        let resharing_config = ResharingConfig::new(
            Some(shares[0].clone()),
            2,
            old_participants,
            2,
            new_participants,
            524342676, // my_id
            public_key,
        )
        .unwrap();

        // ResharingProtocol needs a per-party entropy seed for forward secrecy
        let session_nonce = [0xAA; 32]; // Test session nonce
        let resharing = ResharingProtocol::new(resharing_config, [99u8; 32], &session_nonce);
        let _adapter = DilithiumResharingAdapter::new(resharing);
    }

    #[test]
    fn test_resharing_config_with_new_party() {
        // Test creating resharing config when adding a new party
        let threshold_config = ThresholdConfig::new(2, 3).unwrap();
        let seed = [42u8; 32];
        let (public_key, _shares) = generate_with_dealer(&seed, threshold_config).unwrap();

        // Old committee: 3 parties
        let old_participants = vec![100u32, 200, 300];
        // New committee: 4 parties (adding party 400)
        let new_participants = vec![100u32, 200, 300, 400];

        // Party 400 is joining - they have no existing share
        let resharing_config = ResharingConfig::new(
            None,             // no existing share
            2,                // old threshold
            old_participants, // old participants
            2,                // new threshold
            new_participants, // new participants
            400,              // my_id (new party)
            public_key,
        )
        .unwrap();

        // ResharingProtocol requires a per-party entropy seed; for new parties it's
        // unused in entropy aggregation but the constructor still requires it.
        let session_nonce = [0xBB; 32]; // Test session nonce
        let resharing = ResharingProtocol::new(resharing_config, [99u8; 32], &session_nonce);
        let _adapter = DilithiumResharingAdapter::new(resharing);
    }

    #[test]
    fn test_resharing_config_removing_party() {
        // Test creating resharing config when removing a party
        let threshold_config = ThresholdConfig::new(2, 3).unwrap();
        let seed = [42u8; 32];
        let (public_key, shares) = generate_with_dealer(&seed, threshold_config).unwrap();

        // Old committee: 3 parties
        let old_participants = vec![100u32, 200, 300];
        // New committee: 2 parties (removing party 300)
        let new_participants = vec![100u32, 200];

        // Party 100 is staying
        let resharing_config = ResharingConfig::new(
            Some(shares[0].clone()), // existing share
            2,                       // old threshold
            old_participants,        // old participants
            2,                       // new threshold (both remaining parties needed)
            new_participants,        // new participants
            100,                     // my_id
            public_key,
        )
        .unwrap();

        // Per-party entropy seed for forward secrecy
        let session_nonce = [0xCC; 32]; // Test session nonce
        let resharing = ResharingProtocol::new(resharing_config, [99u8; 32], &session_nonce);
        let _adapter = DilithiumResharingAdapter::new(resharing);
    }

    /// Full integration test for Dilithium key resharing using DKG-generated keys.
    /// This test:
    /// 1. Runs DKG to generate keys with proper network participant IDs
    /// 2. Runs resharing to the same committee (key refresh)
    /// 3. Verifies the public key is preserved
    #[tokio::test]
    async fn test_key_resharing_with_dkg() {
        use crate::providers::dilithium::key_generation::DilithiumKeyGenerationComputation;

        const THRESHOLD: usize = 2;
        const NUM_PARTICIPANTS: usize = 3;

        // Use small sequential IDs (0, 1, 2) for the DKG.
        // The DKG now uses ParticipantList for ID-to-index mapping internally.
        let participant_ids: Vec<ParticipantId> = (0..NUM_PARTICIPANTS)
            .map(|i| ParticipantId::from_raw(i as u32))
            .collect();

        // Step 1: Run DKG to generate keys
        let dkg_participant_ids = participant_ids.clone();

        // Generate Ed25519 transcript-signing keys for all participants up front
        // so each runner closure can build a consistent DkgSignerConfig.
        use crate::providers::dilithium::{DkgSignerConfig, Ed25519TranscriptSigner};
        use ed25519_dalek::SigningKey;
        use std::collections::BTreeMap;
        let mut dkg_signing_keys: BTreeMap<u32, SigningKey> = BTreeMap::new();
        let mut dkg_verifying_keys: BTreeMap<u32, ed25519_dalek::VerifyingKey> = BTreeMap::new();
        for pid in &participant_ids {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let vk = sk.verifying_key();
            dkg_signing_keys.insert(pid.raw(), sk);
            dkg_verifying_keys.insert(pid.raw(), vk);
        }
        let dkg_verifying_keys_for_dkg = dkg_verifying_keys.clone();

        let dkg_client_runner = move |client: Arc<MeshNetworkClient>,
                                      mut channel_receiver: mpsc::UnboundedReceiver<
            NetworkTaskChannel,
        >| {
            let participant_id = client.my_participant_id();
            let all_participant_ids = client.all_participant_ids();
            let key_id = KeyEventId::new(
                EpochId::new(1),
                DomainId(99), // Dilithium domain
                AttemptId::legacy_attempt_id(),
            );

            // Build the DKG signer config for this party using the test-generated keys
            let my_signing_key = dkg_signing_keys
                .get(&participant_id.raw())
                .expect("missing test signing key for participant")
                .clone();
            let signer_config = DkgSignerConfig::new(
                my_signing_key,
                dkg_verifying_keys_for_dkg.clone(),
            );

            async move {
                let channel = if participant_id == all_participant_ids[0] {
                    client.new_channel_for_task(
                        DilithiumTaskId::KeyGeneration { key_event: key_id },
                        client.all_participant_ids(),
                    )?
                } else {
                    channel_receiver
                        .recv()
                        .await
                        .ok_or_else(|| anyhow::anyhow!("No channel"))?
                };

                let key = DilithiumKeyGenerationComputation {
                    threshold: THRESHOLD,
                    signer_config,
                }
                .perform_leader_centric_computation(channel, std::time::Duration::from_secs(120))
                .await?;

                anyhow::Ok(key)
            }
        };

        // Run DKG and collect results
        let dkg_results: Vec<super::DilithiumKeygenOutput> =
            start_root_task_with_periodic_dump(async move {
                run_test_clients(dkg_participant_ids, dkg_client_runner)
                    .await
                    .unwrap()
            })
            .await;

        // Verify DKG succeeded and all parties have the same public key
        assert_eq!(dkg_results.len(), NUM_PARTICIPANTS);
        let public_key = dkg_results[0].public_key.clone();
        for result in &dkg_results {
            assert_eq!(result.public_key, public_key);
        }

        // Create a map from participant ID to their DKG output
        let keygen_by_id: std::collections::HashMap<ParticipantId, super::DilithiumKeygenOutput> =
            participant_ids
                .iter()
                .zip(dkg_results.into_iter())
                .map(|(&id, output)| (id, output))
                .collect();

        // Step 2: Run resharing to the same committee
        let resharing_participant_ids = participant_ids.clone();
        let old_participant_ids = participant_ids.clone();
        let expected_public_key = public_key.clone();

        let resharing_client_runner = move |client: Arc<MeshNetworkClient>,
                                            mut channel_receiver: mpsc::UnboundedReceiver<
            NetworkTaskChannel,
        >| {
            let participant_id = client.my_participant_id();
            let all_participant_ids = client.all_participant_ids();
            let my_keygen = keygen_by_id.get(&participant_id).cloned();
            let my_share = my_keygen.map(|k| k.private_share);
            let pubkey = public_key.clone();
            let old_participants = old_participant_ids.clone();
            let key_id = KeyEventId::new(
                EpochId::new(2), // New epoch for resharing
                DomainId(99),
                AttemptId::legacy_attempt_id(),
            );

            async move {
                let channel = if participant_id == all_participant_ids[0] {
                    client.new_channel_for_task(
                        DilithiumTaskId::KeyResharing { key_event: key_id },
                        client.all_participant_ids(),
                    )?
                } else {
                    channel_receiver
                        .recv()
                        .await
                        .ok_or_else(|| anyhow::anyhow!("No channel"))?
                };

                let key = KeyResharingComputation {
                    new_threshold: THRESHOLD,
                    old_participants,
                    old_threshold: THRESHOLD,
                    my_share,
                    public_key: pubkey,
                }
                .perform_leader_centric_computation(channel, std::time::Duration::from_secs(120))
                .await?;

                anyhow::Ok(key)
            }
        };

        // Run resharing
        start_root_task_with_periodic_dump(async move {
            let results = run_test_clients(resharing_participant_ids, resharing_client_runner)
                .await
                .unwrap();

            // Verify resharing succeeded and public key is preserved
            assert_eq!(results.len(), NUM_PARTICIPANTS);
            for result in &results {
                assert_eq!(
                    result.public_key, expected_public_key,
                    "Public key must not change after resharing"
                );
            }
            println!(
                "Dilithium key resharing (DKG keys) test passed: {} parties reshared successfully",
                results.len()
            );
        })
        .await;
    }
}
