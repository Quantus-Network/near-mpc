//! Dilithium (ML-DSA-87) Signature Provider for NEAR MPC.
//!
//! This module provides threshold Dilithium signatures using the
//! `qp-rusty-crystals-threshold` crate.

mod key_generation;
mod key_resharing;
mod sign;

use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::network::NetworkTaskChannel;
use crate::primitives::MpcTaskId;
use crate::providers::SignatureProvider;
use crate::storage::SignRequestStorage;
use crate::types::SignatureId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::KeyEventId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// Re-export types from qp-rusty-crystals-threshold
pub use qp_rusty_crystals_threshold::Signature as DilithiumSignature;
pub use qp_rusty_crystals_threshold::{PrivateKeyShare, PublicKey as DilithiumPublicKey};

/// Keygen output for Dilithium threshold signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DilithiumKeygenOutput {
    pub public_key: DilithiumPublicKey,
    pub private_share: PrivateKeyShare,
}

/// The Dilithium signature provider.
#[derive(Clone)]
pub struct DilithiumSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<crate::network::MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    keyshares: HashMap<DomainId, DilithiumKeygenOutput>,
}

impl DilithiumSignatureProvider {
    /// Create a new Dilithium signature provider.
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<crate::network::MeshNetworkClient>,
        sign_request_store: Arc<SignRequestStorage>,
        keyshares: HashMap<DomainId, DilithiumKeygenOutput>,
    ) -> Self {
        Self {
            config,
            mpc_config,
            client,
            sign_request_store,
            keyshares,
        }
    }
}

/// Task identifiers for Dilithium MPC operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum DilithiumTaskId {
    /// Key generation task.
    KeyGeneration { key_event: KeyEventId },
    /// Key resharing task.
    KeyResharing { key_event: KeyEventId },
    /// Signature task.
    Signature { id: SignatureId },
}

impl From<DilithiumTaskId> for MpcTaskId {
    fn from(value: DilithiumTaskId) -> Self {
        MpcTaskId::DilithiumTaskId(value)
    }
}

impl SignatureProvider for DilithiumSignatureProvider {
    type PublicKey = DilithiumPublicKey;
    type SecretShare = PrivateKeyShare;
    type KeygenOutput = DilithiumKeygenOutput;
    type Signature = DilithiumSignature;
    type TaskId = DilithiumTaskId;

    async fn make_signature(
        &self,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        self.make_signature_leader(id).await
    }

    async fn run_key_generation_client(
        threshold: usize,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        Self::run_key_generation_client_internal(threshold, channel).await
    }

    async fn run_key_resharing_client(
        new_threshold: usize,
        key_share: Option<PrivateKeyShare>,
        public_key: DilithiumPublicKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        Self::run_key_resharing_client_internal(
            new_threshold,
            key_share,
            public_key,
            old_participants,
            channel,
        )
        .await
    }

    async fn process_channel(&self, channel: NetworkTaskChannel) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::DilithiumTaskId(task) => match task {
                DilithiumTaskId::KeyGeneration { .. } => {
                    anyhow::bail!("Key generation rejected in normal node operation");
                }
                DilithiumTaskId::KeyResharing { .. } => {
                    anyhow::bail!("Key resharing rejected in normal node operation");
                }
                DilithiumTaskId::Signature { id } => {
                    self.make_signature_follower(channel, id).await?;
                }
            },
            _ => anyhow::bail!(
                "dilithium task handler: received unexpected task id: {:?}",
                channel.task_id()
            ),
        }

        Ok(())
    }

    async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()> {
        // Dilithium doesn't need presignatures like ECDSA
        Ok(())
    }
}

/// Conversion trait for Dilithium public keys to contract interface types.
impl crate::providers::PublicKeyConversion for DilithiumPublicKey {
    #[cfg(test)]
    fn to_near_sdk_public_key(&self) -> anyhow::Result<near_sdk::PublicKey> {
        // NEAR SDK doesn't have a Dilithium curve type, so we can't convert directly
        anyhow::bail!("Cannot convert Dilithium public key to near_sdk::PublicKey")
    }

    fn from_near_sdk_public_key(_public_key: &near_sdk::PublicKey) -> anyhow::Result<Self> {
        // NEAR SDK doesn't have a Dilithium curve type
        anyhow::bail!("Cannot convert near_sdk::PublicKey to Dilithium public key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_task_id_serialization() {
        use mpc_contract::primitives::domain::DomainId;
        use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};

        let key_event =
            KeyEventId::new(EpochId::new(1), DomainId(5), AttemptId::legacy_attempt_id());
        let task_id = DilithiumTaskId::KeyGeneration { key_event };

        // Test serialization round-trip
        let serialized = borsh::to_vec(&task_id).unwrap();
        let deserialized: DilithiumTaskId = borsh::from_slice(&serialized).unwrap();
        assert_eq!(task_id, deserialized);
    }

    #[test]
    fn test_dilithium_task_id_to_mpc_task_id() {
        let task_id = DilithiumTaskId::Signature {
            id: Default::default(),
        };
        let mpc_task_id: MpcTaskId = task_id.into();
        assert!(matches!(mpc_task_id, MpcTaskId::DilithiumTaskId(_)));
    }
}
