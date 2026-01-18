//! Dilithium (ML-DSA-87) Signature Provider for NEAR MPC.
//!
//! This module provides threshold Dilithium signatures using the
//! `qp-rusty-crystals-threshold` crate.
//!
//! ## Key Derivation: Dilithium vs ECC
//!
//! A critical difference between Dilithium and ECC-based schemes (Secp256k1, Ed25519)
//! is how key derivation works:
//!
//! ### ECC (Linear Derivation)
//! - Derivation is algebraically linear: `derived_share = master_share + tweak`
//! - The tweak can be applied **during signing** without pre-registration
//! - No DKG required for derived keys
//!
//! ### Dilithium (Non-Linear Derivation)
//! - Derivation is **NOT** linear - there's no simple algebraic relationship
//! - Each derived key requires a **full DKG** to generate shares
//! - Users MUST call `register_dilithium_key` before signing
//! - Signing without a registered derived key will **fail** (not fall back to master)
//!
//! This design ensures:
//! 1. Security: Using the master share would produce signatures for the wrong public key
//! 2. Consistency: On-chain verification uses the derived public key stored during registration
//! 3. Correctness: The contract enforces registration before signing via `DilithiumKeyNotRegistered`
//!
//! ## Persistence
//!
//! Derived keyshares are persisted to the database via `DilithiumDerivedShareStorage`.
//! On startup, the provider loads all existing derived shares from disk. After DKG
//! completes for a new derived key, it is immediately persisted.

mod key_generation;
mod key_registration;
mod key_resharing;
mod sign;

use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::network::NetworkTaskChannel;
use crate::primitives::MpcTaskId;
use crate::providers::SignatureProvider;
use crate::storage::{DilithiumDerivedShareStorage, SignRequestStorage};
use crate::types::SignatureId;
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::KeyEventId;
use mpc_contract::primitives::signature::Tweak;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Re-export types from qp-rusty-crystals-threshold
pub use qp_rusty_crystals_threshold::Signature as DilithiumSignature;
pub use qp_rusty_crystals_threshold::{PrivateKeyShare, PublicKey as DilithiumPublicKey};

// Re-export key registration types
pub use key_registration::DerivedKeyId;

/// Keygen output for Dilithium threshold signatures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DilithiumKeygenOutput {
    pub public_key: DilithiumPublicKey,
    pub private_share: PrivateKeyShare,
}

/// Unique identifier for a key registration request.
///
/// Contains the full 32-byte tweak since it's public information and
/// needed by followers to derive the correct DKG seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct KeyRegistrationId {
    /// The domain ID
    pub domain_id: DomainId,
    /// The full derivation tweak (32 bytes)
    pub tweak: [u8; 32],
}

impl KeyRegistrationId {
    pub fn new(domain_id: DomainId, tweak: &Tweak) -> Self {
        Self {
            domain_id,
            tweak: tweak.as_bytes(),
        }
    }
}

/// The Dilithium signature provider.
#[derive(Clone)]
pub struct DilithiumSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<crate::network::MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    /// Master keyshares indexed by domain ID
    keyshares: HashMap<DomainId, DilithiumKeygenOutput>,
    /// Derived keyshares indexed by (domain_id, tweak)
    /// These are generated via DKG when users call register_dilithium_key.
    /// This is an in-memory cache; derived shares are also persisted to `derived_share_storage`.
    derived_shares: Arc<RwLock<HashMap<DerivedKeyId, DilithiumKeygenOutput>>>,
    /// Persistent storage for derived keyshares
    derived_share_storage: Arc<DilithiumDerivedShareStorage>,
}

impl DilithiumSignatureProvider {
    /// Create a new Dilithium signature provider.
    ///
    /// This constructor loads any existing derived keyshares from persistent storage
    /// into the in-memory cache for fast access during signing.
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<crate::network::MeshNetworkClient>,
        sign_request_store: Arc<SignRequestStorage>,
        keyshares: HashMap<DomainId, DilithiumKeygenOutput>,
        derived_share_storage: Arc<DilithiumDerivedShareStorage>,
    ) -> Self {
        // Load existing derived shares from persistent storage
        let mut derived_shares_map = HashMap::new();
        for domain_id in keyshares.keys() {
            match derived_share_storage.load_all_for_domain(*domain_id) {
                Ok(shares) => {
                    for (id, output) in shares {
                        tracing::info!(
                            "Loaded derived Dilithium share for domain {:?} from storage",
                            id.domain_id
                        );
                        derived_shares_map.insert(id, output);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load derived shares for domain {:?}: {}",
                        domain_id,
                        e
                    );
                }
            }
        }

        if !derived_shares_map.is_empty() {
            tracing::info!(
                "Loaded {} derived Dilithium shares from storage",
                derived_shares_map.len()
            );
        }

        Self {
            config,
            mpc_config,
            client,
            sign_request_store,
            keyshares,
            derived_shares: Arc::new(RwLock::new(derived_shares_map)),
            derived_share_storage,
        }
    }

    /// Get a derived keyshare by its ID.
    pub fn get_derived_share(&self, id: &DerivedKeyId) -> Option<DilithiumKeygenOutput> {
        self.derived_shares.read().unwrap().get(id).cloned()
    }

    /// Store a derived keyshare in both memory and persistent storage.
    pub fn store_derived_share(&self, id: DerivedKeyId, output: DilithiumKeygenOutput) {
        // Persist to database first
        if let Err(e) = self.derived_share_storage.store(&id, &output) {
            tracing::error!(
                "Failed to persist derived Dilithium share for domain {:?}: {}",
                id.domain_id,
                e
            );
            // Continue anyway - at least store in memory
        }

        // Store in memory cache
        self.derived_shares.write().unwrap().insert(id, output);
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
    /// Key registration task (derived key DKG).
    KeyRegistration { id: KeyRegistrationId },
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
                DilithiumTaskId::KeyRegistration { id } => {
                    // Handle key registration as follower
                    self.handle_key_registration_as_follower(channel, id)
                        .await?;
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

    #[test]
    fn test_key_registration_id() {
        let domain_id = DomainId(5);
        let tweak = Tweak::new([42u8; 32]);

        let id = KeyRegistrationId::new(domain_id, &tweak);

        assert_eq!(id.domain_id, domain_id);
        assert_eq!(id.tweak, [42u8; 32]);
    }

    #[test]
    fn test_key_registration_task_id_serialization() {
        let reg_id = KeyRegistrationId {
            domain_id: DomainId(5),
            tweak: [1u8; 32],
        };
        let task_id = DilithiumTaskId::KeyRegistration { id: reg_id };

        // Test serialization round-trip
        let serialized = borsh::to_vec(&task_id).unwrap();
        let deserialized: DilithiumTaskId = borsh::from_slice(&serialized).unwrap();
        assert_eq!(task_id, deserialized);
    }
}
