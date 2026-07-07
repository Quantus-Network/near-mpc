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
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::key_state::KeyEventId;
use mpc_contract::primitives::signature::Tweak;
use qp_rusty_crystals_threshold::keygen::dkg::TranscriptSigner;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

// Re-export types from qp-rusty-crystals-threshold
pub use qp_rusty_crystals_threshold::Signature as DilithiumSignature;
pub use qp_rusty_crystals_threshold::{PrivateKeyShare, PublicKey as DilithiumPublicKey};

// Re-export key registration types
pub use key_registration::DerivedKeyId;

// ============================================================================
// Ed25519 Transcript Signer
// ============================================================================

/// Wrapper type for Ed25519 signatures that implements AsRef<[u8]>.
///
/// The threshold library requires signatures to implement `AsRef<[u8]>` for serialization,
/// but `ed25519_dalek::Signature` doesn't implement this trait directly.
/// We store the raw bytes to satisfy the AsRef requirement.
#[derive(Clone)]
pub struct Ed25519SignatureWrapper {
    bytes: [u8; 64],
}

impl AsRef<[u8]> for Ed25519SignatureWrapper {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Ed25519Signature> for Ed25519SignatureWrapper {
    fn from(sig: Ed25519Signature) -> Self {
        Self {
            bytes: sig.to_bytes(),
        }
    }
}

/// Ed25519-based transcript signer for Mithril DKG.
///
/// Uses the node's P2P Ed25519 key to sign DKG transcripts.
/// This provides authentication during key generation without requiring
/// pre-existing Dilithium keys (solving the bootstrapping problem).
///
/// # Domain separation
///
/// The same `SigningKey` is also used for TLS, libp2p peer identity, and
/// migration handshakes (see `PersistentSecrets::p2p_private_key`). To prevent
/// any cross-protocol signature confusion — e.g. a TLS or libp2p signature
/// being replayable as a DKG-transcript signature, or vice versa — every
/// payload passed to `ed25519_dalek` is prefixed with a fixed protocol /
/// version tag before signing or verifying. Other consumers of the same key
/// do not use this prefix, so the byte strings actually signed in each
/// protocol are disjoint by construction.
///
/// **Versioning:** the prefix carries an explicit version (`v1`). Any future
/// change to the transcript bytes, or to the signing-key derivation, MUST bump
/// the version so old and new signatures cannot be cross-verified.
#[derive(Clone)]
pub struct Ed25519TranscriptSigner {
    signing_key: SigningKey,
}

/// Domain-separation prefix for DKG transcript signatures.
/// Prepended to the 32-byte transcript hash before signing/verifying.
/// MUST be bumped if the transcript format or signing-key derivation ever changes.
const DKG_TRANSCRIPT_SIG_DOMAIN: &[u8] = b"qp-dilithium-dkg-transcript-v1";

/// Build the bytes actually fed to `ed25519_dalek` from a transcript hash.
fn dkg_transcript_sig_payload(transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(DKG_TRANSCRIPT_SIG_DOMAIN.len() + 32);
    payload.extend_from_slice(DKG_TRANSCRIPT_SIG_DOMAIN);
    payload.extend_from_slice(transcript_hash);
    payload
}

impl Ed25519TranscriptSigner {
    /// Create a new transcript signer from an Ed25519 signing key.
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

impl TranscriptSigner for Ed25519TranscriptSigner {
    type Signature = Ed25519SignatureWrapper;
    type PublicKey = VerifyingKey;

    fn sign(&self, transcript_hash: &[u8; 32]) -> Self::Signature {
        let payload = dkg_transcript_sig_payload(transcript_hash);
        Ed25519SignatureWrapper::from(self.signing_key.sign(&payload))
    }

    fn verify(
        public_key: &Self::PublicKey,
        transcript_hash: &[u8; 32],
        signature: &Self::Signature,
    ) -> bool {
        let payload = dkg_transcript_sig_payload(transcript_hash);
        let sig = Ed25519Signature::from_bytes(&signature.bytes);
        public_key.verify(&payload, &sig).is_ok()
    }

    fn verify_bytes(
        public_key: &Self::PublicKey,
        transcript_hash: &[u8; 32],
        signature_bytes: &[u8],
    ) -> bool {
        if signature_bytes.len() != 64 {
            return false;
        }
        let Ok(sig_bytes): Result<[u8; 64], _> = signature_bytes.try_into() else {
            return false;
        };
        let signature = Ed25519Signature::from_bytes(&sig_bytes);
        let payload = dkg_transcript_sig_payload(transcript_hash);
        public_key.verify(&payload, &signature).is_ok()
    }

    fn public_key(&self) -> Self::PublicKey {
        self.signing_key.verifying_key()
    }
}

/// Configuration for transcript signing in Dilithium DKG.
///
/// Contains this party's Ed25519 signing key and public keys of all participants.
#[derive(Clone)]
pub struct DkgSignerConfig {
    /// This party's Ed25519 signer for transcript authentication
    pub my_signer: Ed25519TranscriptSigner,
    /// Public keys of all participants (keyed by raw ParticipantId)
    pub participant_public_keys: BTreeMap<u32, VerifyingKey>,
}

impl DkgSignerConfig {
    /// Create a new DKG signer configuration.
    pub fn new(
        my_signing_key: SigningKey,
        participant_public_keys: BTreeMap<u32, VerifyingKey>,
    ) -> Self {
        Self {
            my_signer: Ed25519TranscriptSigner::new(my_signing_key),
            participant_public_keys,
        }
    }
}

/// Keygen output for Dilithium threshold signatures.
///
/// Uses borsh for internal serialization, with a custom serde implementation
/// that wraps the borsh bytes. This allows integration with near-mpc's
/// serde-based keyshare storage while the threshold crate uses borsh.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DilithiumKeygenOutput {
    pub public_key: DilithiumPublicKey,
    pub private_share: PrivateKeyShare,
}

// Custom serde implementation that serializes as borsh bytes
impl Serialize for DilithiumKeygenOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = borsh::to_vec(self).map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for DilithiumKeygenOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = DilithiumKeygenOutput;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("borsh-encoded DilithiumKeygenOutput bytes")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                borsh::from_slice(v).map_err(serde::de::Error::custom)
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                borsh::from_slice(&v).map_err(serde::de::Error::custom)
            }

            // Also handle seq for JSON compatibility (bytes often serialize as arrays)
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = Vec::new();
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                borsh::from_slice(&bytes).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
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
    /// Signer configuration for DKG transcript signing (used in key registration).
    /// Always present — the coordinator builds it from the node's P2P key on startup.
    dkg_signer_config: DkgSignerConfig,
}

impl DilithiumSignatureProvider {
    /// Create a new Dilithium signature provider.
    ///
    /// This constructor loads any existing derived keyshares from persistent storage
    /// into the in-memory cache for fast access during signing.
    ///
    /// # Arguments
    /// * `dkg_signer_config` - Signer config for DKG transcript signing (used in key registration)
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<crate::network::MeshNetworkClient>,
        sign_request_store: Arc<SignRequestStorage>,
        keyshares: HashMap<DomainId, DilithiumKeygenOutput>,
        derived_share_storage: Arc<DilithiumDerivedShareStorage>,
        dkg_signer_config: DkgSignerConfig,
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
            dkg_signer_config,
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
        _threshold: usize,
        _channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        // This trait method is never called for Dilithium; the keygen path goes
        // directly through `run_key_generation_client_internal`, which takes the
        // additional `DkgSignerConfig` argument that the trait signature cannot
        // express. Compare `VerifyForeignTxProvider`, which uses the same pattern.
        anyhow::bail!(
            "this method is never called; Dilithium keygen uses run_key_generation_client_internal"
        )
    }

    async fn run_key_resharing_client(
        _new_threshold: usize,
        _key_share: Option<PrivateKeyShare>,
        _public_key: DilithiumPublicKey,
        _old_participants: &ParticipantsConfig,
        _channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        // This trait method is never called for Dilithium; the resharing path
        // goes directly through `run_key_resharing_client_internal`, which
        // takes the additional `DkgSignerConfig` and `epoch` arguments that
        // the trait signature cannot express. Same pattern as keygen above.
        anyhow::bail!(
            "this method is never called; Dilithium resharing uses run_key_resharing_client_internal"
        )
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
                    self.handle_key_registration_as_follower(
                        channel,
                        id,
                        self.dkg_signer_config.clone(),
                    )
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

    /// The DKG-transcript-signing key is reused as the node's P2P/TLS key.
    /// Domain separation ensures that a signature produced for some other
    /// protocol's payload (with the same 32-byte shape) cannot be replayed
    /// as a DKG-transcript signature, and vice versa.
    #[test]
    fn dkg_transcript_signature_is_domain_separated() {
        use ed25519_dalek::Signer;
        let mut rng = rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();

        let transcript_hash = [0xABu8; 32];

        // A signature produced by Ed25519TranscriptSigner is a signature over
        // the DOMAIN-PREFIXED payload, not the bare 32-byte hash.
        let signer = Ed25519TranscriptSigner::new(sk.clone());
        let dkg_sig = signer.sign(&transcript_hash);

        // It must verify through the trait (which applies the same prefix on
        // verify), but must NOT verify against the bare hash bytes.
        assert!(Ed25519TranscriptSigner::verify(&vk, &transcript_hash, &dkg_sig));
        let raw_sig = Ed25519Signature::from_bytes(&dkg_sig.bytes);
        assert!(
            vk.verify(&transcript_hash, &raw_sig).is_err(),
            "DKG transcript sig must NOT verify against bare hash bytes (domain separation broken)"
        );

        // Conversely, a signature produced by signing the bare 32-byte hash
        // with the SAME key (i.e. some other protocol that happened to pick
        // the same shape) must NOT verify as a DKG-transcript signature.
        let cross_protocol_sig = sk.sign(&transcript_hash);
        let wrapped = Ed25519SignatureWrapper::from(cross_protocol_sig);
        assert!(
            !Ed25519TranscriptSigner::verify(&vk, &transcript_hash, &wrapped),
            "Cross-protocol signature over bare hash must NOT verify as a DKG-transcript signature"
        );
        assert!(!Ed25519TranscriptSigner::verify_bytes(
            &vk,
            &transcript_hash,
            &cross_protocol_sig.to_bytes()
        ));
    }
}
