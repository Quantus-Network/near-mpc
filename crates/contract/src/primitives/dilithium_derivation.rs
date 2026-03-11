//! Dilithium key derivation primitives.
//!
//! This module contains types for Dilithium derived key registration and storage.
//! Unlike ECC schemes where derived keys can be computed on-the-fly using linear
//! derivation (derived_key = master_key + tweak), Dilithium requires a full DKG
//! protocol for each derived key. This module provides the types needed to:
//!
//! 1. Register a derived key (triggers full DKG among MPC nodes)
//! 2. Store the resulting public key in the contract
//! 3. Look up derived keys for signing

use crate::primitives::domain::DomainId;
use crate::primitives::signature::Tweak;
use contract_interface::types as dtos;
use near_account_id::AccountId;
use near_sdk::near;
use sha3::{Digest, Sha3_256};

/// Domain separator for NEAR MPC Dilithium tweak derivation.
/// This is different from the ECC domain separator to ensure derived keys
/// are independent across schemes.
const DILITHIUM_TWEAK_DERIVATION_PREFIX: &str = "near-mpc-dilithium v1.0 derivation:";

/// Derive a tweak for Dilithium key derivation.
///
/// This follows the same pattern as ECC derivation but with a Dilithium-specific
/// domain separator to ensure derived keys are independent across schemes.
///
/// # Arguments
/// * `predecessor_id` - The NEAR account ID requesting the derivation
/// * `path` - The derivation path (e.g., "ethereum", "bitcoin/0")
///
/// # Returns
/// A `Tweak` containing the 32-byte derived value
pub fn derive_dilithium_tweak(predecessor_id: &AccountId, path: &str) -> Tweak {
    // Use length-prefixed encoding to prevent ambiguity
    // Format: prefix || len(account_id) as u32 || account_id || path
    // This ensures "alice,near" + "eth" differs from "alice" + "near,eth"
    let account_len = predecessor_id.as_str().len() as u32;

    let mut hasher = Sha3_256::new();
    hasher.update(DILITHIUM_TWEAK_DERIVATION_PREFIX.as_bytes());
    hasher.update(account_len.to_le_bytes());
    hasher.update(predecessor_id.as_str().as_bytes());
    hasher.update(path.as_bytes());

    let result: [u8; 32] = hasher.finalize().into();
    Tweak::new(result)
}

/// Identifier for a derived Dilithium key, indexed by tweak.
///
/// The tweak is deterministically derived from (account_id, path), so this single
/// index supports both user queries (via `get_dilithium_derived_key_info`) and
/// signature verification in `respond()`.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[near(serializers=[borsh, json])]
pub struct DilithiumTweakKeyId {
    /// The derivation tweak
    pub tweak: Tweak,
    /// The domain ID
    pub domain_id: DomainId,
}

impl DilithiumTweakKeyId {
    /// Create a new tweak-based key identifier.
    pub fn new(tweak: Tweak, domain_id: DomainId) -> Self {
        Self { tweak, domain_id }
    }

    /// Create from a key registration.
    pub fn from_registration(registration: &DilithiumKeyRegistration) -> Self {
        Self {
            tweak: registration.tweak.clone(),
            domain_id: registration.domain_id,
        }
    }
}

/// Request to register a Dilithium derived key.
///
/// This is stored in `pending_dilithium_key_requests` while the MPC nodes
/// run DKG to generate the derived key.
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[near(serializers=[borsh, json])]
pub struct DilithiumKeyRegistration {
    /// The derivation tweak (derived from account + path)
    pub tweak: Tweak,
    /// The domain ID (identifies the master key)
    pub domain_id: DomainId,
    /// The account requesting registration
    pub account_id: AccountId,
    /// The derivation path
    pub path: String,
}

impl DilithiumKeyRegistration {
    /// Create a new key registration request.
    pub fn new(predecessor_id: &AccountId, path: &str, domain_id: DomainId) -> Self {
        let tweak = derive_dilithium_tweak(predecessor_id, path);
        Self {
            tweak,
            domain_id,
            account_id: predecessor_id.clone(),
            path: path.to_string(),
        }
    }
}

/// Arguments for the `register_dilithium_key` endpoint.
#[derive(Clone, Debug)]
#[near(serializers=[json])]
pub struct RegisterDilithiumKeyArgs {
    /// The derivation path (e.g., "ethereum", "bitcoin/0")
    pub path: String,
    /// The domain ID (must be a Dilithium domain)
    pub domain_id: DomainId,
}

/// Response containing the derived public key.
///
/// Returned by MPC nodes after DKG completes.
#[derive(Clone, Debug)]
#[near(serializers=[borsh, json])]
pub struct DilithiumKeyResponse {
    /// The derived Dilithium public key (2592 bytes for ML-DSA-87)
    pub public_key: dtos::DilithiumPublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_dilithium_tweak_deterministic() {
        let account_id: AccountId = "alice.near".parse().unwrap();
        let path = "ethereum";

        let tweak1 = derive_dilithium_tweak(&account_id, path);
        let tweak2 = derive_dilithium_tweak(&account_id, path);

        assert_eq!(tweak1.as_bytes(), tweak2.as_bytes());
    }

    #[test]
    fn test_derive_dilithium_tweak_different_accounts() {
        let alice: AccountId = "alice.near".parse().unwrap();
        let bob: AccountId = "bob.near".parse().unwrap();
        let path = "ethereum";

        let tweak_alice = derive_dilithium_tweak(&alice, path);
        let tweak_bob = derive_dilithium_tweak(&bob, path);

        assert_ne!(tweak_alice.as_bytes(), tweak_bob.as_bytes());
    }

    #[test]
    fn test_derive_dilithium_tweak_different_paths() {
        let account_id: AccountId = "alice.near".parse().unwrap();

        let tweak_eth = derive_dilithium_tweak(&account_id, "ethereum");
        let tweak_btc = derive_dilithium_tweak(&account_id, "bitcoin");

        assert_ne!(tweak_eth.as_bytes(), tweak_btc.as_bytes());
    }

    #[test]
    fn test_derive_dilithium_tweak_no_collision() {
        // Ensure length-prefixed encoding prevents collisions
        let account1: AccountId = "alice".parse().unwrap();
        let account2: AccountId = "alic".parse().unwrap();

        let tweak1 = derive_dilithium_tweak(&account1, "eth");
        let tweak2 = derive_dilithium_tweak(&account2, "eeth");

        assert_ne!(tweak1.as_bytes(), tweak2.as_bytes());
    }

    #[test]
    fn test_dilithium_tweak_key_id() {
        let account_id: AccountId = "alice.near".parse().unwrap();
        let path = "ethereum";
        let domain_id = DomainId(5);

        let tweak = derive_dilithium_tweak(&account_id, path);
        let tweak_id = DilithiumTweakKeyId::new(tweak.clone(), domain_id);

        // Same tweak and domain should be equal
        let tweak_id2 = DilithiumTweakKeyId::new(tweak, domain_id);
        assert_eq!(tweak_id, tweak_id2);

        // Different domain should not be equal
        let tweak3 = derive_dilithium_tweak(&account_id, path);
        let tweak_id3 = DilithiumTweakKeyId::new(tweak3, DomainId(6));
        assert_ne!(tweak_id, tweak_id3);
    }

    #[test]
    fn test_dilithium_tweak_key_id_from_registration() {
        let account_id: AccountId = "alice.near".parse().unwrap();
        let path = "ethereum";
        let domain_id = DomainId(5);

        let registration = DilithiumKeyRegistration::new(&account_id, path, domain_id);
        let tweak_id = DilithiumTweakKeyId::from_registration(&registration);

        assert_eq!(tweak_id.tweak, registration.tweak);
        assert_eq!(tweak_id.domain_id, domain_id);
    }
}
