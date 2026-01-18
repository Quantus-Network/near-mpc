use crate::db::{DBCol, SecretDB};
use crate::metrics;
use crate::providers::dilithium::{DerivedKeyId, DilithiumKeygenOutput};
use crate::types::{CKDId, CKDRequest};
use crate::types::{DilithiumKeyRegistrationId, DilithiumKeyRegistrationRequest};
use crate::types::{SignatureId, SignatureRequest};
use mpc_contract::primitives::domain::DomainId;
use std::sync::Arc;
use tokio::sync::broadcast;

pub struct SignRequestStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<SignatureId>,
}

impl SignRequestStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(500);
        Ok(Self { db, add_sender: tx })
    }

    /// If given request is already in the database, returns false.
    /// Otherwise, inserts the request and returns true.
    pub fn add(&self, request: &SignatureRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        if self
            .db
            .get(DBCol::SignRequest, &key)
            .expect("Unrecoverable error reading from database")
            .is_some()
        {
            return false;
        }
        let value_ser = serde_json::to_vec(&request).unwrap();
        let mut update = self.db.update();
        update.put(DBCol::SignRequest, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        let _ = self.add_sender.send(request.id);
        true
    }

    /// Blocks until a signature request with given id is present, then returns it.
    /// This behavior is necessary because a peer might initiate computation for a signature
    /// request before our indexer has caught up to the request. We need proof of the request
    /// from on-chain in order to participate in the computation.
    pub async fn get(&self, id: SignatureId) -> Result<SignatureRequest, anyhow::Error> {
        let key = borsh::to_vec(&id)?;
        let mut rx = self.add_sender.subscribe();
        if let Some(request_ser) = self.db.get(DBCol::SignRequest, &key)? {
            return Ok(serde_json::from_slice(&request_ser)?);
        }
        loop {
            let added_id = match rx.recv().await {
                Ok(added_id) => added_id,
                Err(e) => match e {
                    broadcast::error::RecvError::Closed => {
                        metrics::SIGN_REQUEST_CHANNEL_FAILED.inc();
                        return Err(anyhow::anyhow!("Error in sign_request channel recv, {e}"));
                    }
                    broadcast::error::RecvError::Lagged(msg_n) => {
                        tracing::info!("{msg_n} messages lagged during sign_request channel recv");
                        continue;
                    }
                },
            };
            if added_id == id {
                break;
            }
        }
        let request_ser = self.db.get(DBCol::SignRequest, &key)?.unwrap();
        Ok(serde_json::from_slice(&request_ser)?)
    }
}

pub struct CKDRequestStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<CKDId>,
}

impl CKDRequestStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(500);
        Ok(Self { db, add_sender: tx })
    }

    /// If given request is already in the database, returns false.
    /// Otherwise, inserts the request and returns true.
    pub fn add(&self, request: &CKDRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        if self
            .db
            .get(DBCol::CKDRequest, &key)
            .expect("Unrecoverable error reading from database")
            .is_some()
        {
            return false;
        }
        let value_ser = serde_json::to_vec(&request).unwrap();
        let mut update = self.db.update();
        update.put(DBCol::CKDRequest, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        let _ = self.add_sender.send(request.id);
        true
    }

    /// Blocks until a ckd request with given id is present, then returns it.
    /// This behavior is necessary because a peer might initiate computation for a ckd
    /// request before our indexer has caught up to the request. We need proof of the request
    /// from on-chain in order to participate in the computation.
    pub async fn get(&self, id: CKDId) -> Result<CKDRequest, anyhow::Error> {
        let key = borsh::to_vec(&id)?;
        let mut rx = self.add_sender.subscribe();
        if let Some(request_ser) = self.db.get(DBCol::CKDRequest, &key)? {
            return Ok(serde_json::from_slice(&request_ser)?);
        }
        loop {
            let added_id = match rx.recv().await {
                Ok(added_id) => added_id,
                Err(e) => match e {
                    broadcast::error::RecvError::Closed => {
                        metrics::CKD_REQUEST_CHANNEL_FAILED.inc();
                        return Err(anyhow::anyhow!("Error in ckd_request channel recv, {e}"));
                    }
                    broadcast::error::RecvError::Lagged(msg_n) => {
                        tracing::info!("{msg_n} messages lagged during ckd_request channel recv");
                        continue;
                    }
                },
            };
            if added_id == id {
                break;
            }
        }
        let request_ser = self.db.get(DBCol::CKDRequest, &key)?.unwrap();
        Ok(serde_json::from_slice(&request_ser)?)
    }
}

/// Storage for Dilithium key registration requests.
///
/// Similar to SignRequestStorage and CKDRequestStorage, this tracks pending
/// key registration requests from the chain. The requests are stored until
/// DKG completes and the response is sent to the contract.
pub struct DilithiumKeyRegistrationStorage {
    db: Arc<SecretDB>,
    add_sender: broadcast::Sender<DilithiumKeyRegistrationId>,
}

impl DilithiumKeyRegistrationStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        let (tx, _) = tokio::sync::broadcast::channel(100);
        Ok(Self { db, add_sender: tx })
    }

    /// If given request is already in the database, returns false.
    /// Otherwise, inserts the request and returns true.
    pub fn add(&self, request: &DilithiumKeyRegistrationRequest) -> bool {
        let key = borsh::to_vec(&request.id).unwrap();
        if self
            .db
            .get(DBCol::DilithiumKeyRegistrationRequest, &key)
            .expect("Unrecoverable error reading from database")
            .is_some()
        {
            return false;
        }
        let value_ser = serde_json::to_vec(&request).unwrap();
        let mut update = self.db.update();
        update.put(DBCol::DilithiumKeyRegistrationRequest, &key, &value_ser);
        update
            .commit()
            .expect("Unrecoverable error writing to database");
        let _ = self.add_sender.send(request.id);
        true
    }
}

/// Storage for derived Dilithium keyshares.
///
/// These are generated via DKG when users call `register_dilithium_key`.
/// Unlike master keyshares which use the complex permanent/temporary storage,
/// derived keyshares are simply persisted to the database after DKG completes.
pub struct DilithiumDerivedShareStorage {
    db: Arc<SecretDB>,
}

impl DilithiumDerivedShareStorage {
    pub fn new(db: Arc<SecretDB>) -> anyhow::Result<Self> {
        Ok(Self { db })
    }

    /// Store a derived keyshare.
    pub fn store(&self, id: &DerivedKeyId, output: &DilithiumKeygenOutput) -> anyhow::Result<()> {
        let key = Self::make_key(id);
        let value = serde_json::to_vec(output)?;
        let mut update = self.db.update();
        update.put(DBCol::DilithiumDerivedShare, &key, &value);
        update.commit()?;
        tracing::info!(
            "Stored derived Dilithium share for domain {:?}",
            id.domain_id
        );
        Ok(())
    }

    /// Load all derived keyshares for a given domain.
    /// Returns a vector of (DerivedKeyId, DilithiumKeygenOutput) pairs.
    pub fn load_all_for_domain(
        &self,
        domain_id: DomainId,
    ) -> anyhow::Result<Vec<(DerivedKeyId, DilithiumKeygenOutput)>> {
        // Create range for this domain: [domain_id, 0...0] to [domain_id, ff...ff]
        let start_key = Self::make_key(&DerivedKeyId {
            domain_id,
            tweak: [0u8; 32],
        });
        let end_key = Self::make_key(&DerivedKeyId {
            domain_id,
            tweak: [0xffu8; 32],
        });

        let mut results = Vec::new();
        for item in self
            .db
            .iter_range(DBCol::DilithiumDerivedShare, &start_key, &end_key)
        {
            let (key_bytes, value_bytes) = item?;
            if let Some(id) = Self::parse_key(&key_bytes) {
                let output: DilithiumKeygenOutput = serde_json::from_slice(&value_bytes)?;
                results.push((id, output));
            }
        }
        Ok(results)
    }

    /// Create a storage key from a DerivedKeyId.
    /// Format: [domain_id as 8 bytes big-endian] [tweak as 32 bytes]
    fn make_key(id: &DerivedKeyId) -> Vec<u8> {
        let mut key = Vec::with_capacity(8 + 32);
        key.extend_from_slice(&id.domain_id.0.to_be_bytes());
        key.extend_from_slice(&id.tweak);
        key
    }

    /// Parse a storage key back to a DerivedKeyId.
    fn parse_key(key: &[u8]) -> Option<DerivedKeyId> {
        if key.len() != 40 {
            return None;
        }
        let domain_id = DomainId(u64::from_be_bytes(key[0..8].try_into().ok()?));
        let mut tweak = [0u8; 32];
        tweak.copy_from_slice(&key[8..40]);
        Some(DerivedKeyId { domain_id, tweak })
    }
}

#[cfg(test)]
mod dilithium_derived_share_tests {
    use super::*;

    #[test]
    fn test_dilithium_derived_share_key_serialization() {
        let domain_id = DomainId(5);
        let tweak1 = [1u8; 32];
        let tweak2 = [2u8; 32];

        let id1 = DerivedKeyId {
            domain_id,
            tweak: tweak1,
        };
        let id2 = DerivedKeyId {
            domain_id,
            tweak: tweak2,
        };
        let id3 = DerivedKeyId {
            domain_id: DomainId(6),
            tweak: tweak1,
        };

        // Keys should be different
        let key1 = DilithiumDerivedShareStorage::make_key(&id1);
        let key2 = DilithiumDerivedShareStorage::make_key(&id2);
        let key3 = DilithiumDerivedShareStorage::make_key(&id3);

        assert_ne!(key1, key2);
        assert_ne!(key1, key3);

        // Keys should be 40 bytes (8 for domain + 32 for tweak)
        assert_eq!(key1.len(), 40);

        // Parse should round-trip
        let parsed1 = DilithiumDerivedShareStorage::parse_key(&key1).unwrap();
        assert_eq!(parsed1.domain_id, id1.domain_id);
        assert_eq!(parsed1.tweak, id1.tweak);

        let parsed2 = DilithiumDerivedShareStorage::parse_key(&key2).unwrap();
        assert_eq!(parsed2.domain_id, id2.domain_id);
        assert_eq!(parsed2.tweak, id2.tweak);

        let parsed3 = DilithiumDerivedShareStorage::parse_key(&key3).unwrap();
        assert_eq!(parsed3.domain_id, id3.domain_id);
        assert_eq!(parsed3.tweak, id3.tweak);
    }

    #[test]
    fn test_dilithium_derived_share_key_ordering() {
        // Keys should be ordered by domain_id first, then by tweak
        let id_d5_t1 = DerivedKeyId {
            domain_id: DomainId(5),
            tweak: [1u8; 32],
        };
        let id_d5_t2 = DerivedKeyId {
            domain_id: DomainId(5),
            tweak: [2u8; 32],
        };
        let id_d6_t1 = DerivedKeyId {
            domain_id: DomainId(6),
            tweak: [1u8; 32],
        };

        let key_d5_t1 = DilithiumDerivedShareStorage::make_key(&id_d5_t1);
        let key_d5_t2 = DilithiumDerivedShareStorage::make_key(&id_d5_t2);
        let key_d6_t1 = DilithiumDerivedShareStorage::make_key(&id_d6_t1);

        // Domain 5 keys should come before domain 6 keys
        assert!(key_d5_t1 < key_d6_t1);
        assert!(key_d5_t2 < key_d6_t1);

        // Within same domain, tweak ordering matters
        assert!(key_d5_t1 < key_d5_t2);
    }
}

#[cfg(test)]
mod tests {
    use mpc_contract::primitives::{
        domain::DomainId,
        signature::{Payload, Tweak},
    };
    use near_indexer_primitives::CryptoHash;

    use crate::types::CKDRequest;
    use crate::{
        db::SecretDB,
        storage::{CKDRequestStorage, SignRequestStorage},
        types::SignatureRequest,
    };

    #[tokio::test]
    async fn test_sig_request_storage() {
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let storage = SignRequestStorage::new(db).unwrap();

        let req1 = SignatureRequest {
            id: CryptoHash(rand::random()),
            // All other fields are irrelevant for the test.
            receipt_id: CryptoHash([0; 32]),
            entropy: [0; 32],
            payload: Payload::from_legacy_ecdsa([0; 32]),
            timestamp_nanosec: 0,
            tweak: Tweak::new([0; 32]),
            domain: DomainId::legacy_ecdsa_id(),
        };
        assert!(storage.add(&req1));
        assert!(!storage.add(&req1));
        assert!(storage.get(req1.id).await.is_ok());
        let req2 = SignatureRequest {
            id: CryptoHash(rand::random()),
            // All other fields are irrelevant for the test.
            receipt_id: CryptoHash([0; 32]),
            entropy: [0; 32],
            payload: Payload::from_legacy_ecdsa([0; 32]),
            timestamp_nanosec: 0,
            tweak: Tweak::new([0; 32]),
            domain: DomainId::legacy_ecdsa_id(),
        };
        storage.add(&req2);
        assert!(storage.get(req1.id).await.is_ok());
        assert!(storage.get(req2.id).await.is_ok());
    }

    #[tokio::test]
    async fn test_ckd_request_storage() {
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let storage = CKDRequestStorage::new(db).unwrap();

        let req1 = CKDRequest {
            id: CryptoHash(rand::random()),
            // All other fields are irrelevant for the test.
            receipt_id: CryptoHash([0; 32]),
            app_public_key:
                "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                    .parse()
                    .unwrap(),
            app_id: [1u8; 32].into(),
            entropy: [0; 32],
            timestamp_nanosec: 0,
            domain_id: DomainId::legacy_ecdsa_id(),
        };
        assert!(storage.add(&req1));
        assert!(!storage.add(&req1));
        assert!(storage.get(req1.id).await.is_ok());
        let req2 = CKDRequest {
            id: CryptoHash(rand::random()),
            // All other fields are irrelevant for the test.
            receipt_id: CryptoHash([0; 32]),
            app_public_key:
                "bls12381g1:6KtVVcAAGacrjNGePN8bp3KV6fYGrw1rFsyc7cVJCqR16Zc2ZFg3HX3hSZxSfv1oH6"
                    .parse()
                    .unwrap(),
            app_id: [1u8; 32].into(),
            entropy: [0; 32],
            timestamp_nanosec: 0,
            domain_id: DomainId::legacy_ecdsa_id(),
        };
        storage.add(&req2);
        assert!(storage.get(req1.id).await.is_ok());
        assert!(storage.get(req2.id).await.is_ok());
    }
}
