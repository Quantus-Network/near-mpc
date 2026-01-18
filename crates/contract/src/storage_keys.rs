use near_sdk::{near, BorshStorageKey};

// !!! IMPORTANT !!!
// for backwards compatibility, ensure the order is preserved and only append to this list
// Renaming is OK.
#[near(serializers=[borsh] )]
#[derive(Hash, Clone, Debug, PartialEq, Eq, BorshStorageKey)]
pub enum StorageKey {
    _DeprecatedPendingRequests,
    /// Proposed updates to the contract code and config.
    _DeprecatedProposedUpdatesEntries,
    _DeprecatedRequestsByTimestamp,
    PendingSignatureRequestsV2,
    ProposedUpdatesEntriesV2,
    ProposedUpdatesVotesV2,
    TeeParticipantAttestation,
    PendingCKDRequests,
    BackupServicesInfo,
    NodeMigrations,
    /// Storage for registered Dilithium derived public keys.
    /// Maps DilithiumTweakKeyId (tweak, domain) -> DilithiumPublicKey
    /// The tweak is deterministically derived from (account_id, path).
    DilithiumDerivedKeys,
    /// Storage for pending Dilithium key registration requests.
    /// Maps DilithiumKeyRegistration -> YieldIndex
    PendingDilithiumKeyRequests,
}
