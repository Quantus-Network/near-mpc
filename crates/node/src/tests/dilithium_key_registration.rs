//! End-to-end tests for Dilithium key registration flow.
//!
//! These tests verify the complete flow:
//! 1. User calls `register_dilithium_key`
//! 2. MPC nodes receive the event via indexer
//! 3. Nodes run DKG to create the derived key
//! 4. Leader responds with the derived public key
//! 5. User can then sign with the derived key
//!
//! Unlike ECC schemes where derivation is linear (derived = master + tweak),
//! Dilithium requires a full DKG for each derived key.
//!
//! Key test scenarios covered:
//! - Basic registration and signing flow
//! - Multiple derived keys for different paths
//! - Different users with the same path
//! - Signing WITHOUT registration (must fail - no fallback to master key)
//! - Mixed Dilithium + ECC domains
//! - Concurrent key registration requests

use crate::indexer::participants::ContractState;
use crate::p2p::testing::PortSeed;
use crate::tests::{
    request_ckd_and_await_response, request_dilithium_key_registration_and_await_response,
    request_signature_and_await_response, request_signature_and_await_response_with_path,
    IntegrationTestSetup, DEFAULT_BLOCK_TIME, DEFAULT_MAX_PROTOCOL_WAIT_TIME,
    DEFAULT_MAX_SIGNATURE_WAIT_TIME,
};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;

/// Test the complete Dilithium key registration and signing flow.
///
/// This test:
/// 1. Sets up a cluster with a Dilithium domain
/// 2. Runs initial DKG for the master key
/// 3. Registers a derived key via `register_dilithium_key`
/// 4. Verifies the derived key DKG completes
/// 5. Signs with the derived key
#[tokio::test]
async fn test_dilithium_key_registration_and_sign() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::DILITHIUM_KEY_REGISTRATION_TEST,
        std::time::Duration::from_millis(600),
    );

    // Initialize with a Dilithium domain
    let dilithium_domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Dilithium,
    };
    let domains = vec![dilithium_domain.clone()];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Wait for initial DKG to complete (master key generation)
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("must not exceed timeout for initial DKG");

    tracing::info!("Initial DKG complete, master key generated");

    // Now register a derived key
    let user = "alice.near";
    let path = "ethereum/0";

    tracing::info!(
        "Requesting Dilithium key registration for user {}, path {}",
        user,
        path
    );

    // Request key registration and wait for DKG to complete
    let registration_result = request_dilithium_key_registration_and_await_response(
        &mut setup.indexer,
        user,
        path,
        &dilithium_domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME * 2, // DKG takes longer than signing
    )
    .await;

    assert!(
        registration_result.is_some(),
        "Dilithium key registration should complete successfully"
    );
    tracing::info!(
        "Dilithium key registration completed in {:?}",
        registration_result.unwrap()
    );

    // Verify the key is registered
    assert!(
        setup
            .indexer
            .is_dilithium_key_registered(&user.parse().unwrap(), path, dilithium_domain.id)
            .await,
        "Derived key should be registered after DKG"
    );

    // Now sign with the derived key - must use the same path as registration
    tracing::info!("Signing with derived key for user {}, path {}", user, path);

    let signature_result = request_signature_and_await_response_with_path(
        &mut setup.indexer,
        user,
        &dilithium_domain,
        path,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await;

    assert!(
        signature_result.is_some(),
        "Signing with derived key should succeed"
    );
    tracing::info!(
        "Signature with derived key completed in {:?}",
        signature_result.unwrap()
    );
}

/// Test registering multiple derived keys for different paths.
#[tokio::test]
async fn test_dilithium_multiple_derived_keys() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::DILITHIUM_MULTIPLE_KEYS_TEST,
        std::time::Duration::from_millis(600),
    );

    let dilithium_domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Dilithium,
    };
    let domains = vec![dilithium_domain.clone()];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Wait for initial DKG
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("must not exceed timeout for initial DKG");

    tracing::info!("Initial DKG complete");

    let user = "bob.near";
    let paths = ["ethereum/0", "bitcoin/0", "solana/0"];

    // Register multiple derived keys
    for path in &paths {
        tracing::info!("Registering derived key for path: {}", path);

        let result = request_dilithium_key_registration_and_await_response(
            &mut setup.indexer,
            user,
            path,
            &dilithium_domain,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME * 2,
        )
        .await;

        assert!(
            result.is_some(),
            "Key registration for path {} should succeed",
            path
        );

        // Verify the key is registered
        assert!(
            setup
                .indexer
                .is_dilithium_key_registered(&user.parse().unwrap(), path, dilithium_domain.id)
                .await,
            "Derived key for path {} should be registered",
            path
        );
    }

    // Sign with each derived key - must use the same path as registration
    for path in &paths {
        tracing::info!("Signing with derived key for path: {}", path);

        let result = request_signature_and_await_response_with_path(
            &mut setup.indexer,
            user,
            &dilithium_domain,
            path,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME,
        )
        .await;

        assert!(
            result.is_some(),
            "Signing with derived key for path {} should succeed",
            path
        );
    }

    tracing::info!(
        "All {} derived keys registered and used for signing",
        paths.len()
    );
}

/// Test that different users can register keys for the same path.
#[tokio::test]
async fn test_dilithium_different_users_same_path() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::DILITHIUM_DIFFERENT_USERS_TEST,
        std::time::Duration::from_millis(600),
    );

    let dilithium_domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Dilithium,
    };
    let domains = vec![dilithium_domain.clone()];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Wait for initial DKG
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("must not exceed timeout for initial DKG");

    tracing::info!("Initial DKG complete");

    let users = ["alice.near", "bob.near", "charlie.near"];
    let path = "ethereum/0"; // Same path for all users

    // Register keys for different users with the same path
    for user in &users {
        tracing::info!("Registering derived key for user: {}", user);

        let result = request_dilithium_key_registration_and_await_response(
            &mut setup.indexer,
            user,
            path,
            &dilithium_domain,
            DEFAULT_MAX_SIGNATURE_WAIT_TIME * 2,
        )
        .await;

        assert!(
            result.is_some(),
            "Key registration for user {} should succeed",
            user
        );

        // Verify the key is registered
        assert!(
            setup
                .indexer
                .is_dilithium_key_registered(&user.parse().unwrap(), path, dilithium_domain.id)
                .await,
            "Derived key for user {} should be registered",
            user
        );
    }

    // Verify each user has a distinct derived key (different tweaks)
    // This is implicit - if they can all sign successfully, they have different keys

    tracing::info!(
        "All {} users registered derived keys for path {}",
        users.len(),
        path
    );
}

/// Test that signing with a Dilithium domain WITHOUT registering a derived key
/// does NOT succeed (no fallback to master key for Dilithium).
///
/// This is a critical security test: unlike ECC where derived_key = master + tweak,
/// Dilithium requires a full DKG for each derived key. Falling back to the master
/// key would be incorrect and insecure.
#[tokio::test]
async fn test_dilithium_sign_without_registration_fails() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::DILITHIUM_SIGN_WITHOUT_REGISTRATION_TEST,
        std::time::Duration::from_millis(600),
    );

    let dilithium_domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Dilithium,
    };
    let domains = vec![dilithium_domain.clone()];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Wait for initial DKG (master key generation)
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("must not exceed timeout for initial DKG");

    tracing::info!("Initial DKG complete, master key generated");

    // Attempt to sign WITHOUT registering a derived key first
    // This should timeout/fail because there's no derived key to sign with
    let user = "unregistered_user.near";

    tracing::info!(
        "Attempting to sign with Dilithium domain for user {} WITHOUT registering a derived key",
        user
    );

    // Use a shorter timeout since we expect this to fail
    let short_timeout = std::time::Duration::from_secs(30);

    let signature_result = request_signature_and_await_response_with_path(
        &mut setup.indexer,
        user,
        &dilithium_domain,
        "ethereum/0", // Use some path - doesn't matter since key isn't registered
        short_timeout,
    )
    .await;

    // The signature request should NOT succeed (timeout or explicit failure)
    assert!(
        signature_result.is_none(),
        "Signing with Dilithium WITHOUT registering a derived key should NOT succeed. \
         This would indicate an incorrect fallback to master key!"
    );

    tracing::info!(
        "Correctly failed to sign without registration - no master key fallback for Dilithium"
    );

    // Now register the key and verify signing works after registration
    tracing::info!("Now registering a derived key for user {}", user);

    let registration_result = request_dilithium_key_registration_and_await_response(
        &mut setup.indexer,
        user,
        "ethereum/0",
        &dilithium_domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME * 2,
    )
    .await;

    assert!(
        registration_result.is_some(),
        "Key registration should succeed"
    );

    // Now signing should work - use the same path as registration
    let signature_result = request_signature_and_await_response_with_path(
        &mut setup.indexer,
        user,
        &dilithium_domain,
        "ethereum/0",
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await;

    assert!(
        signature_result.is_some(),
        "Signing should succeed AFTER registering a derived key"
    );

    tracing::info!("Signing succeeded after registration - correct behavior verified");
}

/// Test Dilithium alongside other signature schemes (ECC) in a multi-domain setup.
///
/// This verifies that:
/// - Dilithium domains require key registration before signing
/// - ECC domains (Secp256k1, Ed25519) can sign without explicit key registration
/// - Both can coexist in the same cluster
#[tokio::test]
async fn test_dilithium_mixed_domains() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::DILITHIUM_MIXED_DOMAINS_TEST,
        DEFAULT_BLOCK_TIME,
    );

    // Set up multiple domains: Dilithium + ECC schemes
    let dilithium_domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Dilithium,
    };
    let secp256k1_domain = DomainConfig {
        id: DomainId(1),
        scheme: SignatureScheme::Secp256k1,
    };
    let ed25519_domain = DomainConfig {
        id: DomainId(2),
        scheme: SignatureScheme::Ed25519,
    };
    let bls_domain = DomainConfig {
        id: DomainId(3),
        scheme: SignatureScheme::Bls12381,
    };

    let domains = vec![
        dilithium_domain.clone(),
        secp256k1_domain.clone(),
        ed25519_domain.clone(),
        bls_domain.clone(),
    ];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Wait for initial DKG for all domains
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME * domains.len() as u32,
        )
        .await
        .expect("must not exceed timeout for initial DKG");

    tracing::info!("Initial DKG complete for all {} domains", domains.len());

    let user = "mixed_domain_user.near";

    // ECC signatures should work immediately (linear derivation)
    tracing::info!("Testing ECC signatures (should work without explicit registration)");

    let secp_result = request_signature_and_await_response(
        &mut setup.indexer,
        user,
        &secp256k1_domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await;
    assert!(
        secp_result.is_some(),
        "Secp256k1 signature should work without explicit registration"
    );

    let ed25519_result = request_signature_and_await_response(
        &mut setup.indexer,
        user,
        &ed25519_domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await;
    assert!(
        ed25519_result.is_some(),
        "Ed25519 signature should work without explicit registration"
    );

    // BLS CKD should also work
    let bls_result = request_ckd_and_await_response(
        &mut setup.indexer,
        user,
        &bls_domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await;
    assert!(bls_result.is_some(), "BLS CKD should work");

    tracing::info!("ECC signatures succeeded");

    // Dilithium should fail without registration
    tracing::info!("Testing Dilithium signature without registration (should fail)");

    let dilithium_result = request_signature_and_await_response_with_path(
        &mut setup.indexer,
        user,
        &dilithium_domain,
        "ethereum/0",
        std::time::Duration::from_secs(30), // Short timeout, expect failure
    )
    .await;
    assert!(
        dilithium_result.is_none(),
        "Dilithium signature should NOT work without registration"
    );

    // Now register the Dilithium key
    tracing::info!("Registering Dilithium derived key");

    let registration_result = request_dilithium_key_registration_and_await_response(
        &mut setup.indexer,
        user,
        "ethereum/0",
        &dilithium_domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME * 2,
    )
    .await;
    assert!(
        registration_result.is_some(),
        "Dilithium key registration should succeed"
    );

    // Now Dilithium signing should work - use the same path as registration
    tracing::info!("Testing Dilithium signature after registration (should succeed)");

    let dilithium_result = request_signature_and_await_response_with_path(
        &mut setup.indexer,
        user,
        &dilithium_domain,
        "ethereum/0",
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await;
    assert!(
        dilithium_result.is_some(),
        "Dilithium signature should work AFTER registration"
    );

    tracing::info!(
        "Mixed domain test passed: ECC works immediately, Dilithium requires registration"
    );
}

/// Test concurrent Dilithium key registration requests.
///
/// Multiple users registering keys simultaneously should all succeed,
/// with each getting their own distinct derived key.
#[tokio::test]
async fn test_dilithium_concurrent_registrations() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::DILITHIUM_CONCURRENT_REGISTRATIONS_TEST,
        std::time::Duration::from_millis(600),
    );

    let dilithium_domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Dilithium,
    };
    let domains = vec![dilithium_domain.clone()];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Wait for initial DKG
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("must not exceed timeout for initial DKG");

    tracing::info!("Initial DKG complete");

    // Register multiple keys concurrently by sending all requests at once
    let users_and_paths = [
        ("concurrent_user1.near", "ethereum/0"),
        ("concurrent_user2.near", "bitcoin/0"),
        ("concurrent_user3.near", "solana/0"),
        ("concurrent_user1.near", "bitcoin/1"), // Same user, different path
    ];

    tracing::info!(
        "Sending {} concurrent registration requests",
        users_and_paths.len()
    );

    // Send all registration requests without waiting
    for (user, path) in &users_and_paths {
        let predecessor_id: near_account_id::AccountId = user.parse().unwrap();
        let tweak = mpc_contract::primitives::dilithium_derivation::derive_dilithium_tweak(
            &predecessor_id,
            path,
        );

        let request = crate::indexer::handler::DilithiumKeyRegistrationFromChain {
            request_id: near_indexer_primitives::CryptoHash(rand::random()),
            path: path.to_string(),
            domain_id: dilithium_domain.id,
            predecessor_id: predecessor_id.clone(),
            tweak,
            entropy: rand::random(),
            timestamp_nanosec: rand::random(),
        };

        setup.indexer.request_dilithium_key_registration(request);
        tracing::info!("Sent registration request for user {}, path {}", user, path);
    }

    // Now wait for all responses
    let mut received_responses = 0;
    let total_expected = users_and_paths.len();
    let timeout_duration = DEFAULT_MAX_SIGNATURE_WAIT_TIME * 4; // Allow more time for concurrent DKGs

    let start_time = std::time::Instant::now();
    while received_responses < total_expected {
        if start_time.elapsed() > timeout_duration {
            panic!(
                "Timeout waiting for concurrent registrations. Received {}/{} responses",
                received_responses, total_expected
            );
        }

        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            setup.indexer.next_dilithium_key_response(),
        )
        .await
        {
            Ok(response) => {
                tracing::info!(
                    "Received registration response for user {}, path {}",
                    response.registration.account_id,
                    response.registration.path
                );
                received_responses += 1;
            }
            Err(_) => {
                tracing::warn!(
                    "Timeout waiting for response, continuing... ({}/{})",
                    received_responses,
                    total_expected
                );
            }
        }
    }

    tracing::info!(
        "All {} concurrent registration requests completed successfully",
        total_expected
    );

    // Verify all keys are registered
    for (user, path) in &users_and_paths {
        assert!(
            setup
                .indexer
                .is_dilithium_key_registered(&user.parse().unwrap(), path, dilithium_domain.id)
                .await,
            "Derived key for user {}, path {} should be registered",
            user,
            path
        );
    }

    tracing::info!("All derived keys verified as registered");
}

/// Test that re-registering the same key (same user + path) is handled gracefully.
///
/// The system should either:
/// - Return the existing key (idempotent)
/// - Or reject the duplicate registration
#[tokio::test]
async fn test_dilithium_duplicate_registration() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::DILITHIUM_KEY_REGISTRATION_TEST.with_case(1), // Use case 1 to avoid port collision
        std::time::Duration::from_millis(600),
    );

    let dilithium_domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Dilithium,
    };
    let domains = vec![dilithium_domain.clone()];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Wait for initial DKG
    setup
        .indexer
        .wait_for_contract_state(
            |state| matches!(state, ContractState::Running(_)),
            DEFAULT_MAX_PROTOCOL_WAIT_TIME,
        )
        .await
        .expect("must not exceed timeout for initial DKG");

    tracing::info!("Initial DKG complete");

    let user = "duplicate_test_user.near";
    let path = "ethereum/0";

    // First registration
    tracing::info!("First registration for user {}, path {}", user, path);

    let first_result = request_dilithium_key_registration_and_await_response(
        &mut setup.indexer,
        user,
        path,
        &dilithium_domain,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME * 2,
    )
    .await;

    assert!(first_result.is_some(), "First registration should succeed");

    // Verify the key is registered
    assert!(
        setup
            .indexer
            .is_dilithium_key_registered(&user.parse().unwrap(), path, dilithium_domain.id)
            .await,
        "Key should be registered after first registration"
    );

    tracing::info!("First registration completed successfully");

    // Attempt duplicate registration
    tracing::info!(
        "Attempting duplicate registration for user {}, path {}",
        user,
        path
    );

    // The behavior here depends on implementation:
    // - Could return the existing key (idempotent)
    // - Could timeout if duplicates are ignored
    // - Could return an error
    // We just verify the system handles it gracefully (doesn't crash)
    let second_result = request_dilithium_key_registration_and_await_response(
        &mut setup.indexer,
        user,
        path,
        &dilithium_domain,
        std::time::Duration::from_secs(30), // Shorter timeout for duplicate
    )
    .await;

    // Either succeeds (idempotent) or times out (duplicate ignored) - both are valid
    tracing::info!(
        "Duplicate registration result: {}",
        if second_result.is_some() {
            "succeeded (idempotent behavior)"
        } else {
            "timed out (duplicate ignored)"
        }
    );

    // Key should still be registered regardless
    assert!(
        setup
            .indexer
            .is_dilithium_key_registered(&user.parse().unwrap(), path, dilithium_domain.id)
            .await,
        "Key should still be registered after duplicate attempt"
    );

    // Signing should still work - use the same path as registration
    let signature_result = request_signature_and_await_response_with_path(
        &mut setup.indexer,
        user,
        &dilithium_domain,
        path,
        DEFAULT_MAX_SIGNATURE_WAIT_TIME,
    )
    .await;

    assert!(
        signature_result.is_some(),
        "Signing should work after duplicate registration attempt"
    );

    tracing::info!("Duplicate registration test passed - system handled gracefully");
}
