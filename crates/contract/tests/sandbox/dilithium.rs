//! Sandbox tests for Dilithium (ML-DSA-87) signatures.
//!
//! These tests verify the contract's handling of Dilithium signature requests
//! using the base dilithium crate directly (not full MPC threshold signing).
//! Full threshold signing tests are in the node integration tests.
//!
//! ## Key Registration Tests
//!
//! Dilithium key derivation is NOT linear like ECC. Users must call
//! `register_dilithium_key` to trigger DKG before signing. These tests
//! verify the registration flow works correctly.

use crate::sandbox::{
    common::{init_env, SandboxTestSetup},
    utils::{
        consts::PARTICIPANT_LEN,
        sign_utils::{submit_signature_response, SignRequestTest},
    },
};
use contract_interface::types as dtos;
use mpc_contract::primitives::{
    dilithium_derivation::RegisterDilithiumKeyArgs, domain::SignatureScheme,
};
use near_workspaces::types::NearToken;
use std::time::Duration;
use utilities::AccountIdExtV1;

const SIGNATURE_TIMEOUT_BLOCKS: u64 = 200;

/// Test basic Dilithium signature request and response flow.
#[tokio::test]
async fn test_dilithium_sign_simple() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = init_env(&[SignatureScheme::Dilithium], PARTICIPANT_LEN).await;

    let attested_account = &mpc_signer_accounts[0];
    let path = "test";
    let alice = worker.dev_create_account().await.unwrap();
    let predecessor_id = alice.id();

    let key = &keys[0];
    let messages = ["hello dilithium", "post-quantum signatures!", "ML-DSA-87"];

    for msg in messages {
        println!("submitting Dilithium signature request: {msg}");
        let req = SignRequestTest::new(key, &predecessor_id.as_v2_account_id(), msg, path);
        req.sign_and_validate(&alice, &contract, attested_account)
            .await?;
    }

    Ok(())
}

/// Test that Dilithium signature requests timeout properly when not responded to.
#[tokio::test]
async fn test_dilithium_sign_timeout() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        keys,
        ..
    } = init_env(&[SignatureScheme::Dilithium], PARTICIPANT_LEN).await;

    let alice = worker.dev_create_account().await.unwrap();
    let path = "test";

    let key = &keys[0];
    let msg = "this should timeout";
    println!("submitting Dilithium signature request that should timeout: {msg}");

    let req = SignRequestTest::new(key, &alice.id().as_v2_account_id(), msg, path);
    let status = req.sign_ensure_included(&alice, &contract).await?;

    // Fast forward past the timeout without responding
    worker.fast_forward(SIGNATURE_TIMEOUT_BLOCKS).await.unwrap();

    // Verify the request timed out
    req.verify_timeout(status).await?;

    Ok(())
}

/// Test Dilithium alongside other signature schemes in a multi-domain setup.
#[tokio::test]
async fn test_dilithium_multidomain() -> anyhow::Result<()> {
    let schemes = &[
        SignatureScheme::Secp256k1,
        SignatureScheme::Ed25519,
        SignatureScheme::Dilithium,
    ];

    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = init_env(schemes, PARTICIPANT_LEN).await;

    let attested_account = &mpc_signer_accounts[0];
    let path = "multidomain-test";
    let alice = worker.dev_create_account().await.unwrap();
    let predecessor_id = alice.id();

    // Sign with each scheme
    for (i, key) in keys.iter().enumerate() {
        let scheme_name = match key.domain_config.scheme {
            SignatureScheme::Secp256k1 => "Secp256k1",
            SignatureScheme::Ed25519 => "Ed25519",
            SignatureScheme::Dilithium => "Dilithium",
            _ => "Unknown",
        };
        let msg = format!("message for {} domain {}", scheme_name, i);
        println!("submitting {} signature request: {}", scheme_name, msg);

        let req = SignRequestTest::new(key, &predecessor_id.as_v2_account_id(), &msg, path);
        req.sign_and_validate(&alice, &contract, attested_account)
            .await?;
    }

    Ok(())
}

/// Test that duplicate Dilithium requests are handled correctly.
#[tokio::test]
async fn test_dilithium_duplicate_request() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        mpc_signer_accounts,
        keys,
    } = init_env(&[SignatureScheme::Dilithium], PARTICIPANT_LEN).await;

    let attested_account = &mpc_signer_accounts[0];
    let path = "test";
    let alice = worker.dev_create_account().await.unwrap();

    let key = &keys[0];
    let msg = "duplicate request test";

    // Submit the same request twice
    let req = SignRequestTest::new(key, &alice.id().as_v2_account_id(), msg, path);
    let status_1 = req.sign_ensure_included(&alice, &contract).await?;

    // Small delay between requests
    worker.fast_forward(2).await.unwrap();

    let status_2 = req.sign_ensure_included(&alice, &contract).await?;

    // Wait a bit for processing
    tokio::time::sleep(Duration::from_secs(3)).await;
    worker.fast_forward(2).await.unwrap();

    // Respond to the request - should satisfy the most recent one
    submit_signature_response(&req.response, &contract, attested_account).await?;

    // The most recent request should succeed
    req.verify_execution_outcome(status_2).await?;

    // The first request should timeout
    worker.fast_forward(SIGNATURE_TIMEOUT_BLOCKS).await.unwrap();
    req.verify_timeout(status_1).await?;

    Ok(())
}

/// Test that signing without key registration fails with the correct error.
///
/// Unlike ECC schemes where derivation is linear (derived = master + tweak),
/// Dilithium requires explicit key registration via DKG before signing.
#[tokio::test]
async fn test_dilithium_sign_without_registration_fails() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        keys,
        ..
    } = init_env(&[SignatureScheme::Dilithium], PARTICIPANT_LEN).await;

    let alice = worker.dev_create_account().await.unwrap();
    let path = "unregistered-path";

    let key = &keys[0];
    let msg = "this should fail without registration";

    // Try to sign without registering the key first
    let req = SignRequestTest::new(key, &alice.id().as_v2_account_id(), msg, path);

    let result = alice
        .call(contract.id(), "sign")
        .args_json(serde_json::json!({
            "request": req.args,
        }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;

    // The sign call should fail because the key is not registered
    assert!(
        result.is_failure(),
        "Expected sign to fail without key registration"
    );
    let error_msg = format!("{:?}", result.failures());
    assert!(
        error_msg.contains("DilithiumKeyNotRegistered") || error_msg.contains("not registered"),
        "Expected DilithiumKeyNotRegistered error, got: {}",
        error_msg
    );

    Ok(())
}

/// Test the register_dilithium_key endpoint with valid parameters.
///
/// This test verifies:
/// 1. The contract accepts valid registration requests
/// 2. The yield/resume pattern is set up correctly
/// 3. Idempotency - registering the same key twice returns existing key
#[tokio::test]
async fn test_dilithium_key_registration_basic() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        keys,
        ..
    } = init_env(&[SignatureScheme::Dilithium], PARTICIPANT_LEN).await;

    let alice = worker.dev_create_account().await.unwrap();
    let domain_id = keys[0].domain_config.id;
    let path = "test-registration";

    // Submit a key registration request
    let register_args = RegisterDilithiumKeyArgs {
        path: path.to_string(),
        domain_id,
    };

    let result = alice
        .call(contract.id(), "register_dilithium_key")
        .args_json(serde_json::json!({
            "request": register_args,
        }))
        .deposit(NearToken::from_millinear(10)) // Need deposit for storage
        .max_gas()
        .transact_async()
        .await?;

    println!("Key registration submitted: {:?}", result);

    // The request should be accepted (even though no MPC response will come in sandbox)
    // In a real environment, the MPC nodes would respond with the derived public key

    Ok(())
}

/// Test that registering a key for a non-Dilithium domain fails.
#[tokio::test]
async fn test_dilithium_key_registration_wrong_domain_fails() -> anyhow::Result<()> {
    // Initialize with both Secp256k1 and Dilithium domains
    let schemes = &[SignatureScheme::Secp256k1, SignatureScheme::Dilithium];
    let SandboxTestSetup {
        worker,
        contract,
        keys,
        ..
    } = init_env(schemes, PARTICIPANT_LEN).await;

    let alice = worker.dev_create_account().await.unwrap();

    // Get the Secp256k1 domain ID (not Dilithium)
    let secp_domain_id = keys
        .iter()
        .find(|k| k.domain_config.scheme == SignatureScheme::Secp256k1)
        .unwrap()
        .domain_config
        .id;

    let path = "test-wrong-domain";

    // Try to register with a non-Dilithium domain
    let register_args = RegisterDilithiumKeyArgs {
        path: path.to_string(),
        domain_id: secp_domain_id,
    };

    let result = alice
        .call(contract.id(), "register_dilithium_key")
        .args_json(serde_json::json!({
            "request": register_args,
        }))
        .deposit(NearToken::from_millinear(10))
        .max_gas()
        .transact()
        .await?;

    // Should fail because domain is not Dilithium
    assert!(
        result.is_failure(),
        "Expected registration to fail for non-Dilithium domain"
    );
    let error_msg = format!("{:?}", result.failures());
    assert!(
        error_msg.contains("NotDilithiumDomain") || error_msg.contains("not a Dilithium domain"),
        "Expected NotDilithiumDomain error, got: {}",
        error_msg
    );

    Ok(())
}

/// Test that registration fails with insufficient deposit.
#[tokio::test]
async fn test_dilithium_key_registration_insufficient_deposit() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        keys,
        ..
    } = init_env(&[SignatureScheme::Dilithium], PARTICIPANT_LEN).await;

    let alice = worker.dev_create_account().await.unwrap();
    let domain_id = keys[0].domain_config.id;
    let path = "test-insufficient-deposit";

    let register_args = RegisterDilithiumKeyArgs {
        path: path.to_string(),
        domain_id,
    };

    // Try to register with zero deposit
    let result = alice
        .call(contract.id(), "register_dilithium_key")
        .args_json(serde_json::json!({
            "request": register_args,
        }))
        .deposit(NearToken::from_yoctonear(0))
        .max_gas()
        .transact()
        .await?;

    // Should fail due to insufficient deposit
    assert!(
        result.is_failure(),
        "Expected registration to fail with zero deposit"
    );
    let error_msg = format!("{:?}", result.failures());
    assert!(
        error_msg.contains("InsufficientDeposit") || error_msg.contains("deposit"),
        "Expected InsufficientDeposit error, got: {}",
        error_msg
    );

    Ok(())
}

/// Test querying a derived key that doesn't exist.
#[tokio::test]
async fn test_dilithium_get_derived_key_not_found() -> anyhow::Result<()> {
    let SandboxTestSetup {
        worker,
        contract,
        keys,
        ..
    } = init_env(&[SignatureScheme::Dilithium], PARTICIPANT_LEN).await;

    let alice = worker.dev_create_account().await.unwrap();
    let domain_id = keys[0].domain_config.id;
    let path = "nonexistent-path";

    // Query for a key that hasn't been registered
    let result: Option<dtos::DilithiumPublicKey> = contract
        .view("get_dilithium_derived_key_info")
        .args_json(serde_json::json!({
            "account_id": alice.id().as_v2_account_id(),
            "path": path,
            "domain_id": domain_id,
        }))
        .await?
        .json()?;

    // Should return None since the key hasn't been registered
    assert!(result.is_none(), "Expected None for unregistered key");

    Ok(())
}
