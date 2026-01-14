//! Sandbox tests for Dilithium (ML-DSA-87) signatures.
//!
//! These tests verify the contract's handling of Dilithium signature requests
//! using the base dilithium crate directly (not full MPC threshold signing).
//! Full threshold signing tests are in the node integration tests.

use crate::sandbox::{
    common::{init_env, SandboxTestSetup},
    utils::{
        consts::PARTICIPANT_LEN,
        sign_utils::{submit_signature_response, SignRequestTest},
    },
};
use mpc_contract::primitives::domain::SignatureScheme;
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
