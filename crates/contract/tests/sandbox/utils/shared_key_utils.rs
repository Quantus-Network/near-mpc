use contract_interface::types::{self as dtos, Bls12381G1PublicKey};
use elliptic_curve::{Field as _, Group as _};
use k256::elliptic_curve::{sec1::ToEncodedPoint as _, PrimeField as _};
use mpc_contract::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        signature::Tweak,
    },
};
use rand::rngs::OsRng;
use rand::RngCore;
use rand_core::CryptoRngCore;
use threshold_signatures::{
    blstrs,
    confidential_key_derivation::{self as ckd},
    ecdsa as ts_ecdsa, eddsa,
    frost_ed25519::{keys::SigningShare, Ed25519Group, Group as _, VerifyingKey},
    frost_secp256k1::{self, Secp256K1Group},
};

// Dilithium types - use base crate for sandbox tests since we don't have full MPC
pub use qp_rusty_crystals_dilithium::{
    ml_dsa_87::{
        Keypair as DilithiumKeypair,
        PublicKey as DilithiumPublicKeyBase,
        SecretKey as DilithiumSecretKey,
    },
    SensitiveBytes32,
};
pub use qp_rusty_crystals_threshold::PublicKey as DilithiumPublicKey;

#[derive(Debug, Clone)]
pub struct DomainKey {
    pub domain_config: DomainConfig,
    pub domain_secret_key: SharedSecretKey,
    pub domain_public_key: PublicKeyExtended,
}

impl DomainKey {
    pub fn domain_id(&self) -> DomainId {
        self.domain_config.id
    }
}

#[derive(Debug, Clone)]
pub enum SharedSecretKey {
    Secp256k1(ts_ecdsa::KeygenOutput),
    Ed25519(eddsa::KeygenOutput),
    Bls12381(ckd::KeygenOutput),
Dilithium(DilithiumKeygenOutput),
}

/// Keygen output for Dilithium signatures (for sandbox tests).
/// This uses the base dilithium crate directly since we don't need full MPC in contract tests.
#[derive(Debug, Clone)]
pub struct DilithiumKeygenOutput {
    pub public_key_bytes: [u8; 2592],
    pub secret_key_bytes: [u8; 4896],
}

pub fn new_secp256k1() -> (dtos::PublicKey, ts_ecdsa::KeygenOutput) {
    let scalar = k256::Scalar::random(&mut rand::thread_rng());
    let private_share = frost_secp256k1::keys::SigningShare::new(scalar);
    let public_key_element = Secp256K1Group::generator() * scalar;
    let public_key = frost_secp256k1::VerifyingKey::new(public_key_element);

    let keygen_output = ts_ecdsa::KeygenOutput {
        private_share,
        public_key,
    };

    let compressed_key = public_key.to_element().to_encoded_point(false);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&compressed_key.as_bytes()[1..]);
    let pk = dtos::PublicKey::Secp256k1(dtos::Secp256k1PublicKey::from(bytes));

    (pk, keygen_output)
}

pub fn make_key_for_domain(domain_scheme: SignatureScheme) -> (dtos::PublicKey, SharedSecretKey) {
    match domain_scheme {
        SignatureScheme::Secp256k1 | SignatureScheme::V2Secp256k1 => {
            let (pk, sk) = new_secp256k1();
            (pk, SharedSecretKey::Secp256k1(sk))
        }
        SignatureScheme::Ed25519 => {
            let (pk, sk) = new_ed25519();
            (pk, SharedSecretKey::Ed25519(sk))
        }
        SignatureScheme::Bls12381 => {
            let (pk, sk) = new_bls12381();
            (pk, SharedSecretKey::Bls12381(sk))
        }
        SignatureScheme::Dilithium => {
            let (pk, sk) = new_dilithium();
            (pk, SharedSecretKey::Dilithium(sk))
        }
    }
}

pub fn new_ed25519() -> (dtos::PublicKey, eddsa::KeygenOutput) {
    let scalar = curve25519_dalek::Scalar::random(&mut OsRng);
    let private_share = SigningShare::new(scalar);
    let public_key_element = Ed25519Group::generator() * scalar;
    let public_key = VerifyingKey::new(public_key_element);

    let keygen_output = eddsa::KeygenOutput {
        private_share,
        public_key,
    };

    let compressed_key = public_key.to_element().compress().as_bytes().to_vec();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&compressed_key);
    let pk = dtos::PublicKey::Ed25519(dtos::Ed25519PublicKey::from(bytes));

    (pk, keygen_output)
}

/// Generate a new Dilithium key pair for sandbox tests.
/// Uses the base dilithium crate directly since we don't need full MPC infrastructure.
pub fn new_dilithium() -> (dtos::PublicKey, DilithiumKeygenOutput) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    // Generate a keypair using the base dilithium crate
    let entropy = SensitiveBytes32::new(&mut seed);
    let keypair = DilithiumKeypair::generate(entropy);

    let keygen_output = DilithiumKeygenOutput {
        public_key_bytes: keypair.public.to_bytes(),
        secret_key_bytes: keypair.secret.to_bytes(),
    };

    // Convert public key to contract interface type
    let mut boxed_bytes = Box::new([0u8; 2592]);
    boxed_bytes.copy_from_slice(&keypair.public.to_bytes());
    let pk = dtos::PublicKey::Dilithium(dtos::DilithiumPublicKey::from(boxed_bytes));

    (pk, keygen_output)
}

/// Sign a message with a Dilithium key for sandbox tests.
/// Uses the base dilithium crate directly.
pub fn sign_with_dilithium(
    keygen_output: &DilithiumKeygenOutput,
    message: &[u8],
) -> Vec<u8> {
    let secret_key = DilithiumSecretKey::from_bytes(&keygen_output.secret_key_bytes)
        .expect("Valid secret key");

    // Sign with empty context (matching the NEAR MPC implementation)
    let signature = secret_key.sign(message, None, None)
        .expect("Signing should succeed");

    signature.to_vec()
}

pub fn new_bls12381() -> (dtos::PublicKey, ckd::KeygenOutput) {
    let scalar = ckd::Scalar::random(&mut OsRng);
    let private_share = ckd::SigningShare::new(scalar);
    let public_key_element = ckd::ElementG2::generator() * scalar;
    let public_key = ckd::VerifyingKey::new(public_key_element);

    let keygen_output = ckd::KeygenOutput {
        private_share,
        public_key,
    };

    let compressed_key = public_key.to_element().to_compressed();
    let pk = dtos::PublicKey::from(dtos::Bls12381G2PublicKey::from(compressed_key));

    (pk, keygen_output)
}

pub fn derive_secret_key_secp256k1(
    secret_key: &ts_ecdsa::KeygenOutput,
    tweak: &Tweak,
) -> ts_ecdsa::KeygenOutput {
    let tweak = k256::Scalar::from_repr(tweak.as_bytes().into()).unwrap();
    let private_share =
        frost_secp256k1::keys::SigningShare::new(secret_key.private_share.to_scalar() + tweak);
    let public_key = frost_secp256k1::VerifyingKey::new(
        secret_key.public_key.to_element() + Secp256K1Group::generator() * tweak,
    );
    ts_ecdsa::KeygenOutput {
        private_share,
        public_key,
    }
}

pub fn derive_secret_key_ed25519(
    secret_key: &eddsa::KeygenOutput,
    tweak: &Tweak,
) -> eddsa::KeygenOutput {
    let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak.as_bytes());
    let private_share = SigningShare::new(secret_key.private_share.to_scalar() + tweak);
    let public_key =
        VerifyingKey::new(secret_key.public_key.to_element() + Ed25519Group::generator() * tweak);

    eddsa::KeygenOutput {
        private_share,
        public_key,
    }
}

pub fn generate_random_app_public_key(rng: &mut impl CryptoRngCore) -> Bls12381G1PublicKey {
    let x = blstrs::Scalar::random(rng);
    let big_x = blstrs::G1Projective::generator() * x;
    Bls12381G1PublicKey::from(big_x.to_compressed())
}
