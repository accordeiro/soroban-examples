#![cfg(test)]

use super::*;
use ed25519_dalek::Keypair;
use rand::thread_rng;
use soroban_sdk::testutils::ed25519::Sign;

use soroban_auth::{Ed25519Signature, SignaturePayload, SignaturePayloadV0};
use soroban_sdk::{BytesN, Env, RawVal, Symbol, Vec};

fn generate_keypair() -> Keypair {
    Keypair::generate(&mut thread_rng())
}

fn make_identifier(e: &Env, kp: &Keypair) -> Identifier {
    Identifier::Ed25519(kp.public.to_bytes().into_val(e))
}

fn make_signature(e: &Env, kp: &Keypair, function: &str, args: Vec<RawVal>) -> Signature {
    let msg = SignaturePayload::V0(SignaturePayloadV0 {
        function: Symbol::from_str(function),
        contract: BytesN::from_array(e, &[0; 32]),
        network: e.ledger().network_passphrase(),
        args,
    });
    Signature::Ed25519(Ed25519Signature {
        public_key: BytesN::from_array(e, &kp.public.to_bytes()),
        signature: kp.sign(msg).unwrap().into_val(e),
    })
}

#[test]
fn test_set_owner() {
    let env = Env::default();
    let contract_id = BytesN::from_array(&env, &[0; 32]);
    env.register_contract(&contract_id, AuthTokenContract);
    let client = AuthTokenContractClient::new(&env, contract_id);

    let owner_kp = generate_keypair();
    let owner_id = make_identifier(&env, &owner_kp);
    client.set_owner(&owner_id);
}

#[test]
#[should_panic(expected = "owner already set. can't be overriden.")]
fn test_cannot_set_owner_twice() {
    let env = Env::default();

    let contract_id = BytesN::from_array(&env, &[0; 32]);
    env.register_contract(&contract_id, AuthTokenContract);
    let client = AuthTokenContractClient::new(&env, contract_id);

    let owner_kp = generate_keypair();
    let owner_id = make_identifier(&env, &owner_kp);
    client.set_owner(&owner_id);

    let malicious_kp = generate_keypair();
    let malicious_id = make_identifier(&env, &malicious_kp);
    client.set_owner(&malicious_id);
}

#[test]
fn test_add_admin() {
    let env = Env::default();
    let contract_id = BytesN::from_array(&env, &[0; 32]);
    env.register_contract(&contract_id, AuthTokenContract);
    let client = AuthTokenContractClient::new(&env, contract_id);

    let owner_kp = generate_keypair();
    let owner_id = make_identifier(&env, &owner_kp);
    client.set_owner(&owner_id);

    let admin_kp = generate_keypair();
    let admin_id = make_identifier(&env, &admin_kp);

    let owner_nonce = client.nonce(&owner_id);
    let owner_sig = make_signature(
        &env,
        &owner_kp,
        "add_admin",
        (&admin_id, &owner_id, &owner_nonce).into_val(&env),
    );

    client.add_admin(&admin_id, &owner_sig, &owner_nonce);

    let admins = client.get_admins();
    assert!(admins.contains_key(admin_id));
}
