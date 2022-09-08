#![no_std]

#[cfg(feature = "testutils")]
extern crate std;

mod test;

use soroban_auth::{
    check_auth, NonceAuth, {Identifier, Signature},
};
use soroban_sdk::{contractimpl, contracttype, symbol, BigInt, Env, IntoVal, Map};

#[contracttype]
pub enum DataStoreKey {
    Owner,
    Admins,
    Nonce(Identifier),
}

fn read_nonce(e: &Env, id: Identifier) -> BigInt {
    let key = DataStoreKey::Nonce(id);
    e.contract_data()
        .get(key)
        .unwrap_or_else(|| Ok(BigInt::zero(e)))
        .unwrap()
}

struct NonceSignature(Signature);

impl NonceAuth for NonceSignature {
    fn read_nonce(e: &Env, id: Identifier) -> BigInt {
        read_nonce(e, id)
    }

    fn read_and_increment_nonce(&self, e: &Env, id: Identifier) -> BigInt {
        let key = DataStoreKey::Nonce(id.clone());
        let nonce = Self::read_nonce(e, id);
        e.contract_data().set(key, &nonce + 1);
        nonce
    }

    fn signature(&self) -> &Signature {
        &self.0
    }
}

pub struct AuthTokenContract;

#[contractimpl]
impl AuthTokenContract {
    pub fn set_owner(e: Env, owner: Identifier) {
        assert!(
            !e.contract_data().has(DataStoreKey::Owner),
            "owner already set. can't be overriden."
        );
        e.contract_data().set(DataStoreKey::Owner, owner);
    }

    pub fn add_admin(e: Env, admin_id: Identifier, sig: Signature, nonce: BigInt) {
        let auth_id = sig.get_identifier(&e);
        assert!(
            auth_id
                == e.contract_data()
                    .get_unchecked(DataStoreKey::Owner)
                    .unwrap(),
            "only owner can add admins."
        );

        check_auth(
            &e,
            &NonceSignature(sig),
            nonce.clone(),
            symbol!("add_admin"),
            (&admin_id, auth_id, nonce).into_val(&e),
        );

        let mut admins: Map<Identifier, ()> = e
            .contract_data()
            .get(DataStoreKey::Admins)
            .unwrap_or_else(|| Ok(Map::new(&e)))
            .unwrap();

        admins.set(admin_id, ());

        e.contract_data().set(DataStoreKey::Admins, admins);
    }

    pub fn get_admins(e: Env) -> Map<Identifier, ()> {
        e.contract_data()
            .get_unchecked(DataStoreKey::Admins)
            .unwrap()
    }

    pub fn nonce(e: Env, id: Identifier) -> BigInt {
        read_nonce(&e, id)
    }
}
