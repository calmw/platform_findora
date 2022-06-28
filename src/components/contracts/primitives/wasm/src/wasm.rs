#![allow(clippy::unused_unit)]

use core::fmt::Display;
use ethereum::{
    LegacyTransactionMessage, TransactionV0 as LegacyTransaction,
    TransactionV2 as Transaction,
};
use ethereum_types::{H160, H256};
use fp_types::{
    actions::{
        ethereum::Action as EthAction, ethereum::LegacyAction as LegacyEthAction,
        Action, LegacyAction,
    },
    assemble::{LegacyUncheckedTransaction, UncheckedTransaction},
    crypto::secp256k1_ecdsa_recover,
};
use fp_utils::tx::EvmRawTxWrapper;
use ruc::{d, err::RucResult};
use sha3::{Digest, Keccak256};
use wasm_bindgen::prelude::*;

#[inline(always)]
pub(crate) fn error_to_jsvalue<T: Display>(e: T) -> JsValue {
    JsValue::from_str(&e.to_string())
}

#[inline(always)]
pub fn legacy_recover_signer(transaction: &LegacyTransaction) -> Option<H160> {
    let mut sig = [0u8; 65];
    let mut msg = [0u8; 32];
    sig[0..32].copy_from_slice(&transaction.signature.r()[..]);
    sig[32..64].copy_from_slice(&transaction.signature.s()[..]);
    sig[64] = transaction.signature.standard_v();
    msg.copy_from_slice(&LegacyTransactionMessage::from(transaction.clone()).hash()[..]);

    let pubkey = secp256k1_ecdsa_recover(&sig, &msg).ok()?;
    Some(H160::from(H256::from_slice(
        Keccak256::digest(&pubkey).as_slice(),
    )))
}

#[inline(always)]
pub fn recover_signer(transaction: &Transaction) -> Option<H160> {
    let mut sig = [0u8; 65];
    let mut msg = [0u8; 32];
    match transaction {
        Transaction::Legacy(t) => {
            sig[0..32].copy_from_slice(&t.signature.r()[..]);
            sig[32..64].copy_from_slice(&t.signature.s()[..]);
            sig[64] = t.signature.standard_v();
            msg.copy_from_slice(
                &ethereum::LegacyTransactionMessage::from(t.clone()).hash()[..],
            );
        }
        Transaction::EIP1559(t) => {
            sig[0..32].copy_from_slice(&t.r[..]);
            sig[32..64].copy_from_slice(&t.s[..]);
            sig[64] = t.odd_y_parity as u8;
            msg.copy_from_slice(
                &ethereum::EIP1559TransactionMessage::from(t.clone()).hash()[..],
            );
        }
        _ => {
            return None;
        }
    }
    let pubkey = fp_types::crypto::secp256k1_ecdsa_recover(&sig, &msg).ok()?;
    Some(H160::from(H256::from_slice(
        Keccak256::digest(&pubkey).as_slice(),
    )))
}

pub fn recover_tx_signer(raw_tx: String) -> Result<String, JsValue> {
    let tx_bytes = base64::decode_config(&raw_tx, base64::URL_SAFE)
        .c(d!())
        .map_err(error_to_jsvalue)?;
    let raw_tx = EvmRawTxWrapper::unwrap(&tx_bytes)
        .c(d!())
        .map_err(error_to_jsvalue)?;

    let unchecked_tx: UncheckedTransaction<()> = serde_json::from_slice(raw_tx)
        .c(d!())
        .map_err(error_to_jsvalue)?;
    if let Action::Ethereum(EthAction::Transact(tx)) = unchecked_tx.function {
        let signer = recover_signer(&tx).c(d!()).map_err(error_to_jsvalue)?;
        Ok(format!("{:?}", signer))
    } else {
        Err(error_to_jsvalue("invalid raw tx"))
    }
}

pub fn evm_tx_hash(raw_tx: String) -> Result<String, JsValue> {
    let tx_bytes = base64::decode_config(&raw_tx, base64::URL_SAFE)
        .c(d!())
        .map_err(error_to_jsvalue)?;
    let raw_tx = EvmRawTxWrapper::unwrap(&tx_bytes)
        .c(d!())
        .map_err(error_to_jsvalue)?;

    let unchecked_tx: UncheckedTransaction<()> = serde_json::from_slice(raw_tx)
        .c(d!())
        .map_err(error_to_jsvalue)?;
    if let Action::Ethereum(EthAction::Transact(tx)) = unchecked_tx.function {
        let hash = H256::from_slice(Keccak256::digest(&rlp::encode(&tx)).as_slice());
        Ok(format!("{:?}", hash))
    } else {
        Err(error_to_jsvalue("invalid raw tx"))
    }
}

use std::fs;
use std::io::Write;

#[cfg(test)]
#[allow(missing_docs)]
mod test {
    use super::*;
    use fp_types::actions::Action;

    #[test]
    fn recover_signer_works() {
        let raw_tx = String::from("ZXZtOnsic2lnbmF0dXJlIjpudWxsLCJmdW5jdGlvbiI6eyJFdGhlcmV1bSI6eyJUcmFuc2FjdCI6eyJub25jZSI6IjB4MSIsImdhc19wcmljZSI6IjB4MTc0ODc2ZTgwMCIsImdhc19saW1pdCI6IjB4NTIwOCIsImFjdGlvbiI6eyJDYWxsIjoiMHgyYWQzMjg0NmM2ZGQyZmZkM2VkYWRiZTUxY2Q1YWUwNGFhNWU1NzVlIn0sInZhbHVlIjoiMHg1NmJjNzVlMmQ2MzEwMDAwMCIsImlucHV0IjpbXSwic2lnbmF0dXJlIjp7InYiOjEwODIsInIiOiIweGY4YWVmN2Y4MDUzZDg5ZmVlMzk1MGM0ZDcwMjA4MGJmM2E4MDcyYmVkNWQ4NGEzYWYxOWEzNjAwODFiNjM2YTIiLCJzIjoiMHgyOTYyOTlhOGYyNDMwYjg2ZmQzZWI5NzZlYWJjNzMwYWMxY2ZiYmJlMzZlYjY5ZWFlMzM4Y2ZmMzNjNGE5OGMxIn19fX19");
        let tx_bytes = base64::decode_config(&raw_tx, base64::URL_SAFE).unwrap();
        let evm_tx = EvmRawTxWrapper::unwrap(&tx_bytes).unwrap();
        let unchecked_tx: LegacyUncheckedTransaction<()> =
            serde_json::from_slice(evm_tx).unwrap();
        if let LegacyAction::Ethereum(LegacyEthAction::Transact(tx)) =
            unchecked_tx.function
        {
            let signer = legacy_recover_signer(&tx).unwrap();
            assert_eq!(
                format!("{:?}", signer),
                "0xa5225cbee5052100ec2d2d94aa6d258558073757"
            );
        } else {
            panic!()
        }
    }

    #[test]
    fn evm_tx_hash_works() {
        let raw_tx = String::from("eyJzaWduYXR1cmUiOm51bGwsImZ1bmN0aW9uIjp7IkV0aGVyZXVtIjp7IlRyYW5zYWN0Ijp7Im5vbmNlIjoiMHg5IiwiZ2FzX3ByaWNlIjoiMHhlOGQ0YTUxMDAwIiwiZ2FzX2xpbWl0IjoiMHg1MjA4IiwiYWN0aW9uIjp7IkNhbGwiOiIweGE1MjI1Y2JlZTUwNTIxMDBlYzJkMmQ5NGFhNmQyNTg1NTgwNzM3NTcifSwidmFsdWUiOiIweDk4YTdkOWI4MzE0YzAwMDAiLCJpbnB1dCI6W10sInNpZ25hdHVyZSI6eyJ2IjoxMDgyLCJyIjoiMHg4MDBjZjQ5ZTAzMmJhYzY4MjY3MzdhZGJhZDEzN2Y0MTk5OTRjNjgxZWE1ZDUyYjliMGJhZDJmNDAyYjMwMTI0IiwicyI6IjB4Mjk1Mjc3ZWY2NTYzNDAwY2VkNjFiODhkM2ZiNGM3YjMyY2NkNTcwYThiOWJiOGNiYmUyNTkyMTRhYjdkZTI1YSJ9fX19fQ==");
        let tx_bytes = base64::decode_config(&raw_tx, base64::URL_SAFE).unwrap();
        let unchecked_tx: LegacyUncheckedTransaction<()> =
            serde_json::from_slice(tx_bytes.as_slice()).unwrap();
        if let LegacyAction::Ethereum(LegacyEthAction::Transact(tx)) =
            unchecked_tx.function
        {
            let hash = H256::from_slice(Keccak256::digest(&rlp::encode(&tx)).as_slice());
            println!("{:?}", hash);
            assert_eq!(
                format!("{:?}", hash),
                "0x0eeb0ff455b1b57b821634cf853e7247e584a675610f13097cc49c2022505df3"
            );
        } else {
            panic!()
        }
    }
}
