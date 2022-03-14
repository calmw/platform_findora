use std::os::raw::c_char;

use crate::rust::{account::EVMTransactionBuilder, c_char_to_string, string_to_c_char};

use zei::xfr::sig::XfrKeyPair;

use fp_types::U256;

#[no_mangle]
/// Construct a EVM Transaction that transfer account balance to UTXO.
/// @param {unsigned long long} amount - Amount to transfer.
/// @param {XfrKeyPair} fra_kp - Fra key pair.
/// @param {String} address - EVM address.
/// @param {String} eth_phrase - The account mnemonic.
/// @param {String} nonce - Json encoded U256(256 bits unsigned integer).
pub extern "C" fn findora_ffi_new_withdraw_transaction(
    amount: u64,
    fra_kp: &XfrKeyPair,
    address: *const c_char,
    eth_phrase: *const c_char,
    nonce: *const c_char,
) -> *mut EVMTransactionBuilder {
    let nonce: U256 = {
        let nonce_str = c_char_to_string(nonce);
        match serde_json::from_str(&nonce_str) {
            Ok(n) => n,
            Err(e) => {
                println!("{:?}", e);
                return core::ptr::null_mut();
            }
        }
    };

    let address = {
        let addr = c_char_to_string(address);
        if addr.is_empty() {
            None
        } else {
            Some(addr)
        }
    };

    let eth_phrase = {
        let phrase = c_char_to_string(eth_phrase);
        if phrase.is_empty() {
            None
        } else {
            Some(phrase)
        }
    };

    match EVMTransactionBuilder::new_transfer_from_account(
        amount, address, fra_kp, eth_phrase, nonce,
    ) {
        Ok(tx) => tx.into_ptr(),
        Err(e) => {
            println!("{:?}", e);
            core::ptr::null_mut()
        }
    }
}

#[no_mangle]
/// # Safety
/// Generate the base64 encoded transaction data.
pub unsafe extern "C" fn findora_ffi_evm_transaction_data(
    tx: *mut EVMTransactionBuilder,
) -> *const c_char {
    let tx = &*tx;
    string_to_c_char(tx.serialized_transaction_base64())
}

#[no_mangle]
/// # Safety
/// Free the memory.
/// **Danger:**, this will make the tx pointer a dangling pointer.
pub unsafe extern "C" fn findora_ffi_free_evm_transaction(
    tx: *mut EVMTransactionBuilder,
) {
    let _ = Box::from_raw(tx);
}