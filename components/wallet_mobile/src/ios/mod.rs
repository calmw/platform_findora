pub mod fee_inputs;
pub mod free;
pub mod tx_builder;

use crate::rust::types;

use crate::rust::*;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use zei::xfr::structs::ASSET_TYPE_LENGTH;

#[no_mangle]
pub extern "C" fn findora_ffi_build_id() -> *mut c_char {
    string_to_c_char(build_id())
}

#[no_mangle]
pub extern "C" fn findora_ffi_random_asset_type() -> *mut c_char {
    string_to_c_char(random_asset_type())
}

#[no_mangle]
pub extern "C" fn findora_ffi_asset_type_from_value(code: *const c_char) -> *mut c_char {
    let mut dst = [0u8; ASSET_TYPE_LENGTH];
    let c_str = unsafe { CStr::from_ptr(code) };
    dst.copy_from_slice(c_str.to_bytes());
    string_to_c_char(rs_asset_type_from_value(dst))
}

#[no_mangle]
pub extern "C" fn findora_ffi_verify_authenticated_txn(
    state_commitment: *const c_char,
    authenticated_txn: *const c_char,
) -> bool {
    let state_commitment = c_char_to_string(state_commitment);
    let authenticated_txn = c_char_to_string(authenticated_txn);
    rs_verify_authenticated_txn(state_commitment, authenticated_txn).unwrap_or(false)
}

// TODO
#[no_mangle]
pub extern "C" fn findora_ffi_authenticated_kv_lookup_new()
-> *mut types::AuthenticatedKVLookup {
    unimplemented!()
    // let val = AuthenticatedKVLookup{
    // };
    //
    // let boxed_data = Box::new(val);
    // Box::into_raw(boxed_data)
}

#[no_mangle]
pub unsafe extern "C" fn findora_ffi_verify_authenticated_custom_data_result(
    state_commitment: *const c_char,
    authenticated_res: *const types::AuthenticatedKVLookup,
) -> bool {
    let state_commitment = c_char_to_string(state_commitment);
    rs_verify_authenticated_custom_data_result(state_commitment, &*authenticated_res)
        .unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn findora_ffi_calculate_fee(
    ir_numerator: u64,
    ir_denominator: u64,
    outstanding_balance: u64,
) -> u64 {
    calculate_fee(ir_numerator, ir_denominator, outstanding_balance)
}

#[no_mangle]
pub extern "C" fn findora_ffi_get_null_pk() -> *mut types::XfrPublicKey {
    let pk = get_null_pk().into();
    Box::into_raw(Box::new(pk))
}

#[no_mangle]
pub extern "C" fn findora_ffi_create_default_policy_info() -> *mut c_char {
    string_to_c_char(create_default_policy_info())
}

#[no_mangle]
pub extern "C" fn findora_ffi_create_debt_policy_info(
    ir_numerator: u64,
    ir_denominator: u64,
    fiat_code: *const c_char,
    loan_amount: u64,
) -> *mut c_char {
    assert!(!fiat_code.is_null());

    if let Ok(info) = rs_create_debt_policy_info(
        ir_numerator,
        ir_denominator,
        c_char_to_string(fiat_code),
        loan_amount,
    ) {
        string_to_c_char(info)
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn findora_ffi_create_debt_memo(
    ir_numerator: u64,
    ir_denominator: u64,
    fiat_code: *const c_char,
    loan_amount: u64,
) -> *mut c_char {
    assert!(!fiat_code.is_null());

    if let Ok(info) = rs_create_debt_memo(
        ir_numerator,
        ir_denominator,
        c_char_to_string(fiat_code),
        loan_amount,
    ) {
        string_to_c_char(info)
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn findora_ffi_generate_mnemonic_custom(
    words_len: u8,
    lang: *const c_char,
) -> *mut c_char {
    assert!(!lang.is_null());

    if let Ok(info) =
        rs_generate_mnemonic_custom(words_len, c_char_to_string(lang).as_str())
    {
        string_to_c_char(info)
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn findora_ffi_decryption_pbkdf2_aes256gcm(
    enc_key_pair: *mut c_char,
    password: *const c_char,
) -> *mut c_char {
    assert!(!enc_key_pair.is_null());
    assert!(!password.is_null());

    let c_str = unsafe { CString::from_raw(enc_key_pair) };
    let plaintext =
        decryption_pbkdf2_aes256gcm(c_str.into_bytes(), c_char_to_string(password));
    string_to_c_char(plaintext)
}

#[no_mangle]
pub extern "C" fn findora_ffi_encryption_pbkdf2_aes256gcm(
    key_pair: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    assert!(!key_pair.is_null());
    assert!(!password.is_null());

    let res = encryption_pbkdf2_aes256gcm(
        c_char_to_string(key_pair),
        c_char_to_string(password),
    );

    string_to_c_char(String::from_utf8(res).unwrap())
}

#[no_mangle]
pub extern "C" fn findora_ffi_keypair_from_str(
    key_pair_str: *const c_char,
) -> *mut types::XfrKeyPair {
    assert!(!key_pair_str.is_null());
    let val = types::XfrKeyPair::from(keypair_from_str(c_char_to_string(key_pair_str)));

    let boxed_data = Box::new(val);
    Box::into_raw(boxed_data)
}

#[no_mangle]
pub unsafe extern "C" fn findora_ffi_public_key_to_bech32(
    key: *const types::XfrPublicKey,
) -> *mut c_char {
    assert!(!key.is_null());

    string_to_c_char(public_key_to_bech32(&*key))
}

#[no_mangle]
pub unsafe extern "C" fn findora_ffi_get_pub_key_str(
    key: *const types::XfrKeyPair,
) -> *mut c_char {
    assert!(!key.is_null());

    string_to_c_char(get_pub_key_str(&*key))
}

#[no_mangle]
pub unsafe extern "C" fn findora_ffi_restore_keypair_from_mnemonic_default(
    phrase: *const c_char,
) -> *mut types::XfrKeyPair {
    assert!(!phrase.is_null());

    if let Ok(info) =
        rs_restore_keypair_from_mnemonic_default(c_char_to_string(phrase).as_str())
    {
        let boxed_data = Box::new(types::XfrKeyPair::from(info));
        Box::into_raw(boxed_data)
    } else {
        ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn findora_ffi_keypair_to_str(
    key_pair: *const types::XfrKeyPair,
) -> *mut c_char {
    assert!(!key_pair.is_null());

    string_to_c_char(keypair_to_str(&*key_pair))
}

#[no_mangle]
pub unsafe extern "C" fn findora_ffi_create_keypair_from_secret(
    sk_str: *const c_char,
) -> *mut types::XfrKeyPair {
    assert!(!sk_str.is_null());

    if let Some(info) = create_keypair_from_secret(c_char_to_string(sk_str)) {
        let boxed_data = Box::new(types::XfrKeyPair::from(info));
        Box::into_raw(boxed_data)
    } else {
        ptr::null_mut()
    }
}
