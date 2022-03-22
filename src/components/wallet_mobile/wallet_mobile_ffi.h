#ifndef wallet_mobile_ffi_h
#define wallet_mobile_ffi_h

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * When an asset is defined, several options governing the assets must be
 * specified:
 * 1. **Traceable**: Records and identities of traceable assets can be decrypted by a provided tracing key. By defaults, assets do not have
 * any tracing policies.
 * 2. **Transferable**: Non-transferable assets can only be transferred once from the issuer to another user. By default, assets are transferable.
 * 3. **Updatable**: Whether the asset memo can be updated. By default, assets are not updatable.
 * 4. **Transfer signature rules**: Signature weights and threshold for a valid transfer. By
 *    default, there are no special signature requirements.
 * 5. **Max units**: Optional limit on the total number of units of this asset that can be issued.
 *    By default, assets do not have issuance caps.
 * @see {@link module:Findora-Wasm~TracingPolicies|TracingPolicies} for more information about tracing policies.
 * @see {@link module:Findora-Wasm~TransactionBuilder#add_operation_update_memo|add_operation_update_memo} for more information about how to add
 * a memo update operation to a transaction.
 * @see {@link module:Findora-Wasm~SignatureRules|SignatureRules} for more information about co-signatures.
 * @see {@link
 * module:Findora-Wasm~TransactionBuilder#add_operation_create_asset|add_operation_create_asset}
 * for information about how to add asset rules to an asset definition.
 */
typedef struct AssetRules AssetRules;

/**
 * Object representing an asset definition. Used to fetch tracing policies and any other
 * information that may be required to construct a valid transfer or issuance.
 */
typedef struct AssetType AssetType;

/**
 * This object represents an asset record owned by a ledger key pair.
 * @see {@link module:Findora-Wasm.open_client_asset_record|open_client_asset_record} for information about how to decrypt an encrypted asset
 * record.
 */
typedef struct ClientAssetRecord ClientAssetRecord;

typedef struct CredIssuerPublicKey CredIssuerPublicKey;

typedef struct CredIssuerSecretKey CredIssuerSecretKey;

typedef struct CredUserPublicKey CredUserPublicKey;

typedef struct CredUserSecretKey CredUserSecretKey;

/**
 * Key pair of a credential issuer.
 */
typedef struct CredentialIssuerKeyPair CredentialIssuerKeyPair;

/**
 * Key pair of a credential user.
 */
typedef struct CredentialUserKeyPair CredentialUserKeyPair;

typedef struct EVMTransactionBuilder EVMTransactionBuilder;

typedef struct FeeInputs FeeInputs;

typedef struct OpenAssetRecord OpenAssetRecord;

/**
 * Asset owner memo. Contains information needed to decrypt an asset record.
 * @see {@link module:Findora-Wasm.ClientAssetRecord|ClientAssetRecord} for more details about asset records.
 */
typedef struct OwnerMemo OwnerMemo;

/**
 * Public parameters necessary for generating asset records. Generating this is expensive and
 * should be done as infrequently as possible.
 * @see {@link module:Findora-Wasm~TransactionBuilder#add_basic_issue_asset|add_basic_issue_asset}
 * for information using public parameters to create issuance asset records.
 */
typedef struct PublicParams PublicParams;

/**
 * Stores threshold and weights for a multisignature requirement.
 */
typedef struct SignatureRules SignatureRules;

/**
 * A collection of tracing policies. Use this object when constructing asset transfers to generate
 * the correct tracing proofs for traceable assets.
 */
typedef struct TracingPolicies TracingPolicies;

/**
 * Tracing policy for asset transfers. Can be configured to track credentials, the asset type and
 * amount, or both.
 */
typedef struct TracingPolicy TracingPolicy;

/**
 * Structure that allows users to construct arbitrary transactions.
 */
typedef struct TransactionBuilder TransactionBuilder;

/**
 * Structure that enables clients to construct complex transfers.
 */
typedef struct TransferOperationBuilder TransferOperationBuilder;

/**
 * Indicates whether the TXO ref is an absolute or relative value.
 */
typedef struct TxoRef TxoRef;

typedef struct Vec_ClientAssetRecord Vec_ClientAssetRecord;

typedef struct XfrKeyPair XfrKeyPair;

typedef struct XfrPublicKey XfrPublicKey;

typedef struct ByteBuffer {
  int64_t len;
  uint8_t *data;
} ByteBuffer;

/**
 * Returns the git commit hash and commit date of the commit this library was built against.
 */
char *findora_ffi_build_id(void);

char *findora_ffi_random_asset_type(void);

/**
 * Generates asset type as a Base64 string from a JSON-serialized JavaScript value.
 */
char *findora_ffi_asset_type_from_value(struct ByteBuffer code);

/**
 * Given a serialized state commitment and transaction, returns true if the transaction correctly
 * hashes up to the state commitment and false otherwise.
 * @param {string} state_commitment - String representing the state commitment.
 * @param {string} authenticated_txn - String representing the transaction.
 * @see {@link module:Network~Network#getTxn|Network.getTxn} for instructions on fetching a transaction from the ledger.
 * @see {@link module:Network~Network#getStateCommitment|Network.getStateCommitment}
 * for instructions on fetching a ledger state commitment.
 * @throws Will throw an error if the state commitment or the transaction fails to deserialize.
 */
bool findora_ffi_verify_authenticated_txn(const char *state_commitment,
                                          const char *authenticated_txn);

struct XfrPublicKey *findora_ffi_get_null_pk(void);

/**
 * Generate mnemonic with custom length and language.
 * - @param `wordslen`: acceptable value are one of [ 12, 15, 18, 21, 24 ]
 * - @param `lang`: acceptable value are one of [ "en", "zh", "zh_traditional", "fr", "it", "ko", "sp", "jp" ]
 */
char *findora_ffi_generate_mnemonic_custom(uint8_t words_len,
                                           const char *lang);

/**
 * # Safety
 *
 */
char *findora_ffi_decryption_pbkdf2_aes256gcm(char *enc_key_pair, const char *password);

struct ByteBuffer findora_ffi_encryption_pbkdf2_aes256gcm(const char *key_pair,
                                                          const char *password);

/**
 * Constructs a transfer key pair from a hex-encoded string.
 * The encode a key pair, use `keypair_to_str` function.
 */
struct XfrKeyPair *findora_ffi_keypair_from_str(const char *key_pair_str);

/**
 * # Safety
 *
 * Returns bech32 encoded representation of an XfrPublicKey.
 */
char *findora_ffi_public_key_to_bech32(const struct XfrPublicKey *key);

/**
 * # Safety
 *
 * Extracts the public key as a string from a transfer key pair.
 */
char *findora_ffi_get_pub_key_str(const struct XfrKeyPair *key);

/**
 * # Safety
 *
 * Extracts the private key as a string from a transfer key pair.
 */
char *findora_ffi_get_priv_key_str(const struct XfrKeyPair *key);

/**
 * # Safety
 *
 * Restore the XfrKeyPair from a mnemonic with a default bip44-path,
 * that is "m/44'/917'/0'/0/0" ("m/44'/coin'/account'/change/address").
 */
struct XfrKeyPair *findora_ffi_restore_keypair_from_mnemonic_default(const char *phrase);

/**
 * # Safety
 *
 * Expresses a transfer key pair as a hex-encoded string.
 * To decode the string, use `keypair_from_str` function.
 */
char *findora_ffi_keypair_to_str(const struct XfrKeyPair *key_pair);

/**
 * # Safety
 *
 */
struct XfrKeyPair *findora_ffi_create_keypair_from_secret(const char *sk_str);

/**
 * # Safety
 *
 */
struct XfrPublicKey *findora_ffi_get_pk_from_keypair(const struct XfrKeyPair *key_pair);

/**
 * # Safety
 *
 * Creates a new transfer key pair.
 */
struct XfrKeyPair *findora_ffi_new_keypair(void);

/**
 * # Safety
 *
 */
char *findora_ffi_bech32_to_base64(const char *pk);

/**
 * # Safety
 *
 */
char *findora_ffi_base64_to_bech32(const char *pk);

/**
 * # Safety
 * Builds an asset type from a JSON-encoded JavaScript value.
 */
struct AssetType *findora_ffi_asset_type_from_json(const char *asset_type_json);

/**
 * # Safety
 *
 * Fetch the tracing policies associated with this asset type.
 */
struct TracingPolicies *findora_ffi_asset_type_get_tracing_policies(const struct AssetType *asset_type);

/**
 * # Safety
 *
 * Converts a base64 encoded public key string to a public key.
 */
struct XfrPublicKey *findora_ffi_public_key_from_base64(const char *pk);

/**
 * Creates a relative txo reference as a JSON string. Relative txo references are offset
 * backwards from the operation they appear in -- 0 is the most recent, (n-1) is the first output
 * of the transaction.
 *
 * Use relative txo indexing when referring to outputs of intermediate operations (e.g. a
 * transaction containing both an issuance and a transfer).
 *
 * # Arguments
 * @param {BigInt} idx -  Relative TXO (transaction output) SID.
 */
struct TxoRef *findora_ffi_txo_ref_relative(uint64_t idx);

/**
 * Creates an absolute transaction reference as a JSON string.
 *
 * Use absolute txo indexing when referring to an output that has been assigned a utxo index (i.e.
 * when the utxo has been committed to the ledger in an earlier transaction).
 *
 * # Arguments
 * @param {BigInt} idx -  Txo (transaction output) SID.
 */
struct TxoRef *findora_ffi_txo_ref_absolute(uint64_t idx);

/**
 * # Safety
 *
 * Returns a object containing decrypted owner record information,
 * where `amount` is the decrypted asset amount, and `asset_type` is the decrypted asset type code.
 *
 * @param {ClientAssetRecord} record - Owner record.
 * @param {OwnerMemo} owner_memo - Owner memo of the associated record.
 * @param {XfrKeyPair} keypair - Keypair of asset owner.
 * @see {@link module:Findora-Wasm~ClientAssetRecord#from_json_record|ClientAssetRecord.from_json_record} for information about how to construct an asset record object
 * from a JSON result returned from the ledger server.
 */
struct OpenAssetRecord *findora_ffi_open_client_asset_record(const struct ClientAssetRecord *record,
                                                             const struct OwnerMemo *owner_memo,
                                                             const struct XfrKeyPair *keypair);

/**
 * # Safety
 *
 * pub enum AssetRecordType {
 *     NonConfidentialAmount_ConfidentialAssetType = 0,
 *     ConfidentialAmount_NonConfidentialAssetType = 1,
 *     ConfidentialAmount_ConfidentialAssetType = 2,
 *     NonConfidentialAmount_NonConfidentialAssetType = 3,
 * }
 */
int32_t findora_ffi_open_client_asset_record_get_record_type(const struct OpenAssetRecord *record);

/**
 * # Safety
 *
 */
char *findora_ffi_open_client_asset_record_get_asset_type(const struct OpenAssetRecord *record);

/**
 * # Safety
 *
 */
uint64_t findora_ffi_open_client_asset_record_get_amount(const struct OpenAssetRecord *record);

/**
 * # Safety
 *
 */
struct XfrPublicKey *findora_ffi_open_client_asset_record_get_pub_key(const struct OpenAssetRecord *record);

/**
 * # Safety
 *
 * Builds a client record from a JSON-encoded JavaScript value.
 *
 * @param {JsValue} val - JSON-encoded autehtnicated asset record fetched from ledger server with the `utxo_sid/{sid}` route,
 * where `sid` can be fetched from the query server with the `get_owned_utxos/{address}` route.
 * Note: The first field of an asset record is `utxo`. See the example below.
 *
 * @example
 * "utxo":{
 *   "amount":{
 *     "NonConfidential":5
 *   },
 *  "asset_type":{
 *     "NonConfidential":[113,168,158,149,55,64,18,189,88,156,133,204,156,46,106,46,232,62,69,233,157,112,240,132,164,120,4,110,14,247,109,127]
 *   },
 *   "public_key":"Glf8dKF6jAPYHzR_PYYYfzaWqpYcMvnrIcazxsilmlA="
 * }
 *
 * @see {@link module:Findora-Network~Network#getUtxo|Network.getUtxo} for information about how to
 * fetch an asset record from the ledger server.
 */
struct ClientAssetRecord *findora_ffi_client_asset_record_from_json(const char *val);

/**
 * # Safety
 *
 * Builds an owner memo from a JSON-serialized JavaScript value.
 * @param {JsValue} val - JSON owner memo fetched from query server with the `get_owner_memo/{sid}` route,
 * where `sid` can be fetched from the query server with the `get_owned_utxos/{address}` route. See the example below.
 *
 * @example
 * {
 *   "blind_share":[91,251,44,28,7,221,67,155,175,213,25,183,70,90,119,232,212,238,226,142,159,200,54,19,60,115,38,221,248,202,74,248],
 *   "lock":{"ciphertext":[119,54,117,136,125,133,112,193],"encoded_rand":"8KDql2JphPB5WLd7-aYE1bxTQAcweFSmrqymLvPDntM="}
 * }
 */
struct OwnerMemo *findora_ffi_owner_memo_from_json(const char *val);

/**
 * Generates a new credential issuer key.
 * @param {JsValue} attributes - Array of attribute types of the form `[{name: "credit_score",
 * size: 3}]`. The size refers to byte-size of the credential. In this case, the "credit_score"
 * attribute is represented as a 3 byte string "760". `attributes` is the list of attribute types
 * that the issuer can sign off on.
 */
struct CredentialIssuerKeyPair *findora_ffi_credential_issuer_key_gen(const char *attributes);

/**
 * Returns the credential issuer's public key.
 */
struct CredIssuerPublicKey *findora_ffi_credential_issuer_key_pair_get_pk(const struct CredentialIssuerKeyPair *pair);

/**
 * Returns the credential issuer's secret key.
 */
struct CredIssuerSecretKey *findora_ffi_credential_issuer_key_pair_get_sk(const struct CredentialIssuerKeyPair *pair);

/**
 * Generates a new credential user key.
 * @param {CredIssuerPublicKey} issuer_pub_key - The credential issuer that can sign off on this
 * user's attributes.
 */
struct CredentialUserKeyPair *findora_ffi_credential_user_key_gen(const struct CredIssuerPublicKey *issuer_pub_key);

/**
 * Returns the credential issuer's public key.
 */
struct CredUserPublicKey *findora_ffi_cred_issuer_public_key_get_pk(const struct CredentialUserKeyPair *pair);

/**
 * Returns the credential issuer's secret key.
 */
struct CredUserSecretKey *findora_ffi_cred_issuer_public_key_get_sk(const struct CredentialUserKeyPair *pair);

/**
 * Create a default set of asset rules. See class description for defaults.
 */
struct AssetRules *findora_ffi_asset_rules_new(void);

/**
 * Adds an asset tracing policy.
 * @param {TracingPolicy} policy - Tracing policy for the new asset.
 */
struct AssetRules *findora_ffi_asset_rules_add_tracing_policy(const struct AssetRules *ar,
                                                              const struct TracingPolicy *policy);

/**
 * Set a cap on the number of units of this asset that can be issued.
 * @param {BigInt} max_units - Maximum number of units that can be issued.
 */
struct AssetRules *findora_ffi_asset_rules_set_max_units(const struct AssetRules *ar,
                                                         uint64_t max_units);

/**
 * Transferability toggle. Assets that are not transferable can only be transferred by the asset
 * issuer.
 * @param {boolean} transferable - Boolean indicating whether asset can be transferred.
 */
struct AssetRules *findora_ffi_asset_rules_set_transferable(const struct AssetRules *ar,
                                                            bool transferable);

/**
 * The updatable flag determines whether the asset memo can be updated after issuance.
 * @param {boolean} updatable - Boolean indicating whether asset memo can be updated.
 * @see {@link module:Findora-Wasm~TransactionBuilder#add_operation_update_memo|add_operation_update_memo} for more information about how to add
 * a memo update operation to a transaction.
 */
struct AssetRules *findora_ffi_asset_rules_set_updatable(const struct AssetRules *ar,
                                                         bool updatable);

/**
 * Co-signature rules. Assets with co-signatue rules require additional weighted signatures to
 * be transferred.
 * @param {SignatureRules} multisig_rules - Co-signature restrictions.
 */
struct AssetRules *findora_ffi_asset_rules_set_transfer_multisig_rules(const struct AssetRules *ar,
                                                                       const struct SignatureRules *multisig_rules);

/**
 * Set the decimal number of asset. Return error string if failed, otherwise return changed asset.
 * #param {Number} decimals - The number of decimals used to set its user representation.
 * Decimals should be 0 ~ 255.
 */
struct AssetRules *findora_ffi_asset_rules_set_decimals(const struct AssetRules *ar,
                                                        uint8_t decimals);

/**
 * Construct a EVM Transaction that transfer account balance to UTXO.
 * @param {unsigned long long} amount - Amount to transfer.
 * @param {XfrKeyPair} fra_kp - Fra key pair.
 * @param {String} address - EVM address.
 * @param {String} eth_phrase - The account mnemonic.
 * @param {String} nonce - Json encoded U256(256 bits unsigned integer).
 */
struct EVMTransactionBuilder *findora_ffi_new_evm_transaction_transfer_from_account(const char *amount,
                                                                                    const struct XfrKeyPair *fra_kp,
                                                                                    const char *address,
                                                                                    const char *eth_phrase,
                                                                                    const char *nonce);

/**
 * # Safety
 * Generate the base64 encoded transaction data.
 */
const char *findora_ffi_evm_transaction_data(struct EVMTransactionBuilder *tx);

/**
 * # Safety
 * Free the memory.
 * **Danger:**, this will make the tx pointer a dangling pointer.
 */
void findora_ffi_free_evm_transaction(struct EVMTransactionBuilder *tx);

/**
 * Serialize ethereum address used to abci query nonce.
 */
const char *get_serialized_address(const char *address);

/**
 * Fee smaller than this value will be denied.
 */
uint64_t findora_ffi_fra_get_minimal_fee(void);

/**
 * The destination for fee to be transfered to.
 */
struct XfrPublicKey *findora_ffi_fra_get_dest_pubkey(void);

struct FeeInputs *findora_ffi_fee_inputs_new(void);

/**
 * # Safety
 *
 */
void findora_ffi_fee_inputs_append(struct FeeInputs *ptr,
                                   const char *am,
                                   const struct TxoRef *tr,
                                   const struct ClientAssetRecord *ar,
                                   const struct OwnerMemo *om,
                                   const struct XfrKeyPair *kp);

/**
 * The system address used to reveive delegation principals.
 */
char *findora_ffi_get_delegation_target_address(void);

char *findora_ffi_get_coinbase_address(void);

char *findora_ffi_get_coinbase_principal_address(void);

uint64_t findora_ffi_get_delegation_min_amount(void);

uint64_t findora_ffi_get_delegation_max_amount(void);

/**
 * # Safety
 *
 */
void findora_ffi_xfr_public_key_free(struct XfrPublicKey *ptr);

/**
 * # Safety
 *
 */
void findora_ffi_fee_inputs_free(struct FeeInputs *ptr);

/**
 * @param kp: owner's XfrKeyPair
 */
struct TransactionBuilder *findora_ffi_transaction_builder_add_fee_relative_auto(const struct TransactionBuilder *builder,
                                                                                 const struct XfrKeyPair *kp);

/**
 * Use this func to get the necessary infomations for generating `Relative Inputs`
 *
 * - TxoRef::Relative("Element index of the result")
 * - ClientAssetRecord::from_json("Element of the result")
 */
struct Vec_ClientAssetRecord findora_ffi_transaction_builder_get_relative_outputs(const struct TransactionBuilder *builder);

/**
 * As the last operation of any transaction,
 * add a static fee to the transaction.
 */
struct TransactionBuilder *findora_ffi_transaction_builder_add_fee(const struct TransactionBuilder *builder,
                                                                   const struct FeeInputs *inputs);

/**
 * A simple fee checker for mainnet v1.0.
 *
 * SEE [check_fee](ledger::data_model::Transaction::check_fee)
 */
bool findora_ffi_transaction_builder_check_fee(const struct TransactionBuilder *builder);

/**
 * Create a new transaction builder.
 * @param {BigInt} seq_id - Unique sequence ID to prevent replay attacks.
 */
struct TransactionBuilder *findora_ffi_transaction_builder_new(uint64_t seq_id);

/**
 * Wraps around TransactionBuilder to add an asset definition operation to a transaction builder instance.
 * @example <caption> Error handling </caption>
 * try {
 *     await wasm.add_operation_create_asset(wasm.new_keypair(), "test_memo", wasm.random_asset_type(), wasm.AssetRules.default());
 * } catch (err) {
 *     console.log(err)
 * }
 *
 * @param {XfrKeyPair} key_pair -  Issuer XfrKeyPair.
 * @param {string} memo - Text field for asset definition.
 * @param {string} token_code - Optional Base64 string representing the token code of the asset to be issued.
 * If empty, a token code will be chosen at random.
 * @param {AssetRules} asset_rules - Asset rules object specifying which simple policies apply
 * to the asset.
 */
struct TransactionBuilder *findora_ffi_transaction_builder_add_operation_create_asset(const struct TransactionBuilder *builder,
                                                                                      const struct XfrKeyPair *key_pair,
                                                                                      const char *memo,
                                                                                      const char *token_code,
                                                                                      const struct AssetRules *asset_rules);

/**
 * Wraps around TransactionBuilder to add an asset issuance to a transaction builder instance.
 *
 * Use this function for simple one-shot issuances.
 *
 * @param {XfrKeyPair} key_pair  - Issuer XfrKeyPair.
 * and types of traced assets.
 * @param {string} code - base64 string representing the token code of the asset to be issued.
 * @param {BigInt} seq_num - Issuance sequence number. Every subsequent issuance of a given asset type must have a higher sequence number than before.
 * @param {BigInt} amount - Amount to be issued.
 * @param {boolean} conf_amount - `true` means the asset amount is confidential, and `false` means it's nonconfidential.
 * @param {PublicParams} zei_params - Public parameters necessary to generate asset records.
 */
struct TransactionBuilder *findora_ffi_transaction_builder_add_basic_issue_asset(const struct TransactionBuilder *builder,
                                                                                 const struct XfrKeyPair *key_pair,
                                                                                 const char *code,
                                                                                 uint64_t seq_num,
                                                                                 const char *amount,
                                                                                 bool conf_amount,
                                                                                 const struct PublicParams *zei_params);

/**
 * Adds an operation to the transaction builder that adds a hash to the ledger's custom data
 * store.
 * @param {XfrKeyPair} auth_key_pair - Asset creator key pair.
 * @param {String} code - base64 string representing token code of the asset whose memo will be updated.
 * transaction validates.
 * @param {String} new_memo - The new asset memo.
 * @see {@link module:Findora-Wasm~AssetRules#set_updatable|AssetRules.set_updatable} for more information about how
 * to define an updatable asset.
 */
struct TransactionBuilder *findora_ffi_transaction_builder_add_operation_update_memo(const struct TransactionBuilder *builder,
                                                                                     const struct XfrKeyPair *auth_key_pair,
                                                                                     const char *code,
                                                                                     const char *new_memo);

struct TransactionBuilder *findora_ffi_transaction_builder_add_operation_delegate(const struct TransactionBuilder *builder,
                                                                                  const struct XfrKeyPair *keypair,
                                                                                  const char *amount,
                                                                                  const char *validator);

struct TransactionBuilder *findora_ffi_transaction_builder_add_operation_undelegate(const struct TransactionBuilder *builder,
                                                                                    const struct XfrKeyPair *keypair);

struct TransactionBuilder *findora_ffi_transaction_builder_add_operation_undelegate_partially(const struct TransactionBuilder *builder,
                                                                                              const struct XfrKeyPair *keypair,
                                                                                              const char *am,
                                                                                              const char *target_validator);

struct TransactionBuilder *findora_ffi_transaction_builder_add_operation_claim(const struct TransactionBuilder *builder,
                                                                               const struct XfrKeyPair *keypair);

struct TransactionBuilder *findora_ffi_transaction_builder_add_operation_claim_custom(const struct TransactionBuilder *builder,
                                                                                      const struct XfrKeyPair *keypair,
                                                                                      const char *am);

/**
 * Adds a serialized transfer asset operation to a transaction builder instance.
 * @param {string} op - a JSON-serialized transfer operation.
 * @see {@link module:Findora-Wasm~TransferOperationBuilder} for details on constructing a transfer operation.
 * @throws Will throw an error if `op` fails to deserialize.
 */
struct TransactionBuilder *findora_ffi_transaction_builder_add_transfer_operation(const struct TransactionBuilder *builder,
                                                                                  const char *op);

/**
 * Adds a serialized transfer account operation to a transaction builder instance.
 * @param {string} address - a String which is hex-encoded EVM address or base64 encoded xfr public key or bech32 encoded xfr public key.
 * @param {unsigned long long} amount - Amount to be transfered.
 * @param {XfrKeyPair} kp - Fra ownner key pair.
 * @return null if `address` or 'kp' is incorrect.
 */
struct TransactionBuilder *findora_ffi_transaction_builder_add_operation_convert_account(const struct TransactionBuilder *builder,
                                                                                         const char *address,
                                                                                         const char *amount,
                                                                                         const struct XfrKeyPair *kp);

struct TransactionBuilder *findora_ffi_transaction_builder_sign(const struct TransactionBuilder *builder,
                                                                const struct XfrKeyPair *kp);

/**
 * Extracts the serialized form of a transaction.
 */
char *findora_ffi_transaction_builder_transaction(const struct TransactionBuilder *builder);

/**
 * Calculates transaction handle.
 */
char *findora_ffi_transaction_builder_transaction_handle(const struct TransactionBuilder *builder);

/**
 * Fetches a client record from a transaction.
 * @param {number} idx - Record to fetch. Records are added to the transaction builder sequentially.
 */
struct ClientAssetRecord *findora_ffi_transaction_builder_get_owner_record(const struct TransactionBuilder *builder,
                                                                           uintptr_t idx);

/**
 * Fetches an owner memo from a transaction
 * @param {number} idx - Owner memo to fetch. Owner memos are added to the transaction builder sequentially.
 */
struct OwnerMemo *findora_ffi_transaction_builder_get_owner_memo(const struct TransactionBuilder *builder,
                                                                 uintptr_t idx);

/**
 * Create a new transfer operation builder.
 */
struct TransferOperationBuilder *findora_ffi_transfer_operation_builder_new(void);

/**
 * # Safety
 *
 * Debug function that does not need to go into the docs.
 */
char *findora_ffi_transfer_operation_builder_debug(const struct TransferOperationBuilder *builder);

/**
 * # Safety
 *
 * Wraps around TransferOperationBuilder to add an input to a transfer operation builder.
 */
struct TransferOperationBuilder *findora_ffi_transfer_operation_builder_add_input_with_tracing(const struct TransferOperationBuilder *builder,
                                                                                               const struct TxoRef *txo_ref,
                                                                                               const struct ClientAssetRecord *asset_record,
                                                                                               const struct OwnerMemo *owner_memo,
                                                                                               const struct TracingPolicies *tracing_policies,
                                                                                               const struct XfrKeyPair *key,
                                                                                               const char *amount);

/**
 * # Safety
 *
 * Wraps around TransferOperationBuilder to add an input to a transfer operation builder.
 */
struct TransferOperationBuilder *findora_ffi_transfer_operation_builder_add_input_no_tracing(const struct TransferOperationBuilder *builder,
                                                                                             const struct TxoRef *txo_ref,
                                                                                             const struct ClientAssetRecord *asset_record,
                                                                                             const struct OwnerMemo *owner_memo,
                                                                                             const struct XfrKeyPair *key,
                                                                                             const char *amount);

/**
 * # Safety
 *
 * Wraps around TransferOperationBuilder to add an output to a transfer operation builder.
 */
struct TransferOperationBuilder *findora_ffi_transfer_operation_builder_add_output_with_tracing(const struct TransferOperationBuilder *builder,
                                                                                                const char *amount,
                                                                                                const struct XfrPublicKey *recipient,
                                                                                                const struct TracingPolicies *tracing_policies,
                                                                                                const char *code,
                                                                                                bool conf_amount,
                                                                                                bool conf_type);

/**
 * # Safety
 *
 * Wraps around TransferOperationBuilder to add an output to a transfer operation builder.
 */
struct TransferOperationBuilder *findora_ffi_transfer_operation_builder_add_output_no_tracing(const struct TransferOperationBuilder *builder,
                                                                                              const char *amount,
                                                                                              const struct XfrPublicKey *recipient,
                                                                                              const char *code,
                                                                                              bool conf_amount,
                                                                                              bool conf_type);

/**
 * # Safety
 *
 * Wraps around TransferOperationBuilder to ensure the transfer inputs and outputs are balanced.
 * This function will add change outputs for all unspent portions of input records.
 * @throws Will throw an error if the transaction cannot be balanced.
 */
struct TransferOperationBuilder *findora_ffi_transfer_operation_builder_balance(const struct TransferOperationBuilder *builder);

/**
 * # Safety
 *
 * Wraps around TransferOperationBuilder to finalize the transaction.
 */
struct TransferOperationBuilder *findora_ffi_transfer_operation_builder_create(const struct TransferOperationBuilder *builder);

/**
 * # Safety
 *
 * Wraps around TransferOperationBuilder to add a signature to the operation.
 *
 * All input owners must sign.
 */
struct TransferOperationBuilder *findora_ffi_transfer_operation_builder_sign(const struct TransferOperationBuilder *builder,
                                                                             const struct XfrKeyPair *kp);

/**
 * # Safety
 *
 */
char *findora_ffi_transfer_operation_builder_builder(const struct TransferOperationBuilder *builder);

/**
 * # Safety
 *
 * Wraps around TransferOperationBuilder to extract an operation expression as JSON.
 */
char *findora_ffi_transfer_operation_builder_transaction(const struct TransferOperationBuilder *builder);

#endif /* wallet_mobile_ffi_h */
