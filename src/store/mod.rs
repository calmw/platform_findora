use crate::data_model;
use crate::data_model::AssetTokenProperties;
use crate::data_model::AssetCreation;
use crate::data_model::Operation::asset_creation;
use zei::utxo_transaction::{TxOutput, TxPublicFields};
use zei::keys::{ZeiPublicKey};
use chrono::format::Pad;
use crate::data_model::{
    Asset, AssetIssuance, AssetPolicyKey, AssetToken, AssetTokenCode, AssetTransfer, AssetType,
    CustomAssetPolicy, Operation, PrivateAsset, SmartContract, SmartContractKey, Transaction,
    TxSequenceNumber, Utxo, UtxoAddress, Address, LedgerSignature, Digest, AssetCreationBody
};
use std::collections::{HashMap};
use std::io::{self, Write};

pub trait LedgerAccess {
    fn check_utxo(&self, addr: &UtxoAddress) -> Option<Utxo>;
    fn get_asset_token(&self, code: &AssetTokenCode) -> Option<AssetToken>;
    fn get_asset_policy(&self, key: &AssetPolicyKey) -> Option<CustomAssetPolicy>;
    fn get_smart_contract(&self, key: &SmartContractKey) -> Option<SmartContract>;
}

pub trait LedgerUpdate {
    fn apply_transaction(&mut self, txn: Transaction) -> ();
}

pub trait LedgerValidate {
    fn validate_transaction(&mut self, txn: &Transaction) -> bool;
}

pub struct NextIndex {
    tx_index: TxSequenceNumber,
    op_index: u16,
    utxo_index: u16,
}

impl NextIndex {
    pub fn new() -> NextIndex {
        NextIndex {
            tx_index: TxSequenceNumber { val: 0 },
            op_index: 0,
            utxo_index: 0,
        }
    }
}

pub struct LedgerState {
    txs: Vec<Transaction>,
    utxos: HashMap<UtxoAddress, Utxo>,
    contracts: HashMap<SmartContractKey, SmartContract>,
    policies: HashMap<AssetPolicyKey, CustomAssetPolicy>,
    tokens: HashMap<AssetTokenCode, AssetToken>,
    issuance_num: HashMap<AssetTokenCode, u64>,
    next_index: NextIndex,
}

impl LedgerState {
    pub fn new() -> LedgerState {
        LedgerState {
            txs: Vec::new(),
            utxos: HashMap::new(),
            contracts: HashMap::new(),
            policies: HashMap::new(),
            tokens: HashMap::new(),
            issuance_num: HashMap::new(),
            next_index: NextIndex::new(),
        }
    }

    fn add_txo(&mut self, txo: &TxOutput) {
        let utxo_addr = UtxoAddress {
            transaction_id: TxSequenceNumber {
                val: self.next_index.tx_index.val,
            },
            operation_index: self.next_index.op_index,
            output_index: self.next_index.utxo_index,
        };
        let utxo_ref = Utxo {
            key: utxo_addr,
            digest: [0; 32], // TODO(Kevin): add code to calculate hash
            output: txo.clone(),
        };

        self.utxos.insert(utxo_addr, utxo_ref);
        self.next_index.utxo_index += 1;
    }

    fn apply_asset_transfer(&mut self, transfer: &AssetTransfer) -> () {
        for utxo in &transfer.body.inputs {
            self.utxos.remove(&utxo);
        }

        for out in &transfer.body.transfer.get_outputs() {
            self.add_txo(out);
        }
    }

    fn apply_asset_issuance(&mut self, issue: &AssetIssuance) -> () {
        // TODO Add checking mechanism that seq_num has not already been applied
        for out in &issue.body.outputs {
            self.add_txo(out);
            //TODO Change updating AssetToken to work with Zei Output types
           // match &out.asset {
           //     AssetType::Normal(a) => {
           //         if let Some(token) = self.tokens.get_mut(&a.code) {
           //             token.units += a.amount;
           //         }
           //         //TODO: We should never have the if statement above fail, but should we write something if it does
           //     }
           //     //TODO: (Kevin) Implement Private Asset Issuance
           //     AssetType::Private(_) => println!("Private Issuance Not Implemented!"),
           // }
        }
    }

    fn apply_asset_creation(&mut self, create: &AssetCreation) -> () {
        // TODO: check to make sure that another asset token with the same key has not been created
        let token: AssetToken = AssetToken {
            properties: create.body.properties.clone(),
            ..Default::default()
        };
        self.tokens.insert(token.properties.code.clone(), token);
    }

    fn apply_operation(&mut self, op: &Operation) -> () {
        self.next_index.utxo_index = 0;
        match op {
            Operation::asset_transfer(transfer) => self.apply_asset_transfer(transfer),
            Operation::asset_issuance(issuance) => self.apply_asset_issuance(issuance),
            Operation::asset_creation(creation) => self.apply_asset_creation(creation),
        }
        self.next_index.op_index += 1;
    }

    // Asset Transfer is valid if UTXOs exist on ledger and match zei transaction, zei transaction is valid, and if LedgerSignature is valid
    fn validate_asset_transfer(&mut self, transfer: &AssetTransfer) -> bool {
        // [1] signatures are valid
        for signature in &transfer.body_signatures {
            if !signature.verify(&transfer.body.digest) {
                return false;
            }
        }

        // [2] utxos exist on ledger - need to match zei transaction
        for utxo_addr in &transfer.body.inputs {
            if !self.check_utxo(utxo_addr).is_some() {
                return false;
            }
            let v = &transfer.body.operation_signatures;
            let v = v.into_iter().filter(|&x| x.address.key == self.utxos.get(utxo_addr).as_ref().unwrap().output.get_pk()).collect::<Vec<_>>();
            
            if v.len() == 0 {
                return false;
            }
        }

        // [3] zei transaction is valid
        let zeiTxn = &transfer.body.transfer;
        if !zeiTxn.verify() {
            return false;
        }

        true
    }

    // Asset Issuance is Valid if Signature is valid, the operation is unique, and the assets in the TxOutputs are owned by the signatory
    fn validate_asset_issuance(&mut self, issue: &AssetIssuance) -> bool {
        if (self.issuance_num.contains_key(&issue.body.code)) {
            return false;
        }

        if !issue.signature.verify(&issue.body.digest)
        {
            return false;
        }
    
        for output in &issue.body.outputs {
            //NEED TO VERIFY TXOUTPUTS OWNED BY SIGNATORY
        }

        true
    }

    // Asset Creation is invalid if the signature is not valid or the code is already used by a different asset
    fn validate_asset_creation(&mut self, create: &AssetCreation) -> bool {
        !self.tokens.contains_key(&create.body.properties.code) &&
            create.signature.verify(&create.body.digest)
    }

    fn validate_operation(&mut self, op: &Operation) -> bool {
        match op {
            Operation::asset_transfer(transfer) => self.validate_asset_transfer(transfer),
            Operation::asset_issuance(issuance) => self.validate_asset_issuance(issuance),
            Operation::asset_creation(creation) => self.validate_asset_creation(creation),
        }
    }

}

impl LedgerUpdate for LedgerState {
    fn apply_transaction(&mut self, txn: Transaction) -> () {
        self.next_index.op_index = 0;

        // Apply the operations
        for op in &txn.operations {
            self.apply_operation(op);
        }
        self.next_index.tx_index.val += 1;
        self.txs.push(txn);
    }
}

impl LedgerValidate for LedgerState {
    fn validate_transaction(&mut self, txn: &Transaction) -> bool {
        for op in &txn.operations {
            if !self.validate_operation(op) {
                return false;
            }
        }
        true
    }
}

impl LedgerAccess for LedgerState {
    fn check_utxo(&self, addr: &UtxoAddress) -> Option<Utxo> {
        match self.utxos.get(addr) {
            Some(utxo) => Some(utxo.clone()),
            None => None,
        }
    }

    fn get_asset_token(&self, code: &AssetTokenCode) -> Option<AssetToken> {
        match self.tokens.get(code) {
            Some(token) => Some(token.clone()),
            None => None,
        }
    }

    fn get_asset_policy(&self, key: &AssetPolicyKey) -> Option<CustomAssetPolicy> {
        match self.policies.get(key) {
            Some(policy) => Some(policy.clone()),
            None => None,
        }
    }

    fn get_smart_contract(&self, key: &SmartContractKey) -> Option<SmartContract> {
        match self.contracts.get(key) {
            Some(contract) => Some(contract.clone()),
            None => None,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_model::{Address, LedgerSignature};
    use rand_chacha::ChaChaRng;
    use rand::{SeedableRng, Rng, CryptoRng};
    use curve25519_dalek::scalar::Scalar;
    use blake2::{Blake2b};
    use zei::keys::{ZeiPublicKey, ZeiSecretKey, ZeiSignature, ZeiKeyPair};

    fn build_keys<R: CryptoRng + Rng>(prng: &mut R) -> (ZeiPublicKey, ZeiSecretKey) {
        let key = ZeiKeyPair::generate(prng);
        (key.get_pk_ref().clone(), key.get_sk())
    }

    // fn compute_digest(msg: &[u8]) {

    // }

   #[test]
   fn asset_creation() {
       let mut prng = ChaChaRng::from_seed([0u8; 32]);
       let (public_key, secret_key) = build_keys(&mut prng);

       let mut state = LedgerState::new();
       let mut token_properties: AssetTokenProperties = Default::default();
       let token_code1 = AssetTokenCode { val: [1; 16] };

       token_properties.code = token_code1;
       token_properties.issuer = Address { key : public_key};
       token_properties.updatable = true;

       let asset_body = AssetCreationBody { properties: token_properties, digest: [0; 32]};

       let mut tx = Transaction::create_empty();

       let sign = secret_key.sign::<blake2::Blake2b>(&asset_body.digest, &public_key);

       let create_asset = AssetCreation {
            body: asset_body,
            signature: LedgerSignature{ address: Address { key: public_key }, signature: sign },
        };

        let create_op = Operation::asset_creation(create_asset);
        tx.operations.push(create_op);

        assert_eq!(true, state.validate_transaction(&tx));
        
        state.apply_transaction(tx);
        assert_eq!(true, state.get_asset_token(&token_code1).is_some());

        assert_eq!(
           token_properties,
           state.get_asset_token(&token_code1).unwrap().properties
        );

        assert_eq!(0, state.get_asset_token(&token_code1).unwrap().units);
    }   


   // // #[test]
   // fn asset_issued() {
   //     let mut state = LedgerState::new();
   //     let token_code1 = AssetTokenCode { val: [1; 16] };
   //     let mut token_properties: AssetTokenProperties = Default::default();
   //     token_properties.code = token_code1;

   //     let mut tx = Transaction::create_empty();
   //     let create_asset = CreateAssetToken {
   //         properties: token_properties,
   //         signature: [0; 32],
   //     };
   //     let create_op = Operation::create_token(create_asset);
   //     tx.operations.push(create_op);
   //     let issued = TxOutput {
   //         address: Address { key: [0; 32] },
   //         asset: AssetType::Normal(Asset {
   //             code: AssetTokenCode { val: [1; 16] },
   //             amount: 100,
   //         }),
   //     };
   //     let issue_op = Operation::asset_issuance(AssetIssuance {
   //         nonce: 0,
   //         code: token_code1,
   //         outputs: vec![issued.clone()],
   //         signature: [0; 32], //Empty signature
   //     });
   //     tx.operations.push(issue_op);
   //     //let issue_op = O
   //     state.apply_transaction(&tx);
   //     // Update units as would be done once asset is issued
   //     assert_eq!(100, state.get_asset_token(&token_code1).unwrap().units);
   //     let utxo_loc = UtxoAddress {
   //         transaction_id: TxSequenceNumber { val: 0 },
   //         operation_index: 1,
   //         output_index: 0,
   //     };
   //     assert_eq!(true, state.check_utxo(&utxo_loc).is_some());
   //     assert_eq!(issued.address, state.check_utxo(&utxo_loc).unwrap().address);
   //     assert_eq!(issued.asset, state.check_utxo(&utxo_loc).unwrap().asset);
   // }

   // // #[test]
   // fn asset_transferred() {
   //     let mut state = LedgerState::new();
   //     let token_code1 = AssetTokenCode { val: [1; 16] };
   //     let mut token_properties: AssetTokenProperties = Default::default();
   //     token_properties.code = token_code1;

   //     let mut tx = Transaction::create_empty();
   //     let create_asset = CreateAssetToken {
   //         properties: token_properties,
   //         signature: [0; 32],
   //     };

   //     let create_op = Operation::create_token(create_asset);
   //     tx.operations.push(create_op);
   //     let issued = TxOutput {
   //         address: Address { key: [5; 32] },
   //         asset: AssetType::Normal(Asset {
   //             code: AssetTokenCode { val: [1; 16] },
   //             amount: 100,
   //         }),
   //     };
   //     let issue_op = Operation::asset_issuance(AssetIssuance {
   //         nonce: 0,
   //         code: token_code1,
   //         outputs: vec![issued.clone()],
   //         signature: [0; 32], //Empty signature
   //     });
   //     tx.operations.push(issue_op);
   //     //let issue_op = O
   //     state.apply_transaction(&tx);
   //     // Update units as would be done once asset is issued
   //     let utxo_loc = UtxoAddress {
   //         transaction_id: TxSequenceNumber { val: 0 },
   //         operation_index: 1,
   //         output_index: 0,
   //     };
   //     assert_eq!(true, state.check_utxo(&utxo_loc).is_some());
   //     assert_eq!(issued.address, state.check_utxo(&utxo_loc).unwrap().address);
   //     assert_eq!(issued.asset, state.check_utxo(&utxo_loc).unwrap().asset);

   //     let mut tx2 = Transaction::create_empty();
   //     let transfer_to = TxOutput {
   //         address: Address { key: [7; 32] },
   //         asset: AssetType::Normal(Asset {
   //             code: AssetTokenCode { val: [1; 16] },
   //             amount: 100,
   //         }),
   //     };
   //     let transfer_op = Operation::asset_transfer(AssetTransfer {
   //         nonce: 0,
   //         variables: Vec::new(),
   //         confidential_asset_flag: false,
   //         confidential_amount_flag: false,
   //         input_utxos: vec![state.check_utxo(&utxo_loc).unwrap()],
   //         outputs: vec![transfer_to.clone()],
   //         signatures: vec![[0; 32]],
   //     });
   //     tx2.operations.push(transfer_op);
   //     state.apply_transaction(&tx2);
   //     assert_eq!(true, state.check_utxo(&utxo_loc).is_none());
   //     let utxo_loc = UtxoAddress {
   //         transaction_id: TxSequenceNumber { val: 1 },
   //         operation_index: 0,
   //         output_index: 0,
   //     };
   //     assert_eq!(true, state.check_utxo(&utxo_loc).is_some());
   //     assert_eq!(
   //         transfer_to.address,
   //         state.check_utxo(&utxo_loc).unwrap().address
   //     );
   //     assert_eq!(
   //         transfer_to.asset,
   //         state.check_utxo(&utxo_loc).unwrap().asset
   //     );
   // }
}
