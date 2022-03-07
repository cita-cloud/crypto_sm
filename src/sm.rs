// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use cita_cloud_proto::blockchain::raw_transaction::Tx::{NormalTx, UtxoTx};
use cita_cloud_proto::blockchain::{RawTransaction, RawTransactions};
use cloud_util::common::get_tx_hash;
use prost::Message;
use status_code::StatusCode;

pub const SM2_SIGNATURE_BYTES_LEN: usize = 128;
pub const HASH_BYTES_LEN: usize = 32;
pub const ADDR_BYTES_LEN: usize = 20;

fn sm3_hash(input: &[u8]) -> [u8; HASH_BYTES_LEN] {
    let mut result = [0u8; HASH_BYTES_LEN];
    result.copy_from_slice(libsm::sm3::hash::Sm3Hash::new(input).get_hash().as_ref());
    result
}

fn sm2_sign(
    pubkey: &[u8],
    privkey: &[u8],
    msg: &[u8],
) -> Result<[u8; SM2_SIGNATURE_BYTES_LEN], StatusCode> {
    let key_pair = efficient_sm2::KeyPair::new(privkey).map_err(|e| {
        log::warn!("sm2_sign: KeyPair_new failed: {}", e);
        StatusCode::ConstructKeyPairError
    })?;
    let sig = key_pair.sign(msg).map_err(|e| {
        log::warn!("sm2_sign: KeyPair_sign failed: {}", e);
        StatusCode::SignError
    })?;

    let mut sig_bytes = [0u8; SM2_SIGNATURE_BYTES_LEN];
    sig_bytes[..32].copy_from_slice(&sig.r());
    sig_bytes[32..64].copy_from_slice(&sig.s());
    sig_bytes[64..].copy_from_slice(pubkey);
    Ok(sig_bytes)
}

fn sm2_recover(signature: &[u8], message: &[u8]) -> Result<Vec<u8>, StatusCode> {
    let r = &signature[0..32];
    let s = &signature[32..64];
    let pk = &signature[64..];

    let public_key = efficient_sm2::PublicKey::new(&pk[..32], &pk[32..]);
    let sig = efficient_sm2::Signature::new(r, s).map_err(|e| {
        log::warn!("sm2_recover: Signature_new failed: {}", e);
        StatusCode::ConstructSigError
    })?;

    sig.verify(&public_key, message).map_err(|e| {
        log::warn!("sm2_recover: Signature_verify failed: {}", e);
        StatusCode::SigCheckError
    })?;

    Ok(pk.to_vec())
}

pub fn hash_data(data: &[u8]) -> Vec<u8> {
    sm3_hash(data).to_vec()
}

pub fn verify_data_hash(data: &[u8], hash: &[u8]) -> Result<(), StatusCode> {
    if hash.len() != HASH_BYTES_LEN {
        Err(StatusCode::HashLenError)
    } else if hash == hash_data(data) {
        Ok(())
    } else {
        Err(StatusCode::HashCheckError)
    }
}

pub fn sk2pk(sk: &[u8]) -> Vec<u8> {
    let keypair = efficient_sm2::KeyPair::new(sk).unwrap();
    keypair.public_key().bytes_less_safe()[1..].to_vec()
}

#[allow(dead_code)]
pub fn sk2address(sk: &[u8]) -> Vec<u8> {
    let pk = sk2pk(sk);
    pk2address(&pk)
}

pub fn pk2address(pk: &[u8]) -> Vec<u8> {
    hash_data(pk)[HASH_BYTES_LEN - ADDR_BYTES_LEN..].to_vec()
}

pub fn sign_message(pubkey: &[u8], privkey: &[u8], msg: &[u8]) -> Result<Vec<u8>, StatusCode> {
    Ok(sm2_sign(pubkey, privkey, msg)?.to_vec())
}

pub fn recover_signature(msg: &[u8], signature: &[u8]) -> Result<Vec<u8>, StatusCode> {
    if signature.len() != SM2_SIGNATURE_BYTES_LEN {
        Err(StatusCode::SigLenError)
    } else {
        sm2_recover(signature, msg)
    }
}

pub fn check_transactions(raw_txs: &RawTransactions) -> StatusCode {
    use rayon::prelude::*;

    match tokio::task::block_in_place(|| {
        raw_txs
            .body
            .par_iter()
            .map(|raw_tx| {
                check_transaction(raw_tx).map_err(|status| {
                    log::warn!(
                        "check_raw_tx tx(0x{}) failed: {}",
                        hex::encode(get_tx_hash(raw_tx).unwrap()),
                        status
                    );
                    status
                })?;

                Ok(())
            })
            .collect::<Result<(), StatusCode>>()
    }) {
        Ok(()) => StatusCode::Success,
        Err(status) => status,
    }
}

fn check_transaction(raw_tx: &RawTransaction) -> Result<(), StatusCode> {
    match raw_tx.tx.as_ref() {
        Some(NormalTx(normal_tx)) => {
            if normal_tx.witness.is_none() {
                return Err(StatusCode::NoneWitness);
            }

            let witness = normal_tx.witness.as_ref().unwrap();
            let signature = &witness.signature;
            let sender = &witness.sender;

            let mut tx_bytes: Vec<u8> = Vec::new();
            if let Some(tx) = &normal_tx.transaction {
                tx.encode(&mut tx_bytes).map_err(|_| {
                    log::warn!("check_raw_tx: encode transaction failed");
                    StatusCode::EncodeError
                })?;
            } else {
                return Err(StatusCode::NoneTransaction);
            }

            let tx_hash = &normal_tx.transaction_hash;

            verify_data_hash(&tx_bytes, tx_hash)?;

            if &pk2address(&recover_signature(tx_hash, signature)?) == sender {
                Ok(())
            } else {
                Err(StatusCode::SigCheckError)
            }
        }
        Some(UtxoTx(utxo_tx)) => {
            let witnesses = &utxo_tx.witnesses;

            // limit witnesses length is 1
            if witnesses.len() != 1 {
                return Err(StatusCode::InvalidWitness);
            }

            let mut tx_bytes: Vec<u8> = Vec::new();
            if let Some(tx) = utxo_tx.transaction.as_ref() {
                tx.encode(&mut tx_bytes).map_err(|_| {
                    log::warn!("check_raw_tx: encode utxo failed");
                    StatusCode::EncodeError
                })?;
            } else {
                return Err(StatusCode::NoneUtxo);
            }

            let tx_hash = &utxo_tx.transaction_hash;
            verify_data_hash(&tx_bytes, tx_hash)?;

            for (_i, w) in witnesses.iter().enumerate() {
                let signature = &w.signature;
                let sender = &w.sender;

                if &pk2address(&recover_signature(tx_hash, signature)?) != sender {
                    return Err(StatusCode::SigCheckError);
                }
            }
            Ok(())
        }
        None => Err(StatusCode::NoneRawTx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sm3_test() {
        let hash_empty: [u8; HASH_BYTES_LEN] = [
            0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f, 0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8,
            0x1a, 0x8f, 0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74, 0x7e, 0xd0, 0x35, 0xeb,
            0x50, 0x82, 0xaa, 0x2b,
        ];
        assert_eq!(sm3_hash(&[]), hash_empty);
    }

    #[test]
    fn test_data_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7];
        let hash = hash_data(&data);
        assert!(verify_data_hash(&data, &hash).is_ok());
    }
}
