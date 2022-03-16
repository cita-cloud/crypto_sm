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

use crate::sm::{hash_data, pk2address, recover_signature, sign_message, sk2pk, verify_data_hash};
use status_code::StatusCode;
use std::fs;
use std::path::Path;

pub const CONFIG_TYPE: &str = "sm";

pub struct Crypto {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl Crypto {
    pub fn new(private_key_path: impl AsRef<Path>) -> Self {
        let buf_string = fs::read_to_string(private_key_path).unwrap();
        let buf_trimmed = buf_string.trim();
        let hex_private_key = buf_trimmed.strip_prefix("0x").unwrap_or(buf_trimmed);
        if hex_private_key.len() != 64 {
            panic!("not private key in private_key_path");
        }
        let private_key = hex::decode(hex_private_key).expect("decode private_key failed");
        let public_key = sk2pk(&private_key);
        Crypto {
            private_key,
            public_key,
        }
    }

    pub fn hash_data(&self, data: &[u8]) -> Vec<u8> {
        hash_data(data)
    }

    pub fn verify_data_hash(&self, data: &[u8], hash: &[u8]) -> StatusCode {
        verify_data_hash(data, hash).map_or_else(|e| e, |_| StatusCode::Success)
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Vec<u8>, StatusCode> {
        let privkey = &self.private_key;
        let pubkey = &self.public_key;
        sign_message(pubkey, privkey, msg)
    }

    pub fn recover_signature(&self, msg: &[u8], signature: &[u8]) -> Result<Vec<u8>, StatusCode> {
        let pub_key = recover_signature(msg, signature)?;
        Ok(pk2address(&pub_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm::sk2address;

    #[test]
    fn test_signature() {
        let crypto = Crypto::new("example/private_key");
        // message must be a hash value
        let message = &hash_data("rivtower".as_bytes());
        let privkey = &crypto.private_key;
        let pubkey = &sk2pk(privkey);
        let signature = &sign_message(pubkey, privkey, message).unwrap();
        assert_eq!(
            crypto.recover_signature(message, signature),
            Ok(sk2address(privkey))
        );
    }
}
