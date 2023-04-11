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

use cloud_util::{common::read_toml, tracer::LogConfig};
use serde_derive::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct CryptoConfig {
    pub crypto_port: u16,
    pub enable_metrics: bool,
    pub metrics_port: u16,
    pub metrics_buckets: Vec<f64>,
    /// log config
    pub log_config: LogConfig,
    /// domain
    pub domain: String,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            crypto_port: 50005,
            enable_metrics: true,
            metrics_port: 60005,
            metrics_buckets: vec![
                0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0, 25.0, 50.0, 75.0, 100.0, 250.0, 500.0,
            ],
            log_config: Default::default(),
            domain: Default::default(),
        }
    }
}

impl CryptoConfig {
    pub fn new(config_str: &str) -> Self {
        read_toml(config_str, "crypto_sm")
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoConfig;

    #[test]
    fn basic_test() {
        let config = CryptoConfig::new("example/config.toml");

        assert_eq!(config.crypto_port, 50005);
        assert_eq!(config.domain, "test-chain-node1");
    }
}
