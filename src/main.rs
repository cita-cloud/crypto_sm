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

mod config;
mod crypto;
mod sm;

use clap::Parser;
use git_version::git_version;
use log::{debug, info, warn};

const GIT_VERSION: &str = git_version!(
    args = ["--tags", "--always", "--dirty=-modified"],
    fallback = "unknown"
);
const GIT_HOMEPAGE: &str = "https://github.com/cita-cloud/crypto_sm";

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Parser)]
#[clap(version = "7.0.0", author = "Rivtower Technologies.")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    /// print information from git
    #[clap(name = "git")]
    GitInfo,
    /// run this service
    #[clap(name = "run")]
    Run(RunOpts),
}

/// A subcommand for run
#[derive(Parser)]
struct RunOpts {
    /// Chain config path
    #[clap(short = 'c', long = "config", default_value = "config.toml")]
    config_path: String,
    /// private key path
    #[clap(short = 'p', long = "private_key_path", default_value = "private_key")]
    private_key_path: String,
    /// log config path
    #[clap(short = 'l', long = "log", default_value = "crypto-log4rs.yaml")]
    log_file: String,
}

fn main() {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let opts: Opts = Opts::parse();

    // You can handle information about subcommands by requesting their matches by name
    // (as below), requesting just the name used, or both at the same time
    match opts.subcmd {
        SubCommand::GitInfo => {
            println!("git version: {}", GIT_VERSION);
            println!("homepage: {}", GIT_HOMEPAGE);
        }
        SubCommand::Run(opts) => {
            let fin = run(opts);
            warn!("Should not reach here {:?}", fin);
        }
    }
}

use cita_cloud_proto::blockchain::RawTransactions;
use cita_cloud_proto::common::{Empty, Hash, HashResponse};
use cita_cloud_proto::crypto::{
    crypto_service_server::CryptoService, crypto_service_server::CryptoServiceServer,
    GetCryptoInfoResponse, HashDataRequest, RecoverSignatureRequest, RecoverSignatureResponse,
    SignMessageRequest, SignMessageResponse, VerifyDataHashRequest,
};
use tonic::{transport::Server, Request, Response, Status};

use crate::config::CryptoConfig;
use crate::crypto::Crypto;
use crate::sm::{check_transactions, ADDR_BYTES_LEN, SM2_SIGNATURE_BYTES_LEN};

use status_code::StatusCode;
use std::net::AddrParseError;

// grpc server of RPC
pub struct CryptoServer {
    crypto: Crypto,
}

impl CryptoServer {
    fn new(crypto: Crypto) -> Self {
        CryptoServer { crypto }
    }
}

#[tonic::async_trait]
impl CryptoService for CryptoServer {
    async fn get_crypto_info(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<GetCryptoInfoResponse>, Status> {
        debug!("get_crypto_info");
        Ok(Response::new(GetCryptoInfoResponse {
            status: Some(StatusCode::Success.into()),
            name: crypto::CONFIG_TYPE.to_string(),
            hash_len: sm::HASH_BYTES_LEN as u32,
            signature_len: sm::SM2_SIGNATURE_BYTES_LEN as u32,
            address_len: sm::ADDR_BYTES_LEN as u32,
        }))
    }

    async fn hash_data(
        &self,
        request: Request<HashDataRequest>,
    ) -> Result<Response<HashResponse>, Status> {
        debug!("hash_data request: {:?}", request);

        let req = request.into_inner();
        let data = req.data;

        Ok(Response::new(HashResponse {
            status: Some(StatusCode::Success.into()),
            hash: Some(Hash {
                hash: self.crypto.hash_data(&data),
            }),
        }))
    }

    async fn verify_data_hash(
        &self,
        request: Request<VerifyDataHashRequest>,
    ) -> Result<Response<cita_cloud_proto::common::StatusCode>, Status> {
        debug!("verify_data_hash request: {:?}", request);

        let req = request.into_inner();
        let data = req.data;
        let hash = req.hash;

        Ok(Response::new(
            self.crypto.verify_data_hash(&data, &hash).into(),
        ))
    }

    // Err code maybe return: aborted/invalid_argument
    async fn sign_message(
        &self,
        request: Request<SignMessageRequest>,
    ) -> Result<Response<SignMessageResponse>, Status> {
        debug!("sign_message request: {:?}", request);

        let req = request.into_inner();
        let msg = req.msg;

        self.crypto.sign_message(&msg).map_or_else(
            |status| {
                Ok(Response::new(SignMessageResponse {
                    status: Some(status.into()),
                    signature: [0; SM2_SIGNATURE_BYTES_LEN].to_vec(),
                }))
            },
            |signature| {
                Ok(Response::new(SignMessageResponse {
                    status: Some(StatusCode::Success.into()),
                    signature,
                }))
            },
        )
    }

    // Err code maybe return: invalid_argument
    async fn recover_signature(
        &self,
        request: Request<RecoverSignatureRequest>,
    ) -> Result<Response<RecoverSignatureResponse>, Status> {
        debug!("recover_signature request: {:?}", request);

        let req = request.into_inner();
        let msg = req.msg;
        let signature = req.signature;

        self.crypto.recover_signature(&msg, &signature).map_or_else(
            |status| {
                Ok(Response::new(RecoverSignatureResponse {
                    status: Some(status.into()),
                    address: [0; ADDR_BYTES_LEN].to_vec(),
                }))
            },
            |address| {
                Ok(Response::new(RecoverSignatureResponse {
                    status: Some(StatusCode::Success.into()),
                    address,
                }))
            },
        )
    }

    async fn check_transactions(
        &self,
        request: Request<RawTransactions>,
    ) -> Result<Response<cita_cloud_proto::common::StatusCode>, Status> {
        debug!("check_transactions request: {:?}", request);
        let req = request.into_inner();
        Ok(Response::new(check_transactions(&req).into()))
    }
}

#[tokio::main]
async fn run(opts: RunOpts) -> Result<(), StatusCode> {
    let config = CryptoConfig::new(&opts.config_path);
    // init log4rs
    log4rs::init_file(&opts.log_file, Default::default())
        .map_err(|e| println!("log init err: {}", e))
        .unwrap();

    let grpc_port = config.crypto_port.to_string();

    info!("grpc port of this service: {}", grpc_port);

    let addr_str = format!("0.0.0.0:{}", grpc_port);
    let addr = addr_str.parse().map_err(|e: AddrParseError| {
        warn!("grpc listen addr parse failed: {} ", e.to_string());
        StatusCode::FatalError
    })?;

    info!("start grpc server!");
    Server::builder()
        .add_service(CryptoServiceServer::new(CryptoServer::new(Crypto::new(
            &opts.private_key_path,
        ))))
        .serve(addr)
        .await
        .map_err(|e| {
            warn!("start crypto grpc server failed: {} ", e.to_string());
            StatusCode::FatalError
        })?;

    Ok(())
}
