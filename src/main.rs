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
mod health_check;
mod sm;
mod util;

#[macro_use]
extern crate tracing;

use crate::crypto::Crypto;
use cita_cloud_proto::blockchain::RawTransactions;
use cita_cloud_proto::common::{Empty, Hash, HashResponse, StatusCode};
use cita_cloud_proto::crypto::{
    crypto_service_server::CryptoService, crypto_service_server::CryptoServiceServer,
    GetCryptoInfoResponse, HashDataRequest, RecoverSignatureRequest, RecoverSignatureResponse,
    SignMessageRequest, SignMessageResponse, VerifyDataHashRequest,
};
use cita_cloud_proto::health_check::health_server::HealthServer;
use cita_cloud_proto::status_code::StatusCodeEnum;
use clap::Parser;
use cloud_util::metrics::{run_metrics_exporter, MiddlewareLayer};
use config::CryptoConfig;
use health_check::HealthCheckServer;
use sm::{crypto_check_batch, ADDR_BYTES_LEN, SM2_SIGNATURE_BYTES_LEN};
use std::net::AddrParseError;
use tonic::{transport::Server, Request, Response, Status};
use util::clap_about;

#[derive(Parser)]
#[clap(version, about = clap_about())]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
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
}

fn main() {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let opts: Opts = Opts::parse();

    // You can handle information about subcommands by requesting their matches by name
    // (as below), requesting just the name used, or both at the same time
    match opts.subcmd {
        SubCommand::Run(opts) => {
            if let Err(e) = run(opts) {
                warn!("Should not reach here {e:?}");
            }
        }
    }
}

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
    #[instrument(skip_all)]
    async fn get_crypto_info(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<GetCryptoInfoResponse>, Status> {
        cloud_util::tracer::set_parent(&request);
        debug!("get_crypto_info");
        Ok(Response::new(GetCryptoInfoResponse {
            status: Some(StatusCodeEnum::Success.into()),
            name: crypto::CONFIG_TYPE.to_string(),
            hash_len: sm::HASH_BYTES_LEN as u32,
            signature_len: sm::SM2_SIGNATURE_BYTES_LEN as u32,
            address_len: sm::ADDR_BYTES_LEN as u32,
        }))
    }

    #[instrument(skip_all)]
    async fn hash_data(
        &self,
        request: Request<HashDataRequest>,
    ) -> Result<Response<HashResponse>, Status> {
        cloud_util::tracer::set_parent(&request);
        debug!("hash_data request: {:?}", request);

        let req = request.into_inner();
        let data = req.data;

        Ok(Response::new(HashResponse {
            status: Some(StatusCodeEnum::Success.into()),
            hash: Some(Hash {
                hash: self.crypto.hash_data(&data),
            }),
        }))
    }

    #[instrument(skip_all)]
    async fn verify_data_hash(
        &self,
        request: Request<VerifyDataHashRequest>,
    ) -> Result<Response<StatusCode>, Status> {
        cloud_util::tracer::set_parent(&request);
        debug!("verify_data_hash request: {:?}", request);

        let req = request.into_inner();
        let data = req.data;
        let hash = req.hash;

        Ok(Response::new(
            self.crypto.verify_data_hash(&data, &hash).into(),
        ))
    }

    // Err code maybe return: aborted/invalid_argument
    #[instrument(skip_all)]
    async fn sign_message(
        &self,
        request: Request<SignMessageRequest>,
    ) -> Result<Response<SignMessageResponse>, Status> {
        cloud_util::tracer::set_parent(&request);
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
                    status: Some(StatusCodeEnum::Success.into()),
                    signature,
                }))
            },
        )
    }

    // Err code maybe return: invalid_argument
    #[instrument(skip_all)]
    async fn recover_signature(
        &self,
        request: Request<RecoverSignatureRequest>,
    ) -> Result<Response<RecoverSignatureResponse>, Status> {
        cloud_util::tracer::set_parent(&request);
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
                    status: Some(StatusCodeEnum::Success.into()),
                    address,
                }))
            },
        )
    }

    #[instrument(skip_all)]
    async fn check_transactions(
        &self,
        request: Request<RawTransactions>,
    ) -> Result<Response<StatusCode>, Status> {
        cloud_util::tracer::set_parent(&request);
        debug!("check_transactions request: {:?}", request);
        let req = request.into_inner();
        Ok(Response::new(crypto_check_batch(&req).into()))
    }
}

#[tokio::main]
async fn run(opts: RunOpts) -> Result<(), StatusCodeEnum> {
    let rx_signal = cloud_util::graceful_shutdown::graceful_shutdown();

    let config = CryptoConfig::new(&opts.config_path);
    // init tracer
    cloud_util::tracer::init_tracer(config.domain.clone(), &config.log_config)
        .map_err(|e| println!("tracer init err: {e}"))
        .unwrap();

    let grpc_port = config.crypto_port.to_string();

    info!("grpc port of crypto_sm: {}", grpc_port);

    let addr_str = format!("0.0.0.0:{grpc_port}");
    let addr = addr_str.parse().map_err(|e: AddrParseError| {
        warn!("grpc listen addr parse failed: {:?} ", e);
        StatusCodeEnum::FatalError
    })?;

    let layer = if config.enable_metrics {
        tokio::spawn(async move {
            run_metrics_exporter(config.metrics_port).await.unwrap();
        });

        Some(
            tower::ServiceBuilder::new()
                .layer(MiddlewareLayer::new(config.metrics_buckets))
                .into_inner(),
        )
    } else {
        None
    };

    info!("start crypto_sm grpc server");
    if let Some(layer) = layer {
        info!("metrics on");
        Server::builder()
            .layer(layer)
            .add_service(CryptoServiceServer::new(CryptoServer::new(Crypto::new(
                &opts.private_key_path,
            ))))
            .add_service(HealthServer::new(HealthCheckServer {}))
            .serve_with_shutdown(
                addr,
                cloud_util::graceful_shutdown::grpc_serve_listen_term(rx_signal),
            )
            .await
            .map_err(|e| {
                warn!("start crypto_sm grpc server failed: {:?} ", e);
                StatusCodeEnum::FatalError
            })?;
    } else {
        info!("metrics off");
        Server::builder()
            .add_service(CryptoServiceServer::new(CryptoServer::new(Crypto::new(
                &opts.private_key_path,
            ))))
            .add_service(HealthServer::new(HealthCheckServer {}))
            .serve_with_shutdown(
                addr,
                cloud_util::graceful_shutdown::grpc_serve_listen_term(rx_signal),
            )
            .await
            .map_err(|e| {
                warn!("start crypto_sm grpc server failed: {:?} ", e);
                StatusCodeEnum::FatalError
            })?;
    }

    Ok(())
}
