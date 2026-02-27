# CITA-Cloud Crypto SM Service

## 项目基本信息
- **名称**: crypto
- **版本**: 6.7.5
- **描述**: CITA-Cloud 平台的国密（SM）加密服务实现。基于 Rust 语言开发，提供符合 CITA-Cloud 协议标准的加密、签名、哈希等 gRPC 服务。
- **许可证**: Apache-2.0
- **维护者**: Rivtower Technologies

## 核心能力
本项目实现了 `cita_cloud_proto` 定义的 `CryptoService` 接口，主要提供以下国密算法相关功能：

1.  **加密信息查询 (`get_crypto_info`)**
    - 提供当前加密服务的元数据和配置信息。

2.  **哈希计算 (`hash_data`)**
    - 提供数据的哈希计算服务，默认采用 SM3 算法。

3.  **签名 (`sign_message`)**
    - 使用 SM2 算法对消息进行签名。

4.  **签名恢复 (`recover_signature`)**
    - 从签名中恢复公钥或地址，用于验证签名的来源。

5.  **哈希验证 (`verify_data_hash`)**
    - 验证数据与其哈希值是否匹配。

6.  **健康检查**
    - 实现 gRPC 健康检查标准，支持服务健康状态监控。

7.  **监控指标**
    - 集成 Prometheus 指标导出，支持服务运行状态监控。

## 运行依赖
- **开发环境**:
  - Rust (Edition 2024)
  - Protobuf Compiler (protoc)

- **核心依赖库**:
  - `tonic`: gRPC 框架
  - `tokio`: 异步运行时
  - `libsm`, `efficient-sm2`: 国密算法实现
  - `cita_cloud_proto`: CITA-Cloud 协议定义
  - `cloud-util`: 云原生工具库

## 使用示例

### 编译构建
```bash
cargo build --release
```

### 运行服务
服务可以通过命令行启动，支持指定配置文件和私钥路径。

**基本命令格式**:
```bash
crypto run [OPTIONS]
```

**参数说明**:
- `-c, --config <FILE>`: 配置文件路径 (默认: "config.toml")
- `-p, --private_key_path <FILE>`: 私钥文件路径 (默认: "private_key")

**运行示例**:
```bash
# 使用默认配置运行
cargo run -- run

# 指定配置文件和私钥路径运行
cargo run -- run -c my_config.toml -p my_private_key
```

### 配置文件示例 (config.toml)
```toml
# 示例配置结构 (需根据实际 config.rs 确认)
grpc_port = 50005
```
