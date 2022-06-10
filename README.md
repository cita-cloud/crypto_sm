# crypto_sm
`CITA-Cloud`中[crypto微服务](https://github.com/cita-cloud/cita_cloud_proto/blob/master/protos/crypto.proto)的实现，采用国密签名算法（`sm2`）和哈希算法(`sm3`)组合。
## 编译docker镜像
```
docker build -t citacloud/crypto_sm .
```
## 使用方法

```
$ crypto -h
crypto 6.5.0
Rivtower Technologies.
This doc string acts as a help message when the user runs '--help' as do all doc strings on fields

USAGE:
    crypto <SUBCOMMAND>

OPTIONS:
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    help    Print this message or the help of the given subcommand(s)
    run     run this service
```

### crypto-run

运行`crypto`服务。

```
$ crypto run -h
crypto-run 
run this service

USAGE:
    crypto run [OPTIONS]

OPTIONS:
    -c, --config <CONFIG_PATH>                   Chain config path [default: config.toml]
    -h, --help                                   Print help information
    -l, --log <LOG_FILE>                         log config path [default: crypto-log4rs.yaml]
    -p, --private_key_path <PRIVATE_KEY_PATH>    private key path [default: private_key]
```

参数：
1. 微服务配置文件。

    参见示例`example/config.toml`。

    其中：
    * `crypto_port` 为该服务监听的端口号。
2. 日志配置文件。

    参见示例`crypto-log4rs.yaml`。

    其中：

    * `level` 为日志等级。可选项有：`Error`，`Warn`，`Info`，`Debug`，`Trace`，默认为`Info`。
    * `appenders` 为输出选项，类型为一个数组。可选项有：标准输出(`stdout`)和滚动的日志文件（`journey-service`），默认为同时输出到两个地方。
3. 私钥文件路径。
    文件内容参见示例`example/private_key`。

```
$ crypto run -c example/config.toml -l crypto-log4rs.yaml -p example/private_key
2022-03-09T15:28:49.436281304+08:00 INFO crypto - grpc port of this service: 60005
2022-03-09T15:28:49.436368800+08:00 INFO crypto - start grpc server!
```

## 设计

只是对签名算法（`sm2`）和哈希算法(`sm3`)的简单封装。
