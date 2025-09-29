[![dependency status](https://deps.rs/repo/github/silicon-heaven/shvbroker-rs/status.svg)](https://deps.rs/repo/github/silicon-heaven/shvbroker-rs)

# shvbroker-rs
Rust implementation of SHV broker

## Install

Use CI build on [releases](https://github.com/silicon-heaven/shvbroker-rs/releases) 

## Build

```
cargo build --release --all-features
```

## Run

Print default config
```
./shvbroker --print-config
```

Edit config, save config, run broker
```
./shvbroker --config myconfig.yaml
```

