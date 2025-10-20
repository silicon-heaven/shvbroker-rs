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

## Migrating Legacy SHVBroker Configuration

### Overview

`shvbroker_migrate_legacy` is a command-line tool used to convert legacy **C++ SHVBroker** configuration and access database files into the **YAML** and **SQLite** formats used by **shvbroker-rs**.

This migration process includes:

- Converting the legacy `.cfg` configuration file to `shvbroker.yml`
- Migrating the legacy Access-style `.db` file to `shvbroker.sqlite`
- Preserving users, mounts, and roles data in the new format

---

### Usage

```bash
shvbroker_migrate_legacy --legacy-config <LEGACY_CONFIG_PATH> [--result-config <RESULT_CONFIG_PATH>]
```

#### Required Arguments

| Flag                     | Description                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------------- |
| `--legacy-config <PATH>` | Path to the legacy SHVBroker configuration file (in CPON format, e.g., `shvbroker.cfg`). |

#### Optional Arguments

| Flag                     | Description                                                                                                                                            |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--result-config <PATH>` | Output path for the converted YAML configuration file. If not specified, the tool will write `shvbroker.yml` in the same directory as the legacy file. |

### Examples

#### Convert a legacy config file in-place

``` bash
shvbroker_migrate_legacy --legacy-config /etc/shvbroker/shvbroker.cfg
```

What this does:

  - Reads the legacy configuration from `/etc/shvbroker/shvbroker.cfg`.
  - Writes the converted YAML to `/etc/shvbroker/shvbroker.yml` (same directory by default).
  - If the legacy configuration refers to an access DB (for example `shvbroker.cfg.db`), migrates it to `shvbroker.sqlite` in the configured data directory.

#### Specify a custom output path

``` bash
shvbroker_migrate_legacy \
  --legacy-config /etc/shvbroker/shvbroker.cfg \
  --result-config /tmp/new_shvbroker.yml
```

This saves the converted configuration to `/tmp/new_shvbroker.yml` instead of the default `shvbroker.yml` in the config directory.

### Database Migration Details

If the legacy configuration enables access database (i.e. `use_access_db: true` in the migrated config), the tool will:

 1. Determine the data directory:
    - If the `data_directory` in the new `broker_config` is a relative path, it will be joined with the config file's directory.
    - If `data_directory` is absolute, it will be used as-is.
 2. Locate the legacy DB file:
    - Uses the database field from the legacy SQL config if present, extracting only the filename (e.g. `shvbroker.cfg.db`).
    - If missing, defaults to `shvbroker.cfg.db`.
 3. Create a new SQLite database `shvbroker.sqlite` in the data directory.
 4. Migrate the following tables/objects from the legacy DB into the new DB:
    - **users**
    - **mounts**
    - **roles**

The tool reads the legacy DB in read-only mode and writes the new DB using the updated schema.
