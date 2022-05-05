# Ditto authtool

A CLI tool and Rust library to generate authentication for devices in [a Ditto mesh](https://ditto.live).

To generate a key for [shared key authentication](https://docs.ditto.live/security/shared-key) install the tool and run:

```
ditto-authtool generate-shared-key
```

## Install

### Prebuilt Release

Head to the [Releases page](https://github.com/getditto/authtool/releases) and download the binary for your platform.

### From Source

Ensure you have a stable Rust toolchain installed with [rustup](https://rustup.rs/). Clone this repository and open a
terminal inside it. Run:

```
cargo install --path . 
```

The `ditto-authtool` binary will be built and placed in your PATH (generally `~/.cargo/bin`).

### Library Use

The `ditto-authtool` crate can also be embedded in your own Rust software to automate your authentication workflows.
Generate docs with `cargo doc --open`.
