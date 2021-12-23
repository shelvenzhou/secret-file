# Build

Install Rust and Cargo following the [installation guide](https://doc.rust-lang.org/cargo/getting-started/installation.html). You need to install the latest nightly version of Rust.

Install the `cargo-contract` to compile the ink! contract

```shell
cargo install cargo-contract --force
```

Compile the contract

```shell
cargo +nightly contract build
```

and run the unittests

```shell
cargo +nightly contract test
```
