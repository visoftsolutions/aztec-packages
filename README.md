# `noir_rs`: Rust-based zkSNARK Proving&Verifying tool for noir-lang

## Introduction

Welcome to `noir_rs`, a pure Rust implementation for generating and verifying zkSNARK proofs. This lightweight, Rust-centric library is designed for ease of use, mobile compatibility, and performance, eliminating the need for WebAssembly (WASM) dependencies.

### Project Origin
#### This project is a fork of [AztecProtocol/aztec-packages](https://github.com/AztecProtocol/aztec-packages), in order to align with the latest versions.
#### Explore source code here: [`noir_rs`](noir/tooling/noir_rs/).

### Build Status
- ![GitHub Workflow Status ArcRunner](https://github.com/visoftsolutions/noir_rs/actions/workflows/build&test.yml/badge.svg)
- ![GitHub Workflow Status ArcRunner](https://github.com/visoftsolutions/noir_rs/actions/workflows/run-examples.yml/badge.svg)
- ![Version](https://img.shields.io/badge/version-0.19.4-darkviolet)

## Add `noir_rs` to your project
```
noir_rs = { git = "https://github.com/visoftsolutions/noir_rs.git", branch = "latest", package = "noir_rs" }
```

## Why `noir_rs`?

- **Rust-centric Design**: Leveraging Rust's impressive performance, safety, and concurrency for a robust zkSNARK platform.
- **Mobile-Friendly**: Optimized for mobile devices, thanks to our Rust-native approach that bypasses WASM.
- **User-Friendly**: A simple, efficient toolkit for developers to generate and verify zkSNARK proofs.

## Built on `noir_rs`

- **Swift Integration**: Check out [noir_swift](https://github.com/visoftsolutions/noir_swift)
- **Java Integration**: Check out [noir_java](https://github.com/visoftsolutions/noir_java)

## Getting Started

### Setting Up

Clone the repository to get started.

### Running Examples

To run a specific `noir_rs` example, use:

```sh
cd noir/tooling/noir_rs/examples/poly_check_circuit
cargo run
```

### Examples list
- [poly_check_circuit](noir/tooling/noir_rs/examples/poly_check_circuit)
- [line_check_circuit](noir/tooling/noir_rs/examples/line_check_circuit) (struct serialization example)

## Building for Different Targets

Rust's cross-platform compatibility allows you to build for various targets. Here are some common ones:

- Linux (x86_64): `x86_64-unknown-linux-gnu`
- Linux (ARMv7): `armv7-unknown-linux-gnueabihf`
- Windows (MSVC): `x86_64-pc-windows-msvc`
- macOS (x86_64): `x86_64-apple-darwin`
- iOS: `aarch64-apple-ios`
- Android: `aarch64-linux-android`

Build for a specific target with:

```
cargo build --target TARGET_TRIPLET
```

Replace `TARGET_TRIPLET` with your desired target. For more targets, refer to the [Rust documentation](https://doc.rust-lang.org/beta/rustc/platform-support.html).