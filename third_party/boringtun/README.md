# BoringTun

`wireguard_ffi.h` is copied unchanged from [BoringTun](https://github.com/cloudflare/boringtun)
0.6.0 (`src/wireguard_ffi.h`), Copyright (c) 2019 Cloudflare, Inc., BSD-3-Clause.

`Cargo.toml` + `lib.rs` build BoringTun with its `ffi-bindings` feature as `libpierce_boringtun.a`.
CMake runs `cargo build --release` here when cargo is installed (`curl https://sh.rustup.rs | sh`,
or `sudo apt install cargo`); without cargo, Pierce builds without the WireGuard data plane.
`Cargo.lock` pins the exact dependency versions.
