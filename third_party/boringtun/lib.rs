// Re-export BoringTun's C API (new_tunnel, wireguard_read/write/tick, x25519_*) so the static
// library this crate builds contains those symbols. The declarations are in wireguard_ffi.h.
pub use boringtun::ffi::*;
