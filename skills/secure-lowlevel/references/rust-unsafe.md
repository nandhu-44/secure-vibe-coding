# Rust: unsafe, FFI and footguns

- Default to safe Rust. Every `unsafe` block gets a `// SAFETY:` comment directly above it, stating why each invariant holds (aligned, non-null, initialized, unaliased, in-bounds, lifetime).
- Keep `unsafe` minimal and wrapped in a safe abstraction whose public API cannot cause UB for any input.
- Enable `#![deny(unsafe_op_in_unsafe_fn)]`, `#![warn(clippy::undocumented_unsafe_blocks)]`. Use `#![forbid(unsafe_code)]` in crates that don't need it.
- FFI: validate pointers/lengths from C (`slice::from_raw_parts` needs a non-null, aligned pointer and correct `len`). Use `CStr::from_ptr` only on NUL-terminated data. Never unwind panics across FFI (`catch_unwind` or `extern "C-unwind"`).
- Avoid `mem::transmute`, `mem::uninitialized` (use `MaybeUninit`), `get_unchecked` unless proven in bounds, `from_utf8_unchecked` on untrusted bytes, and `static mut`.
- Integer overflow wraps silently in release. Use `checked_*`/`saturating_*` for length/size math on untrusted input, or enable `overflow-checks`.
- `unwrap()`/`expect()`/indexing on untrusted input is a DoS (panic). Return `Result`.
- Deserialization: `serde` with `#[serde(deny_unknown_fields)]`, size limits (bincode `with_limit`), recursion limits.
- Verify with `cargo miri test`, `cargo +nightly fuzz`, `cargo audit` / `cargo deny`, and `cargo geiger` (unsafe inventory).
- Crypto: `ring`, `rustls`, RustCrypto crates. Compare with `subtle::ConstantTimeEq`. Wipe secrets with `zeroize`.
