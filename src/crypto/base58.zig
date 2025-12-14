//! Compatibility shim for Base58/Base58Check.
//!
//! The production implementation lives in `src/utils/base58.zig`.
//! This module exists to keep the historical `src/crypto/base58.zig` import path
//! working for downstream users.

const base58 = @import("../utils/base58.zig");

pub const encode = base58.encode;
pub const decode = base58.decode;
pub const encodeCheck = base58.encodeCheck;
pub const decodeCheck = base58.decodeCheck;
