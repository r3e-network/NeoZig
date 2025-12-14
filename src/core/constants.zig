//! Neo blockchain constants and configuration values
//!
//! Complete conversion from NeoSwift/Sources/NeoSwift/NeoConstants.swift
//! All constants match the original Swift implementation for compatibility.

const std = @import("std");

/// Maximum number of public keys that can take part in a multi-signature address
pub const MAX_PUBLIC_KEYS_PER_MULTISIG_ACCOUNT: u32 = 1024;

/// Hash and key sizes (matching Swift constants)
pub const HASH160_SIZE: usize = 20;
pub const HASH256_SIZE: usize = 32;
pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE_COMPRESSED: usize = 33;
pub const SIGNATURE_SIZE: usize = 64;
pub const VERIFICATION_SCRIPT_SIZE: usize = 40;

/// Transaction and contract limits
pub const CURRENT_TX_VERSION: u8 = 0;
pub const MAX_TRANSACTION_SIZE: u32 = 102400;
pub const MAX_TRANSACTION_ATTRIBUTES: u8 = 16;
pub const MAX_SIGNER_SUBITEMS: u8 = 16;
pub const MAX_MANIFEST_SIZE: u32 = 0xFFFF;
pub const MAX_ITERATOR_ITEMS_DEFAULT: u32 = 100;

/// Network magic numbers
pub const NetworkMagic = struct {
    // Neo N3 magic numbers as reported by `getversion`.
    //
    // Little-endian bytes:
    // - MAINNET: 4e 45 4f 33 => "NEO3"
    // - TESTNET: 4e 33 54 35 => "N3T5"
    pub const MAINNET: u32 = 0x334f454e;
    pub const TESTNET: u32 = 0x3554334e;
};

/// Default magic used when the RPC endpoint does not report protocol metadata
pub const DEFAULT_NETWORK_MAGIC: u32 = NetworkMagic.MAINNET;

/// secp256r1 curve parameters (converted from Swift)
pub const Secp256r1 = struct {
    /// Field prime p
    pub const P: u256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    /// Curve order n
    pub const N: u256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    /// Half curve order (for canonical signatures)
    pub const HALF_CURVE_ORDER: u256 = N >> 1;
    /// Curve coefficient A
    pub const A: u256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    /// Curve coefficient B
    pub const B: u256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    /// Generator point X coordinate
    pub const GX: u256 = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    /// Generator point Y coordinate
    pub const GY: u256 = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
};

/// Address and WIF constants
pub const AddressConstants = struct {
    pub const ADDRESS_VERSION: u8 = 0x35;
    pub const MULTISIG_ADDRESS_VERSION: u8 = 0x35;
    pub const WIF_VERSION: u8 = 0x80;
    pub const WIF_VERSION_TESTNET: u8 = 0xEF;
};

/// Native contract script hashes
pub const NativeContracts = struct {
    pub const NEO_TOKEN: [20]u8 = [_]u8{ 0xef, 0x4f, 0x3d, 0x0b, 0x94, 0xe8, 0x8c, 0x2f, 0x5b, 0xc9, 0x2e, 0x9b, 0xde, 0x5a, 0x8b, 0x25, 0x4b, 0x71, 0x42, 0x85 };
    pub const GAS_TOKEN: [20]u8 = [_]u8{ 0xd2, 0xa4, 0xcf, 0xf3, 0x1a, 0x0a, 0xa7, 0x93, 0x3e, 0x4d, 0xa7, 0x8b, 0x46, 0x97, 0x7c, 0xa0, 0xd8, 0x13, 0x68, 0xa7 };
    pub const POLICY_CONTRACT: [20]u8 = [_]u8{ 0xcc, 0x5e, 0x4e, 0xdd, 0x86, 0xf3, 0x40, 0x45, 0x8c, 0x96, 0x5a, 0x2e, 0x1f, 0x08, 0x95, 0x24, 0xbc, 0x6d, 0x2e, 0x8c };
    pub const CONTRACT_MANAGEMENT: [20]u8 = [_]u8{ 0xff, 0xfd, 0xc9, 0x37, 0x64, 0xdb, 0xad, 0xdd, 0x97, 0xc4, 0x8f, 0x25, 0x2a, 0x53, 0xea, 0x46, 0x43, 0xfa, 0xa3, 0xfd };
    pub const ROLE_MANAGEMENT: [20]u8 = [_]u8{ 0x74, 0x2d, 0x9e, 0xbe, 0x1d, 0xc8, 0x89, 0x91, 0x8f, 0xa6, 0x5b, 0x64, 0xbd, 0x35, 0x48, 0x6c, 0x7e, 0x65, 0xb4, 0xc0 };
};

/// Fee constants
pub const FeeConstants = struct {
    pub const MIN_NETWORK_FEE: u64 = 1000000;
    pub const GAS_DECIMALS: u8 = 8;
    pub const NEO_DECIMALS: u8 = 0;
    pub const SYSTEM_FEE_FACTOR: u32 = 30;
};

/// Interop service IDs
pub const InteropServices = struct {
    // Interop service hashes are defined as the little-endian u32 value of the
    // first 4 bytes of SHA256(<ascii method name>), matching Neo N3.
    pub const SYSTEM_CONTRACT_CALL: u32 = 0x525b7d62; // sha256("System.Contract.Call")[0..4] == 62 7d 5b 52
    pub const SYSTEM_CRYPTO_CHECK_SIG: u32 = 0x27b3e756; // sha256("System.Crypto.CheckSig")[0..4] == 56 e7 b3 27
    pub const SYSTEM_CRYPTO_CHECK_MULTISIG: u32 = 0x3adcd09e; // sha256("System.Crypto.CheckMultisig")[0..4] == 9e d0 dc 3a
    pub const SYSTEM_CRYPTO_RIPEMD160: u32 = 0x99b42d80; // sha256("System.Crypto.Ripemd160")[0..4] == 80 2d b4 99
    pub const SYSTEM_CRYPTO_SHA256: u32 = 0x0e594654; // sha256("System.Crypto.Sha256")[0..4] == 54 46 59 0e

    // Legacy aliases (kept for compatibility with earlier SDK versions).
    pub const NEO_CRYPTO_RIPEMD160: u32 = SYSTEM_CRYPTO_RIPEMD160;
    pub const NEO_CRYPTO_SHA256: u32 = SYSTEM_CRYPTO_SHA256;
};

test "constants validation" {
    const testing = std.testing;

    // Validate key sizes match original Swift implementation
    try testing.expectEqual(@as(usize, 20), HASH160_SIZE);
    try testing.expectEqual(@as(usize, 32), HASH256_SIZE);
    try testing.expectEqual(@as(usize, 32), PRIVATE_KEY_SIZE);
    try testing.expectEqual(@as(usize, 33), PUBLIC_KEY_SIZE_COMPRESSED);
    try testing.expectEqual(@as(usize, 64), SIGNATURE_SIZE);

    // Validate transaction limits
    try testing.expectEqual(@as(u8, 0), CURRENT_TX_VERSION);
    try testing.expectEqual(@as(u32, 102400), MAX_TRANSACTION_SIZE);
    try testing.expectEqual(@as(u8, 16), MAX_TRANSACTION_ATTRIBUTES);

    // Validate selected interop service hashes (SHA256 prefix bytes)
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;

    std.crypto.hash.sha2.Sha256.hash("System.Contract.Call", &digest, .{});
    var syscall_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &syscall_bytes, InteropServices.SYSTEM_CONTRACT_CALL, .little);
    try testing.expectEqualSlices(u8, digest[0..4], &syscall_bytes);

    std.crypto.hash.sha2.Sha256.hash("System.Crypto.CheckSig", &digest, .{});
    std.mem.writeInt(u32, &syscall_bytes, InteropServices.SYSTEM_CRYPTO_CHECK_SIG, .little);
    try testing.expectEqualSlices(u8, digest[0..4], &syscall_bytes);

    std.crypto.hash.sha2.Sha256.hash("System.Crypto.CheckMultisig", &digest, .{});
    std.mem.writeInt(u32, &syscall_bytes, InteropServices.SYSTEM_CRYPTO_CHECK_MULTISIG, .little);
    try testing.expectEqualSlices(u8, digest[0..4], &syscall_bytes);

    std.crypto.hash.sha2.Sha256.hash("System.Crypto.Ripemd160", &digest, .{});
    std.mem.writeInt(u32, &syscall_bytes, InteropServices.SYSTEM_CRYPTO_RIPEMD160, .little);
    try testing.expectEqualSlices(u8, digest[0..4], &syscall_bytes);

    std.crypto.hash.sha2.Sha256.hash("System.Crypto.Sha256", &digest, .{});
    std.mem.writeInt(u32, &syscall_bytes, InteropServices.SYSTEM_CRYPTO_SHA256, .little);
    try testing.expectEqualSlices(u8, digest[0..4], &syscall_bytes);
}
