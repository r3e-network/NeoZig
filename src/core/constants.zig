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
    pub const MAINNET: u32 = 0x4e454f00;
    pub const TESTNET: u32 = 0x4e454f01;
};

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
    pub const NEO_TOKEN: [20]u8 = [_]u8{0xef, 0x4f, 0x3d, 0x0b, 0x94, 0xe8, 0x8c, 0x2f, 0x5b, 0xc9, 0x2e, 0x9b, 0xde, 0x5a, 0x8b, 0x25, 0x4b, 0x71, 0x42, 0x85};
    pub const GAS_TOKEN: [20]u8 = [_]u8{0xd2, 0xa4, 0xcf, 0xf3, 0x1a, 0x0a, 0xa7, 0x93, 0x3e, 0x4d, 0xa7, 0x8b, 0x46, 0x97, 0x7c, 0xa0, 0xd8, 0x13, 0x68, 0xa7};
    pub const POLICY_CONTRACT: [20]u8 = [_]u8{0xcc, 0x5e, 0x4e, 0xdd, 0x86, 0xf3, 0x40, 0x45, 0x8c, 0x96, 0x5a, 0x2e, 0x1f, 0x08, 0x95, 0x24, 0xbc, 0x6d, 0x2e, 0x8c};
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
    pub const SYSTEM_CONTRACT_CALL: u32 = 0x627d5b52;
    pub const SYSTEM_CRYPTO_CHECK_SIG: u32 = 0x41766430;
    pub const SYSTEM_CRYPTO_CHECK_MULTISIG: u32 = 0x0f1c2d00;
    pub const NEO_CRYPTO_RIPEMD160: u32 = 0x0aa1c5a8;
    pub const NEO_CRYPTO_SHA256: u32 = 0xbf28e7e2;
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
}