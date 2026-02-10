//! Neo blockchain constants and configuration values
//!
//! Neo N3 constants
//! Core protocol constants for the Neo N3 blockchain.
//!
//! ## Neo N3 Version Compatibility
//!
//! This SDK is compatible with Neo N3 v3.9.x including v3.9.1.
//!
//! Key compatibility points:
//! - VM opcodes include PUSHT (0x08), PUSHF (0x09), MODMUL (0xA5), MODPOW (0xA6), ABORTMSG (0xE0), ASSERTMSG (0xE1)
//! - Interop services and pricing match Neo 3.9.x
//! - Native contract hashes are aligned with v3.9.x
//! - `getversion` parsing includes hardfork metadata
//!
//! See: https://docs.neo.org/docs/en-us/develop/write/version.html

const std = @import("std");

/// Maximum number of public keys that can take part in a multi-signature address
pub const MAX_PUBLIC_KEYS_PER_MULTISIG_ACCOUNT: u32 = 1024;

/// Hash and key sizes
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
pub const MAX_VAR_STRING_SIZE: u32 = 1024 * 1024; // 1MB

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

/// Neo N3 Protocol Version
pub const NeoVersion = struct {
    /// Major version number
    pub const MAJOR: u32 = 3;
    /// Minor version number
    pub const MINOR: u32 = 9;
    /// Patch version number (v3.9.1)
    pub const PATCH: u32 = 1;
    /// Full version string
    pub const STRING: []const u8 = "3.9.1";
    /// Protocol version for getversion RPC
    pub const PROTOCOL_VERSION: u32 = 0;
};

/// Default magic used when the RPC endpoint does not report protocol metadata
pub const DEFAULT_NETWORK_MAGIC: u32 = NetworkMagic.MAINNET;

/// secp256r1 curve parameters
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
///
/// These hashes are aligned with Neo N3 v3.9.1.
/// See: https://docs.neo.org/docs/en-us/develop/write/native.html
pub const NativeContracts = struct {
    /// ContractManagement contract (updated in v3.9.0)
    pub const CONTRACT_MANAGEMENT: [20]u8 = [_]u8{ 0xff, 0xfd, 0xc9, 0x37, 0x64, 0xdb, 0xad, 0xdd, 0x97, 0xc4, 0x8f, 0x25, 0x2a, 0x53, 0xea, 0x46, 0x43, 0xfa, 0xa3, 0xfd };
    /// StdLib contract
    pub const STD_LIB: [20]u8 = [_]u8{ 0xac, 0xce, 0x6f, 0xd8, 0x0d, 0x44, 0xe1, 0x79, 0x6a, 0xa0, 0xc2, 0xc6, 0x25, 0xe9, 0xe4, 0xe0, 0xce, 0x39, 0xef, 0xc0 };
    /// CryptoLib contract
    pub const CRYPTO_LIB: [20]u8 = [_]u8{ 0x72, 0x6c, 0xb6, 0xe0, 0xcd, 0x86, 0x28, 0xa1, 0x35, 0x0a, 0x61, 0x13, 0x84, 0x68, 0x89, 0x11, 0xab, 0x75, 0xf5, 0x1b };
    /// LedgerContract (added in v3.9.0)
    pub const LEDGER_CONTRACT: [20]u8 = [_]u8{ 0xda, 0x65, 0xb6, 0x00, 0xf7, 0x12, 0x4c, 0xe6, 0xc7, 0x99, 0x50, 0xc1, 0x77, 0x2a, 0x36, 0x40, 0x31, 0x04, 0xf2, 0xbe };
    /// NeoToken contract
    pub const NEO_TOKEN: [20]u8 = [_]u8{ 0xef, 0x40, 0x73, 0xa0, 0xf2, 0xb3, 0x05, 0xa3, 0x8e, 0xc4, 0x05, 0x0e, 0x4d, 0x3d, 0x28, 0xbc, 0x40, 0xea, 0x63, 0xf5 };
    /// GasToken contract
    pub const GAS_TOKEN: [20]u8 = [_]u8{ 0xd2, 0xa4, 0xcf, 0xf3, 0x19, 0x13, 0x01, 0x61, 0x55, 0xe3, 0x8e, 0x47, 0x4a, 0x2c, 0x06, 0xd0, 0x8b, 0xe2, 0x76, 0xcf };
    /// PolicyContract contract
    pub const POLICY_CONTRACT: [20]u8 = [_]u8{ 0xcc, 0x5e, 0x4e, 0xdd, 0x9f, 0x5f, 0x8d, 0xba, 0x8b, 0xb6, 0x57, 0x34, 0x54, 0x1d, 0xf7, 0xa1, 0xc0, 0x81, 0xc6, 0x7b };
    /// RoleManagement contract
    pub const ROLE_MANAGEMENT: [20]u8 = [_]u8{ 0x49, 0xcf, 0x4e, 0x53, 0x78, 0xff, 0xcd, 0x4d, 0xec, 0x03, 0x4f, 0xd9, 0x8a, 0x17, 0x4c, 0x54, 0x91, 0xe3, 0x95, 0xe2 };
    /// OracleContract
    pub const ORACLE_CONTRACT: [20]u8 = [_]u8{ 0xfe, 0x92, 0x4b, 0x7c, 0xfe, 0x89, 0xdd, 0xd2, 0x71, 0xab, 0xaf, 0x72, 0x10, 0xa8, 0x0a, 0x7e, 0x11, 0x17, 0x87, 0x58 };
    /// NotaryContract (added in v3.9.0)
    pub const NOTARY: [20]u8 = [_]u8{ 0xc1, 0xe1, 0x4f, 0x19, 0xc3, 0xe6, 0x0d, 0x0b, 0x92, 0x44, 0xd0, 0x6d, 0xd7, 0xba, 0x9b, 0x11, 0x31, 0x35, 0xec, 0x3b };
    /// TreasuryContract (added in v3.9.0)
    pub const TREASURY: [20]u8 = [_]u8{ 0x15, 0x63, 0x26, 0xf2, 0x5b, 0x1b, 0x5d, 0x83, 0x9a, 0x4d, 0x32, 0x6a, 0xea, 0xa7, 0x53, 0x83, 0xc9, 0x56, 0x3a, 0xc1 };
};

/// Fee constants
pub const FeeConstants = struct {
    pub const MIN_NETWORK_FEE: u64 = 1000000;
    pub const GAS_DECIMALS: u8 = 8;
    pub const NEO_DECIMALS: u8 = 0;
    pub const SYSTEM_FEE_FACTOR: u32 = 30;
};

/// Neo N3 v3.9.1 Interop Services
///
/// Interop service hashes are defined as the little-endian u32 value of the
/// first 4 bytes of SHA256(<ascii method name>), matching Neo N3 v3.9.1.
///
/// See: https://docs.neo.org/docs/en-us/develop/write/interop.html
pub const InteropServices = struct {
    // Contract Call
    pub const SYSTEM_CONTRACT_CALL: u32 = 0x525b7d62;
    pub const SYSTEM_CONTRACT_CREATEMULTISIGACCOUNT: u32 = 0x1b5f9793;
    pub const SYSTEM_CONTRACT_CREATESTANDARDACCOUNT: u32 = 0x6de2c376;
    pub const SYSTEM_CONTRACT_CALCULATENETWORKFEE: u32 = 0x8a287441;
    pub const SYSTEM_CONTRACT_GETCALLFLAGS: u32 = 0xc007c0a4;
    pub const SYSTEM_CONTRACT_GETVERSIONS: u32 = 0xb9ea7ba2;

    // Crypto
    pub const SYSTEM_CRYPTO_CHECK_SIG: u32 = 0x27b3e756;
    pub const SYSTEM_CRYPTO_CHECK_MULTISIG: u32 = 0x3adcd09e;
    pub const SYSTEM_CRYPTO_RIPEMD160: u32 = 0x99b42d80;
    pub const SYSTEM_CRYPTO_SHA256: u32 = 0x0e594654;

    // Runtime
    pub const SYSTEM_RUNTIME_GETTIME: u32 = 0xbce7c833;
    pub const SYSTEM_RUNTIME_GETTRIGGER: u32 = 0x7c8d8d07;
    pub const SYSTEM_RUNTIME_LOG: u32 = 0x9c0f0a7d;
    pub const SYSTEM_RUNTIME_NOTIFY: u32 = 0xd2c1b624;
    pub const SYSTEM_RUNTIME_CHECKWITNESS: u32 = 0x2926d483;
    pub const SYSTEM_RUNTIME_BURNGAS: u32 = 0x6f7b6340;
    pub const SYSTEM_RUNTIME_GETEXECUTIONSCRIPTTRIGGER: u32 = 0xd2c95629;
    pub const SYSTEM_RUNTIME_GETCALLINGSCRIPTHASH: u32 = 0x6a24777b;
    pub const SYSTEM_RUNTIME_GETENTRYSCRIPTHASH: u32 = 0xf0ca4b9d;
    pub const SYSTEM_RUNTIME_GETCURRENTSCRIPTHASH: u32 = 0xb2f944dd;
    pub const SYSTEM_RUNTIME_GETRANDOM: u32 = 0xa7a3b73e;

    // Legacy aliases (kept for compatibility)
    pub const NEO_CRYPTO_RIPEMD160: u32 = SYSTEM_CRYPTO_RIPEMD160;
    pub const NEO_CRYPTO_SHA256: u32 = SYSTEM_CRYPTO_SHA256;
};

test "constants validation" {
    const testing = std.testing;

    // Validate key sizes match Neo N3 specification
    try testing.expectEqual(@as(usize, 20), HASH160_SIZE);
    try testing.expectEqual(@as(usize, 32), HASH256_SIZE);
    try testing.expectEqual(@as(usize, 32), PRIVATE_KEY_SIZE);
    try testing.expectEqual(@as(usize, 33), PUBLIC_KEY_SIZE_COMPRESSED);
    try testing.expectEqual(@as(usize, 64), SIGNATURE_SIZE);

    // Validate transaction limits
    try testing.expectEqual(@as(u8, 0), CURRENT_TX_VERSION);
    try testing.expectEqual(@as(u32, 102400), MAX_TRANSACTION_SIZE);
    try testing.expectEqual(@as(u8, 16), MAX_TRANSACTION_ATTRIBUTES);

    // Validate exposed Neo version metadata
    try testing.expectEqual(@as(u32, 3), NeoVersion.MAJOR);
    try testing.expectEqual(@as(u32, 9), NeoVersion.MINOR);
    try testing.expectEqual(@as(u32, 1), NeoVersion.PATCH);
    try testing.expectEqualStrings("3.9.1", NeoVersion.STRING);

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
