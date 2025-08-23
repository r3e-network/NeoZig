//! Cryptographic operations module for Neo blockchain
//!
//! This module provides comprehensive cryptographic functionality including:
//! - ECDSA key generation and management
//! - Digital signature creation and verification
//! - Hash functions (SHA256, RIPEMD160)
//! - WIF (Wallet Import Format) encoding/decoding
//! - Random number generation
//! - Key derivation functions

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;

// Export crypto submodules
pub const keys = @import("keys.zig");
pub const signatures = @import("signatures.zig");
pub const hashing = @import("hashing.zig");
pub const wif = @import("wif.zig");
pub const random = @import("random.zig");
pub const secp256r1 = @import("secp256r1.zig");
pub const ripemd160 = @import("ripemd160.zig");

// Re-export commonly used types
pub const PrivateKey = keys.PrivateKey;
pub const PublicKey = keys.PublicKey;
pub const KeyPair = keys.KeyPair;
pub const Signature = signatures.Signature;

/// Generates a new cryptographically secure private key
pub fn generatePrivateKey() PrivateKey {
    return PrivateKey.generate();
}

/// Generates a new key pair (private + public key)
pub fn generateKeyPair(compressed: bool) !KeyPair {
    return try KeyPair.generate(compressed);
}

/// Signs a message with a private key
pub fn signMessage(message: []const u8, private_key: PrivateKey) !Signature {
    const message_hash = Hash256.sha256(message);
    return try private_key.sign(message_hash);
}

/// Signs a hash with a private key
pub fn signHash(hash: Hash256, private_key: PrivateKey) !Signature {
    return try private_key.sign(hash);
}

/// Verifies a signature against a message and public key
pub fn verifyMessage(signature: Signature, message: []const u8, public_key: PublicKey) !bool {
    const message_hash = Hash256.sha256(message);
    return try signature.verify(message_hash, public_key);
}

/// Verifies a signature against a hash and public key
pub fn verifyHash(signature: Signature, hash: Hash256, public_key: PublicKey) !bool {
    return try signature.verify(hash, public_key);
}

/// Computes SHA256 hash of data
pub fn sha256(data: []const u8) Hash256 {
    return Hash256.sha256(data);
}

/// Computes RIPEMD160 hash of data
pub fn ripemd160Hash(data: []const u8) !Hash160 {
    const hash_bytes = ripemd160.ripemd160(data);
    return Hash160.init(hash_bytes);
}

/// Computes Hash160 (RIPEMD160 of SHA256)
pub fn hash160(data: []const u8) !Hash160 {
    const sha_hash = sha256(data);
    return try ripemd160Hash(sha_hash.toSlice());
}

/// Encodes a private key to WIF format
pub fn encodeWIF(private_key: PrivateKey, compressed: bool, network: NetworkType, allocator: std.mem.Allocator) ![]u8 {
    return try wif.encode(private_key, compressed, network, allocator);
}

/// Decodes a WIF string to private key
pub fn decodeWIF(wif_string: []const u8, allocator: std.mem.Allocator) !WIFDecodeResult {
    return try wif.decode(wif_string, allocator);
}

/// Network type for WIF encoding
pub const NetworkType = wif.NetworkType;

/// Result of WIF decoding operation
pub const WIFDecodeResult = wif.WIFDecodeResult;

test "crypto module integration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test key generation
    const private_key = generatePrivateKey();
    try testing.expect(private_key.isValid());
    
    const key_pair = try generateKeyPair(true);
    try testing.expect(key_pair.private_key.isValid());
    try testing.expect(key_pair.public_key.isValid());
    
    // Test message signing and verification
    const message = "Hello Neo Blockchain";
    const signature = try signMessage(message, private_key);
    
    const public_key = try private_key.getPublicKey(true);
    const valid = try verifyMessage(signature, message, public_key);
    try testing.expect(valid);
    
    // Test hash functions
    const sha_result = sha256(message);
    try testing.expect(!sha_result.isZero());
    
    const hash160_result = try hash160(message);
    try testing.expect(!hash160_result.isZero());
}