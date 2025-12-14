//! BIP32 HD Wallet implementation
//!
//! Complete conversion from NeoSwift Bip32ECKeyPair.swift
//! Provides hierarchical deterministic wallet functionality.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const PrivateKey = @import("keys.zig").PrivateKey;
const PublicKey = @import("keys.zig").PublicKey;
const KeyPair = @import("keys.zig").KeyPair;
const hashing = @import("hashing.zig");
const secure = @import("../utils/secure.zig");

/// BIP32 HD key pair (converted from Swift Bip32ECKeyPair)
pub const Bip32ECKeyPair = struct {
    /// Hardened derivation bit (matches Swift HARDENED_BIT)
    pub const HARDENED_BIT: i32 = -2147483648; // 0x80000000

    /// Base key pair
    key_pair: KeyPair,
    /// Whether parent has private key
    parent_has_private: bool,
    /// Child number in derivation path
    child_number: i32,
    /// Derivation depth
    depth: i32,
    /// Chain code for key derivation
    chain_code: [32]u8,
    /// Parent fingerprint
    parent_fingerprint: i32,
    /// Public key point
    public_key_point: [33]u8, // Compressed public key
    /// Key identifier (Hash160 of public key)
    identifier: [20]u8,
    /// Key fingerprint
    fingerprint: i32,

    const Self = @This();

    /// Creates BIP32 key pair (equivalent to Swift init)
    pub fn init(
        private_key: PrivateKey,
        public_key: PublicKey,
        child_number: i32,
        chain_code: [32]u8,
        parent: ?*const Self,
    ) !Self {
        const parent_has_private = parent != null;
        const depth = if (parent) |p| p.depth + 1 else 0;
        const parent_fingerprint = if (parent) |p| p.fingerprint else 0;

        // Calculate identifier (Hash160 of compressed public key)
        // Avoid returning a slice referencing a temporary `PublicKey` created by
        // `toCompressed()`.
        var compressed_pub_key_value = public_key;
        if (!compressed_pub_key_value.compressed) {
            compressed_pub_key_value = try compressed_pub_key_value.toCompressed();
        }
        const compressed_pub_key = compressed_pub_key_value.toSlice();

        const identifier = try calculateIdentifier(compressed_pub_key);

        // Calculate fingerprint from identifier
        const fingerprint = calculateFingerprint(identifier);

        var public_key_point: [33]u8 = undefined;
        @memcpy(&public_key_point, compressed_pub_key[0..33]);

        return Self{
            .key_pair = KeyPair.init(private_key, public_key),
            .parent_has_private = parent_has_private,
            .child_number = child_number,
            .depth = depth,
            .chain_code = chain_code,
            .parent_fingerprint = parent_fingerprint,
            .public_key_point = public_key_point,
            .identifier = identifier,
            .fingerprint = fingerprint,
        };
    }

    /// Creates from private key and chain code (equivalent to Swift create(privateKey:chainCode:))
    pub fn createFromPrivateKey(private_key: PrivateKey, chain_code: [32]u8) !Self {
        const public_key = try private_key.getPublicKey(true);
        return try Self.init(private_key, public_key, 0, chain_code, null);
    }

    /// Creates from bytes (equivalent to Swift create(privateKey:chainCode:))
    pub fn createFromBytes(private_key_bytes: [32]u8, chain_code: [32]u8) !Self {
        const private_key = try PrivateKey.init(private_key_bytes);
        return try Self.createFromPrivateKey(private_key, chain_code);
    }

    /// Generates key pair from seed (equivalent to Swift generateKeyPair(seed:))
    pub fn generateKeyPair(seed: []const u8, allocator: std.mem.Allocator) !Self {
        _ = allocator;
        const hmac_key = "Bitcoin seed";

        // Generate HMAC-SHA512 of seed with "Bitcoin seed" key
        var hmac_result = hmacSha512(hmac_key, seed);
        defer std.crypto.secureZero(u8, &hmac_result);

        // Split into private key and chain code
        var private_key_bytes: [32]u8 = undefined;
        var chain_code: [32]u8 = undefined;

        @memcpy(&private_key_bytes, hmac_result[0..32]);
        @memcpy(&chain_code, hmac_result[32..64]);

        return try Self.createFromBytes(private_key_bytes, chain_code);
    }

    /// Derives child key (equivalent to Swift deriveChild)
    pub fn deriveChild(self: Self, child_number: u32, hardened: bool, allocator: std.mem.Allocator) !Self {
        const actual_child_number = if (hardened)
            @as(i32, @bitCast(child_number | 0x80000000))
        else
            @as(i32, @intCast(child_number));

        // Prepare derivation data
        var derivation_data = ArrayList(u8).init(allocator);
        defer {
            secure.secureZeroBytes(derivation_data.items);
            derivation_data.deinit();
        }

        if (hardened) {
            // Use private key for hardened derivation
            try derivation_data.append(0x00); // Padding
            try derivation_data.appendSlice(self.key_pair.private_key.toSlice());
        } else {
            // Use public key for non-hardened derivation
            try derivation_data.appendSlice(&self.public_key_point);
        }

        // Add child number as big-endian 32-bit integer
        const child_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, @bitCast(actual_child_number)));
        try derivation_data.appendSlice(&child_bytes);

        // Generate HMAC-SHA512 with chain code
        var hmac_result = hmacSha512(&self.chain_code, derivation_data.items);
        defer std.crypto.secureZero(u8, &hmac_result);

        // Split result
        const left_32 = hmac_result[0..32];
        var new_chain_code: [32]u8 = undefined;
        @memcpy(&new_chain_code, hmac_result[32..64]);

        // Calculate new private key (add to parent private key mod curve order)
        const left_scalar = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, left_32));
        const parent_scalar = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, self.key_pair.private_key.toSlice()));

        const secp256r1 = @import("secp256r1.zig");
        const new_scalar = (left_scalar +% parent_scalar) % secp256r1.Secp256r1.N;

        if (new_scalar == 0) {
            return errors.CryptoError.KeyDerivationFailed; // Invalid key, try next index
        }

        // Create new key pair
        const new_private_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, new_scalar));
        const new_private_key = try PrivateKey.init(new_private_bytes);
        const new_public_key = try new_private_key.getPublicKey(true);

        return try Self.init(new_private_key, new_public_key, actual_child_number, new_chain_code, &self);
    }

    /// Derives from path (equivalent to Swift derivation path operations)
    pub fn deriveFromPath(self: Self, derivation_path: []const u32, allocator: std.mem.Allocator) !Self {
        var current_key = self;

        for (derivation_path) |index| {
            const hardened = (index & 0x80000000) != 0;
            const child_index = index & 0x7FFFFFFF;

            current_key = try current_key.deriveChild(child_index, hardened, allocator);
        }

        return current_key;
    }

    /// Zeroizes sensitive material.
    pub fn deinit(self: *Self) void {
        self.key_pair.zeroize();
        std.crypto.secureZero(u8, &self.chain_code);
        std.crypto.secureZero(u8, &self.identifier);
    }

    /// Gets extended private key (equivalent to Swift extended key serialization)
    pub fn getExtendedPrivateKey(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var extended_key = ArrayList(u8).init(allocator);
        defer {
            secure.secureZeroBytes(extended_key.items);
            extended_key.deinit();
        }

        // Version (4 bytes) - mainnet private key
        try extended_key.appendSlice(&[_]u8{ 0x04, 0x88, 0xAD, 0xE4 });

        // Depth (1 byte)
        try extended_key.append(@intCast(self.depth));

        // Parent fingerprint (4 bytes)
        const parent_fp_bytes = std.mem.toBytes(std.mem.nativeToBig(i32, self.parent_fingerprint));
        try extended_key.appendSlice(&parent_fp_bytes);

        // Child number (4 bytes)
        const child_bytes = std.mem.toBytes(std.mem.nativeToBig(i32, self.child_number));
        try extended_key.appendSlice(&child_bytes);

        // Chain code (32 bytes)
        try extended_key.appendSlice(&self.chain_code);

        // Private key with 0x00 prefix (33 bytes)
        try extended_key.append(0x00);
        try extended_key.appendSlice(self.key_pair.private_key.toSlice());

        // Encode with Base58Check
        const base58 = @import("../utils/base58.zig");
        return try base58.encodeCheck(extended_key.items, allocator);
    }

    /// Gets extended public key (equivalent to Swift extended public key serialization)
    pub fn getExtendedPublicKey(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var extended_key = ArrayList(u8).init(allocator);
        defer {
            secure.secureZeroBytes(extended_key.items);
            extended_key.deinit();
        }

        // Version (4 bytes) - mainnet public key
        try extended_key.appendSlice(&[_]u8{ 0x04, 0x88, 0xB2, 0x1E });

        // Depth (1 byte)
        try extended_key.append(@intCast(self.depth));

        // Parent fingerprint (4 bytes)
        const parent_fp_bytes = std.mem.toBytes(std.mem.nativeToBig(i32, self.parent_fingerprint));
        try extended_key.appendSlice(&parent_fp_bytes);

        // Child number (4 bytes)
        const child_bytes = std.mem.toBytes(std.mem.nativeToBig(i32, self.child_number));
        try extended_key.appendSlice(&child_bytes);

        // Chain code (32 bytes)
        try extended_key.appendSlice(&self.chain_code);

        // Public key (33 bytes)
        try extended_key.appendSlice(&self.public_key_point);

        // Encode with Base58Check
        const base58 = @import("../utils/base58.zig");
        return try base58.encodeCheck(extended_key.items, allocator);
    }

    /// Checks if derivation index is hardened (equivalent to Swift hardened checking)
    pub fn isHardened(index: u32) bool {
        return (index & 0x80000000) != 0;
    }

    /// Creates hardened index (equivalent to Swift hardened index creation)
    pub fn hardenedIndex(index: u32) u32 {
        return index | 0x80000000;
    }
};

/// Helper functions
/// Calculates identifier from public key (equivalent to Swift identifier calculation)
fn calculateIdentifier(compressed_public_key: []const u8) ![20]u8 {
    // Hash160 of compressed public key
    const ripemd160_impl = @import("ripemd160.zig");
    const sha_hash = Hash256.sha256(compressed_public_key);
    return ripemd160_impl.ripemd160(sha_hash.toSlice());
}

/// Calculates fingerprint from identifier (equivalent to Swift fingerprint calculation)
fn calculateFingerprint(identifier: [20]u8) i32 {
    // Take first 4 bytes of identifier and convert to int32
    const a = @as(i32, identifier[3]);
    const b = @as(i32, identifier[2]) << 8;
    const c = @as(i32, identifier[1]) << 16;
    const d = @as(i32, identifier[0]) << 24;

    return a | b | c | d;
}

/// HMAC-SHA512 implementation for BIP32
fn hmacSha512(key: []const u8, message: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(&out, message, key);
    return out;
}

// Tests (converted from Swift Bip32ECKeyPair tests)
test "Bip32ECKeyPair creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test key pair generation from seed (equivalent to Swift generateKeyPair tests)
    const test_seed = "test seed for BIP32 key generation";
    const master_key = try Bip32ECKeyPair.generateKeyPair(test_seed, allocator);

    // Test master key properties (equivalent to Swift master key tests)
    try testing.expectEqual(@as(i32, 0), master_key.depth);
    try testing.expectEqual(@as(i32, 0), master_key.child_number);
    try testing.expectEqual(@as(i32, 0), master_key.parent_fingerprint);
    try testing.expect(!master_key.parent_has_private);

    // Test that key pair is valid
    try testing.expect(master_key.key_pair.isValid());
}

test "Bip32ECKeyPair child derivation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const test_seed = "test seed for child derivation";
    const master_key = try Bip32ECKeyPair.generateKeyPair(test_seed, allocator);

    // Test non-hardened child derivation (equivalent to Swift child derivation tests)
    const child_key = try master_key.deriveChild(0, false, allocator);

    try testing.expectEqual(@as(i32, 1), child_key.depth);
    try testing.expectEqual(@as(i32, 0), child_key.child_number);
    try testing.expect(child_key.parent_has_private);
    try testing.expectEqual(master_key.fingerprint, child_key.parent_fingerprint);

    // Test hardened child derivation
    const hardened_child = try master_key.deriveChild(0, true, allocator);

    try testing.expectEqual(@as(i32, 1), hardened_child.depth);
    try testing.expect(Bip32ECKeyPair.isHardened(@bitCast(hardened_child.child_number)));

    // Test that children are different
    try testing.expect(!child_key.key_pair.private_key.eql(hardened_child.key_pair.private_key));
}

test "Bip32ECKeyPair derivation path" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const test_seed = "test seed for derivation path";
    const master_key = try Bip32ECKeyPair.generateKeyPair(test_seed, allocator);

    // Test derivation path: m/44'/60'/0'/0/0 (equivalent to Swift path derivation tests)
    const derivation_path = [_]u32{
        Bip32ECKeyPair.hardenedIndex(44), // 44'
        Bip32ECKeyPair.hardenedIndex(60), // 60'
        Bip32ECKeyPair.hardenedIndex(0), // 0'
        0, // 0
        0, // 0
    };

    const derived_key = try master_key.deriveFromPath(&derivation_path, allocator);

    try testing.expectEqual(@as(i32, 5), derived_key.depth);
    try testing.expect(derived_key.key_pair.isValid());

    // Test that derived key is different from master
    try testing.expect(!master_key.key_pair.private_key.eql(derived_key.key_pair.private_key));
}

test "Bip32ECKeyPair extended key serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const test_seed = "test seed for extended key serialization";
    const master_key = try Bip32ECKeyPair.generateKeyPair(test_seed, allocator);

    // Test extended private key (equivalent to Swift extended private key tests)
    const extended_private = try master_key.getExtendedPrivateKey(allocator);
    defer allocator.free(extended_private);

    try testing.expect(extended_private.len > 0);

    // Extended private keys should start with "xprv" when base58 decoded
    // (This is validated by the version bytes 0x0488ADE4)

    // Test extended public key (equivalent to Swift extended public key tests)
    const extended_public = try master_key.getExtendedPublicKey(allocator);
    defer allocator.free(extended_public);

    try testing.expect(extended_public.len > 0);
    try testing.expect(!std.mem.eql(u8, extended_private, extended_public));
}

test "Bip32ECKeyPair hardened index operations" {
    const testing = std.testing;

    // Test hardened index operations (equivalent to Swift hardened tests)
    const normal_index: u32 = 123;
    const hardened_index = Bip32ECKeyPair.hardenedIndex(normal_index);

    try testing.expect(Bip32ECKeyPair.isHardened(hardened_index));
    try testing.expect(!Bip32ECKeyPair.isHardened(normal_index));

    // Test hardened bit
    try testing.expectEqual(@as(i32, -2147483648), Bip32ECKeyPair.HARDENED_BIT);
    try testing.expectEqual(@as(u32, 0x80000000), @as(u32, @bitCast(Bip32ECKeyPair.HARDENED_BIT)));
}
