//! EC Key Pair implementation
//!
//! Complete conversion from NeoSwift ECKeyPair.swift
//! Provides SECP-256r1 key pair management with Swift API compatibility.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const PrivateKey = @import("keys.zig").PrivateKey;
const PublicKey = @import("keys.zig").PublicKey;
const ECDSASignature = @import("ecdsa_signature.zig").ECDSASignature;

/// Elliptic Curve SECP-256r1 key pair (converted from Swift ECKeyPair)
pub const ECKeyPair = struct {
    /// Private key component
    private_key: PrivateKey,
    /// Public key component
    public_key: PublicKey,

    const Self = @This();

    /// Creates EC key pair (equivalent to Swift init(privateKey:publicKey:))
    pub fn init(private_key: PrivateKey, public_key: PublicKey) Self {
        return Self{
            .private_key = private_key,
            .public_key = public_key,
        };
    }

    /// Creates key pair from private key (equivalent to Swift create(privateKey:))
    pub fn create(private_key: PrivateKey) !Self {
        const public_key = try private_key.getPublicKey(true);
        return Self.init(private_key, public_key);
    }

    /// Creates random key pair (equivalent to Swift create())
    pub fn createRandom() !Self {
        const private_key = PrivateKey.generate();
        const public_key = try private_key.getPublicKey(true);
        return Self.init(private_key, public_key);
    }

    /// Creates key pair from private key bytes (equivalent to Swift create(privateKey: Bytes))
    pub fn createFromBytes(private_key_bytes: [32]u8) !Self {
        const private_key = try PrivateKey.init(private_key_bytes);
        return try Self.create(private_key);
    }

    /// Creates key pair from private key hex (equivalent to Swift create(privateKey: String))
    pub fn createFromHex(private_key_hex: []const u8) !Self {
        const private_key = try PrivateKey.fromHex(private_key_hex);
        return try Self.create(private_key);
    }

    /// Gets NEO address (equivalent to Swift getAddress())
    pub fn getAddress(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const script_hash = try self.getScriptHash(allocator);
        return try script_hash.toAddress(allocator);
    }

    /// Gets script hash (equivalent to Swift getScriptHash())
    pub fn getScriptHash(self: Self, allocator: std.mem.Allocator) !Hash160 {
        // Avoid returning a slice referencing a temporary `PublicKey` created by
        // `toCompressed()`.
        var compressed_public_key_value = self.public_key;
        if (!compressed_public_key_value.compressed) {
            compressed_public_key_value = try compressed_public_key_value.toCompressed();
        }

        const script = try @import("../script/script_builder.zig").ScriptBuilder.buildVerificationScript(
            compressed_public_key_value.toSlice(),
            allocator,
        );
        defer allocator.free(script);

        return try Hash160.fromScript(script);
    }

    /// Signs message hash (equivalent to Swift sign(messageHash:))
    pub fn sign(self: Self, message_hash: []const u8) ![2]u256 {
        if (message_hash.len != constants.HASH256_SIZE) {
            return errors.ValidationError.InvalidLength;
        }
        const signature = self.signAndGetECDSASignature(message_hash);
        return [2]u256{ signature.getR(), signature.getS() };
    }

    /// Signs and gets ECDSA signature (equivalent to Swift signAndGetECDSASignature(messageHash:))
    pub fn signAndGetECDSASignature(self: Self, message_hash: []const u8) ECDSASignature {
        const hash256 = Hash256.initWithBytes(message_hash) catch {
            return ECDSASignature.init(0, 0);
        };

        // Create signature using secp256r1
        const signature = self.private_key.sign(hash256) catch {
            return ECDSASignature.init(0, 0); // Return zero signature on error
        };

        return ECDSASignature.fromBytes(signature.bytes);
    }

    /// Verifies signature (equivalent to Swift signature verification)
    pub fn verifySignature(self: Self, message_hash: []const u8, signature: ECDSASignature) !bool {
        if (message_hash.len != constants.HASH256_SIZE) {
            return errors.ValidationError.InvalidLength;
        }

        const hash256 = try Hash256.initWithBytes(message_hash);
        const zig_signature = @import("signatures.zig").Signature.init(signature.toBytes());

        return try zig_signature.verify(hash256, self.public_key);
    }

    /// Gets private key (equivalent to Swift .privateKey property)
    pub fn getPrivateKey(self: Self) PrivateKey {
        return self.private_key;
    }

    /// Gets public key (equivalent to Swift .publicKey property)
    pub fn getPublicKey(self: Self) PublicKey {
        return self.public_key;
    }

    /// Validates key pair consistency (equivalent to Swift validation)
    pub fn isValid(self: Self) bool {
        // Verify that public key matches private key
        const derived_public = self.private_key.getPublicKey(self.public_key.compressed) catch return false;
        return self.public_key.eql(derived_public);
    }

    /// Securely clears private key (equivalent to Swift secure disposal)
    pub fn zeroize(self: *Self) void {
        self.private_key.zeroize();
    }

    pub fn deinit(self: *Self) void {
        self.zeroize();
    }

    /// Exports private key as WIF (equivalent to Swift WIF export)
    pub fn exportWIF(self: Self, compressed: bool, network: @import("wif.zig").NetworkType, allocator: std.mem.Allocator) ![]u8 {
        return try @import("wif.zig").encode(self.private_key, compressed, network, allocator);
    }

    /// Imports key pair from WIF (equivalent to Swift WIF import)
    pub fn importFromWIF(wif: []const u8, allocator: std.mem.Allocator) !Self {
        const wif_result = try @import("wif.zig").decode(wif, allocator);
        defer @constCast(&wif_result).deinit();
        return try Self.create(wif_result.private_key);
    }

    /// Gets encoded private key (equivalent to Swift private key encoding)
    pub fn getEncodedPrivateKey(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try self.private_key.toHex(allocator);
    }

    /// Gets encoded public key (equivalent to Swift public key encoding)
    pub fn getEncodedPublicKey(self: Self, compressed: bool, allocator: std.mem.Allocator) ![]u8 {
        if (compressed and self.public_key.compressed) {
            return try self.public_key.toHex(allocator);
        } else if (!compressed and !self.public_key.compressed) {
            return try self.public_key.toHex(allocator);
        } else if (compressed and !self.public_key.compressed) {
            const compressed_key = try self.public_key.toCompressed();
            return try compressed_key.toHex(allocator);
        } else {
            const uncompressed_key = try self.public_key.toUncompressed();
            return try uncompressed_key.toHex(allocator);
        }
    }

    /// Compares key pairs for equality
    pub fn eql(self: Self, other: Self) bool {
        return self.private_key.eql(other.private_key) and self.public_key.eql(other.public_key);
    }

    /// Hash function for HashMap usage
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.private_key.toSlice());
        hasher.update(self.public_key.toSlice());
        return hasher.final();
    }
};

// Tests (converted from Swift ECKeyPair tests)
test "ECKeyPair creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test random key pair creation (equivalent to Swift create() tests)
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }

    try testing.expect(key_pair.isValid());
    try testing.expect(key_pair.getPrivateKey().isValid());
    try testing.expect(key_pair.getPublicKey().isValid());

    // Test address generation (equivalent to Swift getAddress() tests)
    const address = try key_pair.getAddress(allocator);
    defer allocator.free(address);

    try testing.expect(address.len > 0);

    // Test script hash generation (equivalent to Swift getScriptHash() tests)
    const script_hash = try key_pair.getScriptHash(allocator);
    try testing.expect(!script_hash.eql(Hash160.ZERO));
}

test "ECKeyPair creation from private key" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test creation from bytes (equivalent to Swift create(privateKey: Bytes) tests)
    var private_key_bytes: [32]u8 = undefined;
    for (&private_key_bytes, 0..) |*byte, i| {
        byte.* = @intCast((i + 1) % 256);
    }

    const key_pair_from_bytes = try ECKeyPair.createFromBytes(private_key_bytes);
    defer {
        var mutable_key_pair = key_pair_from_bytes;
        mutable_key_pair.zeroize();
    }

    try testing.expect(key_pair_from_bytes.isValid());

    // Test creation from hex (equivalent to Swift create(privateKey: String) tests)
    const private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const key_pair_from_hex = try ECKeyPair.createFromHex(private_key_hex);
    defer {
        var mutable_key_pair = key_pair_from_hex;
        mutable_key_pair.zeroize();
    }

    try testing.expect(key_pair_from_hex.isValid());

    // Test encoded private key matches input
    const encoded_private = try key_pair_from_hex.getEncodedPrivateKey(allocator);
    defer allocator.free(encoded_private);

    try testing.expectEqualStrings(private_key_hex, encoded_private);
}

test "ECKeyPair signing operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    _ = allocator;

    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }

    // Test message signing (equivalent to Swift sign(messageHash:) tests)
    const message = "Test message for ECKeyPair signing";
    const message_hash = Hash256.sha256(message);

    const signature_components = try key_pair.sign(message_hash.toSlice());
    try testing.expect(signature_components[0] != 0); // R component
    try testing.expect(signature_components[1] != 0); // S component

    // Test ECDSA signature creation (equivalent to Swift signAndGetECDSASignature tests)
    const ecdsa_signature = key_pair.signAndGetECDSASignature(message_hash.toSlice());
    try testing.expect(ecdsa_signature.isValid());
    try testing.expect(ecdsa_signature.isCanonical());

    // Test signature verification
    const verification_result = try key_pair.verifySignature(message_hash.toSlice(), ecdsa_signature);
    try testing.expect(verification_result);

    // Test signature with wrong message fails
    const wrong_message = "Wrong message";
    const wrong_hash = Hash256.sha256(wrong_message);
    const wrong_verification = try key_pair.verifySignature(wrong_hash.toSlice(), ecdsa_signature);
    try testing.expect(!wrong_verification);

    const short_hash = "short";
    try testing.expectError(errors.ValidationError.InvalidLength, key_pair.sign(short_hash));
    try testing.expectError(errors.ValidationError.InvalidLength, key_pair.verifySignature(short_hash, ecdsa_signature));
    try testing.expect(!key_pair.signAndGetECDSASignature(short_hash).isValid());
}

test "ECKeyPair WIF operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }

    // Test WIF export (equivalent to Swift WIF export tests)
    const wif_compressed = try key_pair.exportWIF(true, .mainnet, allocator);
    defer allocator.free(wif_compressed);

    const wif_uncompressed = try key_pair.exportWIF(false, .mainnet, allocator);
    defer allocator.free(wif_uncompressed);

    try testing.expect(wif_compressed.len > 0);
    try testing.expect(wif_uncompressed.len > 0);
    try testing.expect(!std.mem.eql(u8, wif_compressed, wif_uncompressed));

    // Test WIF import (equivalent to Swift WIF import tests)
    const imported_key_pair = try ECKeyPair.importFromWIF(wif_compressed, allocator);
    defer {
        var mutable_imported = imported_key_pair;
        mutable_imported.zeroize();
    }

    try testing.expect(key_pair.getPrivateKey().eql(imported_key_pair.getPrivateKey()));
}

test "ECKeyPair encoding operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }

    // Test private key encoding (equivalent to Swift private key encoding tests)
    const encoded_private = try key_pair.getEncodedPrivateKey(allocator);
    defer allocator.free(encoded_private);

    try testing.expect(encoded_private.len == 64); // 32 bytes * 2 hex chars

    // Test public key encoding (equivalent to Swift public key encoding tests)
    const encoded_public_compressed = try key_pair.getEncodedPublicKey(true, allocator);
    defer allocator.free(encoded_public_compressed);

    const encoded_public_uncompressed = try key_pair.getEncodedPublicKey(false, allocator);
    defer allocator.free(encoded_public_uncompressed);

    try testing.expect(encoded_public_compressed.len == 66); // 33 bytes * 2 hex chars
    try testing.expect(encoded_public_uncompressed.len == 130); // 65 bytes * 2 hex chars

    // Compressed should start with 02 or 03
    try testing.expect(std.mem.startsWith(u8, encoded_public_compressed, "02") or
        std.mem.startsWith(u8, encoded_public_compressed, "03"));

    // Uncompressed should start with 04
    try testing.expect(std.mem.startsWith(u8, encoded_public_uncompressed, "04"));
}

test "ECKeyPair validation and comparison" {
    const testing = std.testing;
    const allocator = testing.allocator;
    _ = allocator;

    // Test key pair validation (equivalent to Swift validation tests)
    const key_pair1 = try ECKeyPair.createRandom();
    defer {
        var mutable_key_pair1 = key_pair1;
        mutable_key_pair1.zeroize();
    }

    const key_pair2 = try ECKeyPair.createRandom();
    defer {
        var mutable_key_pair2 = key_pair2;
        mutable_key_pair2.zeroize();
    }

    try testing.expect(key_pair1.isValid());
    try testing.expect(key_pair2.isValid());

    // Test equality (equivalent to Swift equality tests)
    try testing.expect(key_pair1.eql(key_pair1));
    try testing.expect(!key_pair1.eql(key_pair2));

    // Test hash function (equivalent to Swift Hashable tests)
    const hash1 = key_pair1.hash();
    const hash1_again = key_pair1.hash();
    const hash2 = key_pair2.hash();

    try testing.expectEqual(hash1, hash1_again);
    try testing.expect(hash1 != hash2);
}
