//! Sign utilities implementation
//!
//! Complete conversion from NeoSwift Sign.swift
//! Provides message signing with recovery and validation utilities.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;
const ECKeyPair = @import("ec_key_pair.zig").ECKeyPair;
const ECDSASignature = @import("ecdsa_signature.zig").ECDSASignature;
const PublicKey = @import("keys.zig").PublicKey;
const secp256r1 = @import("secp256r1.zig");

/// Sign utilities (converted from Swift Sign enum)
pub const Sign = struct {
    /// Lower real V constant (matches Swift LOWER_REAL_V)
    pub const LOWER_REAL_V: u8 = 27;

    /// Signs hex message (equivalent to Swift signHexMessage)
    pub fn signHexMessage(message_hex: []const u8, key_pair: ECKeyPair, allocator: std.mem.Allocator) !SignatureData {
        const message_bytes = try @import("../utils/string_extensions.zig").StringUtils.bytesFromHex(message_hex, allocator);
        defer allocator.free(message_bytes);

        return try signMessage(message_bytes, key_pair, allocator);
    }

    /// Signs string message (equivalent to Swift signMessage(_ message: String))
    pub fn signStringMessage(message: []const u8, key_pair: ECKeyPair, allocator: std.mem.Allocator) !SignatureData {
        return try signMessage(message, key_pair, allocator);
    }

    /// Signs message bytes (equivalent to Swift signMessage(_ message: Bytes))
    pub fn signMessage(message: []const u8, key_pair: ECKeyPair, allocator: std.mem.Allocator) !SignatureData {
        // Hash the message
        const message_hash = Hash256.sha256(message);

        const expected_public = key_pair.getPublicKey();

        // Get ECDSA signature
        const ecdsa_sig = key_pair.signAndGetECDSASignature(message_hash.toSlice());

        // Find recovery ID
        var rec_id: i32 = -1;

        var i: u8 = 0;
        while (i <= 3) : (i += 1) {
            if (try recoverPublicKeyBytes(i, ecdsa_sig, message_hash, allocator)) |recovered_key| {
                defer allocator.free(recovered_key);

                var recovered_public = try PublicKey.init(recovered_key, false);
                if (expected_public.compressed) {
                    recovered_public = try recovered_public.toCompressed();
                }

                if (recovered_public.eql(expected_public)) {
                    rec_id = i;
                    break;
                }
            }
        }

        if (rec_id == -1) {
            return errors.throwIllegalState("Could not construct recoverable key");
        }

        return SignatureData.init(
            @as(u8, @intCast(rec_id + LOWER_REAL_V)),
            ecdsa_sig.getR(),
            ecdsa_sig.getS(),
        );
    }

    /// Recovers uncompressed public key bytes for a given recovery identifier.
    fn recoverPublicKeyBytes(
        recovery_id: u8,
        signature: ECDSASignature,
        message_hash: Hash256,
        allocator: std.mem.Allocator,
    ) !?[]u8 {
        if (secp256r1.recoverPoint(recovery_id, signature.getR(), signature.getS(), message_hash.toSlice())) |point| {
            var encoded: [65]u8 = undefined;
            encoded[0] = 0x04;
            const px = std.mem.toBytes(std.mem.nativeToBig(u256, point.x));
            const py = std.mem.toBytes(std.mem.nativeToBig(u256, point.y));
            @memcpy(encoded[1..33], &px);
            @memcpy(encoded[33..65], &py);

            const output = try allocator.alloc(u8, encoded.len);
            @memcpy(output, &encoded);
            return output;
        }
        return null;
    }

    /// Recovers public key from signature (equivalent to Swift recoverFromSignature)
    pub fn recoverFromSignature(
        signature: SignatureData,
        message: []const u8,
        allocator: std.mem.Allocator,
    ) !?[]u8 {
        const message_hash = Hash256.sha256(message);
        const ecdsa_sig = ECDSASignature.init(signature.r, signature.s);

        const preferred_recovery = signature.v - LOWER_REAL_V;
        if (preferred_recovery < 4) {
            if (try recoverPublicKeyBytes(preferred_recovery, ecdsa_sig, message_hash, allocator)) |bytes| {
                return bytes;
            }
        }

        var recovery_id: u8 = 0;
        while (recovery_id <= 3) : (recovery_id += 1) {
            if (recovery_id == preferred_recovery) continue;
            if (try recoverPublicKeyBytes(recovery_id, ecdsa_sig, message_hash, allocator)) |bytes| {
                return bytes;
            }
        }

        return null;
    }

    /// Verifies signature (equivalent to Swift signature verification)
    pub fn verifySignature(
        signature_data: SignatureData,
        message: []const u8,
        public_key: PublicKey,
        allocator: std.mem.Allocator,
    ) !bool {
        _ = allocator;

        const message_hash = Hash256.sha256(message);
        const ecdsa_sig = ECDSASignature.init(signature_data.r, signature_data.s);

        const zig_signature = @import("signatures.zig").Signature.init(ecdsa_sig.toBytes());
        return try zig_signature.verify(message_hash, public_key);
    }

    /// Signs message hash directly (utility method)
    pub fn signHash(hash: Hash256, key_pair: ECKeyPair, allocator: std.mem.Allocator) !SignatureData {
        return try signMessage(hash.toSlice(), key_pair, allocator);
    }

    /// Creates signature from components (utility method)
    pub fn createSignatureFromComponents(v: u8, r: u256, s: u256) SignatureData {
        return SignatureData.init(v, r, s);
    }
};

/// Signature data structure (converted from Swift SignatureData)
pub const SignatureData = struct {
    /// Recovery ID + 27
    v: u8,
    /// R component of ECDSA signature
    r: u256,
    /// S component of ECDSA signature
    s: u256,

    const Self = @This();

    /// Creates signature data (equivalent to Swift init)
    pub fn init(v: u8, r: u256, s: u256) Self {
        return Self{ .v = v, .r = r, .s = s };
    }

    /// Gets recovery ID (equivalent to Swift recovery ID extraction)
    pub fn getRecoveryId(self: Self) u8 {
        return self.v - Sign.LOWER_REAL_V;
    }

    /// Gets concatenated signature (equivalent to Swift concatenated property)
    pub fn getConcatenated(self: Self) [65]u8 {
        var result: [65]u8 = undefined;

        const r_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.r));
        const s_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.s));

        @memcpy(result[0..32], &r_bytes);
        @memcpy(result[32..64], &s_bytes);
        result[64] = self.v;

        return result;
    }

    /// Gets signature without recovery ID (equivalent to Swift signature bytes)
    pub fn getSignatureBytes(self: Self) [64]u8 {
        var result: [64]u8 = undefined;

        const r_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.r));
        const s_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.s));

        @memcpy(result[0..32], &r_bytes);
        @memcpy(result[32..64], &s_bytes);

        return result;
    }

    /// Converts to ECDSA signature (utility method)
    pub fn toECDSASignature(self: Self) ECDSASignature {
        return ECDSASignature.init(self.r, self.s);
    }

    /// Creates from ECDSA signature (utility method)
    pub fn fromECDSASignature(signature: ECDSASignature, recovery_id: u8) Self {
        return Self.init(recovery_id + Sign.LOWER_REAL_V, signature.getR(), signature.getS());
    }

    /// Validates signature data
    pub fn isValid(self: Self) bool {
        // Validate V is in expected range
        if (self.v < Sign.LOWER_REAL_V or self.v > Sign.LOWER_REAL_V + 3) {
            return false;
        }

        // Validate R and S are non-zero and in valid range
        return self.r > 0 and self.r < secp256r1.Secp256r1.N and
            self.s > 0 and self.s < secp256r1.Secp256r1.N;
    }

    /// Converts to canonical form (equivalent to Swift canonicalization)
    pub fn toCanonical(self: Self) Self {
        if (self.s <= secp256r1.Secp256r1.HALF_CURVE_ORDER) {
            return self;
        } else {
            // Make S canonical by subtracting from curve order
            const canonical_s = secp256r1.Secp256r1.N - self.s;

            // Adjust recovery ID for canonical S
            const adjusted_v = if (self.v % 2 == 0) self.v + 1 else self.v - 1;

            return Self.init(adjusted_v, self.r, canonical_s);
        }
    }

    /// Compares signature data for equality
    pub fn eql(self: Self, other: Self) bool {
        return self.v == other.v and self.r == other.r and self.s == other.s;
    }

    /// Hash function for HashMap usage
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&[_]u8{self.v});

        const r_bytes = std.mem.toBytes(self.r);
        const s_bytes = std.mem.toBytes(self.s);

        hasher.update(&r_bytes);
        hasher.update(&s_bytes);

        return hasher.final();
    }
};

// Tests (converted from Swift Sign tests)
test "Sign message operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create test key pair
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }

    // Test string message signing (equivalent to Swift signMessage tests)
    const message = "Test message for signing";
    const signature_data = try Sign.signStringMessage(message, key_pair, allocator);

    try testing.expect(signature_data.isValid());
    try testing.expect(signature_data.v >= Sign.LOWER_REAL_V);
    try testing.expect(signature_data.v <= Sign.LOWER_REAL_V + 3);
    try testing.expect(signature_data.r != 0);
    try testing.expect(signature_data.s != 0);

    // Test hex message signing (equivalent to Swift signHexMessage tests)
    const hex_message = "48656c6c6f204e656f"; // "Hello Neo" in hex
    const hex_signature_data = try Sign.signHexMessage(hex_message, key_pair, allocator);

    try testing.expect(hex_signature_data.isValid());

    // Test signature verification (equivalent to Swift verification tests)
    const verification_result = try Sign.verifySignature(signature_data, message, key_pair.getPublicKey(), allocator);
    try testing.expect(verification_result);
}

test "SignatureData operations" {
    const testing = std.testing;

    // Test signature data creation (equivalent to Swift SignatureData tests)
    const test_r: u256 = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0;
    const test_s: u256 = 0x0FEDCBA987654321FEDCBA987654321FEDCBA987654321FEDCBA987654321;
    const test_v: u8 = 28;

    const signature_data = SignatureData.init(test_v, test_r, test_s);

    try testing.expectEqual(test_v, signature_data.v);
    try testing.expectEqual(test_r, signature_data.r);
    try testing.expectEqual(test_s, signature_data.s);
    try testing.expect(signature_data.isValid());

    // Test recovery ID extraction
    const recovery_id = signature_data.getRecoveryId();
    try testing.expectEqual(@as(u8, 1), recovery_id); // 28 - 27 = 1

    // Test concatenated signature
    const concatenated = signature_data.getConcatenated();
    try testing.expectEqual(@as(usize, 65), concatenated.len);
    try testing.expectEqual(test_v, concatenated[64]);

    // Test signature bytes (without recovery ID)
    const sig_bytes = signature_data.getSignatureBytes();
    try testing.expectEqual(@as(usize, 64), sig_bytes.len);
}

test "SignatureData canonical operations" {
    const testing = std.testing;

    // Test canonical signature (S <= half curve order)
    const canonical_s = secp256r1.Secp256r1.HALF_CURVE_ORDER - 1;
    const canonical_sig = SignatureData.init(28, 123, canonical_s);

    const canonicalized = canonical_sig.toCanonical();
    try testing.expect(canonical_sig.eql(canonicalized)); // Should be unchanged

    // Test non-canonical signature (S > half curve order)
    const non_canonical_s = secp256r1.Secp256r1.HALF_CURVE_ORDER + 1;
    const non_canonical_sig = SignatureData.init(28, 123, non_canonical_s);

    const canonicalized_non = non_canonical_sig.toCanonical();
    try testing.expect(!non_canonical_sig.eql(canonicalized_non)); // Should be changed
    try testing.expect(canonicalized_non.s <= secp256r1.Secp256r1.HALF_CURVE_ORDER);
}

test "SignatureData conversion operations" {
    const testing = std.testing;

    // Test conversion to/from ECDSA signature
    const original_ecdsa = ECDSASignature.init(12345, 67890);
    const signature_data = SignatureData.fromECDSASignature(original_ecdsa, 1);

    try testing.expectEqual(@as(u8, 28), signature_data.v); // 1 + 27
    try testing.expectEqual(@as(u256, 12345), signature_data.r);
    try testing.expectEqual(@as(u256, 67890), signature_data.s);

    const converted_ecdsa = signature_data.toECDSASignature();
    try testing.expect(original_ecdsa.eql(converted_ecdsa));
}

test "SignatureData equality and hashing" {
    const testing = std.testing;

    // Test equality (equivalent to Swift equality tests)
    const sig1 = SignatureData.init(28, 123, 456);
    const sig2 = SignatureData.init(28, 123, 456);
    const sig3 = SignatureData.init(29, 123, 456);

    try testing.expect(sig1.eql(sig2));
    try testing.expect(!sig1.eql(sig3));

    // Test hashing (equivalent to Swift Hashable tests)
    const hash1 = sig1.hash();
    const hash2 = sig2.hash();
    const hash3 = sig3.hash();

    try testing.expectEqual(hash1, hash2);
    try testing.expect(hash1 != hash3);
}
