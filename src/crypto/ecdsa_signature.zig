//! ECDSA Signature implementation
//!
//! Complete conversion from NeoSwift ECDSASignature.swift
//! Provides detailed ECDSA signature management and validation.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const secp256r1 = @import("secp256r1.zig");

/// ECDSA signature with detailed component access (converted from Swift ECDSASignature)
pub const ECDSASignature = struct {
    /// R component of signature
    r: u256,
    /// S component of signature
    s: u256,

    const Self = @This();

    /// Creates ECDSA signature from R and S components (equivalent to Swift init(r:s:))
    pub fn init(r: u256, s: u256) Self {
        return Self{ .r = r, .s = s };
    }

    /// Creates from raw signature bytes (equivalent to Swift init(signature:))
    pub fn fromBytes(signature_bytes: [64]u8) Self {
        const r = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, signature_bytes[0..32]));
        const s = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, signature_bytes[32..64]));

        return Self.init(r, s);
    }

    /// Gets R component as big integer (equivalent to Swift .r property)
    pub fn getR(self: Self) u256 {
        return self.r;
    }

    /// Gets S component as big integer (equivalent to Swift .s property)
    pub fn getS(self: Self) u256 {
        return self.s;
    }

    /// Checks if signature is canonical (equivalent to Swift .isCanonical property)
    pub fn isCanonical(self: Self) bool {
        return self.s <= secp256r1.Secp256r1.HALF_CURVE_ORDER;
    }

    /// Makes signature canonical by adjusting S component (equivalent to Swift canonicalization)
    pub fn toCanonical(self: Self) Self {
        if (self.isCanonical()) {
            return self;
        } else {
            // If S > half_order, set S = order - S
            const canonical_s = secp256r1.Secp256r1.N - self.s;
            return Self.init(self.r, canonical_s);
        }
    }

    /// Converts to raw signature bytes (equivalent to Swift byte representation)
    pub fn toBytes(self: Self) [64]u8 {
        var signature_bytes: [64]u8 = undefined;

        const r_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.r));
        const s_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.s));

        @memcpy(signature_bytes[0..32], &r_bytes);
        @memcpy(signature_bytes[32..64], &s_bytes);

        return signature_bytes;
    }

    /// Converts to DER encoding (equivalent to Swift DER serialization)
    pub fn toDER(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var der = ArrayList(u8).init(allocator);
        defer der.deinit();

        // SEQUENCE tag
        try der.append(0x30);

        // Reserve a single-byte length (P-256 signatures always fit in short-form DER).
        const length_pos = der.items.len;
        try der.append(0x00);

        // Add R INTEGER
        try der.append(0x02); // INTEGER tag

        const r_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.r));

        // Find first non-zero byte
        var r_start: usize = 0;
        while (r_start < 32 and r_bytes[r_start] == 0) {
            r_start += 1;
        }

        if (r_start == 32) {
            try der.append(1);
            try der.append(0x00);
        } else {
            const r_content = r_bytes[r_start..];
            const r_needs_padding = (r_content[0] & 0x80) != 0;
            const r_len: u8 = @intCast(r_content.len + (if (r_needs_padding) @as(usize, 1) else 0));
            try der.append(r_len);
            if (r_needs_padding) try der.append(0x00); // Ensure positive integer encoding
            try der.appendSlice(r_content);
        }

        // Add S INTEGER
        try der.append(0x02); // INTEGER tag

        const s_bytes = std.mem.toBytes(std.mem.nativeToBig(u256, self.s));

        // Find first non-zero byte
        var s_start: usize = 0;
        while (s_start < 32 and s_bytes[s_start] == 0) {
            s_start += 1;
        }

        if (s_start == 32) {
            try der.append(1);
            try der.append(0x00);
        } else {
            const s_content = s_bytes[s_start..];
            const s_needs_padding = (s_content[0] & 0x80) != 0;
            const s_len: u8 = @intCast(s_content.len + (if (s_needs_padding) @as(usize, 1) else 0));
            try der.append(s_len);
            if (s_needs_padding) try der.append(0x00);
            try der.appendSlice(s_content);
        }

        // Update sequence length
        const total_len = der.items.len - 2; // Exclude SEQUENCE tag and length
        if (total_len >= 128) return errors.CryptoError.InvalidSignature;
        der.items[length_pos] = @intCast(total_len);

        return try der.toOwnedSlice();
    }

    /// Parses from DER encoding (equivalent to Swift DER parsing)
    pub fn fromDER(der_bytes: []const u8) !Self {
        if (der_bytes.len < 6) return errors.CryptoError.InvalidSignature;

        var pos: usize = 0;

        // Check SEQUENCE tag
        if (der_bytes[pos] != 0x30) return errors.CryptoError.InvalidSignature;
        pos += 1;

        // Parse sequence length (short-form expected, but accept long-form)
        if (pos >= der_bytes.len) return errors.CryptoError.InvalidSignature;
        var seq_len: usize = 0;
        const len_byte = der_bytes[pos];
        pos += 1;
        if ((len_byte & 0x80) == 0) {
            seq_len = len_byte;
        } else {
            const len_len: usize = len_byte & 0x7F;
            if (len_len == 0 or len_len > 4) return errors.CryptoError.InvalidSignature;
            if (pos + len_len > der_bytes.len) return errors.CryptoError.InvalidSignature;
            seq_len = 0;
            for (0..len_len) |i| {
                seq_len = (seq_len << 8) | der_bytes[pos + i];
            }
            pos += len_len;
        }
        if (pos + seq_len != der_bytes.len) return errors.CryptoError.InvalidSignature;

        // Parse R INTEGER
        if (pos >= der_bytes.len or der_bytes[pos] != 0x02) return errors.CryptoError.InvalidSignature;
        pos += 1;

        if (pos >= der_bytes.len) return errors.CryptoError.InvalidSignature;
        const r_len = der_bytes[pos];
        pos += 1;

        if (r_len == 0) return errors.CryptoError.InvalidSignature;
        if (pos + r_len > der_bytes.len) return errors.CryptoError.InvalidSignature;

        // Extract R value, handling padding
        var r_bytes: [32]u8 = std.mem.zeroes([32]u8);
        var r_start: usize = 0; // bytes to skip in the DER integer
        if (der_bytes[pos] == 0x00) {
            if (r_len == 1) {
                r_start = 0;
            } else {
                if ((der_bytes[pos + 1] & 0x80) == 0) return errors.CryptoError.InvalidSignature;
                r_start = 1;
            }
        } else {
            if ((der_bytes[pos] & 0x80) != 0) return errors.CryptoError.InvalidSignature;
        }

        const r_value_len: usize = r_len - r_start;
        if (r_value_len > 32) return errors.CryptoError.InvalidSignature;
        const r_copy_len = r_value_len;
        const r_offset = 32 - r_copy_len;
        @memcpy(r_bytes[r_offset..32], der_bytes[pos + r_start .. pos + r_start + r_copy_len]);
        pos += r_len;

        // Parse S INTEGER
        if (pos >= der_bytes.len or der_bytes[pos] != 0x02) return errors.CryptoError.InvalidSignature;
        pos += 1;

        if (pos >= der_bytes.len) return errors.CryptoError.InvalidSignature;
        const s_len = der_bytes[pos];
        pos += 1;

        if (s_len == 0) return errors.CryptoError.InvalidSignature;
        if (pos + s_len > der_bytes.len) return errors.CryptoError.InvalidSignature;

        // Extract S value, handling padding
        var s_bytes: [32]u8 = std.mem.zeroes([32]u8);
        var s_start: usize = 0;
        if (der_bytes[pos] == 0x00) {
            if (s_len == 1) {
                s_start = 0;
            } else {
                if ((der_bytes[pos + 1] & 0x80) == 0) return errors.CryptoError.InvalidSignature;
                s_start = 1;
            }
        } else {
            if ((der_bytes[pos] & 0x80) != 0) return errors.CryptoError.InvalidSignature;
        }

        const s_value_len: usize = s_len - s_start;
        if (s_value_len > 32) return errors.CryptoError.InvalidSignature;
        const s_copy_len = s_value_len;
        const s_offset = 32 - s_copy_len;
        @memcpy(s_bytes[s_offset..32], der_bytes[pos + s_start .. pos + s_start + s_copy_len]);
        pos += s_len;

        const r = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, &r_bytes));
        const s = std.mem.bigToNative(u256, std.mem.bytesToValue(u256, &s_bytes));

        return Self.init(r, s);
    }

    /// Validates signature components (equivalent to Swift validation)
    pub fn isValid(self: Self) bool {
        // R and S must be in range [1, n-1]
        return self.r > 0 and self.r < secp256r1.Secp256r1.N and
            self.s > 0 and self.s < secp256r1.Secp256r1.N;
    }

    /// Compares signatures for equality (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return self.r == other.r and self.s == other.s;
    }

    /// Hash function for HashMap usage (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);

        const r_bytes = std.mem.toBytes(self.r);
        const s_bytes = std.mem.toBytes(self.s);

        hasher.update(&r_bytes);
        hasher.update(&s_bytes);

        return hasher.final();
    }

    /// String representation (equivalent to Swift description)
    pub fn toString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "ECDSASignature(r: {}, s: {})",
            .{ self.r, self.s },
        );
    }
};

// Tests (converted from Swift ECDSASignature tests)
test "ECDSASignature creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    _ = allocator;

    // Test signature creation (equivalent to Swift ECDSASignature tests)
    const r: u256 = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF;
    const s: u256 = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321;

    const signature = ECDSASignature.init(r, s);

    try testing.expectEqual(r, signature.getR());
    try testing.expectEqual(s, signature.getS());

    // Test byte conversion
    const signature_bytes = signature.toBytes();
    const from_bytes = ECDSASignature.fromBytes(signature_bytes);

    try testing.expect(signature.eql(from_bytes));
}

test "ECDSASignature canonical operations" {
    const testing = std.testing;

    // Test canonical signature (equivalent to Swift isCanonical tests)
    const low_s: u256 = secp256r1.Secp256r1.HALF_CURVE_ORDER - 1;
    const high_s: u256 = secp256r1.Secp256r1.HALF_CURVE_ORDER + 1;

    const canonical_sig = ECDSASignature.init(1, low_s);
    const non_canonical_sig = ECDSASignature.init(1, high_s);

    try testing.expect(canonical_sig.isCanonical());
    try testing.expect(!non_canonical_sig.isCanonical());

    // Test canonicalization
    const canonicalized = non_canonical_sig.toCanonical();
    try testing.expect(canonicalized.isCanonical());
    try testing.expect(canonicalized.getS() <= secp256r1.Secp256r1.HALF_CURVE_ORDER);
}

test "ECDSASignature DER encoding/decoding" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test DER encoding (equivalent to Swift DER tests)
    const signature = ECDSASignature.init(
        0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0,
        0x0FEDCBA987654321FEDCBA987654321FEDCBA987654321FEDCBA987654321,
    );

    const der_bytes = try signature.toDER(allocator);
    defer allocator.free(der_bytes);

    try testing.expect(der_bytes.len > 6);
    try testing.expectEqual(@as(u8, 0x30), der_bytes[0]); // SEQUENCE tag

    // Test DER decoding
    const parsed_signature = try ECDSASignature.fromDER(der_bytes);
    try testing.expect(signature.eql(parsed_signature));
}

test "ECDSASignature DER encodes zero components" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const signature = ECDSASignature.init(0, 0);
    const der_bytes = try signature.toDER(allocator);
    defer allocator.free(der_bytes);

    const expected = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00 };
    try testing.expectEqualSlices(u8, &expected, der_bytes);

    const parsed = try ECDSASignature.fromDER(der_bytes);
    try testing.expect(signature.eql(parsed));
}

test "ECDSASignature DER pads high-bit integers" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const high_bit: u256 = (@as(u256, 1) << 255);
    const signature = ECDSASignature.init(high_bit, high_bit);

    const der_bytes = try signature.toDER(allocator);
    defer allocator.free(der_bytes);

    // Sequence header.
    try testing.expectEqual(@as(u8, 0x30), der_bytes[0]);

    // First INTEGER (r) should be 33 bytes: leading 0x00 padding + 0x80...
    // DER: 30 LL 02 21 00 80 ..(31 zeros).. 02 21 00 80 ..(31 zeros)..
    try testing.expectEqual(@as(u8, 0x02), der_bytes[2]);
    try testing.expectEqual(@as(u8, 33), der_bytes[3]);
    try testing.expectEqual(@as(u8, 0x00), der_bytes[4]);
    try testing.expectEqual(@as(u8, 0x80), der_bytes[5]);

    const parsed = try ECDSASignature.fromDER(der_bytes);
    try testing.expect(signature.eql(parsed));
}

test "ECDSASignature DER rejects non-minimal and negative encodings" {
    const testing = std.testing;

    // Non-minimal: unnecessary leading 0x00 when next byte does not set the high bit.
    const non_minimal = [_]u8{
        0x30, 0x08,
        0x02, 0x02,
        0x00, 0x01,
        0x02, 0x01,
        0x01,
    };
    try testing.expectError(errors.CryptoError.InvalidSignature, ECDSASignature.fromDER(&non_minimal));

    // Negative: missing padding for a value with the high bit set.
    const negative = [_]u8{
        0x30, 0x06,
        0x02, 0x01,
        0x80, 0x02,
        0x01, 0x01,
    };
    try testing.expectError(errors.CryptoError.InvalidSignature, ECDSASignature.fromDER(&negative));
}

test "ECDSASignature validation" {
    const testing = std.testing;

    // Test signature validation (equivalent to Swift validation tests)
    const valid_signature = ECDSASignature.init(1, 1);
    try testing.expect(valid_signature.isValid());

    // Test invalid signatures
    const zero_r_signature = ECDSASignature.init(0, 1);
    try testing.expect(!zero_r_signature.isValid());

    const zero_s_signature = ECDSASignature.init(1, 0);
    try testing.expect(!zero_s_signature.isValid());

    const out_of_range_signature = ECDSASignature.init(secp256r1.Secp256r1.N, 1);
    try testing.expect(!out_of_range_signature.isValid());
}

test "ECDSASignature comparison and hashing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test equality (equivalent to Swift Hashable tests)
    const sig1 = ECDSASignature.init(123, 456);
    const sig2 = ECDSASignature.init(123, 456);
    const sig3 = ECDSASignature.init(123, 789);

    try testing.expect(sig1.eql(sig2));
    try testing.expect(!sig1.eql(sig3));

    // Test hashing (equal objects should have equal hashes)
    const hash1 = sig1.hash();
    const hash2 = sig2.hash();
    const hash3 = sig3.hash();

    try testing.expectEqual(hash1, hash2);
    try testing.expect(hash1 != hash3);

    // Test string representation
    const string_repr = try sig1.toString(allocator);
    defer allocator.free(string_repr);

    try testing.expect(std.mem.indexOf(u8, string_repr, "ECDSASignature") != null);
    try testing.expect(std.mem.indexOf(u8, string_repr, "123") != null);
    try testing.expect(std.mem.indexOf(u8, string_repr, "456") != null);
}
