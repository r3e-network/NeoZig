//! Base58 Encoding Implementation
//!
//! Complete conversion from NeoSwift Base58.swift
//! Provides Base58 and Base58Check encoding/decoding functionality.
//! Imported and modified from Base58Swift (MIT License)

const std = @import("std");

/// Base58 encoding/decoding utilities (converted from Swift Base58)
pub const Base58 = struct {
    /// Length of checksum appended to Base58Check encoded strings
    const CHECKSUM_LENGTH = 4;
    
    /// Base58 alphabet (Bitcoin standard)
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    /// Base58Check encode bytes (equivalent to Swift base58CheckEncode)
    pub fn base58CheckEncode(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const checksum = try calculateChecksum(bytes, allocator);
        defer allocator.free(checksum);
        
        // Combine bytes and checksum
        const checksummed_bytes = try std.mem.concat(allocator, u8, &[_][]const u8{ bytes, checksum });
        defer allocator.free(checksummed_bytes);
        
        return try encode(checksummed_bytes, allocator);
    }
    
    /// Base58Check decode string (equivalent to Swift base58CheckDecode)
    pub fn base58CheckDecode(input: []const u8, allocator: std.mem.Allocator) !?[]u8 {
        const decoded_checksummed = (try decode(input, allocator)) orelse return null;
        defer allocator.free(decoded_checksummed);
        
        if (decoded_checksummed.len < CHECKSUM_LENGTH) {
            return null;
        }
        
        const decoded_bytes = decoded_checksummed[0..(decoded_checksummed.len - CHECKSUM_LENGTH)];
        const decoded_checksum = decoded_checksummed[(decoded_checksummed.len - CHECKSUM_LENGTH)..];
        
        const calculated_checksum = try calculateChecksum(decoded_bytes, allocator);
        defer allocator.free(calculated_checksum);
        
        if (!std.mem.eql(u8, decoded_checksum, calculated_checksum)) {
            return null;
        }
        
        return try allocator.dupe(u8, decoded_bytes);
    }
    
    /// Base58 encode bytes (equivalent to Swift encode)
    pub fn encode(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (bytes.len == 0) {
            return try allocator.dupe(u8, "");
        }
        
        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();
        
        // Convert bytes to big integer
        var big_int = try bytesToBigInt(bytes, allocator);
        defer big_int.deinit();
        
        // Convert to base58
        const radix = try std.math.big.int.Managed.initSet(allocator, 58);
        defer radix.deinit();
        
        var quotient = try std.math.big.int.Managed.init(allocator);
        defer quotient.deinit();
        
        var remainder = try std.math.big.int.Managed.init(allocator);
        defer remainder.deinit();
        
        while (!big_int.eqZero()) {
            try std.math.big.int.Managed.divFloor(&quotient, &remainder, &big_int, &radix);
            
            const remainder_small = remainder.to(u8) catch 0;
            if (remainder_small < ALPHABET.len) {
                try result.insert(0, ALPHABET[remainder_small]);
            }
            
            try big_int.copy(quotient.toConst());
        }
        
        // Handle leading zeros
        for (bytes) |byte| {
            if (byte == 0) {
                try result.insert(0, ALPHABET[0]);
            } else {
                break;
            }
        }
        
        return try result.toOwnedSlice();
    }
    
    /// Base58 decode string (equivalent to Swift decode)
    pub fn decode(input: []const u8, allocator: std.mem.Allocator) !?[]u8 {
        if (input.len == 0) {
            return try allocator.dupe(u8, "");
        }
        
        var answer = try std.math.big.int.Managed.initSet(allocator, 0);
        defer answer.deinit();
        
        var multiplier = try std.math.big.int.Managed.initSet(allocator, 1);
        defer multiplier.deinit();
        
        const radix = try std.math.big.int.Managed.initSet(allocator, 58);
        defer radix.deinit();
        
        // Process characters in reverse
        var i: usize = input.len;
        while (i > 0) {
            i -= 1;
            const char = input[i];
            
            const alphabet_index = std.mem.indexOf(u8, ALPHABET, &[_]u8{char}) orelse return null;
            
            var term = try std.math.big.int.Managed.initSet(allocator, alphabet_index);
            defer term.deinit();
            
            try term.mul(&term, &multiplier);
            try answer.add(&answer, &term);
            try multiplier.mul(&multiplier, &radix);
        }
        
        // Convert back to bytes
        const magnitude_bytes = try bigIntToBytes(&answer, allocator);
        defer allocator.free(magnitude_bytes);
        
        // Count leading zeros in input
        var leading_zeros: usize = 0;
        for (input) |char| {
            if (char == ALPHABET[0]) {
                leading_zeros += 1;
            } else {
                break;
            }
        }
        
        // Combine leading zeros and magnitude bytes
        var result = try std.ArrayList(u8).initCapacity(allocator, leading_zeros + magnitude_bytes.len);
        defer result.deinit();
        
        try result.appendNTimes(0, leading_zeros);
        try result.appendSlice(magnitude_bytes);
        
        return try result.toOwnedSlice();
    }
    
    /// Calculate checksum (equivalent to Swift calculateChecksum)
    fn calculateChecksum(input: []const u8, allocator: std.mem.Allocator) ![]u8 {
        // Double SHA256
        var first_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(input, &first_hash);
        
        var second_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&first_hash, &second_hash);
        
        // Return first 4 bytes
        return try allocator.dupe(u8, second_hash[0..CHECKSUM_LENGTH]);
    }
    
    /// Convert bytes to big integer
    fn bytesToBigInt(bytes: []const u8, allocator: std.mem.Allocator) !std.math.big.int.Managed {
        var result = try std.math.big.int.Managed.initSet(allocator, 0);
        
        var base = try std.math.big.int.Managed.initSet(allocator, 1);
        defer base.deinit();
        
        const multiplier = try std.math.big.int.Managed.initSet(allocator, 256);
        defer multiplier.deinit();
        
        var i: usize = bytes.len;
        while (i > 0) {
            i -= 1;
            
            var term = try std.math.big.int.Managed.initSet(allocator, bytes[i]);
            defer term.deinit();
            
            try term.mul(&term, &base);
            try result.add(&result, &term);
            try base.mul(&base, &multiplier);
        }
        
        return result;
    }
    
    /// Convert big integer to bytes
    fn bigIntToBytes(big_int: *const std.math.big.int.Managed, allocator: std.mem.Allocator) ![]u8 {
        if (big_int.eqZero()) {
            return try allocator.dupe(u8, &[_]u8{0});
        }
        
        var result = std.ArrayList(u8).init(allocator);
        defer result.deinit();
        
        var temp = try std.math.big.int.Managed.init(allocator);
        defer temp.deinit();
        try temp.copy(big_int.toConst());
        
        const divisor = try std.math.big.int.Managed.initSet(allocator, 256);
        defer divisor.deinit();
        
        var quotient = try std.math.big.int.Managed.init(allocator);
        defer quotient.deinit();
        
        var remainder = try std.math.big.int.Managed.init(allocator);
        defer remainder.deinit();
        
        while (!temp.eqZero()) {
            try std.math.big.int.Managed.divFloor(&quotient, &remainder, &temp, &divisor);
            
            const remainder_byte = remainder.to(u8) catch 0;
            try result.insert(0, remainder_byte);
            
            try temp.copy(quotient.toConst());
        }
        
        return try result.toOwnedSlice();
    }
};

// Tests (converted from Swift Base58 tests)
test "Base58 encode/decode basic" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test basic encoding (equivalent to Swift encode tests)
    const test_bytes = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
    const encoded = try Base58.encode(&test_bytes, allocator);
    defer allocator.free(encoded);
    
    try testing.expect(encoded.len > 0);
    
    // Test decoding
    const decoded = (try Base58.decode(encoded, allocator)).?;
    defer allocator.free(decoded);
    
    try testing.expectEqualSlices(u8, &test_bytes, decoded);
}

test "Base58 empty input handling" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test empty encoding
    const empty_encoded = try Base58.encode(&[_]u8{}, allocator);
    defer allocator.free(empty_encoded);
    
    try testing.expectEqualStrings("", empty_encoded);
    
    // Test empty decoding
    const empty_decoded = (try Base58.decode("", allocator)).?;
    defer allocator.free(empty_decoded);
    
    try testing.expectEqual(@as(usize, 0), empty_decoded.len);
}

test "Base58Check encode/decode" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test Base58Check encoding/decoding (equivalent to Swift base58CheckEncode/decode tests)
    const test_bytes = [_]u8{ 0x21, 0x03, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc };
    
    const encoded = try Base58.base58CheckEncode(&test_bytes, allocator);
    defer allocator.free(encoded);
    
    try testing.expect(encoded.len > 0);
    
    // Test decoding
    const decoded = (try Base58.base58CheckDecode(encoded, allocator)).?;
    defer allocator.free(decoded);
    
    try testing.expectEqualSlices(u8, &test_bytes, decoded);
}

test "Base58Check invalid checksum" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test invalid Base58Check (equivalent to Swift invalid checksum tests)
    const invalid_result = try Base58.base58CheckDecode("invalid", allocator);
    try testing.expect(invalid_result == null);
}

test "Base58 leading zeros" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test leading zeros handling (equivalent to Swift leading zeros tests)
    const test_bytes = [_]u8{ 0x00, 0x00, 0x01, 0x02 };
    
    const encoded = try Base58.encode(&test_bytes, allocator);
    defer allocator.free(encoded);
    
    const decoded = (try Base58.decode(encoded, allocator)).?;
    defer allocator.free(decoded);
    
    try testing.expectEqualSlices(u8, &test_bytes, decoded);
}