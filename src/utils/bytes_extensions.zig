//! Bytes Extensions
//!
//! Complete conversion from NeoSwift Bytes.swift extensions
//! Provides all Swift bytes utility methods and conversions.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;

/// Bytes utility functions (converted from Swift Bytes extensions)
pub const BytesUtils = struct {
    /// Converts bytes to big integer (equivalent to Swift .bInt property)
    pub fn toBigInt(bytes: []const u8) u256 {
        if (bytes.len == 0) return 0;
        
        var result: u256 = 0;
        for (bytes) |byte| {
            result = (result << 8) | byte;
        }
        return result;
    }
    
    /// Creates bytes from big integer (utility method)
    pub fn fromBigInt(value: u256, allocator: std.mem.Allocator) ![]u8 {
        if (value == 0) return try allocator.dupe(u8, &[_]u8{0});
        
        var bytes = std.ArrayList(u8).init(allocator);
        defer bytes.deinit();
        
        var temp_value = value;
        while (temp_value > 0) {
            try bytes.append(@intCast(temp_value & 0xFF));
            temp_value >>= 8;
        }
        
        // Reverse to get big-endian order
        const result = try bytes.toOwnedSlice();
        std.mem.reverse(u8, result);
        return result;
    }
    
    /// Base64 encoding (equivalent to Swift .base64Encoded property)
    pub fn base64Encoded(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const encoder = std.base64.standard.Encoder;
        const encoded_len = encoder.calcSize(bytes.len);
        
        const result = try allocator.alloc(u8, encoded_len);
        _ = encoder.encode(result, bytes);
        
        return result;
    }
    
    /// Base64 decoding (utility method)
    pub fn base64Decoded(encoded: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const decoder = std.base64.standard.Decoder;
        const decoded_len = try decoder.calcSizeForSlice(encoded);
        
        const result = try allocator.alloc(u8, decoded_len);
        try decoder.decode(result, encoded);
        
        return result;
    }
    
    /// Base58 encoding (equivalent to Swift .base58Encoded property)
    pub fn base58Encoded(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const base58 = @import("base58.zig");
        return try base58.encode(bytes, allocator);
    }
    
    /// Base58Check encoding (equivalent to Swift .base58CheckEncoded property)
    pub fn base58CheckEncoded(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const base58 = @import("base58.zig");
        return try base58.encodeCheck(bytes, allocator);
    }
    
    /// Hex string without prefix (equivalent to Swift .noPrefixHex property)
    pub fn noPrefixHex(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const hex_string = try @import("bytes.zig").toHex(bytes, allocator);
        defer allocator.free(hex_string);
        
        const cleaned = @import("string_extensions.zig").StringUtils.cleanedHexPrefix(hex_string);
        return try allocator.dupe(u8, cleaned);
    }
    
    /// Variable size calculation (equivalent to Swift .varSize property)
    pub fn varSize(bytes: []const u8) usize {
        const count = bytes.len;
        return @import("numeric_extensions.zig").IntUtils.varSize(@intCast(count)) + count;
    }
    
    /// Script hash to address conversion (equivalent to Swift .scripthashToAddress property)
    pub fn scripthashToAddress(script_hash: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (script_hash.len != 20) {
            return errors.throwIllegalArgument("Script hash must be 20 bytes");
        }
        
        // Create payload: version + reversed script hash
        var payload: [21]u8 = undefined;
        payload[0] = constants.AddressConstants.ADDRESS_VERSION;
        
        // Reverse the script hash (Swift uses reversed())
        var i: usize = 0;
        while (i < 20) : (i += 1) {
            payload[i + 1] = script_hash[19 - i];
        }
        
        // Calculate checksum (first 4 bytes of double SHA256)
        const hash1 = Hash256.sha256(&payload);
        const hash2 = Hash256.sha256(hash1.toSlice());
        const checksum = hash2.toSlice()[0..4];
        
        // Combine payload + checksum
        var full_payload: [25]u8 = undefined;
        @memcpy(full_payload[0..21], &payload);
        @memcpy(full_payload[21..25], checksum);
        
        // Encode with Base58
        return try base58Encoded(&full_payload, allocator);
    }
    
    /// Pads bytes to specified length (equivalent to Swift toPadded)
    pub fn toPadded(bytes: []const u8, length: usize, trailing: bool, allocator: std.mem.Allocator) ![]u8 {
        // Handle leading zero removal (Swift logic)
        const first_zero = bytes.len > 0 and bytes[0] == 0;
        const src_offset: usize = if (first_zero) 1 else 0;
        const bytes_length = bytes.len - src_offset;
        
        if (bytes_length > length) {
            return errors.throwIllegalArgument("Input too large for byte array");
        }
        
        var result = try allocator.alloc(u8, length);
        
        if (trailing) {
            // Pad at end
            @memcpy(result[0..bytes_length], bytes[src_offset..]);
            @memset(result[bytes_length..], 0);
        } else {
            // Pad at beginning
            const padding = length - bytes_length;
            @memset(result[0..padding], 0);
            @memcpy(result[padding..], bytes[src_offset..]);
        }
        
        return result;
    }
    
    /// Trims trailing bytes (equivalent to Swift trimTrailingBytes)
    pub fn trimTrailingBytes(bytes: []const u8, byte_to_trim: u8, allocator: std.mem.Allocator) ![]u8 {
        var end = bytes.len;
        while (end > 0 and bytes[end - 1] == byte_to_trim) {
            end -= 1;
        }
        
        if (end == 0) {
            return try allocator.dupe(u8, &[_]u8{byte_to_trim});
        }
        
        return try allocator.dupe(u8, bytes[0..end]);
    }
    
    /// Trims leading bytes (utility method)
    pub fn trimLeadingBytes(bytes: []const u8, byte_to_trim: u8, allocator: std.mem.Allocator) ![]u8 {
        var start: usize = 0;
        while (start < bytes.len and bytes[start] == byte_to_trim) {
            start += 1;
        }
        
        if (start == bytes.len) {
            return try allocator.dupe(u8, &[_]u8{byte_to_trim});
        }
        
        return try allocator.dupe(u8, bytes[start..]);
    }
    
    /// Reverses bytes (equivalent to Swift .reversed())
    pub fn reversed(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        var result = try allocator.dupe(u8, bytes);
        std.mem.reverse(u8, result);
        return result;
    }
    
    /// Converts bytes to hex string (equivalent to Swift .toHexString())
    pub fn toHexString(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(bytes)});
    }
    
    /// Checks if bytes are all zeros
    pub fn isZero(bytes: []const u8) bool {
        for (bytes) |byte| {
            if (byte != 0) return false;
        }
        return true;
    }
    
    /// Checks if bytes are all ones (0xFF)
    pub fn isMaxValue(bytes: []const u8) bool {
        for (bytes) |byte| {
            if (byte != 0xFF) return false;
        }
        return true;
    }
    
    /// XOR operation on two byte arrays
    pub fn xor(a: []const u8, b: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (a.len != b.len) {
            return errors.ValidationError.InvalidParameter;
        }
        
        var result = try allocator.alloc(u8, a.len);
        
        for (a, b, 0..) |byte_a, byte_b, i| {
            result[i] = byte_a ^ byte_b;
        }
        
        return result;
    }
    
    /// Concatenates multiple byte arrays
    pub fn concatenate(arrays: []const []const u8, allocator: std.mem.Allocator) ![]u8 {
        var total_length: usize = 0;
        for (arrays) |array| {
            total_length += array.len;
        }
        
        var result = try allocator.alloc(u8, total_length);
        var pos: usize = 0;
        
        for (arrays) |array| {
            @memcpy(result[pos..pos + array.len], array);
            pos += array.len;
        }
        
        return result;
    }
};

// Tests (converted from Swift Bytes extension tests)
test "BytesUtils big integer conversion" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test bytes to big integer (equivalent to Swift .bInt tests)
    const test_bytes = [_]u8{ 0x01, 0x23, 0x45, 0x67 };
    const big_int = BytesUtils.toBigInt(&test_bytes);
    try testing.expectEqual(@as(u256, 0x01234567), big_int);
    
    // Test big integer to bytes
    const bytes_from_int = try BytesUtils.fromBigInt(0x01234567, allocator);
    defer allocator.free(bytes_from_int);
    
    try testing.expectEqualSlices(u8, &test_bytes, bytes_from_int);
    
    // Test zero case
    const zero_bytes = [_]u8{0x00, 0x00, 0x00};
    try testing.expectEqual(@as(u256, 0), BytesUtils.toBigInt(&zero_bytes));
    
    const zero_from_int = try BytesUtils.fromBigInt(0, allocator);
    defer allocator.free(zero_from_int);
    try testing.expectEqualSlices(u8, &[_]u8{0}, zero_from_int);
}

test "BytesUtils encoding operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const test_data = "Hello Neo Blockchain";
    
    // Test Base64 encoding (equivalent to Swift .base64Encoded tests)
    const base64_encoded = try BytesUtils.base64Encoded(test_data, allocator);
    defer allocator.free(base64_encoded);
    
    const base64_decoded = try BytesUtils.base64Decoded(base64_encoded, allocator);
    defer allocator.free(base64_decoded);
    
    try testing.expectEqualStrings(test_data, base64_decoded);
    
    // Test Base58 encoding (equivalent to Swift .base58Encoded tests)
    const base58_encoded = try BytesUtils.base58Encoded(test_data, allocator);
    defer allocator.free(base58_encoded);
    
    try testing.expect(base58_encoded.len > 0);
    
    // Test Base58Check encoding (equivalent to Swift .base58CheckEncoded tests)
    const base58_check_encoded = try BytesUtils.base58CheckEncoded(test_data, allocator);
    defer allocator.free(base58_check_encoded);
    
    try testing.expect(base58_check_encoded.len > 0);
    try testing.expect(base58_check_encoded.len > base58_encoded.len); // Should be longer due to checksum
}

test "BytesUtils hex operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test hex conversion (equivalent to Swift hex tests)
    const test_bytes = [_]u8{ 0xAB, 0xCD, 0xEF };
    
    const hex_string = try BytesUtils.toHexString(&test_bytes, allocator);
    defer allocator.free(hex_string);
    try testing.expectEqualStrings("abcdef", hex_string);
    
    const no_prefix_hex = try BytesUtils.noPrefixHex(&test_bytes, allocator);
    defer allocator.free(no_prefix_hex);
    try testing.expectEqualStrings("abcdef", no_prefix_hex);
}

test "BytesUtils padding operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test padding (equivalent to Swift toPadded tests)
    const short_bytes = [_]u8{ 0x12, 0x34 };
    
    // Test leading padding (default)
    const padded_leading = try BytesUtils.toPadded(&short_bytes, 5, false, allocator);
    defer allocator.free(padded_leading);
    
    const expected_leading = [_]u8{ 0x00, 0x00, 0x00, 0x12, 0x34 };
    try testing.expectEqualSlices(u8, &expected_leading, padded_leading);
    
    // Test trailing padding
    const padded_trailing = try BytesUtils.toPadded(&short_bytes, 5, true, allocator);
    defer allocator.free(padded_trailing);
    
    const expected_trailing = [_]u8{ 0x12, 0x34, 0x00, 0x00, 0x00 };
    try testing.expectEqualSlices(u8, &expected_trailing, padded_trailing);
    
    // Test error case (input too large)
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        BytesUtils.toPadded(&short_bytes, 1, false, allocator)
    );
}

test "BytesUtils trimming operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test trailing byte trimming (equivalent to Swift trimTrailingBytes tests)
    const bytes_with_trailing = [_]u8{ 0x12, 0x34, 0x00, 0x00, 0x00 };
    const trimmed_trailing = try BytesUtils.trimTrailingBytes(&bytes_with_trailing, 0x00, allocator);
    defer allocator.free(trimmed_trailing);
    
    const expected_trimmed = [_]u8{ 0x12, 0x34 };
    try testing.expectEqualSlices(u8, &expected_trimmed, trimmed_trailing);
    
    // Test leading byte trimming
    const bytes_with_leading = [_]u8{ 0x00, 0x00, 0x12, 0x34 };
    const trimmed_leading = try BytesUtils.trimLeadingBytes(&bytes_with_leading, 0x00, allocator);
    defer allocator.free(trimmed_leading);
    
    try testing.expectEqualSlices(u8, &expected_trimmed, trimmed_leading);
    
    // Test all same bytes
    const all_zeros = [_]u8{ 0x00, 0x00, 0x00 };
    const trimmed_all_zeros = try BytesUtils.trimTrailingBytes(&all_zeros, 0x00, allocator);
    defer allocator.free(trimmed_all_zeros);
    
    try testing.expectEqualSlices(u8, &[_]u8{0x00}, trimmed_all_zeros);
}

test "BytesUtils script hash to address" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test script hash to address conversion (equivalent to Swift .scripthashToAddress tests)
    const test_script_hash = [_]u8{0x01, 0x02, 0x03, 0x04, 0x05} ++ [_]u8{0x06, 0x07, 0x08, 0x09, 0x0A} ++ [_]u8{0x0B, 0x0C, 0x0D, 0x0E, 0x0F} ++ [_]u8{0x10, 0x11, 0x12, 0x13, 0x14};
    
    const address = try BytesUtils.scripthashToAddress(&test_script_hash, allocator);
    defer allocator.free(address);
    
    try testing.expect(address.len > 0);
    
    // Test invalid script hash length
    const invalid_script_hash = [_]u8{ 0x01, 0x02, 0x03 }; // Too short
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        BytesUtils.scripthashToAddress(&invalid_script_hash, allocator)
    );
}

test "BytesUtils utility operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test byte reversal
    const original = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const reversed_bytes = try BytesUtils.reversed(&original, allocator);
    defer allocator.free(reversed_bytes);
    
    const expected_reversed = [_]u8{ 0x04, 0x03, 0x02, 0x01 };
    try testing.expectEqualSlices(u8, &expected_reversed, reversed_bytes);
    
    // Test XOR operation
    const a = [_]u8{ 0xF0, 0xF0, 0xF0 };
    const b = [_]u8{ 0x0F, 0x0F, 0x0F };
    const xor_result = try BytesUtils.xor(&a, &b, allocator);
    defer allocator.free(xor_result);
    
    const expected_xor = [_]u8{ 0xFF, 0xFF, 0xFF };
    try testing.expectEqualSlices(u8, &expected_xor, xor_result);
    
    // Test concatenation
    const array1 = [_]u8{ 0x01, 0x02 };
    const array2 = [_]u8{ 0x03, 0x04 };
    const arrays = [_][]const u8{ &array1, &array2 };
    
    const concatenated = try BytesUtils.concatenate(&arrays, allocator);
    defer allocator.free(concatenated);
    
    const expected_concat = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try testing.expectEqualSlices(u8, &expected_concat, concatenated);
    
    // Test utility checks
    const zero_bytes = [_]u8{ 0x00, 0x00, 0x00 };
    try testing.expect(BytesUtils.isZero(&zero_bytes));
    try testing.expect(!BytesUtils.isZero(&original));
    
    const max_bytes = [_]u8{ 0xFF, 0xFF, 0xFF };
    try testing.expect(BytesUtils.isMaxValue(&max_bytes));
    try testing.expect(!BytesUtils.isMaxValue(&original));
}

test "BytesUtils variable size calculation" {
    const testing = std.testing;
    
    // Test variable size calculation (equivalent to Swift .varSize tests)
    const small_bytes = [_]u8{ 0x01, 0x02, 0x03 };
    const small_var_size = BytesUtils.varSize(&small_bytes);
    try testing.expect(small_var_size >= 4); // 1 byte length + 3 bytes data
    
    const medium_bytes = [_]u8{0} ** 300;
    const medium_var_size = BytesUtils.varSize(&medium_bytes);
    try testing.expect(medium_var_size >= 303); // 3 bytes length + 300 bytes data
    
    const large_bytes = [_]u8{0} ** 70000;
    const large_var_size = BytesUtils.varSize(&large_bytes);
    try testing.expect(large_var_size >= 70005); // 5 bytes length + 70000 bytes data
}