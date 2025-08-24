//! Hash256 Tests
//!
//! Complete conversion from NeoSwift Hash256Tests.swift
//! Tests Hash256 creation, validation, and operations.

const std = @import("std");
const testing = std.testing;
const Hash256 = @import("../../src/types/hash256.zig").Hash256;
const errors = @import("../../src/core/errors.zig");

/// Test creating Hash256 from valid hash strings (converted from Swift testFromValidHash)
test "Hash256 from valid hash strings" {
    const allocator = testing.allocator;
    
    // Test hash creation with 0x prefix (equivalent to Swift Hash256("0x...") test)
    const hash_with_prefix = try Hash256.initWithString("0xb804a98220c69ab4674e97142beeeb00909113d417b9d6a67c12b71a3974a21a");
    const hash_string_with_prefix = try hash_with_prefix.toString(allocator);
    defer allocator.free(hash_string_with_prefix);
    
    // Should strip 0x prefix in output
    const expected_without_prefix = "b804a98220c69ab4674e97142beeeb00909113d417b9d6a67c12b71a3974a21a";
    const actual_without_prefix = if (std.mem.startsWith(u8, hash_string_with_prefix, "0x"))
        hash_string_with_prefix[2..]
    else
        hash_string_with_prefix;
    
    try testing.expectEqualStrings(expected_without_prefix, actual_without_prefix);
    
    // Test hash creation without 0x prefix (equivalent to Swift Hash256("...") test)
    const hash_without_prefix = try Hash256.initWithString("b804a98220c69ab4674e97142beeeb00909113d417b9d6a67c12b71a3974a21a");
    const hash_string_without_prefix = try hash_without_prefix.toString(allocator);
    defer allocator.free(hash_string_without_prefix);
    
    const actual_without_prefix2 = if (std.mem.startsWith(u8, hash_string_without_prefix, "0x"))
        hash_string_without_prefix[2..]
    else
        hash_string_without_prefix;
    
    try testing.expectEqualStrings(expected_without_prefix, actual_without_prefix2);
    
    // Both hashes should be equal
    try testing.expect(hash_with_prefix.eql(hash_without_prefix));
}

/// Test Hash256 creation error conditions (converted from Swift testCreationThrows)
test "Hash256 creation error conditions" {
    const allocator = testing.allocator;
    
    // Test invalid hex characters (equivalent to Swift "String argument is not hexadecimal" errors)
    const invalid_hex_cases = [_][]const u8{
        "g804a98220c69ab4674e97142beeeb00909113d417b9d6a67c12b71a3974a21a", // Invalid hex character 'g'
        "b804a98220c69ab4674e97142beeeb00909113d417b9d6a67c12b71a3974a21ae", // Odd length
    };
    
    for (invalid_hex_cases) |invalid_hex| {
        try testing.expectError(
            anyerror, // Could be InvalidHex or InvalidLength
            Hash256.initWithString(invalid_hex)
        );
    }
    
    // Test wrong length cases (equivalent to Swift "Hash must be 32 bytes long" errors)
    const wrong_length_cases = [_][]const u8{
        "0xb804a98220c69ab4674e97142beeeb00909113d417b9d6a67c12b71a3974a2",     // 31 bytes
        "0xb804a98220c69ab4674e97142beeeb00909113d417b9d6a67c12b71a3974a21a12", // 33 bytes
    };
    
    for (wrong_length_cases) |wrong_length| {
        try testing.expectError(
            errors.ValidationError.InvalidLength,
            Hash256.initWithString(wrong_length)
        );
    }
}

/// Test Hash256 array operations
test "Hash256 array operations" {
    const allocator = testing.allocator;
    
    // Test Hash256 array conversion
    const hash_string = "b804a98220c69ab4674e97142beeeb00909113d417b9d6a67c12b71a3974a21a";
    const hash256 = try Hash256.initWithString(hash_string);
    
    // Get array representation
    const hash_array = hash256.toSlice();
    try testing.expectEqual(@as(usize, 32), hash_array.len);
    
    // Test little-endian array
    const little_endian_array = hash256.toLittleEndianArray();
    try testing.expectEqual(@as(usize, 32), little_endian_array.len);
    
    // Little-endian should be reverse of big-endian
    var expected_little_endian = try allocator.dupe(u8, hash_array);
    defer allocator.free(expected_little_endian);
    std.mem.reverse(u8, expected_little_endian);
    
    try testing.expectEqualSlices(u8, expected_little_endian, &little_endian_array);
}

/// Test Hash256 serialization
test "Hash256 serialization" {
    const allocator = testing.allocator;
    
    // Test Hash256 serialization
    const hash_string = "b804a98220c69ab4674e97142beeeb00909113d417b9d6a67c12b71a3974a21a";
    const hash256 = try Hash256.initWithString(hash_string);
    
    // Create binary writer
    var writer = @import("../../src/serialization/binary_writer_complete.zig").CompleteBinaryWriter.init(allocator);
    defer writer.deinit();
    
    // Serialize hash
    try hash256.serialize(&writer);
    
    const serialized_data = writer.toArray();
    try testing.expectEqual(@as(usize, 32), serialized_data.len);
    
    // Test deserialization
    var reader = @import("../../src/serialization/binary_reader_complete.zig").CompleteBinaryReader.init(serialized_data);
    const deserialized_hash = try Hash256.deserialize(&reader);
    
    // Should match original
    try testing.expect(hash256.eql(deserialized_hash));
}

/// Test Hash256 hashing operations
test "Hash256 hashing operations" {
    const allocator = testing.allocator;
    
    // Test SHA256 hashing
    const test_data = "Hello, Neo blockchain!";
    const test_bytes = @as([]const u8, test_data);
    
    const hash_result = Hash256.sha256(test_bytes);
    try testing.expect(!hash_result.isZero());
    
    // Test double SHA256 (hash256)
    const double_hash = Hash256.hash256(test_bytes);
    try testing.expect(!double_hash.isZero());
    try testing.expect(!hash_result.eql(double_hash)); // Should be different
    
    // Test consistent hashing
    const hash_again = Hash256.sha256(test_bytes);
    try testing.expect(hash_result.eql(hash_again)); // Same input should give same result
}

/// Test Hash256 utility methods
test "Hash256 utility methods" {
    const allocator = testing.allocator;
    
    // Test zero hash
    const zero_hash = Hash256.ZERO;
    try testing.expect(zero_hash.isZero());
    
    const zero_string = try zero_hash.toString(allocator);
    defer allocator.free(zero_string);
    
    const zero_without_prefix = if (std.mem.startsWith(u8, zero_string, "0x"))
        zero_string[2..]
    else
        zero_string;
    
    // Should be 64 zero characters (32 bytes * 2 hex chars per byte)
    try testing.expectEqual(@as(usize, 64), zero_without_prefix.len);
    
    // All characters should be '0'
    for (zero_without_prefix) |char| {
        try testing.expectEqual(@as(u8, '0'), char);
    }
    
    // Test non-zero hash
    const non_zero_hash = try Hash256.initWithString("b804a98220c69ab4674e97142beeeb00909113d417b9d6a67c12b71a3974a21a");
    try testing.expect(!non_zero_hash.isZero());
    try testing.expect(!non_zero_hash.eql(zero_hash));
}