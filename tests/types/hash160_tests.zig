//! Hash160 Tests
//!
//! Complete conversion from NeoSwift Hash160Tests.swift
//! Tests Hash160 creation, validation, serialization, and operations.

const std = @import("std");
const testing = std.testing;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;
const BinaryWriter = @import("../../src/serialization/binary_writer_complete.zig").CompleteBinaryWriter;
const BinaryReader = @import("../../src/serialization/binary_reader_complete.zig").CompleteBinaryReader;
const errors = @import("../../src/core/errors.zig");

/// Test creating Hash160 from valid hash strings (converted from Swift testFromValidHash)
test "Hash160 from valid hash strings" {
    const allocator = testing.allocator;
    
    // Test hash creation with 0x prefix (equivalent to Swift Hash160("0x...") test)
    const hash_with_prefix = try Hash160.initWithString("0x23ba2703c53263e8d6e522dc32203339dcd8eee9");
    const hash_string_with_prefix = try hash_with_prefix.toString(allocator);
    defer allocator.free(hash_string_with_prefix);
    
    // Should strip 0x prefix in output
    const expected_without_prefix = "23ba2703c53263e8d6e522dc32203339dcd8eee9";
    const actual_without_prefix = if (std.mem.startsWith(u8, hash_string_with_prefix, "0x"))
        hash_string_with_prefix[2..]
    else
        hash_string_with_prefix;
    
    try testing.expectEqualStrings(expected_without_prefix, actual_without_prefix);
    
    // Test hash creation without 0x prefix (equivalent to Swift Hash160("...") test)
    const hash_without_prefix = try Hash160.initWithString("23ba2703c53263e8d6e522dc32203339dcd8eee9");
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

/// Test Hash160 creation error conditions (converted from Swift testCreationThrows)
test "Hash160 creation error conditions" {
    const allocator = testing.allocator;
    
    // Test invalid hex characters (equivalent to Swift "String argument is not hexadecimal" errors)
    const invalid_hex_cases = [_][]const u8{
        "g3ba2703c53263e8d6e522dc32203339dcd8eee9", // Invalid hex character 'g'
        "0x23ba2703c53263e8d6e522dc32203339dcd8eee", // Too short (19 bytes)
        "23ba2703c53263e8d6e522dc32203339dcd8ee",    // Too short without prefix
    };
    
    for (invalid_hex_cases) |invalid_hex| {
        try testing.expectError(
            anyerror, // Could be InvalidHex or InvalidLength
            Hash160.initWithString(invalid_hex)
        );
    }
    
    // Test wrong length cases (equivalent to Swift "Hash must be 20 bytes long" errors)
    const wrong_length_cases = [_][]const u8{
        "23ba2703c53263e8d6e522dc32203339dcd8ee",   // 19 bytes
        "c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b", // 32 bytes (Hash256 length)
    };
    
    for (wrong_length_cases) |wrong_length| {
        try testing.expectError(
            errors.ValidationError.InvalidLength,
            Hash160.initWithString(wrong_length)
        );
    }
}

/// Test Hash160 array conversion (converted from Swift testToArray)
test "Hash160 array conversion" {
    const allocator = testing.allocator;
    
    // Test toLittleEndianArray (equivalent to Swift toLittleEndianArray)
    const hash_string = "23ba2703c53263e8d6e522dc32203339dcd8eee9";
    const hash160 = try Hash160.initWithString(hash_string);
    
    // Get little-endian array
    const little_endian_array = hash160.toLittleEndianArray();
    
    // Convert expected bytes (equivalent to Swift bytesFromHex.reversed())
    const expected_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(hash_string, allocator);
    defer allocator.free(expected_bytes);
    
    // Reverse for little-endian
    var expected_reversed = try allocator.dupe(u8, expected_bytes);
    defer allocator.free(expected_reversed);
    std.mem.reverse(u8, expected_reversed);
    
    // Verify little-endian conversion
    try testing.expectEqualSlices(u8, expected_reversed, &little_endian_array);
    
    // Test toSlice() method
    const slice_array = hash160.toSlice();
    try testing.expectEqualSlices(u8, expected_bytes, slice_array);
}

/// Test Hash160 serialization and deserialization (converted from Swift testSerializeAndDeserialize)
test "Hash160 serialization and deserialization" {
    const allocator = testing.allocator;
    
    // Test serialization (equivalent to Swift serialize test)
    const hash_string = "23ba2703c53263e8d6e522dc32203339dcd8eee9";
    const hash160 = try Hash160.initWithString(hash_string);
    
    // Create binary writer (equivalent to Swift BinaryWriter())
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    // Serialize hash (equivalent to Swift .serialize(writer))
    try hash160.serialize(&writer);
    
    const serialized_data = writer.toArray();
    
    // Expected data is little-endian bytes (equivalent to Swift data.reversed())
    const expected_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(hash_string, allocator);
    defer allocator.free(expected_bytes);
    
    var expected_little_endian = try allocator.dupe(u8, expected_bytes);
    defer allocator.free(expected_little_endian);
    std.mem.reverse(u8, expected_little_endian);
    
    // Verify serialized data matches expected (equivalent to Swift XCTAssertEqual(writer.toArray(), data))
    try testing.expectEqualSlices(u8, expected_little_endian, serialized_data);
    
    // Test deserialization (equivalent to Swift Hash160.from(data))
    var reader = BinaryReader.init(serialized_data);
    const deserialized_hash = try Hash160.deserialize(&reader);
    
    // Verify deserialized hash matches original (equivalent to Swift XCTAssertEqual)
    try testing.expect(hash160.eql(deserialized_hash));
    
    const deserialized_string = try deserialized_hash.toString(allocator);
    defer allocator.free(deserialized_string);
    
    const actual_string = if (std.mem.startsWith(u8, deserialized_string, "0x"))
        deserialized_string[2..]
    else
        deserialized_string;
    
    try testing.expectEqualStrings(hash_string, actual_string);
}

/// Test Hash160 equality and hashing
test "Hash160 equality and hashing" {
    const allocator = testing.allocator;
    
    // Create identical hashes
    const hash1 = try Hash160.initWithString("23ba2703c53263e8d6e522dc32203339dcd8eee9");
    const hash2 = try Hash160.initWithString("0x23ba2703c53263e8d6e522dc32203339dcd8eee9");
    
    // Create different hash
    const hash3 = try Hash160.initWithString("969a77db482f74ce27105f760efa139223431394");
    
    // Test equality
    try testing.expect(hash1.eql(hash2)); // Same hash with/without prefix
    try testing.expect(!hash1.eql(hash3)); // Different hashes
    
    // Test hashing
    const hash_value1 = hash1.hash();
    const hash_value2 = hash2.hash();
    const hash_value3 = hash3.hash();
    
    try testing.expectEqual(hash_value1, hash_value2); // Same hashes should have same hash value
    try testing.expectNotEqual(hash_value1, hash_value3); // Different hashes should have different hash values
}

/// Test Hash160 validation
test "Hash160 validation" {
    const allocator = testing.allocator;
    
    // Test valid hash validation
    const valid_hash = try Hash160.initWithString("23ba2703c53263e8d6e522dc32203339dcd8eee9");
    try valid_hash.validate();
    
    // Test zero hash validation (should be valid)
    const zero_hash = Hash160.ZERO;
    try zero_hash.validate();
    
    // Verify zero hash properties
    try testing.expect(zero_hash.isZero());
    
    const zero_string = try zero_hash.toString(allocator);
    defer allocator.free(zero_string);
    
    const zero_without_prefix = if (std.mem.startsWith(u8, zero_string, "0x"))
        zero_string[2..]
    else
        zero_string;
    
    // Should be all zeros
    try testing.expectEqualStrings("0000000000000000000000000000000000000000", zero_without_prefix);
}

/// Test Hash160 utility methods
test "Hash160 utility methods" {
    const allocator = testing.allocator;
    
    // Test from script hash creation
    const test_script = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const script_hash = try Hash160.fromScript(&test_script);
    
    try script_hash.validate();
    try testing.expect(!script_hash.isZero());
    
    // Test address conversion
    const address = try script_hash.toAddress(allocator);
    defer allocator.free(address);
    
    try testing.expect(address.len > 0);
    try testing.expect(address.len >= 25); // Neo addresses are typically 34 characters
    
    // Test format output
    const formatted = try script_hash.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "Hash160") != null);
}

/// Test Hash160 comparison operations
test "Hash160 comparison operations" {
    const allocator = testing.allocator;
    
    // Test comparison with different hashes
    const hash_a = try Hash160.initWithString("0000000000000000000000000000000000000001");
    const hash_b = try Hash160.initWithString("0000000000000000000000000000000000000002");
    const hash_c = try Hash160.initWithString("ffffffffffffffffffffffffffffffffffffffff");
    
    // Test ordering
    try testing.expect(hash_a.compare(hash_b) < 0); // a < b
    try testing.expect(hash_b.compare(hash_a) > 0); // b > a
    try testing.expect(hash_a.compare(hash_a) == 0); // a == a
    try testing.expect(hash_a.compare(hash_c) < 0); // a < c
    try testing.expect(hash_c.compare(hash_a) > 0); // c > a
}

/// Test Hash160 clone and copy operations
test "Hash160 clone and copy operations" {
    const allocator = testing.allocator;
    
    // Test cloning
    const original_hash = try Hash160.initWithString("23ba2703c53263e8d6e522dc32203339dcd8eee9");
    const cloned_hash = original_hash.clone();
    
    // Should be equal but independent
    try testing.expect(original_hash.eql(cloned_hash));
    
    // Test that they have the same string representation
    const original_string = try original_hash.toString(allocator);
    defer allocator.free(original_string);
    
    const cloned_string = try cloned_hash.toString(allocator);
    defer allocator.free(cloned_string);
    
    try testing.expectEqualStrings(original_string, cloned_string);
}