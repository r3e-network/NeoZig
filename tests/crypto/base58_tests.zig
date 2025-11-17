//! Base58 Tests
//!
//! Complete conversion from NeoSwift Base58Tests.swift
//! Tests Base58 and Base58Check encoding/decoding functionality.

const std = @import("std");


const testing = std.testing;
const Base58 = @import("../../src/crypto/base58.zig").Base58;

/// Test Base58 encoding for valid strings (converted from Swift testBase58EncodingForValidStrings)
test "Base58 encoding for valid strings" {
    const allocator = testing.allocator;
    
    // Test tuples (equivalent to Swift validStringDecodedToEncodedTuples)
    const test_cases = [_]struct {
        decoded: []const u8,
        encoded: []const u8,
    }{
        .{ .decoded = "", .encoded = "" },
        .{ .decoded = " ", .encoded = "Z" },
        .{ .decoded = "-", .encoded = "n" },
        .{ .decoded = "0", .encoded = "q" },
        .{ .decoded = "1", .encoded = "r" },
        .{ .decoded = "-1", .encoded = "4SU" },
        .{ .decoded = "11", .encoded = "4k8" },
        .{ .decoded = "abc", .encoded = "ZiCa" },
        .{ .decoded = "1234598760", .encoded = "3mJr7AoUXx2Wqd" },
        .{ .decoded = "abcdefghijklmnopqrstuvwxyz", .encoded = "3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f" },
    };
    
    for (test_cases) |case| {
        // Encode bytes (equivalent to Swift bytes.base58Encoded)
        const encoded_result = try Base58.encode(@as([]const u8, case.decoded), allocator);
        defer allocator.free(encoded_result);
        
        // Verify encoding (equivalent to Swift XCTAssertEqual)
        try testing.expectEqualStrings(case.encoded, encoded_result);
    }
}

/// Test Base58 decoding for valid strings (converted from Swift testBase58DecodingForValidStrings)
test "Base58 decoding for valid strings" {
    const allocator = testing.allocator;
    
    // Same test cases as encoding test
    const test_cases = [_]struct {
        decoded: []const u8,
        encoded: []const u8,
    }{
        .{ .decoded = "", .encoded = "" },
        .{ .decoded = " ", .encoded = "Z" },
        .{ .decoded = "-", .encoded = "n" },
        .{ .decoded = "0", .encoded = "q" },
        .{ .decoded = "1", .encoded = "r" },
        .{ .decoded = "-1", .encoded = "4SU" },
        .{ .decoded = "11", .encoded = "4k8" },
        .{ .decoded = "abc", .encoded = "ZiCa" },
        .{ .decoded = "1234598760", .encoded = "3mJr7AoUXx2Wqd" },
        .{ .decoded = "abcdefghijklmnopqrstuvwxyz", .encoded = "3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f" },
    };
    
    for (test_cases) |case| {
        // Decode string (equivalent to Swift encoded.base58Decoded)
        const decoded_result = (try Base58.decode(case.encoded, allocator)).?;
        defer allocator.free(decoded_result);
        
        // Verify decoding (equivalent to Swift XCTAssertEqual)
        try testing.expectEqualStrings(case.decoded, decoded_result);
    }
}

/// Test Base58 decoding for invalid strings (converted from Swift testBase58DecodingForInvalidStrings)
test "Base58 decoding for invalid strings" {
    const allocator = testing.allocator;
    
    // Invalid strings (equivalent to Swift invalidStrings array)
    const invalid_strings = [_][]const u8{
        "0",    // Invalid character
        "O",    // Invalid character
        "I",    // Invalid character
        "l",    // Invalid character
        "3mJr0", // Contains invalid character '0'
        "O3yxU", // Contains invalid character 'O'
        "3sNI",  // Contains invalid character 'I'
        "4kl8",  // Contains invalid character 'l'
        "0OIl",  // Multiple invalid characters
        "!@#$%^&*()-_=+~`", // Special characters
    };
    
    for (invalid_strings) |invalid_string| {
        // Should return null for invalid strings (equivalent to Swift XCTAssertNil)
        const result = try Base58.decode(invalid_string, allocator);
        try testing.expect(result == null);
    }
}

/// Test Base58Check encoding (converted from Swift testBase58CheckEncoding)
test "Base58Check encoding" {
    const allocator = testing.allocator;
    
    // Test data (equivalent to Swift inputData)
    const input_data = [_]u8{
        6, 161, 159, 136, 34, 110, 33, 238, 14, 79, 14, 218, 
        133, 13, 109, 40, 194, 236, 153, 44, 61, 157, 254
    };
    
    const expected_output = "tz1Y3qqTg9HdrzZGbEjiCPmwuZ7fWVxpPtRw";
    
    // Encode with checksum (equivalent to Swift base58CheckEncoded)
    const actual_output = try Base58.base58CheckEncode(&input_data, allocator);
    defer allocator.free(actual_output);
    
    // Verify encoding (equivalent to Swift XCTAssertEqual)
    try testing.expectEqualStrings(expected_output, actual_output);
}

/// Test Base58Check decoding (converted from Swift testBase58CheckDecoding)
test "Base58Check decoding" {
    const allocator = testing.allocator;
    
    // Test data (equivalent to Swift test)
    const input_string = "tz1Y3qqTg9HdrzZGbEjiCPmwuZ7fWVxpPtRw";
    const expected_output_data = [_]u8{
        6, 161, 159, 136, 34, 110, 33, 238, 14, 79, 14, 218,
        133, 13, 109, 40, 194, 236, 153, 44, 61, 157, 254
    };
    
    // Decode with checksum validation (equivalent to Swift base58CheckDecoded)
    const actual_output = (try Base58.base58CheckDecode(input_string, allocator)).?;
    defer allocator.free(actual_output);
    
    // Verify decoding (equivalent to Swift XCTAssertEqual)
    try testing.expectEqualSlices(u8, &expected_output_data, actual_output);
}

/// Test Base58Check decoding with invalid characters (converted from Swift testBase58CheckDecodingWithInvalidCharacters)
test "Base58Check decoding with invalid characters" {
    const allocator = testing.allocator;
    
    // Test string with invalid Base58 characters (equivalent to Swift "0oO1lL")
    const invalid_string = "0oO1lL";
    
    // Should return null for invalid characters (equivalent to Swift XCTAssertNil)
    const result = try Base58.base58CheckDecode(invalid_string, allocator);
    try testing.expect(result == null);
}

/// Test Base58Check decoding with invalid checksum (converted from Swift testBase58CheckDecodingWithInvalidChecksum)
test "Base58Check decoding with invalid checksum" {
    const allocator = testing.allocator;
    
    // Test string with corrupted checksum (equivalent to Swift modified string)
    const invalid_checksum_string = "tz1Y3qqTg9HdrzZGbEjiCPmwuZ7fWVxpPtrW"; // Last char changed
    
    // Should return null for invalid checksum (equivalent to Swift XCTAssertNil)
    const result = try Base58.base58CheckDecode(invalid_checksum_string, allocator);
    try testing.expect(result == null);
}

/// Test Base58 roundtrip encoding/decoding
test "Base58 roundtrip encoding and decoding" {
    const allocator = testing.allocator;
    
    // Test various byte arrays for roundtrip conversion
    const test_data = [_][]const u8{
        &[_]u8{},                                    // Empty
        &[_]u8{0},                                   // Single zero
        &[_]u8{255},                                 // Single max byte
        &[_]u8{ 1, 2, 3, 4, 5 },                    // Small array
        &[_]u8{ 0, 0, 1, 2, 3 },                    // Leading zeros
        &[_]u8{ 255, 254, 253, 252, 251, 250 },     // Large bytes
    };
    
    for (test_data) |original_data| {
        // Encode
        const encoded = try Base58.encode(original_data, allocator);
        defer allocator.free(encoded);
        
        // Decode
        const decoded = (try Base58.decode(encoded, allocator)).?;
        defer allocator.free(decoded);
        
        // Should match original
        try testing.expectEqualSlices(u8, original_data, decoded);
    }
}

/// Test Base58Check roundtrip encoding/decoding
test "Base58Check roundtrip encoding and decoding" {
    const allocator = testing.allocator;
    
    // Test various byte arrays for Base58Check roundtrip
    const test_data = [_][]const u8{
        &[_]u8{ 1, 2, 3, 4, 5 },
        &[_]u8{ 255, 254, 253 },
        &[_]u8{ 0, 1, 2, 3 },
        &[_]u8{ 42, 84, 126, 168, 210, 252 },
    };
    
    for (test_data) |original_data| {
        // Encode with checksum
        const encoded = try Base58.base58CheckEncode(original_data, allocator);
        defer allocator.free(encoded);
        
        // Decode with checksum validation
        const decoded = (try Base58.base58CheckDecode(encoded, allocator)).?;
        defer allocator.free(decoded);
        
        // Should match original
        try testing.expectEqualSlices(u8, original_data, decoded);
    }
}

/// Test Base58 edge cases
test "Base58 edge cases" {
    const allocator = testing.allocator;
    
    // Test very large numbers
    const large_data = [_]u8{255} ** 32; // 32 bytes of 0xFF
    
    const encoded_large = try Base58.encode(&large_data, allocator);
    defer allocator.free(encoded_large);
    
    try testing.expect(encoded_large.len > 0);
    
    const decoded_large = (try Base58.decode(encoded_large, allocator)).?;
    defer allocator.free(decoded_large);
    
    try testing.expectEqualSlices(u8, &large_data, decoded_large);
    
    // Test leading zeros preservation
    const leading_zeros_data = [_]u8{ 0, 0, 0, 1, 2, 3 };
    
    const encoded_zeros = try Base58.encode(&leading_zeros_data, allocator);
    defer allocator.free(encoded_zeros);
    
    const decoded_zeros = (try Base58.decode(encoded_zeros, allocator)).?;
    defer allocator.free(decoded_zeros);
    
    try testing.expectEqualSlices(u8, &leading_zeros_data, decoded_zeros);
}

/// Test Base58 performance characteristics
test "Base58 performance characteristics" {
    const allocator = testing.allocator;
    
    // Test encoding/decoding performance with reasonable data
    const test_data = [_]u8{42} ** 1000; // 1KB of data
    
    const start_time = std.time.milliTimestamp();
    
    const encoded = try Base58.encode(&test_data, allocator);
    defer allocator.free(encoded);
    
    const encoded_time = std.time.milliTimestamp() - start_time;
    
    const decode_start = std.time.milliTimestamp();
    
    const decoded = (try Base58.decode(encoded, allocator)).?;
    defer allocator.free(decoded);
    
    const decoded_time = std.time.milliTimestamp() - decode_start;
    
    // Verify correctness
    try testing.expectEqualSlices(u8, &test_data, decoded);
    
    // Performance should be reasonable (under 1 second for 1KB)
    try testing.expect(encoded_time < 1000);
    try testing.expect(decoded_time < 1000);
}