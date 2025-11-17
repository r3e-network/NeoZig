//! WIF Tests
//!
//! Complete conversion from NeoSwift WIFTests.swift
//! Tests WIF (Wallet Import Format) encoding and decoding functionality.

const std = @import("std");


const testing = std.testing;
const WIF = @import("../../src/crypto/wif.zig").WIF;
const errors = @import("../../src/core/errors.zig");

// Test valid WIF to private key conversion (converted from Swift testValidWifToPrivateKey)
test "Valid WIF to private key conversion" {
    const allocator = testing.allocator;
    
    // Test data (equivalent to Swift validWif and privateKey constants)
    const valid_wif = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13A";
    const expected_private_key = "9117f4bf9be717c9a90994326897f4243503accd06712162267e77f18b49c3a3";
    
    // Convert WIF to private key (equivalent to Swift privateKeyFromWIF)
    const private_key_bytes = try WIF.toPrivateKey(valid_wif, allocator);
    defer allocator.free(private_key_bytes);
    
    // Convert to hex string for comparison
    const private_key_hex = try @import("../../src/utils/bytes_extensions.zig").BytesUtils.toHexString(private_key_bytes, allocator);
    defer allocator.free(private_key_hex);
    
    // Verify conversion (equivalent to Swift XCTAssertEqual)
    try testing.expectEqualStrings(expected_private_key, private_key_hex);
}

/// Test wrongly sized WIF validation (converted from Swift testWronglySizedWifs)
test "Wrongly sized WIF validation" {
    const allocator = testing.allocator;
    
    // Test WIF strings with incorrect length (equivalent to Swift tooLarge and tooSmall)
    const too_large_wif = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13Ahc7S";
    const too_small_wif = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWML";
    
    // Both should throw WIF format errors (equivalent to Swift assertThrowsWrongWifFormat)
    try testing.expectError(
        errors.CryptoError.InvalidWIFFormat,
        WIF.toPrivateKey(too_large_wif, allocator)
    );
    
    try testing.expectError(
        errors.CryptoError.InvalidWIFFormat,
        WIF.toPrivateKey(too_small_wif, allocator)
    );
}

/// Test wrong first byte WIF validation (converted from Swift testWrongFirstByteWif)
test "Wrong first byte WIF validation" {
    const allocator = testing.allocator;
    
    // Create WIF with wrong first byte (equivalent to Swift base58[0] = 0x81)
    const valid_wif = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13A";
    
    // Decode valid WIF
    const base58_decoded = try @import("../../src/crypto/base58.zig").Base58.decode(valid_wif, allocator);
    defer allocator.free(base58_decoded.?);
    
    if (base58_decoded) |decoded| {
        // Modify first byte (version byte should be 0x80, change to 0x81)
        var modified_bytes = try allocator.dupe(u8, decoded);
        defer allocator.free(modified_bytes);
        
        modified_bytes[0] = 0x81; // Wrong version byte
        
        // Re-encode to base58
        const wrong_first_byte_wif = try @import("../../src/crypto/base58.zig").Base58.encode(modified_bytes, allocator);
        defer allocator.free(wrong_first_byte_wif);
        
        // Should throw WIF format error (equivalent to Swift assertThrowsWrongWifFormat)
        try testing.expectError(
            errors.CryptoError.InvalidWIFFormat,
            WIF.toPrivateKey(wrong_first_byte_wif, allocator)
        );
    }
}

/// Test wrong byte 33 WIF validation (converted from Swift testWrongByte33Wif)
test "Wrong byte 33 WIF validation" {
    const allocator = testing.allocator;
    
    // Create WIF with wrong compression flag (equivalent to Swift base58[33] = 0x00)
    const valid_wif = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13A";
    
    // Decode valid WIF
    const base58_decoded = try @import("../../src/crypto/base58.zig").Base58.decode(valid_wif, allocator);
    defer allocator.free(base58_decoded.?);
    
    if (base58_decoded) |decoded| {
        // Modify compression flag byte (should be 0x01, change to 0x00)
        var modified_bytes = try allocator.dupe(u8, decoded);
        defer allocator.free(modified_bytes);
        
        modified_bytes[33] = 0x00; // Wrong compression flag
        
        // Re-encode to base58
        const wrong_byte33_wif = try @import("../../src/crypto/base58.zig").Base58.encode(modified_bytes, allocator);
        defer allocator.free(wrong_byte33_wif);
        
        // Should throw WIF format error (equivalent to Swift assertThrowsWrongWifFormat)
        try testing.expectError(
            errors.CryptoError.InvalidWIFFormat,
            WIF.toPrivateKey(wrong_byte33_wif, allocator)
        );
    }
}

/// Test valid private key to WIF conversion (converted from Swift testValidPrivateKeyToWif)
test "Valid private key to WIF conversion" {
    const allocator = testing.allocator;
    
    // Test data (equivalent to Swift privateKey and validWif constants)
    const private_key_hex = "9117f4bf9be717c9a90994326897f4243503accd06712162267e77f18b49c3a3";
    const expected_wif = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13A";
    
    // Convert hex to bytes
    const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(private_key_hex, allocator);
    defer allocator.free(private_key_bytes);
    
    // Convert private key to WIF (equivalent to Swift wifFromPrivateKey)
    const wif_result = try WIF.fromPrivateKey(private_key_bytes, allocator);
    defer allocator.free(wif_result);
    
    // Verify conversion (equivalent to Swift XCTAssertEqual)
    try testing.expectEqualStrings(expected_wif, wif_result);
}

/// Test wrongly sized private key validation (converted from Swift testWronglySizedPrivateKey)
test "Wrongly sized private key validation" {
    const allocator = testing.allocator;
    
    // Test private key with incorrect length (equivalent to Swift wronglySizedPrivateKey)
    const wrongly_sized_private_key = "9117f4bf9be717c9a90994326897f4243503accd06712162267e77f18b49c3"; // Missing 1 byte
    
    // Convert hex to bytes
    const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(wrongly_sized_private_key, allocator);
    defer allocator.free(private_key_bytes);
    
    // Should throw invalid key size error (equivalent to Swift error expectation)
    try testing.expectError(
        errors.CryptoError.InvalidKeySize,
        WIF.fromPrivateKey(private_key_bytes, allocator)
    );
}

/// Test WIF format validation utility
test "WIF format validation utility" {
    const allocator = testing.allocator;
    
    // Test valid WIF format validation
    const valid_wif = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13A";
    try testing.expect(WIF.isValidFormat(valid_wif, allocator));
    
    // Test invalid WIF format validation
    const invalid_wifs = [_][]const u8{
        "invalidwif",
        "",
        "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13", // Too short
        "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13AExtra", // Too long
    };
    
    for (invalid_wifs) |invalid_wif| {
        try testing.expect(!WIF.isValidFormat(invalid_wif, allocator));
    }
}

/// Test WIF roundtrip conversion
test "WIF roundtrip conversion" {
    const allocator = testing.allocator;
    
    // Test multiple private key -> WIF -> private key conversions
    const test_private_keys = [_][]const u8{
        "9117f4bf9be717c9a90994326897f4243503accd06712162267e77f18b49c3a3",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "e6e919577dd7b8e97805151c05ae07ff4f752654d6d8797597aca989c02c4cb3",
    };
    
    for (test_private_keys) |private_key_hex| {
        // Convert hex to bytes
        const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(private_key_hex, allocator);
        defer allocator.free(private_key_bytes);
        
        // Convert to WIF
        const wif_encoded = try WIF.fromPrivateKey(private_key_bytes, allocator);
        defer allocator.free(wif_encoded);
        
        // Convert back to private key
        const decoded_private_key = try WIF.toPrivateKey(wif_encoded, allocator);
        defer allocator.free(decoded_private_key);
        
        // Should match original (roundtrip test)
        try testing.expectEqualSlices(u8, private_key_bytes, decoded_private_key);
        
        // Verify WIF format is valid
        try testing.expect(WIF.isValidFormat(wif_encoded, allocator));
    }
}

/// Test WIF checksum validation
test "WIF checksum validation" {
    const allocator = testing.allocator;
    
    const valid_wif = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13A";
    
    // Decode valid WIF to get structure
    const base58_decoded = try @import("../../src/crypto/base58.zig").Base58.decode(valid_wif, allocator);
    defer allocator.free(base58_decoded.?);
    
    if (base58_decoded) |decoded| {
        // Corrupt the checksum (last 4 bytes)
        var corrupted_bytes = try allocator.dupe(u8, decoded);
        defer allocator.free(corrupted_bytes);
        
        // Modify checksum bytes
        corrupted_bytes[decoded.len - 1] = corrupted_bytes[decoded.len - 1] ^ 0xFF;
        corrupted_bytes[decoded.len - 2] = corrupted_bytes[decoded.len - 2] ^ 0xFF;
        
        // Re-encode with bad checksum
        const corrupted_wif = try @import("../../src/crypto/base58.zig").Base58.encode(corrupted_bytes, allocator);
        defer allocator.free(corrupted_wif);
        
        // Should fail checksum validation
        try testing.expectError(
            errors.CryptoError.InvalidWIFChecksum,
            WIF.toPrivateKey(corrupted_wif, allocator)
        );
    }
}

/// Test edge case private keys
test "Edge case private key WIF conversion" {
    const allocator = testing.allocator;
    
    // Test minimum valid private key (1)
    const min_private_key = [_]u8{0} ** 31 ++ [_]u8{1}; // 32 bytes with value 1
    
    const min_wif = try WIF.fromPrivateKey(&min_private_key, allocator);
    defer allocator.free(min_wif);
    
    const decoded_min = try WIF.toPrivateKey(min_wif, allocator);
    defer allocator.free(decoded_min);
    
    try testing.expectEqualSlices(u8, &min_private_key, decoded_min);
    
    // Test maximum valid private key (just under curve order)
    const max_private_key = [_]u8{
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x50,
    }; // Just under secp256r1 order
    
    const max_wif = try WIF.fromPrivateKey(&max_private_key, allocator);
    defer allocator.free(max_wif);
    
    const decoded_max = try WIF.toPrivateKey(max_wif, allocator);
    defer allocator.free(decoded_max);
    
    try testing.expectEqualSlices(u8, &max_private_key, decoded_max);
}

/// Test WIF network version handling
test "WIF network version handling" {
    const allocator = testing.allocator;
    
    // Create test private key
    const test_private_key = [_]u8{
        0x91, 0x17, 0xf4, 0xbf, 0x9b, 0xe7, 0x17, 0xc9,
        0xa9, 0x09, 0x94, 0x32, 0x68, 0x97, 0xf4, 0x24,
        0x35, 0x03, 0xac, 0xcd, 0x06, 0x71, 0x21, 0x62,
        0x26, 0x7e, 0x77, 0xf1, 0x8b, 0x49, 0xc3, 0xa3,
    };
    
    // Test MainNet WIF encoding
    const mainnet_wif = try WIF.fromPrivateKey(&test_private_key, allocator);
    defer allocator.free(mainnet_wif);
    
    // Verify we can decode it back
    const decoded_mainnet = try WIF.toPrivateKey(mainnet_wif, allocator);
    defer allocator.free(decoded_mainnet);
    
    try testing.expectEqualSlices(u8, &test_private_key, decoded_mainnet);
    
    // Verify WIF format
    try testing.expect(WIF.isValidFormat(mainnet_wif, allocator));
    
    // WIF should start with 'K' or 'L' for compressed keys
    try testing.expect(mainnet_wif[0] == 'K' or mainnet_wif[0] == 'L');
}

/// Test known test vectors for WIF
test "Known WIF test vectors" {
    const allocator = testing.allocator;
    
    // Test vectors with known private key -> WIF mappings
    const test_vectors = [_]struct {
        private_key: []const u8,
        expected_wif: []const u8,
    }{
        .{
            .private_key = "9117f4bf9be717c9a90994326897f4243503accd06712162267e77f18b49c3a3",
            .expected_wif = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13A",
        },
    };
    
    for (test_vectors) |vector| {
        // Convert hex to bytes
        const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(vector.private_key, allocator);
        defer allocator.free(private_key_bytes);
        
        // Test private key -> WIF
        const wif_result = try WIF.fromPrivateKey(private_key_bytes, allocator);
        defer allocator.free(wif_result);
        
        try testing.expectEqualStrings(vector.expected_wif, wif_result);
        
        // Test WIF -> private key
        const decoded_key = try WIF.toPrivateKey(vector.expected_wif, allocator);
        defer allocator.free(decoded_key);
        
        try testing.expectEqualSlices(u8, private_key_bytes, decoded_key);
    }
}

/// Test WIF error messages and types
test "WIF error messages and types" {
    const allocator = testing.allocator;
    
    // Test various invalid WIF formats and verify correct error types
    const invalid_wif_cases = [_]struct {
        wif: []const u8,
        expected_error: anyerror,
    }{
        .{ .wif = "invalidwif", .expected_error = errors.CryptoError.InvalidWIFFormat },
        .{ .wif = "", .expected_error = errors.CryptoError.InvalidWIFFormat },
        .{ .wif = "L", .expected_error = errors.CryptoError.InvalidWIFFormat },
    };
    
    for (invalid_wif_cases) |case| {
        try testing.expectError(
            case.expected_error,
            WIF.toPrivateKey(case.wif, allocator)
        );
        
        // Verify format validation also fails
        try testing.expect(!WIF.isValidFormat(case.wif, allocator));
    }
}