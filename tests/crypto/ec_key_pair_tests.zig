//! EC Key Pair Tests
//!
//! Complete conversion from NeoSwift ECKeyPairTests.swift
//! Tests elliptic curve key pair creation, validation, and operations.

const std = @import("std");
const testing = std.testing;
const ECKeyPair = @import("../../src/crypto/ec_key_pair.zig").ECKeyPair;
const PublicKey = @import("../../src/crypto/keys.zig").PublicKey;
const PrivateKey = @import("../../src/crypto/keys.zig").PrivateKey;

/// Test creating public key from compressed point (converted from Swift testNewPublicKeyFromPoint)
test "Create public key from compressed point" {
    const allocator = testing.allocator;
    
    // Test data (equivalent to Swift encodedPoint)
    const encoded_point = "03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    
    // Create public key from hex string (equivalent to Swift ECPublicKey(encodedPoint))
    const public_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(encoded_point, allocator);
    defer allocator.free(public_key_bytes);
    
    const public_key = try PublicKey.initFromBytes(public_key_bytes);
    
    // Verify encoded form (equivalent to Swift getEncoded(compressed: true))
    const encoded_compressed = public_key.toSlice();
    try testing.expectEqualSlices(u8, public_key_bytes, encoded_compressed);
    
    // Verify hex string form (equivalent to Swift getEncodedCompressedHex())
    const encoded_hex = try public_key.toHexString(allocator);
    defer allocator.free(encoded_hex);
    
    const hex_without_prefix = if (std.mem.startsWith(u8, encoded_hex, "0x"))
        encoded_hex[2..]
    else
        encoded_hex;
    
    try testing.expectEqualStrings(encoded_point, hex_without_prefix);
}

/// Test creating public key from uncompressed point (converted from Swift testNewPublicKeyFromUncompressedPoint)
test "Create public key from uncompressed point" {
    const allocator = testing.allocator;
    
    // Test data (equivalent to Swift uncompressedPoint)
    const uncompressed_point = "04b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e1368165f4f7fb1c5862465543c06dd5a2aa414f6583f92a5cc3e1d4259df79bf6839c9";
    const expected_compressed = "03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    
    // Create public key from uncompressed hex (equivalent to Swift ECPublicKey(uncompressedPoint))
    const uncompressed_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(uncompressed_point, allocator);
    defer allocator.free(uncompressed_bytes);
    
    const public_key = try PublicKey.initFromUncompressedBytes(uncompressed_bytes);
    
    // Verify compressed encoding (equivalent to Swift getEncodedCompressedHex())
    const compressed_hex = try public_key.toHexString(allocator);
    defer allocator.free(compressed_hex);
    
    const hex_without_prefix = if (std.mem.startsWith(u8, compressed_hex, "0x"))
        compressed_hex[2..]
    else
        compressed_hex;
    
    try testing.expectEqualStrings(expected_compressed, hex_without_prefix);
}

/// Test public key creation with invalid size (converted from Swift testNewPublicKeyFromStringWithInvalidSize)
test "Create public key with invalid size" {
    const allocator = testing.allocator;
    
    // Test data (equivalent to Swift tooSmall)
    const valid_point = "03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    const too_small_point = valid_point[0 .. valid_point.len - 2]; // Drop last 2 characters
    
    // Should throw error for invalid size (equivalent to Swift XCTAssertThrowsError)
    const too_small_bytes = @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(too_small_point, allocator) catch {
        // If hex parsing fails, that's also valid - the data is invalid
        return;
    };
    defer allocator.free(too_small_bytes);
    
    try testing.expectError(
        anyerror, // Could be InvalidPublicKey or InvalidKeySize
        PublicKey.initFromBytes(too_small_bytes)
    );
}

/// Test public key creation with hex prefix (converted from Swift testNewPublicKeyFromPointWithHexPrefix)
test "Create public key with hex prefix" {
    const allocator = testing.allocator;
    
    // Test data with 0x prefix (equivalent to Swift prefixed)
    const prefixed_point = "0x03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    const expected_point = "03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    
    // Remove prefix and create public key
    const point_without_prefix = if (std.mem.startsWith(u8, prefixed_point, "0x"))
        prefixed_point[2..]
    else
        prefixed_point;
    
    const public_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(point_without_prefix, allocator);
    defer allocator.free(public_key_bytes);
    
    const public_key = try PublicKey.initFromBytes(public_key_bytes);
    
    // Verify encoded hex form (equivalent to Swift getEncodedCompressedHex())
    const encoded_hex = try public_key.toHexString(allocator);
    defer allocator.free(encoded_hex);
    
    const hex_without_prefix = if (std.mem.startsWith(u8, encoded_hex, "0x"))
        encoded_hex[2..]
    else
        encoded_hex;
    
    try testing.expectEqualStrings(expected_point, hex_without_prefix);
}

/// Test public key serialization (converted from Swift testSerializePublicKey)
test "Public key serialization" {
    const allocator = testing.allocator;
    
    // Test data (equivalent to Swift encodedPoint)
    const encoded_point = "03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    
    // Create public key
    const public_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(encoded_point, allocator);
    defer allocator.free(public_key_bytes);
    
    const public_key = try PublicKey.initFromBytes(public_key_bytes);
    
    // Test serialization (equivalent to Swift toArray())
    const serialized_bytes = public_key.toSlice();
    
    // Verify serialization matches original bytes (equivalent to Swift XCTAssertEqual)
    try testing.expectEqualSlices(u8, public_key_bytes, serialized_bytes);
}

/// Test EC key pair creation and validation
test "EC key pair creation and validation" {
    const allocator = testing.allocator;
    
    // Test random key pair creation
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    // Verify key pair is valid
    try testing.expect(key_pair.isValid());
    
    // Verify public key is on curve
    const public_key = key_pair.getPublicKey();
    try testing.expect(public_key.isOnCurve());
    
    // Verify private key is in valid range
    const private_key = key_pair.getPrivateKey();
    try testing.expect(private_key.isValid());
    
    // Test key pair relationship
    const derived_public_key = try private_key.toPublicKey();
    try testing.expect(public_key.eql(derived_public_key));
}

/// Test EC key pair from known private key
test "EC key pair from known private key" {
    const allocator = testing.allocator;
    
    // Test creating key pair from known private key
    const known_private_key = "e6e919577dd7b8e97805151c05ae07ff4f752654d6d8797597aca989c02c4cb3";
    const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(known_private_key, allocator);
    defer allocator.free(private_key_bytes);
    
    const key_pair = try ECKeyPair.createFromPrivateKey(private_key_bytes);
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    // Verify key pair properties
    try testing.expect(key_pair.isValid());
    
    const private_key = key_pair.getPrivateKey();
    try testing.expectEqualSlices(u8, private_key_bytes, private_key.toSlice());
    
    // Verify public key derivation is consistent
    const public_key1 = key_pair.getPublicKey();
    const public_key2 = try private_key.toPublicKey();
    
    try testing.expect(public_key1.eql(public_key2));
}

/// Test EC key pair signing and verification
test "EC key pair signing and verification" {
    const allocator = testing.allocator;
    
    // Create key pair for signing test
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    // Test message signing
    const test_message = "Hello, Neo blockchain signing test!";
    const message_bytes = @as([]const u8, test_message);
    
    const signature = try key_pair.signMessage(message_bytes, allocator);
    defer signature.deinit(allocator);
    
    // Verify signature components
    try testing.expect(signature.r != 0);
    try testing.expect(signature.s != 0);
    try testing.expect(signature.v >= 27 and signature.v <= 30);
    
    // Verify signature with public key
    const public_key = key_pair.getPublicKey();
    const is_valid = try public_key.verifySignature(message_bytes, signature, allocator);
    
    try testing.expect(is_valid);
    
    // Test signature with different message should fail
    const different_message = "Different message";
    const different_bytes = @as([]const u8, different_message);
    
    const is_invalid = try public_key.verifySignature(different_bytes, signature, allocator);
    try testing.expect(!is_invalid);
}

/// Test EC key pair address generation
test "EC key pair address generation" {
    const allocator = testing.allocator;
    
    // Create key pair
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    // Test address generation
    const address = try key_pair.getAddress(allocator);
    defer allocator.free(address);
    
    // Verify address properties
    try testing.expect(address.len > 0);
    try testing.expect(address.len >= 25); // Neo addresses are typically 34 chars
    try testing.expect(address[0] == 'N'); // Neo addresses start with 'N'
    
    // Test script hash generation
    const script_hash = try key_pair.getScriptHash();
    try testing.expect(!script_hash.isZero());
    
    // Address should be derivable from script hash
    const address_from_hash = try script_hash.toAddress(allocator);
    defer allocator.free(address_from_hash);
    
    try testing.expectEqualStrings(address, address_from_hash);
}