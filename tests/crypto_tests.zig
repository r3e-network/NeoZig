//! Crypto tests converted from Swift
//!
//! Complete conversion of NeoSwift crypto test suite
//! Maintains test compatibility and validates same functionality.

const std = @import("std");
const neo = @import("neo-zig");

// Test data (converted from Swift ECKeyPairTests)
const ENCODED_POINT = "03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
const UNCOMPRESSED_POINT = "04b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e1368165f4f7fb1c5862465543c06dd5a2aa414f6583f92a5cc3e1d4259df79bf6839c9";
const GENERATOR_POINT_COMPRESSED = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";

/// Tests public key creation (converted from Swift testNewPublicKeyFromPoint)
test "public key from compressed point" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const public_key = try neo.crypto.PublicKey.fromHex(ENCODED_POINT);
    
    // Test encoded output matches input (equivalent to Swift getEncoded test)
    const encoded_hex = try public_key.toHex(allocator);
    defer allocator.free(encoded_hex);
    
    try testing.expectEqualStrings(ENCODED_POINT, encoded_hex);
    try testing.expect(public_key.compressed);
    try testing.expect(public_key.isValid());
}

/// Tests uncompressed to compressed conversion (converted from Swift testNewPublicKeyFromUncompressedPoint)
test "public key from uncompressed point" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const uncompressed_key = try neo.crypto.PublicKey.fromHex(UNCOMPRESSED_POINT);
    try testing.expect(!uncompressed_key.compressed);
    try testing.expect(uncompressed_key.isValid());
    
    // Convert to compressed (equivalent to Swift getEncodedCompressedHex)
    const compressed_key = try uncompressed_key.toCompressed();
    const compressed_hex = try compressed_key.toHex(allocator);
    defer allocator.free(compressed_hex);
    
    try testing.expectEqualStrings(ENCODED_POINT, compressed_hex);
}

/// Tests invalid key size (converted from Swift testNewPublicKeyFromStringWithInvalidSize)
test "public key invalid size error" {
    const testing = std.testing;
    
    // Test too small key (equivalent to Swift tooSmall test)
    const too_small = ENCODED_POINT[0..ENCODED_POINT.len-2];
    try testing.expectError(neo.errors.CryptoError.InvalidKey, neo.crypto.PublicKey.fromHex(too_small));
    
    // Test empty key
    try testing.expectError(neo.errors.CryptoError.InvalidKey, neo.crypto.PublicKey.fromHex(""));
    
    // Test invalid hex
    try testing.expectError(neo.errors.CryptoError.InvalidKey, neo.crypto.PublicKey.fromHex("invalid_hex"));
}

/// Tests hex prefix handling (converted from Swift testNewPublicKeyFromPointWithHexPrefix)
test "public key with hex prefix" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const prefixed = "0x" ++ ENCODED_POINT;
    const public_key = try neo.crypto.PublicKey.fromHex(prefixed);
    
    const encoded_hex = try public_key.toHex(allocator);
    defer allocator.free(encoded_hex);
    
    // Should match original without prefix (equivalent to Swift test)
    try testing.expectEqualStrings(ENCODED_POINT, encoded_hex);
}

/// Tests public key serialization (converted from Swift testSerializePublicKey)
test "public key serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const public_key = try neo.crypto.PublicKey.fromHex(ENCODED_POINT);
    
    // Test toArray equivalent (matches Swift toArray() method)
    const key_bytes = public_key.toSlice();
    const expected_bytes = try neo.utils.bytes.fromHex(ENCODED_POINT, allocator);
    defer allocator.free(expected_bytes);
    
    try testing.expectEqualSlices(u8, expected_bytes, key_bytes);
}

/// Tests public key deserialization (converted from Swift testDeserializePublicKey)
test "public key deserialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test generator point deserialization (equivalent to Swift SECP256R1_DOMAIN.g test)
    const generator_bytes = try neo.utils.bytes.fromHex(GENERATOR_POINT_COMPRESSED, allocator);
    defer allocator.free(generator_bytes);
    
    const public_key = try neo.crypto.PublicKey.init(generator_bytes, true);
    try testing.expect(public_key.isValid());
    try testing.expect(public_key.compressed);
    
    // Verify this is the generator point by checking it matches secp256r1 constants
    const generator_hex = try public_key.toHex(allocator);
    defer allocator.free(generator_hex);
    try testing.expectEqualStrings(GENERATOR_POINT_COMPRESSED, generator_hex);
}

/// Tests private key generation (converted from Swift private key tests)
test "private key generation and validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test key generation (equivalent to Swift key generation)
    const private_key1 = neo.crypto.generatePrivateKey();
    const private_key2 = neo.crypto.generatePrivateKey();
    
    try testing.expect(private_key1.isValid());
    try testing.expect(private_key2.isValid());
    try testing.expect(!private_key1.eql(private_key2));
    
    // Test public key derivation (equivalent to Swift getPublicKey)
    const public_key = try private_key1.getPublicKey(true);
    try testing.expect(public_key.isValid());
    try testing.expect(public_key.compressed);
    
    // Test key pair consistency (equivalent to Swift validation)
    const key_pair = try neo.crypto.KeyPair.fromPrivateKey(private_key1, true);
    try testing.expect(key_pair.isValid());
}

/// Tests ECDSA signature operations (converted from Swift signature tests)
test "ECDSA signature creation and verification" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const private_key = neo.crypto.generatePrivateKey();
    const public_key = try private_key.getPublicKey(true);
    
    // Test message signing (equivalent to Swift signing tests)
    const message = "Test message for ECDSA";
    const signature = try neo.crypto.signMessage(message, private_key);
    
    try testing.expect(signature.isValid());
    
    // Test signature verification (equivalent to Swift verification tests)
    const is_valid = try neo.crypto.verifyMessage(signature, message, public_key);
    try testing.expect(is_valid);
    
    // Test signature with wrong message (equivalent to Swift negative tests)
    const wrong_message = "Different message";
    const is_invalid = try neo.crypto.verifyMessage(signature, wrong_message, public_key);
    try testing.expect(!is_invalid);
}

/// Tests hash operations (converted from Swift hash tests)
test "hash function operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const test_data = "Neo blockchain test data";
    
    // Test SHA256 (equivalent to Swift SHA256 tests)
    const sha_hash = neo.crypto.sha256(test_data);
    try testing.expect(!sha_hash.isZero());
    
    // Test consistency - same input should produce same hash
    const sha_hash2 = neo.crypto.sha256(test_data);
    try testing.expect(sha_hash.eql(sha_hash2));
    
    // Test RIPEMD160 (equivalent to Swift RIPEMD160 tests)
    const ripemd_hash = try neo.crypto.ripemd160Hash(test_data);
    try testing.expect(!ripemd_hash.eql(neo.Hash160.ZERO));
    
    // Test Hash160 (SHA256 then RIPEMD160)
    const hash160_result = try neo.crypto.hash160(test_data);
    try testing.expect(!hash160_result.eql(neo.Hash160.ZERO));
}

/// Tests WIF encoding/decoding (converted from Swift WIF tests)
test "WIF encoding and decoding" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const private_key = neo.crypto.generatePrivateKey();
    
    // Test WIF encoding (equivalent to Swift WIF encoding tests)
    const wif_mainnet = try neo.crypto.encodeWIF(private_key, true, .mainnet, allocator);
    defer allocator.free(wif_mainnet);
    
    const wif_testnet = try neo.crypto.encodeWIF(private_key, true, .testnet, allocator);
    defer allocator.free(wif_testnet);
    
    try testing.expect(wif_mainnet.len > 0);
    try testing.expect(wif_testnet.len > 0);
    try testing.expect(!std.mem.eql(u8, wif_mainnet, wif_testnet)); // Different networks
    
    // Test WIF decoding (equivalent to Swift WIF decoding tests)
    const decoded_mainnet = try neo.crypto.decodeWIF(wif_mainnet, allocator);
    try testing.expect(decoded_mainnet.private_key.eql(private_key));
    try testing.expect(decoded_mainnet.compressed);
    try testing.expect(decoded_mainnet.network == .mainnet);
    
    const decoded_testnet = try neo.crypto.decodeWIF(wif_testnet, allocator);
    try testing.expect(decoded_testnet.private_key.eql(private_key));
    try testing.expect(decoded_testnet.compressed);
    try testing.expect(decoded_testnet.network == .testnet);
}

/// Tests address generation (converted from Swift address tests)
test "address generation from public key" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const private_key = neo.crypto.generatePrivateKey();
    const public_key = try private_key.getPublicKey(true);
    
    // Test address creation (equivalent to Swift address generation)
    const address = try public_key.toAddress(constants.AddressConstants.ADDRESS_VERSION);
    try testing.expect(address.isValid());
    try testing.expect(address.isStandard());
    try testing.expect(!address.isMultiSig());
    
    // Test address string conversion (equivalent to Swift address string methods)
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);
    
    try testing.expect(address_str.len > 0);
    
    // Test round-trip conversion (equivalent to Swift round-trip tests)
    const parsed_address = try neo.Address.fromString(address_str, allocator);
    try testing.expect(address.eql(parsed_address));
}

/// Tests Hash160 operations (converted from Swift Hash160Tests)
test "Hash160 creation and operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test zero hash (equivalent to Swift Hash160.ZERO test)
    const zero_hash = neo.Hash160.init();
    try testing.expect(zero_hash.eql(neo.Hash160.ZERO));
    
    // Test hex string creation (equivalent to Swift hex string tests)
    const hex_hash = try neo.Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const hex_str = try hex_hash.string(allocator);
    defer allocator.free(hex_str);
    
    try testing.expectEqualStrings("1234567890abcdef1234567890abcdef12345678", hex_str);
    
    // Test byte array operations (equivalent to Swift toArray/toLittleEndianArray)
    const big_endian = hex_hash.toArray();
    const little_endian = hex_hash.toLittleEndianArray();
    
    try testing.expectEqual(@as(usize, 20), big_endian.len);
    try testing.expectEqual(@as(usize, 20), little_endian.len);
    try testing.expect(!std.mem.eql(u8, &big_endian, &little_endian)); // Should be different
}

/// Tests Hash256 operations (converted from Swift Hash256Tests)
test "Hash256 creation and operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test zero hash
    const zero_hash = neo.Hash256.init();
    try testing.expect(zero_hash.eql(neo.Hash256.ZERO));
    
    // Test hex creation
    const hex_hash = try neo.Hash256.initWithString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const hex_str = try hex_hash.string(allocator);
    defer allocator.free(hex_str);
    
    try testing.expectEqualStrings("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", hex_str);
    
    // Test SHA256 operations
    const data = "Test data for SHA256";
    const sha_result = neo.Hash256.sha256(data);
    try testing.expect(!sha_result.isZero());
    
    // Test double SHA256
    const double_sha = neo.Hash256.doubleSha256(data);
    try testing.expect(!double_sha.isZero());
    try testing.expect(!sha_result.eql(double_sha));
}

/// Tests serialization (converted from Swift serialization tests)
test "hash serialization and deserialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test Hash160 serialization
    const hash160 = try neo.Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try hash160.serialize(&buffer);
    try testing.expectEqual(@as(usize, 20), buffer.items.len);
    
    // Test deserialization
    var stream = std.io.fixedBufferStream(buffer.items);
    const deserialized = try neo.Hash160.deserialize(&stream);
    try testing.expect(hash160.eql(deserialized));
}

/// Tests error handling (converted from Swift error tests)
test "crypto error handling" {
    const testing = std.testing;
    
    // Test invalid key creation (equivalent to Swift error tests)
    const zero_key = std.mem.zeroes([32]u8);
    try testing.expectError(neo.errors.CryptoError.InvalidKey, neo.crypto.PrivateKey.init(zero_key));
    
    // Test invalid hash creation
    try testing.expectError(neo.errors.ValidationError.InvalidParameter, neo.Hash160.initWithString("invalid"));
    try testing.expectError(neo.errors.ValidationError.InvalidParameter, neo.Hash256.initWithString("too_short"));
}