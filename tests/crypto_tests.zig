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

// Tests public key creation (converted from Swift testNewPublicKeyFromPoint)
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

// Tests uncompressed to compressed conversion (converted from Swift testNewPublicKeyFromUncompressedPoint)
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

// Tests invalid key size (converted from Swift testNewPublicKeyFromStringWithInvalidSize)
test "public key invalid size error" {
    const testing = std.testing;

    // Test too small key (equivalent to Swift tooSmall test)
    const too_small = ENCODED_POINT[0 .. ENCODED_POINT.len - 2];
    try testing.expectError(neo.errors.CryptoError.InvalidKey, neo.crypto.PublicKey.fromHex(too_small));

    // Test empty key
    try testing.expectError(neo.errors.CryptoError.InvalidKey, neo.crypto.PublicKey.fromHex(""));

    // Test invalid hex
    try testing.expectError(neo.errors.CryptoError.InvalidKey, neo.crypto.PublicKey.fromHex("invalid_hex"));
}

// Tests hex prefix handling (converted from Swift testNewPublicKeyFromPointWithHexPrefix)
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

// Tests public key serialization (converted from Swift testSerializePublicKey)
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

// Tests public key deserialization (converted from Swift testDeserializePublicKey)
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

// Tests private key generation (converted from Swift private key tests)
test "private key generation and validation" {
    const testing = std.testing;

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

// Tests ECDSA signature operations (converted from Swift signature tests)
test "ECDSA signature creation and verification" {
    const testing = std.testing;

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

// Tests hash operations (converted from Swift hash tests)
test "hash function operations" {
    const testing = std.testing;

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

// Tests WIF encoding/decoding (converted from Swift WIF tests)
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

// Tests address generation (converted from Swift address tests)
test "address generation from public key" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const private_key = neo.crypto.generatePrivateKey();
    const public_key = try private_key.getPublicKey(true);

    // Test address creation (equivalent to Swift address generation)
    const address = try public_key.toAddress(neo.constants.AddressConstants.ADDRESS_VERSION);
    try testing.expect(address.isValid());
    try testing.expect(address.isStandard());
    try testing.expect(!address.isMultiSig());

    // PublicKey-derived and ECKeyPair-derived addresses must match.
    const key_pair = try neo.crypto.ECKeyPair.create(private_key);
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }

    const key_pair_script_hash = try key_pair.getScriptHash(allocator);
    const public_key_script_hash = try public_key.toHash160();
    try testing.expect(public_key_script_hash.eql(key_pair_script_hash));

    // Test address string conversion (equivalent to Swift address string methods)
    const address_str = try address.toString(allocator);
    defer allocator.free(address_str);

    try testing.expect(address_str.len > 0);

    const key_pair_address_str = try key_pair.getAddress(allocator);
    defer allocator.free(key_pair_address_str);
    try testing.expectEqualStrings(key_pair_address_str, address_str);

    // Test round-trip conversion (equivalent to Swift round-trip tests)
    const parsed_address = try neo.Address.fromString(address_str, allocator);
    try testing.expect(address.eql(parsed_address));
}

test "address parsing rejects unknown version" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var payload: [21]u8 = std.mem.zeroes([21]u8);
    payload[0] = 0x01; // Invalid address version for Neo N3

    const encoded = try neo.utils.base58.encodeCheck(&payload, allocator);
    defer allocator.free(encoded);

    try testing.expectError(neo.errors.ValidationError.InvalidAddress, neo.Address.fromString(encoded, allocator));
}

test "NEP-2 encrypt/decrypt known vectors" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const password = "neo";
    const private_key = try neo.crypto.PrivateKey.fromHex("84180ac9d6eb6fba207ea4ef9d2200102d1ebeb4b9c07e2c6a738a42742e27a5");
    const key_pair = try neo.crypto.KeyPair.fromPrivateKey(private_key, true);
    defer {
        var mutable = key_pair;
        mutable.zeroize();
    }

    // Default scrypt params (NeoSwift TestProperties.swift)
    const expected_default = "6PYM7jHL4GmS8Aw2iEFpuaHTCUKjhT4mwVqdoozGU6sUE25BjV4ePXDdLz";
    const encrypted_default = try neo.crypto.nep2.NEP2.encrypt(password, key_pair, neo.wallet.ScryptParams.DEFAULT, allocator);
    defer allocator.free(encrypted_default);
    try testing.expectEqualStrings(expected_default, encrypted_default);

    const decrypted_default = try neo.crypto.nep2.NEP2.decrypt(password, encrypted_default, neo.wallet.ScryptParams.DEFAULT, allocator);
    defer {
        var mutable = decrypted_default;
        mutable.zeroize();
    }
    try testing.expect(decrypted_default.private_key.eql(private_key));

    // Non-default scrypt params (NeoSwift NEP2Tests.swift)
    const custom_params = neo.wallet.ScryptParams.init(256, 1, 1);
    const expected_custom = "6PYM7jHL3uwhP8uuHP9fMGMfJxfyQbanUZPQEh1772iyb7vRnUkbkZmdRT";
    const encrypted_custom = try neo.crypto.nep2.NEP2.encrypt(password, key_pair, custom_params, allocator);
    defer allocator.free(encrypted_custom);
    try testing.expectEqualStrings(expected_custom, encrypted_custom);

    const decrypted_custom = try neo.crypto.nep2.NEP2.decrypt(password, encrypted_custom, custom_params, allocator);
    defer {
        var mutable = decrypted_custom;
        mutable.zeroize();
    }
    try testing.expect(decrypted_custom.private_key.eql(private_key));
}

test "NEP-2 invalid password and format errors" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const encrypted = "6PYM7jHL4GmS8Aw2iEFpuaHTCUKjhT4mwVqdoozGU6sUE25BjV4ePXDdLz";
    try testing.expectError(
        neo.errors.WalletError.InvalidPassword,
        neo.crypto.nep2.NEP2.decrypt("wrong_password", encrypted, neo.wallet.ScryptParams.DEFAULT, allocator),
    );

    try testing.expectError(
        neo.errors.CryptoError.InvalidKey,
        neo.crypto.nep2.NEP2.decrypt("neo", "not_a_nep2_key", neo.wallet.ScryptParams.DEFAULT, allocator),
    );
}

test "NeoSwift default account vectors" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Values from `NeoSwift/Tests/NeoSwiftTests/unit/TestProperties.swift`
    const expected_address = "NM7Aky765FG8NhhwtxjXRx7jEL1cnw7PBP";
    const expected_script_hash = "69ecca587293047be4c59159bf8bc399985c160d";
    const expected_public_key = "033a4d051b04b7fc0230d2b1aaedfd5a84be279a5361a7358db665ad7857787f1b";
    const expected_verification_script = "0c21" ++ expected_public_key ++ "4156e7b327";

    const private_key = try neo.crypto.PrivateKey.fromHex("84180ac9d6eb6fba207ea4ef9d2200102d1ebeb4b9c07e2c6a738a42742e27a5");
    const public_key = try private_key.getPublicKey(true);

    const public_key_hex = try public_key.toHex(allocator);
    defer allocator.free(public_key_hex);
    try testing.expectEqualStrings(expected_public_key, public_key_hex);

    const verification_script = try neo.script.ScriptBuilder.buildVerificationScript(public_key.toSlice(), allocator);
    defer allocator.free(verification_script);

    const verification_script_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(verification_script)});
    defer allocator.free(verification_script_hex);
    try testing.expectEqualStrings(expected_verification_script, verification_script_hex);

    const script_hash = try neo.Hash160.fromScript(verification_script);
    const script_hash_str = try script_hash.toString(allocator);
    defer allocator.free(script_hash_str);
    try testing.expectEqualStrings(expected_script_hash, script_hash_str);

    const address = try script_hash.toAddress(allocator);
    defer allocator.free(address);
    try testing.expectEqualStrings(expected_address, address);
}

// Tests Hash160 operations (converted from Swift Hash160Tests)
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

// Tests Hash256 operations (converted from Swift Hash256Tests)
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

// Tests serialization (converted from Swift serialization tests)
test "hash serialization and deserialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test Hash160 serialization
    const hash160 = try neo.Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");

    var writer = neo.BinaryWriter.init(allocator);
    defer writer.deinit();

    try hash160.serialize(&writer);
    try testing.expectEqual(@as(usize, 20), writer.toSlice().len);

    // Test deserialization
    var reader = neo.BinaryReader.init(writer.toSlice());
    const deserialized = try neo.Hash160.deserialize(&reader);
    try testing.expect(hash160.eql(deserialized));
}

// Tests error handling (converted from Swift error tests)
test "crypto error handling" {
    const testing = std.testing;

    // Test invalid key creation (equivalent to Swift error tests)
    const zero_key = std.mem.zeroes([32]u8);
    try testing.expectError(neo.errors.CryptoError.InvalidKey, neo.crypto.PrivateKey.init(zero_key));

    // Test invalid hash creation
    try testing.expectError(neo.errors.NeoError.IllegalArgument, neo.Hash160.initWithString("invalid"));
    try testing.expectError(neo.errors.NeoError.IllegalArgument, neo.Hash256.initWithString("too_short"));
}
