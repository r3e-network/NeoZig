//! NEP-2 Tests
//!
//! Complete conversion from NeoSwift NEP2Tests.swift
//! Tests NEP-2 encryption and decryption of private keys.

const std = @import("std");


const testing = std.testing;
const NEP2 = @import("../../src/crypto/nep2.zig").NEP2;
const ECKeyPair = @import("../../src/crypto/ec_key_pair.zig").ECKeyPair;
const ScryptParams = @import("../../src/crypto/scrypt_params.zig").ScryptParams;

/// Test constants (equivalent to Swift test constants)
const defaultAccountPassword = "Pwd12345678";
const defaultAccountPrivateKey = "e6e919577dd7b8e97805151c05ae07ff4f752654d6d8797597aca989c02c4cb3";
const defaultAccountEncryptedPrivateKey = "6PYVPVe1fQznphjbUxXP9KZJqPMVnVwCx5s5pr5axRJ8uHkMtZg97eT2kA";

/// Test NEP-2 decryption with default scrypt parameters (converted from Swift testDecryptWithDefaultScryptParams)
test "NEP-2 decrypt with default scrypt parameters" {
    const allocator = testing.allocator;
    
    // Decrypt with default parameters (equivalent to Swift NEP2.decrypt)
    const decrypted_result = try NEP2.decrypt(
        defaultAccountPassword,
        defaultAccountEncryptedPrivateKey,
        ScryptParams.default(),
        allocator,
    );
    defer decrypted_result.deinit(allocator);
    
    // Convert expected private key to bytes for comparison
    const expected_private_key = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(defaultAccountPrivateKey, allocator);
    defer allocator.free(expected_private_key);
    
    // Verify decryption result (equivalent to Swift XCTAssertEqual)
    const decrypted_private_key = decrypted_result.private_key.toSlice();
    try testing.expectEqualSlices(u8, expected_private_key, decrypted_private_key);
}

/// Test NEP-2 decryption with custom scrypt parameters (converted from Swift testDecryptWithNonDefaultScryptParams)
test "NEP-2 decrypt with non-default scrypt parameters" {
    const allocator = testing.allocator;
    
    // Use custom scrypt parameters (equivalent to Swift ScryptParams(256, 1, 1))
    const custom_params = ScryptParams.init(256, 1, 1);
    const custom_encrypted = "6PYM7jHL3uwhP8uuHP9fMGMfJxfyQbanUZPQEh1772iyb7vRnUkbkZmdRT";
    
    // Decrypt with custom parameters
    const decrypted_result = try NEP2.decrypt(
        defaultAccountPassword,
        custom_encrypted,
        custom_params,
        allocator,
    );
    defer decrypted_result.deinit(allocator);
    
    // Convert expected private key to bytes for comparison
    const expected_private_key = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(defaultAccountPrivateKey, allocator);
    defer allocator.free(expected_private_key);
    
    // Verify decryption result (equivalent to Swift XCTAssertEqual)
    const decrypted_private_key = decrypted_result.private_key.toSlice();
    try testing.expectEqualSlices(u8, expected_private_key, decrypted_private_key);
}

/// Test NEP-2 encryption with default scrypt parameters (converted from Swift testEncryptWithDefaultScryptParams)
test "NEP-2 encrypt with default scrypt parameters" {
    const allocator = testing.allocator;
    
    // Create key pair from known private key (equivalent to Swift ECKeyPair.create)
    const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(defaultAccountPrivateKey, allocator);
    defer allocator.free(private_key_bytes);
    
    const key_pair = try ECKeyPair.createFromPrivateKey(private_key_bytes);
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    // Encrypt with default parameters (equivalent to Swift NEP2.encrypt)
    const encrypted_result = try NEP2.encrypt(
        defaultAccountPassword,
        key_pair,
        ScryptParams.default(),
        allocator,
    );
    defer allocator.free(encrypted_result);
    
    // Verify encryption result (equivalent to Swift XCTAssertEqual)
    try testing.expectEqualStrings(defaultAccountEncryptedPrivateKey, encrypted_result);
}

/// Test NEP-2 encryption with custom scrypt parameters (converted from Swift testEncryptWithNonDefaultScryptParams)
test "NEP-2 encrypt with non-default scrypt parameters" {
    const allocator = testing.allocator;
    
    // Use custom scrypt parameters (equivalent to Swift ScryptParams(256, 1, 1))
    const custom_params = ScryptParams.init(256, 1, 1);
    const expected_encrypted = "6PYM7jHL3uwhP8uuHP9fMGMfJxfyQbanUZPQEh1772iyb7vRnUkbkZmdRT";
    
    // Create key pair from known private key
    const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(defaultAccountPrivateKey, allocator);
    defer allocator.free(private_key_bytes);
    
    const key_pair = try ECKeyPair.createFromPrivateKey(private_key_bytes);
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    // Encrypt with custom parameters
    const encrypted_result = try NEP2.encrypt(
        defaultAccountPassword,
        key_pair,
        custom_params,
        allocator,
    );
    defer allocator.free(encrypted_result);
    
    // Verify encryption result (equivalent to Swift XCTAssertEqual)
    try testing.expectEqualStrings(expected_encrypted, encrypted_result);
}

/// Test NEP-2 roundtrip encryption/decryption
test "NEP-2 roundtrip encryption and decryption" {
    const allocator = testing.allocator;
    
    // Create random key pair for roundtrip test
    const original_key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = original_key_pair;
        mutable_kp.zeroize();
    }
    
    const password = "TestPassword123";
    
    // Encrypt the key pair
    const encrypted_key = try NEP2.encrypt(
        password,
        original_key_pair,
        ScryptParams.default(),
        allocator,
    );
    defer allocator.free(encrypted_key);
    
    try testing.expect(encrypted_key.len > 0);
    
    // Decrypt the encrypted key
    const decrypted_result = try NEP2.decrypt(
        password,
        encrypted_key,
        ScryptParams.default(),
        allocator,
    );
    defer decrypted_result.deinit(allocator);
    
    // Verify roundtrip success
    const original_private_key = original_key_pair.getPrivateKey().toSlice();
    const decrypted_private_key = decrypted_result.private_key.toSlice();
    
    try testing.expectEqualSlices(u8, original_private_key, decrypted_private_key);
}

/// Test NEP-2 error conditions
test "NEP-2 error conditions" {
    const allocator = testing.allocator;
    
    // Test invalid password
    try testing.expectError(
        @import("../../src/crypto/nep2_error.zig").NEP2Error.InvalidPassword,
        NEP2.decrypt(
            "wrongpassword",
            defaultAccountEncryptedPrivateKey,
            ScryptParams.default(),
            allocator,
        )
    );
    
    // Test invalid encrypted key format
    try testing.expectError(
        @import("../../src/crypto/nep2_error.zig").NEP2Error.InvalidEncryptedKey,
        NEP2.decrypt(
            defaultAccountPassword,
            "invalidencryptedkey",
            ScryptParams.default(),
            allocator,
        )
    );
    
    // Test empty password
    try testing.expectError(
        @import("../../src/crypto/nep2_error.zig").NEP2Error.InvalidPassword,
        NEP2.decrypt(
            "",
            defaultAccountEncryptedPrivateKey,
            ScryptParams.default(),
            allocator,
        )
    );
}

/// Test NEP-2 with different scrypt parameters
test "NEP-2 with different scrypt parameters" {
    const allocator = testing.allocator;
    
    // Test with fast parameters (for testing)
    const fast_params = ScryptParams.testParams();
    
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    const password = "FastTestPassword";
    
    // Encrypt with fast parameters
    const encrypted_fast = try NEP2.encrypt(password, key_pair, fast_params, allocator);
    defer allocator.free(encrypted_fast);
    
    // Decrypt with same parameters
    const decrypted_fast = try NEP2.decrypt(password, encrypted_fast, fast_params, allocator);
    defer decrypted_fast.deinit(allocator);
    
    // Should match original
    const original_private_key = key_pair.getPrivateKey().toSlice();
    const decrypted_private_key = decrypted_fast.private_key.toSlice();
    
    try testing.expectEqualSlices(u8, original_private_key, decrypted_private_key);
    
    // Test with strong parameters
    const strong_params = ScryptParams.strongParams();
    
    const encrypted_strong = try NEP2.encrypt(password, key_pair, strong_params, allocator);
    defer allocator.free(encrypted_strong);
    
    // Strong and fast encrypted keys should be different
    try testing.expect(!std.mem.eql(u8, encrypted_fast, encrypted_strong));
}

/// Test NEP-2 validation and format checking
test "NEP-2 validation and format checking" {
    const allocator = testing.allocator;
    
    // Test valid NEP-2 format validation
    try testing.expect(NEP2.isValidEncryptedKey(defaultAccountEncryptedPrivateKey));
    
    // Test invalid NEP-2 formats
    const invalid_encrypted_keys = [_][]const u8{
        "invalidkey",
        "",
        "6PYVPVe1fQznphjbUxXP9KZJqPMVnVwCx5s5pr5axRJ8uHkMtZg97eT2", // Too short
        "6PYVPVe1fQznphjbUxXP9KZJqPMVnVwCx5s5pr5axRJ8uHkMtZg97eT2kATooLong", // Too long
    };
    
    for (invalid_encrypted_keys) |invalid_key| {
        try testing.expect(!NEP2.isValidEncryptedKey(invalid_key));
    }
    
    // Test NEP-2 format detection
    try testing.expect(NEP2.detectFormat(defaultAccountEncryptedPrivateKey) == .NEP2);
    try testing.expect(NEP2.detectFormat("invalidkey") == .Unknown);
}

/// Test NEP-2 performance with different parameters
test "NEP-2 performance with different parameters" {
    const allocator = testing.allocator;
    
    const key_pair = try ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    const password = "TestPassword";
    
    // Test fast parameters (should be quick)
    const fast_params = ScryptParams.testParams();
    
    const start_time = std.time.milliTimestamp();
    const encrypted_fast = try NEP2.encrypt(password, key_pair, fast_params, allocator);
    defer allocator.free(encrypted_fast);
    const fast_time = std.time.milliTimestamp() - start_time;
    
    // Fast encryption should complete quickly
    try testing.expect(fast_time < 1000); // Should be under 1 second
    
    // Verify fast encryption works
    const decrypted_fast = try NEP2.decrypt(password, encrypted_fast, fast_params, allocator);
    defer decrypted_fast.deinit(allocator);
    
    const original_key = key_pair.getPrivateKey().toSlice();
    const decrypted_key = decrypted_fast.private_key.toSlice();
    
    try testing.expectEqualSlices(u8, original_key, decrypted_key);
}