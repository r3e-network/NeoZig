//! NEP-2 encrypted private key implementation
//!
//! Complete conversion from NeoSwift NEP2.swift
//! Provides password-based private key encryption/decryption.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const PrivateKey = @import("keys.zig").PrivateKey;
const PublicKey = @import("keys.zig").PublicKey;
const KeyPair = @import("keys.zig").KeyPair;
const hashing = @import("hashing.zig");
const secure = @import("../utils/secure.zig");

fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var diff: u8 = 0;
    for (a, 0..) |byte, i| {
        diff |= byte ^ b[i];
    }
    return diff == 0;
}

/// NEP-2 encryption/decryption (converted from Swift NEP2)
pub const NEP2 = struct {
    /// Constants (match Swift constants)
    pub const DKLEN: u32 = 64;
    pub const NEP2_PRIVATE_KEY_LENGTH: u32 = 39;
    pub const NEP2_PREFIX_1: u8 = 0x01;
    pub const NEP2_PREFIX_2: u8 = 0x42;
    pub const NEP2_FLAGBYTE: u8 = 0xE0;

    /// Decrypts NEP-2 encrypted private key (equivalent to Swift decrypt)
    pub fn decrypt(
        password: []const u8,
        nep2_string: []const u8,
        params: ScryptParams,
        allocator: std.mem.Allocator,
    ) !KeyPair {
        if (password.len == 0) return errors.WalletError.InvalidPassword;

        // Decode Base58Check
        const base58 = @import("../utils/base58.zig");
        const nep2_data = base58.decodeCheck(nep2_string, allocator) catch |err| switch (err) {
            errors.ValidationError.InvalidParameter,
            errors.ValidationError.InvalidChecksum,
            => return errors.CryptoError.InvalidKey,
            else => return err,
        };
        defer {
            secure.secureZeroBytes(nep2_data);
            allocator.free(nep2_data);
        }

        // Validate NEP-2 format
        if (nep2_data.len != NEP2_PRIVATE_KEY_LENGTH) {
            return errors.CryptoError.InvalidKey;
        }

        if (nep2_data[0] != NEP2_PREFIX_1 or nep2_data[1] != NEP2_PREFIX_2 or nep2_data[2] != NEP2_FLAGBYTE) {
            return errors.CryptoError.InvalidKey;
        }

        // Extract components
        const address_hash = nep2_data[3..7];
        const encrypted = nep2_data[7..39];

        // Generate derived key using scrypt
        var derived_key = try generateDerivedScryptKey(password, address_hash, params, allocator);
        defer {
            secure.secureZeroBytes(derived_key);
            allocator.free(derived_key);
        }

        // Decrypt private key
        const decrypted_bytes = try performCipher(encrypted, derived_key[32..64], false, allocator);
        defer {
            secure.secureZeroBytes(decrypted_bytes);
            allocator.free(decrypted_bytes);
        }

        // XOR with first 32 bytes of derived key
        var plain_private_key: [32]u8 = undefined;
        for (derived_key[0..32], decrypted_bytes, 0..) |dk_byte, dec_byte, i| {
            plain_private_key[i] = dk_byte ^ dec_byte;
        }

        // Create key pair
        const private_key = try PrivateKey.init(plain_private_key);
        const key_pair = try KeyPair.fromPrivateKey(private_key, true);

        // Validate address hash using constant-time comparison to prevent timing side-channel attacks
        const new_address_hash = try getAddressHash(key_pair, allocator);
        defer allocator.free(new_address_hash);

        // SECURITY: Use constant-time comparison to prevent timing attacks
        // std.mem.eql uses early-exit which leaks information via timing
        if (!constantTimeEqual(new_address_hash, address_hash)) {
            return errors.WalletError.InvalidPassword;
        }

        std.crypto.secureZero(u8, &plain_private_key);
        return key_pair;
    }

    /// Encrypts private key with NEP-2 (equivalent to Swift encrypt)
    pub fn encrypt(
        password: []const u8,
        key_pair: KeyPair,
        params: ScryptParams,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (password.len == 0) return errors.WalletError.InvalidPassword;
        if (!key_pair.isValid()) return errors.CryptoError.InvalidKeyPair;

        // Get address hash
        const address_hash = try getAddressHash(key_pair, allocator);
        defer allocator.free(address_hash);

        // Generate derived key using scrypt
        var derived_key = try generateDerivedScryptKey(password, address_hash, params, allocator);
        defer {
            secure.secureZeroBytes(derived_key);
            allocator.free(derived_key);
        }

        // XOR private key with first 32 bytes of derived key
        var xor_result: [32]u8 = undefined;
        for (key_pair.private_key.toSlice(), derived_key[0..32], 0..) |pk_byte, dk_byte, i| {
            xor_result[i] = pk_byte ^ dk_byte;
        }

        // Encrypt with AES
        const encrypted = try performCipher(&xor_result, derived_key[32..64], true, allocator);
        defer allocator.free(encrypted);
        std.crypto.secureZero(u8, &xor_result);

        // Build NEP-2 format
        var nep2_data: [NEP2_PRIVATE_KEY_LENGTH]u8 = undefined;
        nep2_data[0] = NEP2_PREFIX_1;
        nep2_data[1] = NEP2_PREFIX_2;
        nep2_data[2] = NEP2_FLAGBYTE;
        @memcpy(nep2_data[3..7], address_hash);
        @memcpy(nep2_data[7..39], encrypted);

        // Encode with Base58Check
        const base58 = @import("../utils/base58.zig");
        return try base58.encodeCheck(&nep2_data, allocator);
    }

    /// Generates derived scrypt key (equivalent to Swift generateDerivedScryptKey)
    fn generateDerivedScryptKey(
        password: []const u8,
        address_hash: []const u8,
        params: ScryptParams,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        return try hashing.scrypt(
            password,
            address_hash,
            params.n,
            params.r,
            params.p,
            DKLEN,
            allocator,
        );
    }

    /// Performs AES encryption/decryption (equivalent to Swift performCipher)
    fn performCipher(
        data: []const u8,
        key: []const u8,
        should_encrypt: bool,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);

        if (should_encrypt) {
            try aesEncrypt(result, key);
        } else {
            try aesDecrypt(result, key);
        }

        return result;
    }

    /// Gets address hash for validation (equivalent to Swift getAddressHash)
    fn getAddressHash(key_pair: KeyPair, allocator: std.mem.Allocator) ![]u8 {
        const address = try key_pair.public_key.toAddress(constants.AddressConstants.ADDRESS_VERSION);
        const address_str = try address.toString(allocator);
        defer allocator.free(address_str);

        const address_hash = Hash256.doubleSha256(address_str);
        return try allocator.dupe(u8, address_hash.toSlice()[0..4]);
    }

    /// AES encryption (equivalent to Swift AES operations)
    fn aesEncrypt(data: []u8, key: []const u8) !void {
        if (data.len != 32 or key.len != 32) {
            return errors.CryptoError.InvalidKey;
        }

        const aes = std.crypto.core.aes.Aes256.initEnc(key[0..32].*);

        // Encrypt two 16-byte blocks
        var block1: [16]u8 = undefined;
        var block2: [16]u8 = undefined;
        @memcpy(&block1, data[0..16]);
        @memcpy(&block2, data[16..32]);

        var encrypted1: [16]u8 = undefined;
        var encrypted2: [16]u8 = undefined;
        aes.encrypt(&encrypted1, &block1);
        aes.encrypt(&encrypted2, &block2);

        @memcpy(data[0..16], &encrypted1);
        @memcpy(data[16..32], &encrypted2);
    }

    /// AES decryption (equivalent to Swift AES operations)
    fn aesDecrypt(data: []u8, key: []const u8) !void {
        if (data.len != 32 or key.len != 32) {
            return errors.CryptoError.InvalidKey;
        }

        const aes = std.crypto.core.aes.Aes256.initDec(key[0..32].*);

        // Decrypt two 16-byte blocks
        var block1: [16]u8 = undefined;
        var block2: [16]u8 = undefined;
        @memcpy(&block1, data[0..16]);
        @memcpy(&block2, data[16..32]);

        var decrypted1: [16]u8 = undefined;
        var decrypted2: [16]u8 = undefined;
        aes.decrypt(&decrypted1, &block1);
        aes.decrypt(&decrypted2, &block2);

        @memcpy(data[0..16], &decrypted1);
        @memcpy(data[16..32], &decrypted2);
    }
};

/// Scrypt parameters (imported from wallet)
const ScryptParams = @import("../wallet/nep6_wallet.zig").ScryptParams;

// Tests (converted from Swift NEP2Tests)
test "NEP2 encryption and decryption" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test key pair creation and NEP-2 encryption
    const key_pair = try KeyPair.generate(true);
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }

    const password = "test_password_123";
    const params = ScryptParams.DEFAULT;

    // Encrypt private key (equivalent to Swift encrypt tests)
    const encrypted_key = try NEP2.encrypt(password, key_pair, params, allocator);
    defer allocator.free(encrypted_key);

    try testing.expect(encrypted_key.len > 0);

    // Decrypt private key (equivalent to Swift decrypt tests)
    const decrypted_key_pair = try NEP2.decrypt(password, encrypted_key, params, allocator);
    defer {
        var mutable_decrypted = decrypted_key_pair;
        mutable_decrypted.zeroize();
    }

    // Verify round-trip (equivalent to Swift round-trip tests)
    try testing.expect(key_pair.private_key.eql(decrypted_key_pair.private_key));
    try testing.expect(key_pair.public_key.eql(decrypted_key_pair.public_key));
}

test "NEP2 format validation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test invalid NEP-2 format (equivalent to Swift validation tests)
    const invalid_nep2 = "invalid_nep2_string";
    try testing.expectError(errors.CryptoError.InvalidKey, NEP2.decrypt("password", invalid_nep2, ScryptParams.DEFAULT, allocator));

    // Test wrong password (equivalent to Swift wrong password tests)
    const key_pair = try KeyPair.generate(true);
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }

    const correct_password = "correct_password";
    const wrong_password = "wrong_password";

    const encrypted = try NEP2.encrypt(correct_password, key_pair, ScryptParams.DEFAULT, allocator);
    defer allocator.free(encrypted);

    try testing.expectError(errors.WalletError.InvalidPassword, NEP2.decrypt(wrong_password, encrypted, ScryptParams.DEFAULT, allocator));
}

test "NEP2 scrypt parameter variations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test with different scrypt parameters (equivalent to Swift parameter tests)
    const key_pair = try KeyPair.generate(true);
    defer {
        var mutable_key_pair = key_pair;
        mutable_key_pair.zeroize();
    }

    const password = "test_password";
    const light_params = ScryptParams.init(512, 1, 1); // Faster for testing

    const encrypted = try NEP2.encrypt(password, key_pair, light_params, allocator);
    defer allocator.free(encrypted);

    const decrypted = try NEP2.decrypt(password, encrypted, light_params, allocator);
    defer {
        var mutable_decrypted = decrypted;
        mutable_decrypted.zeroize();
    }

    try testing.expect(key_pair.private_key.eql(decrypted.private_key));
}
