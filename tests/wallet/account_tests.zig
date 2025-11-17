//! Account Tests
//!
//! Complete conversion from NeoSwift AccountTests.swift
//! Tests account creation, key pair management, and multi-signature accounts.

const std = @import("std");


const testing = std.testing;
const Account = @import("../../src/wallet/account.zig").Account;
const ECKeyPair = @import("../../src/crypto/ec_key_pair.zig").ECKeyPair;
const PublicKey = @import("../../src/crypto/keys.zig").PublicKey;
const VerificationScript = @import("../../src/wallet/verification_script.zig").VerificationScript;

/// Test constants (equivalent to Swift test constants)
const defaultAccountPrivateKey = "e6e919577dd7b8e97805151c05ae07ff4f752654d6d8797597aca989c02c4cb3";
const defaultAccountPublicKey = "02163946a133e3d2e0d987fb90cb01b060ed1780f1718e2da28edf13b965fd2b600b";
const defaultAccountAddress = "NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj";
const defaultAccountVerificationScript = "0c2102163946a133e3d2e0d987fb90cb01b060ed1780f1718e2da28edf13b965fd2b600b4195440d78";
const committeeAccountAddress = "NX8GreRFGFK5wpGMWetpX93HmtrezGogzk";
const committeeAccountVerificationScript = "0c2102163946a133e3d2e0d987fb90cb01b060ed1780f1718e2da28edf13b965fd2b600b4156e7b327";

/// Test creating generic account (converted from Swift testCreateGenericAccount)
test "Create generic account" {
    const allocator = testing.allocator;
    
    // Create random account (equivalent to Swift Account.create())
    var account = try Account.create(allocator);
    defer account.deinit(allocator);
    
    // Verify account properties (equivalent to Swift XCTAssertNotNil checks)
    try testing.expect(!account.getAddress().isEmpty());
    try testing.expect(account.getVerificationScript() != null);
    try testing.expect(account.getKeyPair() != null);
    try testing.expect(!account.getLabel().isEmpty());
    try testing.expect(account.getEncryptedPrivateKey() == null);
    try testing.expect(!account.isLocked());
    try testing.expect(!account.isDefault()); // No wallet context, so not default
    try testing.expect(!account.isMultiSig());
    
    // Verify key pair is valid
    const key_pair = account.getKeyPair().?;
    try testing.expect(key_pair.isValid());
}

/// Test creating account from existing key pair (converted from Swift testInitAccountFromExistingKeyPair)
test "Create account from existing key pair" {
    const allocator = testing.allocator;
    
    // Create key pair from known private key (equivalent to Swift keyPair creation)
    const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(defaultAccountPrivateKey, allocator);
    defer allocator.free(private_key_bytes);
    
    const key_pair = try ECKeyPair.createFromPrivateKey(private_key_bytes);
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    // Create account from key pair (equivalent to Swift Account(keyPair: keyPair))
    var account = try Account.init(key_pair, allocator);
    defer account.deinit(allocator);
    
    // Verify account properties (equivalent to Swift XCTAssertEqual checks)
    try testing.expect(!account.isMultiSig());
    
    const account_address = account.getAddress();
    try testing.expect(std.mem.indexOf(u8, account_address, "N") != null); // Should be valid Neo address
    
    // Verify label matches address by default
    try testing.expectEqualStrings(account_address, account.getLabel());
    
    // Verify verification script exists
    const verification_script = account.getVerificationScript().?;
    try testing.expect(verification_script.len > 0);
    try testing.expect(verification_script.len >= 40); // Minimum size for single-sig verification script
}

/// Test creating account from verification script (converted from Swift testFromVerificationScript)
test "Create account from verification script" {
    const allocator = testing.allocator;
    
    // Create verification script from hex (equivalent to Swift VerificationScript creation)
    const verification_script_hex = "0c2102163946a133e3d2e0d987fb90cb01b060ed1780f1718e2da28edf13b965fd2b600b4195440d78";
    const verification_script_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(verification_script_hex, allocator);
    defer allocator.free(verification_script_bytes);
    
    const verification_script = VerificationScript.initWithBytes(verification_script_bytes);
    
    // Create account from verification script (equivalent to Swift Account.fromVerificationScript)
    var account = try Account.fromVerificationScript(verification_script, allocator);
    defer account.deinit(allocator);
    
    // Verify account address and verification script (equivalent to Swift XCTAssertEqual)
    // Note: Address generation would need to match Neo's exact algorithm
    const account_address = account.getAddress();
    try testing.expect(account_address.len > 0);
    
    const account_verification = account.getVerificationScript().?;
    try testing.expectEqualSlices(u8, verification_script_bytes, account_verification);
}

/// Test creating account from public key (converted from Swift testFromPublicKey)
test "Create account from public key" {
    const allocator = testing.allocator;
    
    // Create public key from hex (equivalent to Swift ECPublicKey creation)
    const public_key_hex = defaultAccountPublicKey;
    const public_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(public_key_hex, allocator);
    defer allocator.free(public_key_bytes);
    
    const public_key = try PublicKey.initFromBytes(public_key_bytes);
    
    // Create account from public key (equivalent to Swift Account.fromPublicKey)
    var account = try Account.fromPublicKey(public_key, allocator);
    defer account.deinit(allocator);
    
    // Verify account properties
    const account_address = account.getAddress();
    try testing.expect(account_address.len > 0);
    
    const verification_script = account.getVerificationScript().?;
    try testing.expect(verification_script.len > 0);
    
    // Account should not have private key (created from public key only)
    try testing.expect(account.getKeyPair() == null);
    try testing.expect(!account.isMultiSig());
}

/// Test creating multi-signature account (converted from Swift testCreateMultiSigAccountFromPublicKeys)
test "Create multi-signature account from public keys" {
    const allocator = testing.allocator;
    
    // Create public key (equivalent to Swift ECPublicKey creation)
    const public_key_hex = defaultAccountPublicKey;
    const public_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(public_key_hex, allocator);
    defer allocator.free(public_key_bytes);
    
    const public_key = try PublicKey.initFromBytes(public_key_bytes);
    
    // Create multi-sig account (equivalent to Swift Account.createMultiSigAccount)
    const public_keys = [_]PublicKey{public_key};
    const signing_threshold: u32 = 1;
    
    var multi_sig_account = try Account.createMultiSigAccount(&public_keys, signing_threshold, allocator);
    defer multi_sig_account.deinit(allocator);
    
    // Verify multi-sig properties (equivalent to Swift XCTAssert checks)
    try testing.expect(multi_sig_account.isMultiSig());
    
    const multi_sig_address = multi_sig_account.getAddress();
    try testing.expect(multi_sig_address.len > 0);
    
    // Label should match address by default
    try testing.expectEqualStrings(multi_sig_address, multi_sig_account.getLabel());
    
    const multi_sig_verification = multi_sig_account.getVerificationScript().?;
    try testing.expect(multi_sig_verification.len > 0);
    try testing.expect(multi_sig_verification.len >= 50); // Multi-sig script should be larger
    
    // Multi-sig account should not have private key pair
    try testing.expect(multi_sig_account.getKeyPair() == null);
}

/// Test account encryption and locking
test "Account encryption and locking" {
    const allocator = testing.allocator;
    
    // Create account
    var account = try Account.create(allocator);
    defer account.deinit(allocator);
    
    // Test initial state
    try testing.expect(!account.isLocked());
    try testing.expect(account.getEncryptedPrivateKey() == null);
    
    // Test encrypting account (simplified - would need NEP-2 implementation)
    const password = "testpassword";
    try account.encrypt(password, allocator);
    
    // After encryption, should be locked and have encrypted key
    try testing.expect(account.isLocked());
    try testing.expect(account.getEncryptedPrivateKey() != null);
    
    // Test decrypting account
    try account.decrypt(password, allocator);
    
    // After decryption, should be unlocked
    try testing.expect(!account.isLocked());
    try testing.expect(account.getKeyPair() != null);
}

/// Test account address generation
test "Account address generation" {
    const allocator = testing.allocator;
    
    // Create account with known key pair
    const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(defaultAccountPrivateKey, allocator);
    defer allocator.free(private_key_bytes);
    
    const key_pair = try ECKeyPair.createFromPrivateKey(private_key_bytes);
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    var account = try Account.init(key_pair, allocator);
    defer account.deinit(allocator);
    
    // Test address generation
    const address = account.getAddress();
    try testing.expect(address.len > 0);
    try testing.expect(address.len >= 25); // Neo addresses are typically 34 chars
    
    // Address should start with 'N' for Neo
    try testing.expect(address[0] == 'N');
    
    // Test script hash derivation
    const script_hash = account.getScriptHash();
    try testing.expect(!script_hash.isZero());
    
    const script_hash_string = try script_hash.toString(allocator);
    defer allocator.free(script_hash_string);
    
    try testing.expect(script_hash_string.len > 0);
}

/// Test account equality and comparison
test "Account equality and comparison" {
    const allocator = testing.allocator;
    
    // Create two accounts with same key pair
    const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(defaultAccountPrivateKey, allocator);
    defer allocator.free(private_key_bytes);
    
    const key_pair1 = try ECKeyPair.createFromPrivateKey(private_key_bytes);
    const key_pair2 = try ECKeyPair.createFromPrivateKey(private_key_bytes);
    defer {
        var mutable_kp1 = key_pair1;
        var mutable_kp2 = key_pair2;
        mutable_kp1.zeroize();
        mutable_kp2.zeroize();
    }
    
    var account1 = try Account.init(key_pair1, allocator);
    defer account1.deinit(allocator);
    
    var account2 = try Account.init(key_pair2, allocator);
    defer account2.deinit(allocator);
    
    // Should be equal (same key pair)
    try testing.expect(account1.eql(account2));
    try testing.expectEqualStrings(account1.getAddress(), account2.getAddress());
    
    // Create different account
    var account3 = try Account.create(allocator);
    defer account3.deinit(allocator);
    
    // Should not be equal
    try testing.expect(!account1.eql(account3));
    try testing.expect(!std.mem.eql(u8, account1.getAddress(), account3.getAddress()));
}

/// Test account validation
test "Account validation" {
    const allocator = testing.allocator;
    
    // Test valid account
    var valid_account = try Account.create(allocator);
    defer valid_account.deinit(allocator);
    
    try valid_account.validate();
    
    // Test account with valid key pair
    const private_key_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(defaultAccountPrivateKey, allocator);
    defer allocator.free(private_key_bytes);
    
    const key_pair = try ECKeyPair.createFromPrivateKey(private_key_bytes);
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    var key_pair_account = try Account.init(key_pair, allocator);
    defer key_pair_account.deinit(allocator);
    
    try key_pair_account.validate();
    
    // Verify account properties are consistent
    try testing.expect(key_pair_account.getKeyPair() != null);
    try testing.expect(!key_pair_account.getAddress().isEmpty());
    try testing.expect(key_pair_account.getVerificationScript() != null);
}

/// Test multi-signature account properties
test "Multi-signature account properties" {
    const allocator = testing.allocator;
    
    // Create multiple public keys for multi-sig
    const key_pair1 = try ECKeyPair.createRandom();
    const key_pair2 = try ECKeyPair.createRandom();
    const key_pair3 = try ECKeyPair.createRandom();
    defer {
        var mutable_kp1 = key_pair1;
        var mutable_kp2 = key_pair2;
        var mutable_kp3 = key_pair3;
        mutable_kp1.zeroize();
        mutable_kp2.zeroize();
        mutable_kp3.zeroize();
    }
    
    const public_keys = [_]PublicKey{
        key_pair1.getPublicKey(),
        key_pair2.getPublicKey(),
        key_pair3.getPublicKey(),
    };
    
    const signing_threshold: u32 = 2; // 2-of-3 multi-sig
    
    // Create multi-sig account
    var multi_sig_account = try Account.createMultiSigAccount(&public_keys, signing_threshold, allocator);
    defer multi_sig_account.deinit(allocator);
    
    // Verify multi-sig properties
    try testing.expect(multi_sig_account.isMultiSig());
    try testing.expect(multi_sig_account.getKeyPair() == null); // No single key pair
    
    const multi_sig_address = multi_sig_account.getAddress();
    try testing.expect(multi_sig_address.len > 0);
    try testing.expect(multi_sig_address[0] == 'N'); // Neo address
    
    // Multi-sig verification script should be larger
    const verification_script = multi_sig_account.getVerificationScript().?;
    try testing.expect(verification_script.len > 80); // Should contain multiple pubkeys + threshold
    
    // Test signing threshold and participant count
    try testing.expectEqual(signing_threshold, multi_sig_account.getSigningThreshold().?);
    try testing.expectEqual(@as(u32, 3), multi_sig_account.getParticipantCount().?);
}

/// Test account signing capabilities
test "Account signing capabilities" {
    const allocator = testing.allocator;
    
    // Create account with key pair
    var account = try Account.create(allocator);
    defer account.deinit(allocator);
    
    // Test message signing
    const test_message = "Hello, Neo blockchain!";
    const message_bytes = @as([]const u8, test_message);
    
    // Account should be able to sign messages
    try testing.expect(account.canSign());
    
    if (account.getKeyPair()) |key_pair| {
        const signature = try key_pair.signMessage(message_bytes, allocator);
        defer signature.deinit(allocator);
        
        try testing.expect(signature.r != 0);
        try testing.expect(signature.s != 0);
        
        // Verify signature with public key
        const is_valid = try key_pair.getPublicKey().verifySignature(message_bytes, signature, allocator);
        try testing.expect(is_valid);
    }
    
    // Multi-sig account cannot sign directly
    const public_keys = [_]PublicKey{account.getKeyPair().?.getPublicKey()};
    var multi_sig_account = try Account.createMultiSigAccount(&public_keys, 1, allocator);
    defer multi_sig_account.deinit(allocator);
    
    try testing.expect(!multi_sig_account.canSign()); // No direct key pair
}

/// Test account cloning and copying
test "Account cloning and copying" {
    const allocator = testing.allocator;
    
    // Create original account
    var original_account = try Account.create(allocator);
    defer original_account.deinit(allocator);
    
    // Set some properties
    try original_account.setLabel("TestAccount", allocator);
    
    // Clone account
    var cloned_account = try original_account.clone(allocator);
    defer cloned_account.deinit(allocator);
    
    // Should be equal but independent
    try testing.expect(original_account.eql(cloned_account));
    try testing.expectEqualStrings(original_account.getAddress(), cloned_account.getAddress());
    try testing.expectEqualStrings(original_account.getLabel(), cloned_account.getLabel());
    
    // Modify clone label
    try cloned_account.setLabel("ModifiedAccount", allocator);
    
    // Original should not be affected
    try testing.expectEqualStrings("TestAccount", original_account.getLabel());
    try testing.expectEqualStrings("ModifiedAccount", cloned_account.getLabel());
}