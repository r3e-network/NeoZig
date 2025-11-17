//! Signer Tests
//!
//! Complete conversion from NeoSwift SignerTests.swift
//! Tests signer creation, witness scopes, and configuration.

const std = @import("std");
const ArrayList = std.array_list.Managed;


const testing = std.testing;
const Account = @import("../../src/wallet/account.zig").Account;
const AccountSigner = @import("../../src/transaction/account_signer.zig").AccountSigner;
const Signer = @import("../../src/transaction/signer.zig").Signer;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;
const WitnessScope = @import("../../src/transaction/witness_scope_complete.zig").WitnessScope;
const ECKeyPair = @import("../../src/crypto/ec_key_pair.zig").ECKeyPair;
const PublicKey = @import("../../src/crypto/keys.zig").PublicKey;
const WIF = @import("../../src/crypto/wif.zig").WIF;

/// Setup test data (equivalent to Swift test class setup)
fn createTestAccount(allocator: std.mem.Allocator) !Account {
    // Create test account from WIF (equivalent to Swift fromWIF setup)
    const test_wif = "Kzt94tAAiZSgH7Yt4i25DW6jJFprZFPSqTgLr5dWmWgKDKCjXMfZ";
    const private_key = try WIF.toPrivateKey(test_wif, allocator);
    defer allocator.free(private_key);
    
    const key_pair = try ECKeyPair.createFromPrivateKey(private_key);
    return try Account.init(key_pair, allocator);
}

fn createTestContracts() ![2]Hash160 {
    // Equivalent to Swift contract1 and contract2 setup
    const contract1_script = [_]u8{ 0xd8, 0x02, 0xa4, 0x01 };
    const contract2_script = [_]u8{ 0xc5, 0x03, 0xb1, 0x12 };
    
    return [2]Hash160{
        try Hash160.fromScript(&contract1_script),
        try Hash160.fromScript(&contract2_script),
    };
}

fn createTestGroupKeys(allocator: std.mem.Allocator) ![2]PublicKey {
    // Equivalent to Swift groupPubKey1 and groupPubKey2 setup
    const key1_hex = "0306d3e7f18e6dd477d34ce3cfeca172a877f3c907cc6c2b66c295d1fcc76ff8f7";
    const key2_hex = "02958ab88e4cea7ae1848047daeb8883daf5fdf5c1301dbbfe973f0a29fe75de60";
    
    const key1_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(key1_hex, allocator);
    defer allocator.free(key1_bytes);
    
    const key2_bytes = try @import("../../src/utils/string_extensions.zig").StringUtils.bytesFromHex(key2_hex, allocator);
    defer allocator.free(key2_bytes);
    
    return [2]PublicKey{
        try PublicKey.initFromBytes(key1_bytes),
        try PublicKey.initFromBytes(key2_bytes),
    };
}

/// Test creating signer with CalledByEntry scope (converted from Swift testCreateSignerWithCallByEntryWitnessScope)
test "Create signer with CalledByEntry witness scope" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    const account_script_hash = account.getScriptHash();
    
    // Create signer (equivalent to Swift AccountSigner.calledByEntry)
    var signer = try AccountSigner.calledByEntry(account, allocator);
    defer signer.deinit(allocator);
    
    // Verify signer properties (equivalent to Swift XCTAssertEqual checks)
    try testing.expect(signer.getScriptHash().eql(account_script_hash));
    try testing.expect(signer.getWitnessScope().isCalledByEntry());
    try testing.expectEqual(@as(usize, 0), signer.getAllowedContracts().len);
    try testing.expectEqual(@as(usize, 0), signer.getAllowedGroups().len);
}

/// Test creating signer with Global scope (converted from Swift testCreateSignerWithGlobalWitnessScope)
test "Create signer with Global witness scope" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    const account_script_hash = account.getScriptHash();
    
    // Create global signer (equivalent to Swift AccountSigner.global)
    var signer = try AccountSigner.global(account, allocator);
    defer signer.deinit(allocator);
    
    // Verify signer properties (equivalent to Swift XCTAssertEqual checks)
    try testing.expect(signer.getScriptHash().eql(account_script_hash));
    try testing.expect(signer.getWitnessScope().isGlobal());
    try testing.expectEqual(@as(usize, 0), signer.getAllowedContracts().len);
    try testing.expectEqual(@as(usize, 0), signer.getAllowedGroups().len);
}

/// Test valid signer with allowed contracts (converted from Swift testBuildValidSigner1)
test "Build valid signer with allowed contracts" {
    const allocator = testing.allocator;
    
    // Create test account and contracts
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    const test_contracts = try createTestContracts();
    const contract1 = test_contracts[0];
    const contract2 = test_contracts[1];
    
    const account_script_hash = account.getScriptHash();
    
    // Create signer with allowed contracts (equivalent to Swift setAllowedContracts)
    var signer = try AccountSigner.calledByEntry(account, allocator);
    defer signer.deinit(allocator);
    
    const allowed_contracts = [_]Hash160{ contract1, contract2 };
    try signer.setAllowedContracts(&allowed_contracts, allocator);
    
    // Verify signer configuration (equivalent to Swift XCTAssertEqual checks)
    try testing.expect(signer.getScriptHash().eql(account_script_hash));
    
    // Should have both CalledByEntry and CustomContracts scopes
    try testing.expect(signer.hasScope(WitnessScope.CalledByEntry));
    try testing.expect(signer.hasScope(WitnessScope.CustomContracts));
    
    // Verify allowed contracts
    const configured_contracts = signer.getAllowedContracts();
    try testing.expectEqual(@as(usize, 2), configured_contracts.len);
    try testing.expect(configured_contracts[0].eql(contract1) or configured_contracts[0].eql(contract2));
    try testing.expect(configured_contracts[1].eql(contract1) or configured_contracts[1].eql(contract2));
    
    // Should have no allowed groups
    try testing.expectEqual(@as(usize, 0), signer.getAllowedGroups().len);
}

/// Test valid signer with None scope converted to CustomContracts (converted from Swift testBuildValidSigner2)
test "Build valid signer from None scope to CustomContracts" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    const test_contracts = try createTestContracts();
    const contract1 = test_contracts[0];
    const contract2 = test_contracts[1];
    
    const account_script_hash = account.getScriptHash();
    
    // Create signer with None scope (equivalent to Swift AccountSigner.none)
    var signer = try AccountSigner.none(account, allocator);
    defer signer.deinit(allocator);
    
    // Add allowed contracts (should convert None to CustomContracts)
    const allowed_contracts = [_]Hash160{ contract1, contract2 };
    try signer.setAllowedContracts(&allowed_contracts, allocator);
    
    // Verify signer configuration (equivalent to Swift XCTAssertEqual checks)
    try testing.expect(signer.getScriptHash().eql(account_script_hash));
    
    // Should have CustomContracts scope (None should be replaced)
    try testing.expect(signer.hasScope(WitnessScope.CustomContracts));
    try testing.expect(!signer.hasScope(WitnessScope.None));
    
    // Verify allowed contracts
    const configured_contracts = signer.getAllowedContracts();
    try testing.expectEqual(@as(usize, 2), configured_contracts.len);
    
    // Should have no allowed groups
    try testing.expectEqual(@as(usize, 0), signer.getAllowedGroups().len);
}

/// Test signer with allowed groups
test "Build signer with allowed groups" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    const test_groups = try createTestGroupKeys(allocator);
    const group1 = test_groups[0];
    const group2 = test_groups[1];
    
    // Create signer with allowed groups
    var signer = try AccountSigner.none(account, allocator);
    defer signer.deinit(allocator);
    
    const allowed_groups = [_]PublicKey{ group1, group2 };
    try signer.setAllowedGroups(&allowed_groups, allocator);
    
    // Verify signer configuration
    try testing.expect(signer.hasScope(WitnessScope.CustomGroups));
    try testing.expect(!signer.hasScope(WitnessScope.None));
    
    // Verify allowed groups
    const configured_groups = signer.getAllowedGroups();
    try testing.expectEqual(@as(usize, 2), configured_groups.len);
    
    // Should have no allowed contracts
    try testing.expectEqual(@as(usize, 0), signer.getAllowedContracts().len);
}

/// Test signer scope combinations
test "Signer scope combinations" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    const test_contracts = try createTestContracts();
    const test_groups = try createTestGroupKeys(allocator);
    
    // Create signer with multiple scope elements
    var signer = try AccountSigner.calledByEntry(account, allocator);
    defer signer.deinit(allocator);
    
    // Add both contracts and groups
    const allowed_contracts = [_]Hash160{test_contracts[0]};
    const allowed_groups = [_]PublicKey{test_groups[0]};
    
    try signer.setAllowedContracts(&allowed_contracts, allocator);
    try signer.setAllowedGroups(&allowed_groups, allocator);
    
    // Verify multiple scopes are configured
    try testing.expect(signer.hasScope(WitnessScope.CalledByEntry));
    try testing.expect(signer.hasScope(WitnessScope.CustomContracts));
    try testing.expect(signer.hasScope(WitnessScope.CustomGroups));
    
    // Verify both allowed contracts and groups are configured
    try testing.expectEqual(@as(usize, 1), signer.getAllowedContracts().len);
    try testing.expectEqual(@as(usize, 1), signer.getAllowedGroups().len);
}

/// Test global scope restrictions
test "Global scope restrictions" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    const test_contracts = try createTestContracts();
    
    // Create global signer
    var global_signer = try AccountSigner.global(account, allocator);
    defer global_signer.deinit(allocator);
    
    // Attempting to set allowed contracts on global scope should fail
    const allowed_contracts = [_]Hash160{test_contracts[0]};
    
    // Global scope should reject adding allowed contracts
    try testing.expectError(
        @import("../../src/transaction/transaction_error.zig").TransactionError.SignerConfiguration,
        global_signer.setAllowedContracts(&allowed_contracts, allocator)
    );
    
    // Global scope should reject adding allowed groups
    const test_groups = try createTestGroupKeys(allocator);
    const allowed_groups = [_]PublicKey{test_groups[0]};
    
    try testing.expectError(
        @import("../../src/transaction/transaction_error.zig").TransactionError.SignerConfiguration,
        global_signer.setAllowedGroups(&allowed_groups, allocator)
    );
}

/// Test signer validation
test "Signer validation" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    // Test valid signer
    var valid_signer = try AccountSigner.calledByEntry(account, allocator);
    defer valid_signer.deinit(allocator);
    
    try valid_signer.validate();
    
    // Test signer can sign for authorized contracts
    const test_contracts = try createTestContracts();
    const allowed_contracts = [_]Hash160{test_contracts[0]};
    
    try valid_signer.setAllowedContracts(&allowed_contracts, allocator);
    
    // Should be able to sign for allowed contract
    try testing.expect(valid_signer.canSignFor(test_contracts[0]));
    
    // Should not be able to sign for non-allowed contract  
    try testing.expect(!valid_signer.canSignFor(test_contracts[1]));
}

/// Test signer equality and hashing
test "Signer equality and hashing" {
    const allocator = testing.allocator;
    
    // Create test accounts
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    // Create identical signers
    var signer1 = try AccountSigner.calledByEntry(account, allocator);
    defer signer1.deinit(allocator);
    
    var signer2 = try AccountSigner.calledByEntry(account, allocator);
    defer signer2.deinit(allocator);
    
    // Create different signer
    var signer3 = try AccountSigner.global(account, allocator);
    defer signer3.deinit(allocator);
    
    // Test equality
    try testing.expect(signer1.eql(signer2));
    try testing.expect(!signer1.eql(signer3));
    
    // Test hashing
    const hash1 = signer1.hash();
    const hash2 = signer2.hash();
    const hash3 = signer3.hash();
    
    try testing.expectEqual(hash1, hash2); // Same signers should have same hash
    try testing.expectNotEqual(hash1, hash3); // Different signers should have different hash
}

/// Test signer estimated witness size
test "Signer estimated witness size" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    // Test basic signer size
    var basic_signer = try AccountSigner.calledByEntry(account, allocator);
    defer basic_signer.deinit(allocator);
    
    const basic_size = basic_signer.getEstimatedWitnessSize();
    try testing.expect(basic_size > 60); // Should be reasonable size for signature + verification
    
    // Test signer with allowed contracts (should be larger)
    const test_contracts = try createTestContracts();
    const allowed_contracts = [_]Hash160{test_contracts[0]};
    
    try basic_signer.setAllowedContracts(&allowed_contracts, allocator);
    
    const enhanced_size = basic_signer.getEstimatedWitnessSize();
    try testing.expect(enhanced_size > basic_size); // Should be larger with custom scope
}

/// Test maximum signer limits
test "Signer maximum limits validation" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    var signer = try AccountSigner.none(account, allocator);
    defer signer.deinit(allocator);
    
    // Test maximum allowed contracts limit
    // Create array with more than MAX_SIGNER_SUBITEMS contracts
    var too_many_contracts = ArrayList(Hash160).init(allocator);
    defer too_many_contracts.deinit();
    
    var i: usize = 0;
    while (i <= @import("../../src/core/constants.zig").MAX_SIGNER_SUBITEMS) : (i += 1) {
        const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
        try too_many_contracts.append(contract_hash);
    }
    
    // Should fail with too many contracts
    try testing.expectError(
        @import("../../src/transaction/transaction_error.zig").TransactionError.SignerConfiguration,
        signer.setAllowedContracts(too_many_contracts.items, allocator)
    );
}

/// Test signer serialization and cloning
test "Signer serialization and cloning" {
    const allocator = testing.allocator;
    
    // Create test account
    var account = try createTestAccount(allocator);
    defer account.deinit(allocator);
    
    // Create configured signer
    var original_signer = try AccountSigner.calledByEntry(account, allocator);
    defer original_signer.deinit(allocator);
    
    const test_contracts = try createTestContracts();
    const allowed_contracts = [_]Hash160{test_contracts[0]};
    try original_signer.setAllowedContracts(&allowed_contracts, allocator);
    
    // Test cloning
    var cloned_signer = try original_signer.clone(allocator);
    defer cloned_signer.deinit(allocator);
    
    // Verify clone is identical
    try testing.expect(original_signer.eql(cloned_signer));
    try testing.expectEqual(original_signer.getAllowedContracts().len, cloned_signer.getAllowedContracts().len);
    
    // Test that clone has independent memory
    const additional_contracts = [_]Hash160{test_contracts[1]};
    try cloned_signer.setAllowedContracts(&additional_contracts, allocator);
    
    // Original should not be affected
    try testing.expectEqual(@as(usize, 1), original_signer.getAllowedContracts().len);
    try testing.expectEqual(@as(usize, 2), cloned_signer.getAllowedContracts().len);
}