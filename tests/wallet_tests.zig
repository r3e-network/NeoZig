//! Wallet tests converted from Swift
//!
//! Complete conversion of NeoSwift wallet test suite.

const std = @import("std");


const neo = @import("neo-zig");

// Tests wallet creation (converted from Swift WalletTests)
test "wallet creation and default properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = neo.wallet.Wallet.init(allocator);
    defer wallet.deinit();
    
    // Test default properties (matches Swift defaults)
    try testing.expectEqualStrings(neo.wallet.Wallet.DEFAULT_WALLET_NAME, wallet.getName());
    try testing.expectEqualStrings(neo.wallet.Wallet.CURRENT_VERSION, wallet.getVersion());
    
    // Test scrypt params default (matches Swift ScryptParams.DEFAULT)
    const scrypt_params = wallet.getScryptParams();
    try testing.expectEqual(@as(u32, 16384), scrypt_params.n);
    try testing.expectEqual(@as(u32, 8), scrypt_params.r);
    try testing.expectEqual(@as(u32, 8), scrypt_params.p);
}

// Tests wallet configuration (converted from Swift wallet configuration tests)
test "wallet name and version configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = neo.wallet.Wallet.init(allocator);
    defer wallet.deinit();
    
    // Test name setting (equivalent to Swift name(_ name: String))
    _ = wallet.name("Custom Wallet Name");
    try testing.expectEqualStrings("Custom Wallet Name", wallet.getName());
    
    // Test version setting (equivalent to Swift version(_ version: String))
    _ = wallet.version("3.1");
    try testing.expectEqualStrings("3.1", wallet.getVersion());
    
    // Test scrypt params setting (equivalent to Swift scryptParams method)
    const custom_params = neo.wallet.ScryptParams.init(1024, 4, 4);
    _ = wallet.scryptParams(custom_params);
    
    const updated_params = wallet.getScryptParams();
    try testing.expectEqual(@as(u32, 1024), updated_params.n);
    try testing.expectEqual(@as(u32, 4), updated_params.r);
    try testing.expectEqual(@as(u32, 4), updated_params.p);
}

// Tests account management (converted from Swift account management tests)
test "wallet account management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = neo.wallet.Wallet.init(allocator);
    defer wallet.deinit();
    
    // Create account (equivalent to Swift createAccount)
    const account = try wallet.createAccount("Test Account");
    
    // Verify account was added (matches Swift account tests)
    try testing.expect(wallet.containsAccount(account));
    try testing.expectEqual(@as(u32, 1), wallet.getAccountCount());
    
    // Test default account behavior (matches Swift defaultAccount logic)
    try testing.expect(wallet.isDefault(account));
    
    const default_account = wallet.getDefaultAccount();
    try testing.expect(default_account != null);
    try testing.expect(default_account.?.getScriptHash().eql(account.getScriptHash()));
}

// Tests account lookup (converted from Swift account lookup tests)
test "wallet account lookup and retrieval" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = neo.wallet.Wallet.init(allocator);
    defer wallet.deinit();
    
    const account = try wallet.createAccount("Lookup Test Account");
    const script_hash = account.getScriptHash();
    
    // Test account retrieval by hash (equivalent to Swift getAccount)
    const found_account = wallet.getAccount(script_hash);
    try testing.expect(found_account != null);
    try testing.expect(found_account.?.getScriptHash().eql(script_hash));
    
    // Test account existence check (equivalent to Swift containsAccount)
    try testing.expect(wallet.containsAccountByHash(script_hash));
    
    // Test non-existent account
    const random_hash = neo.Hash160.ZERO;
    if (!script_hash.eql(random_hash)) {
        try testing.expect(!wallet.containsAccountByHash(random_hash));
        try testing.expect(wallet.getAccount(random_hash) == null);
    }
}

// Tests account removal (converted from Swift account removal tests)
test "wallet account removal" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = neo.wallet.Wallet.init(allocator);
    defer wallet.deinit();
    
    const account1 = try wallet.createAccount("Account 1");
    const account2 = try wallet.createAccount("Account 2");
    
    try testing.expectEqual(@as(u32, 2), wallet.getAccountCount());
    
    // Remove account (equivalent to Swift removeAccount)
    _ = try wallet.removeAccount(account1);
    
    try testing.expectEqual(@as(u32, 1), wallet.getAccountCount());
    try testing.expect(!wallet.containsAccount(account1));
    try testing.expect(wallet.containsAccount(account2));
    
    // Test default account update after removal
    if (wallet.isDefault(account1)) {
        // Default should have moved to remaining account
        try testing.expect(wallet.isDefault(account2));
    }
}

// Tests default account management (converted from Swift default account tests)
test "wallet default account management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = neo.wallet.Wallet.init(allocator);
    defer wallet.deinit();
    
    const account1 = try wallet.createAccount("Account 1");
    const account2 = try wallet.createAccount("Account 2");
    
    // First account should be default
    try testing.expect(wallet.isDefault(account1));
    try testing.expect(!wallet.isDefault(account2));
    
    // Change default account (equivalent to Swift defaultAccount method)
    _ = try wallet.defaultAccount(account2);
    
    try testing.expect(!wallet.isDefault(account1));
    try testing.expect(wallet.isDefault(account2));
    
    const default_account = wallet.getDefaultAccount();
    try testing.expect(default_account != null);
    try testing.expect(default_account.?.getScriptHash().eql(account2.getScriptHash()));
}

// Tests account import (converted from Swift import tests)
test "wallet account import from private key" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = neo.wallet.Wallet.init(allocator);
    defer wallet.deinit();
    
    // Generate test private key
    const private_key = neo.crypto.generatePrivateKey();
    
    // Import account (equivalent to Swift importAccount methods)
    const imported_account = try wallet.importAccount(private_key, "test_password", "Imported Account");
    
    try testing.expect(wallet.containsAccount(imported_account));
    try testing.expectEqual(@as(u32, 1), wallet.getAccountCount());
    
    // Test that account has encrypted private key
    try testing.expect(imported_account.hasPrivateKey());
}

// Tests WIF import (converted from Swift WIF import tests)
test "wallet account import from WIF" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = neo.wallet.Wallet.init(allocator);
    defer wallet.deinit();
    
    // Generate private key and encode to WIF
    const private_key = neo.crypto.generatePrivateKey();
    const wif_string = try neo.crypto.encodeWIF(private_key, true, .mainnet, allocator);
    defer allocator.free(wif_string);
    
    // Import from WIF (equivalent to Swift importAccountFromWIF)
    const imported_account = try wallet.importAccountFromWIF(wif_string, "test_password", "WIF Account");
    
    try testing.expect(wallet.containsAccount(imported_account));
    try testing.expect(imported_account.hasPrivateKey());
    
    // Verify the imported key matches original
    const imported_private_key = try imported_account.getPrivateKey("test_password");
    try testing.expect(imported_private_key.eql(private_key));
}

// Tests error conditions (converted from Swift error tests)
test "wallet error handling" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var wallet = neo.wallet.Wallet.init(allocator);
    defer wallet.deinit();
    
    // Test setting non-existent account as default (equivalent to Swift error test)
    const non_existent_hash = neo.Hash160.ZERO;
    try testing.expectError(
        neo.errors.NeoError.IllegalArgument, 
        wallet.defaultAccountByHash(non_existent_hash)
    );
    
    // Test removing non-existent account
    try testing.expectError(
        neo.errors.WalletError.AccountNotFound,
        wallet.removeAccountByHash(non_existent_hash)
    );
    
    // Test duplicate account addition
    const account = try wallet.createAccount("Test Account");
    try testing.expectError(
        neo.errors.NeoError.IllegalArgument,
        wallet.addAccount(account)
    );
}
