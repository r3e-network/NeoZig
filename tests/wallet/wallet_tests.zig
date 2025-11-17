//! Wallet Tests
//!
//! Complete conversion from NeoSwift WalletTests.swift
//! Tests wallet creation, account management, and validation.

const std = @import("std");


const testing = std.testing;
const Wallet = @import("../../src/wallet/neo_wallet.zig").Wallet;
const Account = @import("../../src/wallet/account.zig").Account;

/// Test creating default wallet (converted from Swift testCreateDefaultWallet)
test "Create default wallet" {
    const allocator = testing.allocator;
    
    // Create default wallet (equivalent to Swift Wallet.create())
    var wallet = try Wallet.create(allocator);
    defer wallet.deinit(allocator);
    
    // Verify wallet properties (equivalent to Swift XCTAssertEqual checks)
    try testing.expectEqualStrings("NeoSwiftWallet", wallet.getName());
    try testing.expectEqualStrings(Wallet.CURRENT_VERSION, wallet.getVersion());
    try testing.expect(!wallet.getAccounts().isEmpty());
    
    // Should have at least one account
    try testing.expect(wallet.getAccountCount() > 0);
    
    // Should have a default account
    try testing.expect(wallet.getDefaultAccount() != null);
}

/// Test creating wallet with accounts (converted from Swift testCreateWalletWithAccounts)
test "Create wallet with accounts" {
    const allocator = testing.allocator;
    
    // Create test accounts (equivalent to Swift Account.create())
    var account1 = try Account.create(allocator);
    defer account1.deinit(allocator);
    
    var account2 = try Account.create(allocator);
    defer account2.deinit(allocator);
    
    // Create wallet with accounts (equivalent to Swift Wallet.withAccounts)
    const accounts = [_]*Account{ &account1, &account2 };
    var wallet = try Wallet.withAccounts(&accounts, allocator);
    defer wallet.deinit(allocator);
    
    // Verify wallet properties (equivalent to Swift XCTAssertIdentical and XCTAssertEqual)
    const default_account = wallet.getDefaultAccount().?;
    try testing.expect(default_account.eql(account1)); // First account should be default
    
    try testing.expectEqual(@as(usize, 2), wallet.getAccountCount());
    
    // Verify both accounts are in wallet (equivalent to Swift contains checks)
    try testing.expect(wallet.containsAccount(account1.getScriptHash()));
    try testing.expect(wallet.containsAccount(account2.getScriptHash()));
}

/// Test creating wallet with no accounts (converted from Swift testCreateWalletWithAccounts_noAccounts)
test "Create wallet with no accounts should fail" {
    const allocator = testing.allocator;
    
    // Empty accounts array (equivalent to Swift Wallet.withAccounts([]))
    const empty_accounts = [_]*Account{};
    
    // Should throw error for no accounts (equivalent to Swift XCTAssertThrowsError)
    try testing.expectError(
        @import("../../src/wallet/wallet_error.zig").WalletError.NoAccountsProvided,
        Wallet.withAccounts(&empty_accounts, allocator)
    );
}

/// Test checking if account is default (converted from Swift testIsDefault_account)
test "Check if account is default" {
    const allocator = testing.allocator;
    
    // Create account and wallet (equivalent to Swift test setup)
    var account = try Account.create(allocator);
    defer account.deinit(allocator);
    
    const accounts = [_]*Account{&account};
    var wallet = try Wallet.withAccounts(&accounts, allocator);
    defer wallet.deinit(allocator);
    
    // Verify account is default (equivalent to Swift XCTAssert(wallet.isDefault(account)))
    try testing.expect(wallet.isDefault(account));
    
    // Create another account that should not be default
    var other_account = try Account.create(allocator);
    defer other_account.deinit(allocator);
    
    try testing.expect(!wallet.isDefault(other_account));
}

/// Test wallet holds account (converted from Swift testHoldsAccount)
test "Wallet holds account verification" {
    const allocator = testing.allocator;
    
    // Create account and wallet (equivalent to Swift test setup)
    var account = try Account.create(allocator);
    defer account.deinit(allocator);
    
    var wallet = try Wallet.create(allocator);
    defer wallet.deinit(allocator);
    
    // Add account to wallet (equivalent to Swift wallet.addAccounts([account]))
    const accounts_to_add = [_]*Account{&account};
    try wallet.addAccounts(&accounts_to_add);
    
    // Verify wallet holds account (equivalent to Swift XCTAssert(wallet.holdsAccount(account.getScriptHash())))
    try testing.expect(try wallet.holdsAccount(account.getScriptHash()));
    
    // Test with account not in wallet
    var other_account = try Account.create(allocator);
    defer other_account.deinit(allocator);
    
    try testing.expect(!(try wallet.holdsAccount(other_account.getScriptHash())));
}

/// Test wallet account management
test "Wallet account management" {
    const allocator = testing.allocator;
    
    // Create wallet with initial account
    var wallet = try Wallet.create(allocator);
    defer wallet.deinit(allocator);
    
    const initial_count = wallet.getAccountCount();
    try testing.expect(initial_count > 0);
    
    // Add more accounts
    var new_account1 = try Account.create(allocator);
    defer new_account1.deinit(allocator);
    
    var new_account2 = try Account.create(allocator);
    defer new_account2.deinit(allocator);
    
    const new_accounts = [_]*Account{ &new_account1, &new_account2 };
    try wallet.addAccounts(&new_accounts);
    
    // Verify account count increased
    try testing.expectEqual(initial_count + 2, wallet.getAccountCount());
    
    // Verify new accounts are in wallet
    try testing.expect(wallet.containsAccount(new_account1.getScriptHash()));
    try testing.expect(wallet.containsAccount(new_account2.getScriptHash()));
}

/// Test wallet account retrieval
test "Wallet account retrieval" {
    const allocator = testing.allocator;
    
    // Create accounts
    var account1 = try Account.create(allocator);
    defer account1.deinit(allocator);
    
    var account2 = try Account.create(allocator);
    defer account2.deinit(allocator);
    
    // Create wallet with accounts
    const accounts = [_]*Account{ &account1, &account2 };
    var wallet = try Wallet.withAccounts(&accounts, allocator);
    defer wallet.deinit(allocator);
    
    // Test getting account by script hash
    const retrieved_account1 = try wallet.getAccount(account1.getScriptHash());
    try testing.expect(retrieved_account1.eql(account1));
    
    const retrieved_account2 = try wallet.getAccount(account2.getScriptHash());
    try testing.expect(retrieved_account2.eql(account2));
    
    // Test getting non-existent account
    var non_existent_account = try Account.create(allocator);
    defer non_existent_account.deinit(allocator);
    
    try testing.expectError(
        @import("../../src/wallet/wallet_error.zig").WalletError.AccountNotFound,
        wallet.getAccount(non_existent_account.getScriptHash())
    );
}

/// Test wallet validation
test "Wallet validation" {
    const allocator = testing.allocator;
    
    // Test valid wallet
    var valid_wallet = try Wallet.create(allocator);
    defer valid_wallet.deinit(allocator);
    
    try valid_wallet.validate();
    
    // Test wallet properties
    try testing.expect(!valid_wallet.getName().isEmpty());
    try testing.expect(!valid_wallet.getVersion().isEmpty());
    try testing.expect(valid_wallet.getAccountCount() > 0);
    try testing.expect(valid_wallet.getDefaultAccount() != null);
}

/// Test wallet encryption and decryption
test "Wallet encryption and decryption" {
    const allocator = testing.allocator;
    
    // Create wallet
    var wallet = try Wallet.create(allocator);
    defer wallet.deinit(allocator);
    
    const password = "TestWalletPassword123";
    
    // Test wallet encryption
    try wallet.encrypt(password, allocator);
    
    // After encryption, accounts should be locked
    const accounts = wallet.getAccounts();
    for (accounts.items) |account| {
        try testing.expect(account.isLocked());
    }
    
    // Test wallet decryption
    try wallet.decrypt(password, allocator);
    
    // After decryption, accounts should be unlocked
    for (accounts.items) |account| {
        try testing.expect(!account.isLocked());
    }
}

/// Test wallet NEP-6 operations
test "Wallet NEP-6 operations" {
    const allocator = testing.allocator;
    
    // Create wallet
    var wallet = try Wallet.create(allocator);
    defer wallet.deinit(allocator);
    
    // Test NEP-6 export
    const password = "ExportPassword123";
    const nep6_json = try wallet.toNEP6(password, allocator);
    defer allocator.free(nep6_json);
    
    try testing.expect(nep6_json.len > 0);
    try testing.expect(std.mem.indexOf(u8, nep6_json, "version") != null);
    try testing.expect(std.mem.indexOf(u8, nep6_json, "accounts") != null);
    
    // Test NEP-6 import
    var imported_wallet = try Wallet.fromNEP6(nep6_json, password, allocator);
    defer imported_wallet.deinit(allocator);
    
    // Should have same number of accounts
    try testing.expectEqual(wallet.getAccountCount(), imported_wallet.getAccountCount());
}