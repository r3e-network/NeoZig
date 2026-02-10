//! Wallet Tests
//!
//!
//! Tests wallet creation, account management, and validation.

const std = @import("std");

const testing = std.testing;
const Wallet = @import("../../src/wallet/neo_wallet.zig").Wallet;
const CompleteNEP6Wallet = @import("../../src/wallet/nep6_complete.zig").CompleteNEP6Wallet;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;
const errors = @import("../../src/core/errors.zig");
const json_utils = @import("../../src/utils/json_utils.zig");

// /// Test creating default wallet
test "Create default wallet" {
    const allocator = testing.allocator;

    // Create wallet and default account
    var wallet = Wallet.init(allocator);
    defer wallet.deinit();
    _ = try wallet.createAccount("Default Account");

    // Verify wallet properties
    try testing.expectEqualStrings("NeoWallet", wallet.getName());
    try testing.expectEqualStrings(Wallet.CURRENT_VERSION, wallet.getVersion());
    try testing.expect(wallet.getAccountCount() > 0);

    // Should have a default account
    try testing.expect(wallet.getDefaultAccount() != null);
}

// /// Test creating wallet with accounts
test "Create wallet with accounts" {
    const allocator = testing.allocator;

    // Create wallet and accounts
    var wallet = Wallet.init(allocator);
    defer wallet.deinit();

    const account1 = try wallet.createAccount("Account 1");
    const account2 = try wallet.createAccount("Account 2");

    const default_account = wallet.getDefaultAccount().?;
    try testing.expect(default_account.getScriptHash().eql(account1.getScriptHash()));

    try testing.expectEqual(@as(u32, 2), wallet.getAccountCount());

    try testing.expect(wallet.containsAccount(account1));
    try testing.expect(wallet.containsAccount(account2));
}

// /// Test creating wallet with no accounts
test "Create wallet with no accounts should fail" {
    const allocator = testing.allocator;

    var wallet = Wallet.init(allocator);
    defer wallet.deinit();

    try testing.expectEqual(@as(u32, 0), wallet.getAccountCount());
    try testing.expect(wallet.getDefaultAccount() == null);
    try testing.expectError(errors.NeoError.IllegalArgument, wallet.defaultAccountByHash(Hash160.ZERO));
}

// /// Test checking if account is default
test "Check if account is default" {
    const allocator = testing.allocator;

    var wallet = Wallet.init(allocator);
    defer wallet.deinit();

    const account = try wallet.createAccount("Default");
    const other_account = try wallet.createAccount("Other");

    try testing.expect(wallet.isDefault(account));
    try testing.expect(!wallet.isDefault(other_account));

    _ = try wallet.defaultAccount(other_account);
    try testing.expect(wallet.isDefault(other_account));
}

// /// Test wallet holds account
test "Wallet holds account verification" {
    const allocator = testing.allocator;

    var wallet = Wallet.init(allocator);
    defer wallet.deinit();

    const account = try wallet.createAccount("Primary");
    try testing.expect(wallet.containsAccount(account));
    try testing.expect(wallet.containsAccountByHash(account.getScriptHash()));

    var other_wallet = Wallet.init(allocator);
    defer other_wallet.deinit();
    const other_account = try other_wallet.createAccount("Other");
    try testing.expect(!wallet.containsAccount(other_account));
    try testing.expect(!wallet.containsAccountByHash(other_account.getScriptHash()));
}

// /// Test wallet account management
test "Wallet account management" {
    const allocator = testing.allocator;

    var wallet = Wallet.init(allocator);
    defer wallet.deinit();

    const initial_count = wallet.getAccountCount();
    try testing.expectEqual(@as(u32, 0), initial_count);

    const new_account1 = try wallet.createAccount("Account 1");
    const new_account2 = try wallet.createAccount("Account 2");

    try testing.expectEqual(initial_count + 2, wallet.getAccountCount());

    try testing.expect(wallet.containsAccount(new_account1));
    try testing.expect(wallet.containsAccount(new_account2));
}

// /// Test wallet account retrieval
test "Wallet account retrieval" {
    const allocator = testing.allocator;

    var wallet = Wallet.init(allocator);
    defer wallet.deinit();

    const account1 = try wallet.createAccount("Account 1");
    const account2 = try wallet.createAccount("Account 2");

    const retrieved_account1 = wallet.getAccount(account1.getScriptHash());
    try testing.expect(retrieved_account1 != null);
    try testing.expect(retrieved_account1.?.getScriptHash().eql(account1.getScriptHash()));

    const retrieved_account2 = wallet.getAccount(account2.getScriptHash());
    try testing.expect(retrieved_account2 != null);
    try testing.expect(retrieved_account2.?.getScriptHash().eql(account2.getScriptHash()));

    const non_existent = wallet.getAccount(Hash160.ZERO);
    try testing.expect(non_existent == null);
}

// /// Test wallet validation
test "Wallet validation" {
    const allocator = testing.allocator;

    var valid_wallet = Wallet.init(allocator);
    defer valid_wallet.deinit();
    _ = try valid_wallet.createAccount("Default");

    try valid_wallet.validate();

    try testing.expect(valid_wallet.getName().len > 0);
    try testing.expect(valid_wallet.getVersion().len > 0);
    try testing.expect(valid_wallet.getAccountCount() > 0);
    try testing.expect(valid_wallet.getDefaultAccount() != null);
}

// /// Test wallet encryption and decryption
test "Wallet encryption and decryption" {
    const allocator = testing.allocator;

    var wallet = CompleteNEP6Wallet.init(allocator, "Encrypted Wallet");
    defer wallet.deinit();

    const password = "TestWalletPassword123";
    const account = try wallet.createAccount(password, "Encrypted Account");
    try testing.expect(account.encrypted_private_key != null);

    const private_key = try account.getPrivateKey(password, wallet.scrypt);
    try testing.expect(private_key.isValid());
}

// /// Test wallet NEP-6 operations
test "Wallet NEP-6 operations" {
    const allocator = testing.allocator;

    var wallet = CompleteNEP6Wallet.init(allocator, "NEP6 Wallet");
    defer wallet.deinit();

    _ = try wallet.createAccount("ExportPassword123", "Exported Account");

    const json_value = try wallet.exportToJson();
    defer json_utils.freeValue(json_value, allocator);

    const imported_wallet = try CompleteNEP6Wallet.importFromJson(json_value, allocator);
    defer imported_wallet.deinit();

    try testing.expectEqual(wallet.accounts.items.len, imported_wallet.accounts.items.len);
}
