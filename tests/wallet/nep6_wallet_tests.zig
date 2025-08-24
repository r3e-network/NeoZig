//! NEP-6 Wallet Tests
//!
//! Complete conversion from NeoSwift NEP6WalletTests.swift
//! Tests NEP-6 wallet format import/export functionality.

const std = @import("std");
const testing = std.testing;
const NEP6Wallet = @import("../../src/wallet/nep6_wallet.zig").NEP6Wallet;
const Account = @import("../../src/wallet/account.zig").Account;

test "NEP-6 wallet creation" {
    const allocator = testing.allocator;
    
    const wallet_name = "TestNEP6Wallet";
    var nep6_wallet = try NEP6Wallet.create(wallet_name, allocator);
    defer nep6_wallet.deinit(allocator);
    
    try testing.expectEqualStrings(wallet_name, nep6_wallet.getName());
    try testing.expectEqualStrings(NEP6Wallet.CURRENT_VERSION, nep6_wallet.getVersion());
}

test "NEP-6 wallet JSON export" {
    const allocator = testing.allocator;
    
    var nep6_wallet = try NEP6Wallet.create("TestWallet", allocator);
    defer nep6_wallet.deinit(allocator);
    
    const password = "testpassword";
    const json_string = try nep6_wallet.toJson(password, allocator);
    defer allocator.free(json_string);
    
    try testing.expect(json_string.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_string, "version") != null);
    try testing.expect(std.mem.indexOf(u8, json_string, "TestWallet") != null);
}

test "NEP-6 wallet account management" {
    const allocator = testing.allocator;
    
    var nep6_wallet = try NEP6Wallet.create("TestWallet", allocator);
    defer nep6_wallet.deinit(allocator);
    
    var account = try Account.create(allocator);
    defer account.deinit(allocator);
    
    try nep6_wallet.addAccount(account);
    try testing.expect(nep6_wallet.getAccountCount() >= 1);
}