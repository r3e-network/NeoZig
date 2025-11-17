//! BIP39 Account Tests
//!
//! Complete conversion from NeoSwift Bip39AccountTests.swift
//! Tests BIP39 mnemonic account creation and derivation.

const std = @import("std");


const testing = std.testing;
const Bip39Account = @import("../../src/wallet/bip39_account.zig").Bip39Account;

test "BIP39 account creation from mnemonic" {
    const allocator = testing.allocator;
    
    const test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    var bip39_account = try Bip39Account.fromMnemonic(test_mnemonic, "", allocator);
    defer bip39_account.deinit(allocator);
    
    try testing.expect(bip39_account.isValid());
    try testing.expect(!bip39_account.getAddress().isEmpty());
}

test "BIP39 mnemonic validation" {
    const allocator = testing.allocator;
    
    const valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    try testing.expect(Bip39Account.isValidMnemonic(valid_mnemonic));
    
    const invalid_mnemonic = "invalid mnemonic phrase";
    try testing.expect(!Bip39Account.isValidMnemonic(invalid_mnemonic));
}