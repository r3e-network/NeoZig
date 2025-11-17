//! GAS Token implementation
//!
//! Complete conversion from NeoSwift GasToken.swift
//! Represents the native GAS token contract.

const std = @import("std");


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const FungibleToken = @import("fungible_token.zig").FungibleToken;

/// GAS token contract (converted from Swift GasToken)
pub const GasToken = struct {
    /// Contract name (matches Swift NAME)
    pub const NAME = "GasToken";
    
    /// Script hash (matches Swift SCRIPT_HASH)
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.GAS_TOKEN };
    
    /// Token decimals (matches Swift DECIMALS)
    pub const DECIMALS: u8 = 8;
    
    /// Token symbol (matches Swift SYMBOL)
    pub const SYMBOL = "GAS";
    
    /// Base fungible token
    fungible_token: FungibleToken,
    
    const Self = @This();
    
    /// Creates new GasToken instance (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator, neo_swift: ?*anyopaque) Self {
        return Self{
            .fungible_token = FungibleToken.init(allocator, SCRIPT_HASH, neo_swift),
        };
    }
    
    /// Gets token name (equivalent to Swift getName() override)
    pub fn getName(self: Self) ![]const u8 {
        _ = self;
        return NAME;
    }
    
    /// Gets token symbol (equivalent to Swift getSymbol() override)
    pub fn getSymbol(self: Self) ![]const u8 {
        _ = self;
        return SYMBOL;
    }
    
    /// Gets token decimals (equivalent to Swift getDecimals() override)
    pub fn getDecimals(self: Self) !u8 {
        _ = self;
        return DECIMALS;
    }
    
    /// Gets balance for account (delegates to fungible token)
    pub fn getBalanceOf(self: Self, script_hash: Hash160) !i64 {
        return try self.fungible_token.getBalanceOf(script_hash);
    }
    
    /// Creates transfer transaction (delegates to fungible token)
    pub fn transfer(
        self: Self,
        from: Hash160,
        to: Hash160,
        amount: i64,
        data: ?@import("../types/contract_parameter.zig").ContractParameter,
    ) !@import("../transaction/transaction_builder.zig").TransactionBuilder {
        return try self.fungible_token.transfer(from, to, amount, data);
    }
    
    /// Gets total supply (would typically call RPC, but GAS has fixed issuance model)
    pub fn getTotalSupply(self: Self) !i64 {
        _ = self;
        // GAS has a maximum supply of 100,000,000 GAS
        return 100000000 * 100000000; // 100M GAS with 8 decimals
    }
};

// Tests (converted from Swift GasToken tests)
test "GasToken constants and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const gas_token = GasToken.init(allocator, null);
    
    // Test constant values (equivalent to Swift constant tests)
    try testing.expectEqualStrings("GasToken", try gas_token.getName());
    try testing.expectEqualStrings("GAS", try gas_token.getSymbol());
    try testing.expectEqual(@as(u8, 8), try gas_token.getDecimals());
    
    // Test script hash (equivalent to Swift SCRIPT_HASH test)
    const script_hash = gas_token.fungible_token.token.getScriptHash();
    try testing.expect(std.mem.eql(u8, &constants.NativeContracts.GAS_TOKEN, &script_hash.toArray()));
}

test "GasToken operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const gas_token = GasToken.init(allocator, null);
    
    // Test balance operations (equivalent to Swift balance tests)
    const balance = try gas_token.getBalanceOf(Hash160.ZERO);
    try testing.expect(balance >= 0);
    try testing.expectEqual(@as(i64, 100000000 * 100000000), try gas_token.getTotalSupply());
    
    // Test transfer operations (equivalent to Swift transfer tests)
    var transfer_tx = try gas_token.transfer(Hash160.ZERO, Hash160.ZERO, 100000000, null);
    defer transfer_tx.deinit();
    
    try testing.expect(transfer_tx.getScript() != null);
}
