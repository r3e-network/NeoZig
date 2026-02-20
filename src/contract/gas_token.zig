//! GAS Token implementation
//!
//! Neo N3 
//! Represents the native GAS token contract.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const FungibleToken = @import("fungible_token.zig").FungibleToken;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;

/// GAS token contract
pub const GasToken = struct {
    /// Contract name
    pub const NAME = "GasToken";

    /// Script hash
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.GAS_TOKEN };

    /// Token decimals
    pub const DECIMALS: u8 = 8;

    /// Token symbol
    pub const SYMBOL = "GAS";

    /// Base fungible token
    fungible_token: FungibleToken,

    const Self = @This();

    /// Creates new GasToken instance
    pub fn init(allocator: std.mem.Allocator, client: ?*anyopaque) Self {
        return Self{
            .fungible_token = FungibleToken.init(allocator, SCRIPT_HASH, client),
        };
    }

    /// Gets token name override
    pub fn getName(self: Self) ![]const u8 {
        _ = self;
        return NAME;
    }

    /// Gets token symbol override
    pub fn getSymbol(self: Self) ![]const u8 {
        return try self.fungible_token.getSymbol();
    }

    /// Gets token decimals override
    pub fn getDecimals(self: Self) !u8 {
        return try self.fungible_token.getDecimals();
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
        data: ?ContractParameter,
    ) !TransactionBuilder {
        return try self.fungible_token.transfer(from, to, amount, data);
    }

    /// Gets total supply (would typically call RPC, but GAS has fixed issuance model)
    pub fn getTotalSupply(self: Self) !i64 {
        return try self.fungible_token.getTotalSupply();
    }

    /// Gets script hash for this token.
    pub fn getScriptHash(self: Self) Hash160 {
        return self.fungible_token.getScriptHash();
    }

    /// Validates the underlying token configuration.
    pub fn validate(self: Self) !void {
        return self.fungible_token.validate();
    }

    /// Returns true if this token is backed by a native contract.
    pub fn isNativeContract(self: Self) bool {
        return self.fungible_token.isNativeContract();
    }
};

// Tests
test "GasToken constants and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const gas_token = GasToken.init(allocator, null);

    // Test constant values
    try testing.expectEqualStrings("GasToken", try gas_token.getName());
    try testing.expectError(errors.NeoError.InvalidConfiguration, gas_token.getSymbol());
    try testing.expectError(errors.NeoError.InvalidConfiguration, gas_token.getDecimals());

    // Test script hash
    const script_hash = gas_token.getScriptHash();
    try testing.expect(std.mem.eql(u8, &constants.NativeContracts.GAS_TOKEN, &script_hash.toArray()));
}

test "GasToken operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const gas_token = GasToken.init(allocator, null);

    // Test balance operations
    try testing.expectError(errors.NeoError.InvalidConfiguration, gas_token.getBalanceOf(Hash160.ZERO));
    try testing.expectError(errors.NeoError.InvalidConfiguration, gas_token.getTotalSupply());

    // Test transfer operations
    var transfer_tx = try gas_token.transfer(Hash160.ZERO, Hash160.ZERO, 100000000, null);
    defer transfer_tx.deinit();

    try testing.expect(transfer_tx.getScript() != null);
}
