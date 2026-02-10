//! Token base implementation
//!
//! Neo N3 base class
//! Provides common token functionality for NEP-17 and NEP-11.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const SmartContract = @import("smart_contract.zig").SmartContract;

/// Base token contract
pub const Token = struct {
    /// Common method names
    pub const SYMBOL = "symbol";
    pub const DECIMALS = "decimals";
    pub const TOTAL_SUPPLY = "totalSupply";

    /// Base smart contract
    smart_contract: SmartContract,

    const Self = @This();

    /// Creates new Token instance
    pub fn init(allocator: std.mem.Allocator, script_hash: Hash160, client: ?*anyopaque) Self {
        return Self{
            .smart_contract = SmartContract.init(allocator, script_hash, client),
        };
    }

    /// Gets token symbol)
    pub fn getSymbol(self: Self) ![]u8 {
        return try self.smart_contract.callFunctionReturningString(SYMBOL, &[_]ContractParameter{});
    }

    /// Gets token decimals)
    pub fn getDecimals(self: Self) !u8 {
        const decimals_result = try self.smart_contract.callFunctionReturningInt(DECIMALS, &[_]ContractParameter{});
        return @intCast(decimals_result);
    }

    /// Gets total supply)
    pub fn getTotalSupply(self: Self) !i64 {
        return try self.smart_contract.callFunctionReturningInt(TOTAL_SUPPLY, &[_]ContractParameter{});
    }

    /// Gets script hash
    pub fn getScriptHash(self: Self) Hash160 {
        return self.smart_contract.getScriptHash();
    }

    /// Validates that the token has a usable script hash.
    pub fn validate(self: Self) !void {
        return self.smart_contract.validate();
    }

    /// Returns true if this token is backed by a native contract.
    pub fn isNativeContract(self: Self) bool {
        return self.smart_contract.isNativeContract();
    }

    /// Converts an amount into fractional units based on decimals.
    pub fn toFractions(amount: f64, decimals: u32) u64 {
        const multiplier = std.math.pow(f64, 10.0, @floatFromInt(decimals));
        return @intFromFloat(amount * multiplier);
    }

    /// Converts fractional units into a decimal amount based on decimals.
    pub fn fromFractions(fractions: u64, decimals: u32) f64 {
        const divisor = std.math.pow(f64, 10.0, @floatFromInt(decimals));
        return @as(f64, @floatFromInt(fractions)) / divisor;
    }
};

// Tests
test "Token creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const token_hash = try Hash160.initWithString("d2a4cff31913016155e38e474a2c06d08be276cf"); // GAS token
    const token = Token.init(allocator, token_hash, null);

    // Test script hash retrieval
    try testing.expect(token.getScriptHash().eql(token_hash));
}

test "Token information methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const token_hash = Hash160.ZERO;
    const token = Token.init(allocator, token_hash, null);

    try testing.expectError(errors.NeoError.InvalidConfiguration, token.getSymbol());
    try testing.expectError(errors.NeoError.InvalidConfiguration, token.getDecimals());
    try testing.expectError(errors.NeoError.InvalidConfiguration, token.getTotalSupply());
}
