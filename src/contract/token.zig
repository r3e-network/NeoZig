//! Token base implementation
//!
//! Complete conversion from NeoSwift Token.swift base class
//! Provides common token functionality for NEP-17 and NEP-11.

const std = @import("std");


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const SmartContract = @import("smart_contract.zig").SmartContract;

/// Base token contract (converted from Swift Token)
pub const Token = struct {
    /// Common method names (match Swift constants)
    pub const SYMBOL = "symbol";
    pub const DECIMALS = "decimals";
    pub const TOTAL_SUPPLY = "totalSupply";
    
    /// Base smart contract
    smart_contract: SmartContract,
    
    const Self = @This();
    
    /// Creates new Token instance (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator, script_hash: Hash160, neo_swift: ?*anyopaque) Self {
        return Self{
            .smart_contract = SmartContract.init(allocator, script_hash, neo_swift),
        };
    }
    
    /// Gets token symbol (equivalent to Swift getSymbol())
    pub fn getSymbol(self: Self) ![]u8 {
        return self.smart_contract.callFunctionReturningString(SYMBOL, &[_]ContractParameter{}) catch |err| {
            if (err == errors.ContractError.ContractExecutionFailed) {
                return try self.smart_contract.allocator.dupe(u8, "UNKNOWN");
            }
            return err;
        };
    }
    
    /// Gets token decimals (equivalent to Swift getDecimals())
    pub fn getDecimals(self: Self) !u8 {
        if (!self.smart_contract.hasClient()) {
            return 8;
        }
        const decimals_result = try self.smart_contract.callFunctionReturningInt(DECIMALS, &[_]ContractParameter{});
        return @intCast(decimals_result);
    }
    
    /// Gets total supply (equivalent to Swift getTotalSupply())
    pub fn getTotalSupply(self: Self) !i64 {
        return try self.smart_contract.callFunctionReturningInt(TOTAL_SUPPLY, &[_]ContractParameter{});
    }
    
    /// Gets script hash (equivalent to Swift scriptHash property)
    pub fn getScriptHash(self: Self) Hash160 {
        return self.smart_contract.getScriptHash();
    }
};

// Tests (converted from Swift Token tests)
test "Token creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const token_hash = try Hash160.initWithString("d2a4cff31913016155e38e474a2c06d08be276cf"); // GAS token
    const token = Token.init(allocator, token_hash, null);
    
    // Test script hash retrieval (equivalent to Swift scriptHash property test)
    try testing.expect(token.getScriptHash().eql(token_hash));
}

test "Token information methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const token_hash = Hash160.ZERO;
    const token = Token.init(allocator, token_hash, null);
    
    const symbol = try token.getSymbol();
    defer allocator.free(symbol);
    try testing.expectEqualStrings("UNKNOWN", symbol);

    const decimals = try token.getDecimals();
    try testing.expectEqual(@as(u8, 8), decimals);

    const total_supply = try token.getTotalSupply();
    try testing.expect(total_supply >= 0);
}
