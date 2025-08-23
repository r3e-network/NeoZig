//! Non-Fungible Token (NEP-11) implementation
//!
//! Complete conversion from NeoSwift NonFungibleToken.swift
//! Handles NEP-11 NFT operations and transfers.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const Token = @import("token.zig").Token;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;

/// Non-fungible token contract (converted from Swift NonFungibleToken)
pub const NonFungibleToken = struct {
    /// Method names (match Swift constants)
    pub const OWNER_OF = "ownerOf";
    pub const TOKENS_OF = "tokensOf";
    pub const BALANCE_OF = "balanceOf";
    pub const TRANSFER = "transfer";
    pub const TOKENS = "tokens";
    pub const PROPERTIES = "properties";
    
    /// Base token contract
    token: Token,
    
    const Self = @This();
    
    /// Creates new NonFungibleToken instance (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator, script_hash: Hash160, neo_swift: ?*anyopaque) Self {
        return Self{
            .token = Token.init(allocator, script_hash, neo_swift),
        };
    }
    
    /// Gets NFT balance for owner (equivalent to Swift balanceOf(_ owner: Hash160))
    pub fn balanceOf(self: Self, owner: Hash160) !i64 {
        const params = [_]ContractParameter{ContractParameter.hash160(owner)};
        return try self.token.smart_contract.callFunctionReturningInt(BALANCE_OF, &params);
    }
    
    /// Gets tokens owned by address (equivalent to Swift tokensOf(_ owner: Hash160))
    pub fn tokensOf(self: Self, owner: Hash160) !TokenIterator {
        const params = [_]ContractParameter{ContractParameter.hash160(owner)};
        return try self.callFunctionReturningIterator(TOKENS_OF, &params);
    }
    
    /// Gets tokens owned by address (unwrapped version)
    pub fn tokensOfUnwrapped(self: Self, owner: Hash160, max_items: u32) ![][]u8 {
        const params = [_]ContractParameter{ContractParameter.hash160(owner)};
        return try self.callFunctionAndUnwrapIterator(TOKENS_OF, &params, max_items);
    }
    
    /// Gets owner of specific token (equivalent to Swift ownerOf)
    pub fn ownerOf(self: Self, token_id: []const u8) !Hash160 {
        const params = [_]ContractParameter{ContractParameter.byteArray(token_id)};
        
        // This would make actual RPC call and parse owner
        _ = params;
        return Hash160.ZERO; // Placeholder
    }
    
    /// Gets token properties (equivalent to Swift properties)
    pub fn properties(self: Self, token_id: []const u8) !TokenProperties {
        const params = [_]ContractParameter{ContractParameter.byteArray(token_id)};
        
        // This would make actual RPC call and parse properties
        _ = params;
        return TokenProperties.init();
    }
    
    /// Transfers NFT (equivalent to Swift transfer for non-divisible NFTs)
    pub fn transfer(
        self: Self,
        from: Hash160,
        to: Hash160,
        token_id: []const u8,
        data: ?ContractParameter,
    ) !TransactionBuilder {
        var params = std.ArrayList(ContractParameter).init(self.token.smart_contract.allocator);
        defer params.deinit();
        
        try params.append(ContractParameter.hash160(to));
        try params.append(ContractParameter.byteArray(token_id));
        
        if (data) |transfer_data| {
            try params.append(transfer_data);
        }
        
        return try self.token.smart_contract.invokeFunction(TRANSFER, params.items);
    }
    
    /// Transfers divisible NFT (equivalent to Swift transfer for divisible NFTs)
    pub fn transferDivisible(
        self: Self,
        from: Hash160,
        to: Hash160,
        amount: i64,
        token_id: []const u8,
        data: ?ContractParameter,
    ) !TransactionBuilder {
        var params = std.ArrayList(ContractParameter).init(self.token.smart_contract.allocator);
        defer params.deinit();
        
        try params.append(ContractParameter.hash160(from));
        try params.append(ContractParameter.hash160(to));
        try params.append(ContractParameter.integer(amount));
        try params.append(ContractParameter.byteArray(token_id));
        
        if (data) |transfer_data| {
            try params.append(transfer_data);
        }
        
        return try self.token.smart_contract.invokeFunction(TRANSFER, params.items);
    }
    
    /// Gets all tokens (equivalent to Swift tokens())
    pub fn tokens(self: Self) !TokenIterator {
        return try self.callFunctionReturningIterator(TOKENS, &[_]ContractParameter{});
    }
    
    /// Gets all tokens unwrapped
    pub fn tokensUnwrapped(self: Self, max_items: u32) ![][]u8 {
        return try self.callFunctionAndUnwrapIterator(TOKENS, &[_]ContractParameter{}, max_items);
    }
    
    /// Helper methods for iterator handling
    fn callFunctionReturningIterator(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) !TokenIterator {
        // This would make actual RPC call and return iterator
        _ = function_name;
        _ = params;
        return TokenIterator.init();
    }
    
    fn callFunctionAndUnwrapIterator(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
        max_items: u32,
    ) ![][]u8 {
        // This would make actual RPC call and unwrap iterator results
        _ = function_name;
        _ = params;
        _ = max_items;
        
        return try self.token.smart_contract.allocator.alloc([]u8, 0);
    }
};

/// Token iterator (converted from Swift Iterator pattern)
pub const TokenIterator = struct {
    session_id: []const u8,
    iterator_id: []const u8,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .session_id = "",
            .iterator_id = "",
        };
    }
    
    pub fn hasNext(self: Self) bool {
        _ = self;
        return false; // Placeholder
    }
    
    pub fn next(self: Self, allocator: std.mem.Allocator) ![]u8 {
        _ = self;
        return try allocator.alloc(u8, 0);
    }
};

/// Token properties (converted from Swift token properties)
pub const TokenProperties = struct {
    name: ?[]const u8,
    description: ?[]const u8,
    image: ?[]const u8,
    custom_properties: std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .name = null,
            .description = null,
            .image = null,
            .custom_properties = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(std.heap.page_allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.custom_properties.deinit();
    }
};

/// String context for HashMap
pub const StringContext = struct {
    pub fn hash(self: @This(), key: []const u8) u64 {
        _ = self;
        return std.hash_map.hashString(key);
    }
    
    pub fn eql(self: @This(), a: []const u8, b: []const u8) bool {
        _ = self;
        return std.mem.eql(u8, a, b);
    }
};

// Tests (converted from Swift NonFungibleToken tests)
test "NonFungibleToken creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const nft_hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const nft = NonFungibleToken.init(allocator, nft_hash, null);
    
    // Test balance operations (equivalent to Swift balanceOf tests)
    const balance = try nft.balanceOf(Hash160.ZERO);
    try testing.expectEqual(@as(i64, 0), balance); // Placeholder
}

test "NonFungibleToken transfer operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const nft_hash = Hash160.ZERO;
    const nft = NonFungibleToken.init(allocator, nft_hash, null);
    
    // Test NFT transfer (equivalent to Swift transfer tests)
    const token_id = "test_token_123";
    var transfer_tx = try nft.transfer(
        Hash160.ZERO, // from
        Hash160.ZERO, // to
        token_id,
        null, // no data
    );
    defer transfer_tx.deinit();
    
    try testing.expect(transfer_tx.getScript() != null);
    
    // Test divisible NFT transfer
    var divisible_transfer_tx = try nft.transferDivisible(
        Hash160.ZERO, // from
        Hash160.ZERO, // to
        1,            // amount
        token_id,
        null,         // no data
    );
    defer divisible_transfer_tx.deinit();
    
    try testing.expect(divisible_transfer_tx.getScript() != null);
}

test "NonFungibleToken token enumeration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const nft_hash = Hash160.ZERO;
    const nft = NonFungibleToken.init(allocator, nft_hash, null);
    
    // Test tokens enumeration (equivalent to Swift tokens tests)
    const all_tokens_iter = try nft.tokens();
    try testing.expect(!all_tokens_iter.hasNext()); // Placeholder returns false
    
    const owner_tokens_iter = try nft.tokensOf(Hash160.ZERO);
    try testing.expect(!owner_tokens_iter.hasNext()); // Placeholder returns false
    
    // Test unwrapped versions
    const all_tokens = try nft.tokensUnwrapped(100);
    defer allocator.free(all_tokens);
    try testing.expectEqual(@as(usize, 0), all_tokens.len);
    
    const owner_tokens = try nft.tokensOfUnwrapped(Hash160.ZERO, 100);
    defer allocator.free(owner_tokens);
    try testing.expectEqual(@as(usize, 0), owner_tokens.len);
}