//! Non-Fungible Token (NEP-11) implementation
//!
//! Complete conversion from NeoSwift NonFungibleToken.swift
//! Handles NEP-11 NFT operations and transfers.

const std = @import("std");
const ArrayList = std.ArrayList;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const StackItem = @import("../types/stack_item.zig").StackItem;
const Token = @import("token.zig").Token;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;
const NeoSwift = @import("../rpc/neo_client.zig").NeoSwift;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const iterator_mod = @import("iterator.zig");

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
        return try self.token.smart_contract.callFunctionReturningHash160(OWNER_OF, &params);
    }
    
    /// Gets token properties (equivalent to Swift properties)
    pub fn properties(self: Self, token_id: []const u8) !TokenProperties {
        const params = [_]ContractParameter{ContractParameter.byteArray(token_id)};

        const smart_contract = self.token.smart_contract;
        if (smart_contract.neo_swift == null) {
            return TokenProperties.initWithAllocator(smart_contract.allocator);
        }

        const neo_swift: *NeoSwift = @ptrCast(@alignCast(smart_contract.neo_swift.?));
        var request = try neo_swift.invokeFunction(smart_contract.script_hash, PROPERTIES, &params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        return try TokenProperties.fromStackItem(stack_item, smart_contract.allocator);
    }
    
    /// Transfers NFT (equivalent to Swift transfer for non-divisible NFTs)
    pub fn transfer(
        self: Self,
        from: Hash160,
        to: Hash160,
        token_id: []const u8,
        data: ?ContractParameter,
    ) !TransactionBuilder {
        var params = ArrayList(ContractParameter).init(self.token.smart_contract.allocator);
        defer params.deinit();
        
        try params.append(ContractParameter.hash160(from));
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
        var params = ArrayList(ContractParameter).init(self.token.smart_contract.allocator);
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
        const smart_contract = self.token.smart_contract;
        if (smart_contract.neo_swift == null) {
            return TokenIterator.init();
        }

        const neo_swift: *NeoSwift = @ptrCast(@alignCast(smart_contract.neo_swift.?));
        var request = try neo_swift.invokeFunction(smart_contract.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const session_id = invocation.session orelse return errors.NetworkError.InvalidResponse;
        const first_item = try invocation.getFirstStackItem();
        const interop = switch (first_item) {
            .InteropInterface => |iface| iface,
            else => return errors.SerializationError.InvalidFormat,
        };

        return try TokenIterator.initWithIterator(
            smart_contract.allocator,
            smart_contract.neo_swift.?,
            session_id,
            interop.iterator_id,
        );
    }
    
    fn callFunctionAndUnwrapIterator(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
        max_items: u32,
    ) ![][]u8 {
        const smart_contract = self.token.smart_contract;
        if (smart_contract.neo_swift == null) {
            return try smart_contract.allocator.alloc([]u8, 0);
        }

        const neo_swift: *NeoSwift = @ptrCast(@alignCast(smart_contract.neo_swift.?));
        var request = try neo_swift.invokeFunction(smart_contract.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const session_id = invocation.session orelse return errors.NetworkError.InvalidResponse;
        const first_item = try invocation.getFirstStackItem();
        const interop = switch (first_item) {
            .InteropInterface => |iface| iface,
            else => return errors.SerializationError.InvalidFormat,
        };

        const mapper = struct {
            fn map(stack_item: StackItem, allocator: std.mem.Allocator) ![]u8 {
                return try stack_item.getByteArray(allocator);
            }
        }.map;

        var iterator = try iterator_mod.Iterator([]u8).init(
            smart_contract.allocator,
            smart_contract.neo_swift.?,
            session_id,
            interop.iterator_id,
            mapper,
        );
        defer iterator.deinit();

        const items = try iterator.traverseAll(max_items);
        iterator.terminateSession() catch {};
        return items;
    }
};

/// Token iterator (converted from Swift Iterator pattern).
/// NOTE: Iterator pagination via RPC is not implemented yet; this is a stub
/// that returns no items.
pub const TokenIterator = struct {
    session_id: []const u8,
    iterator_id: []const u8,
    allocator: std.mem.Allocator,
    inner: ?iterator_mod.Iterator([]u8),
    buffer: ArrayList([]u8),
    exhausted: bool,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .session_id = "",
            .iterator_id = "",
            .allocator = std.heap.page_allocator,
            .inner = null,
            .buffer = ArrayList([]u8).init(std.heap.page_allocator),
            .exhausted = true,
        };
    }

    pub fn initWithIterator(
        allocator: std.mem.Allocator,
        neo_swift: *anyopaque,
        session_id: []const u8,
        iterator_id: []const u8,
    ) !Self {
        const mapper = struct {
            fn map(stack_item: StackItem, alloc: std.mem.Allocator) ![]u8 {
                return try stack_item.getByteArray(alloc);
            }
        }.map;

        const inner_iter = try iterator_mod.Iterator([]u8).init(
            allocator,
            neo_swift,
            session_id,
            iterator_id,
            mapper,
        );

        return Self{
            .session_id = inner_iter.session_id,
            .iterator_id = inner_iter.iterator_id,
            .allocator = allocator,
            .inner = inner_iter,
            .buffer = ArrayList([]u8).init(allocator),
            .exhausted = false,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.inner) |*inner_iter| {
            inner_iter.terminateSession() catch {};
            inner_iter.deinit();
            self.inner = null;
        }

        for (self.buffer.items) |item| {
            self.allocator.free(item);
        }
        self.buffer.deinit();
        self.exhausted = true;
        self.session_id = "";
        self.iterator_id = "";
    }

    fn fetchNext(self: *Self) !bool {
        if (self.exhausted or self.inner == null) return false;

        var inner_iter = &self.inner.?;
        const batch = try inner_iter.traverse(1);
        defer self.allocator.free(batch);

        if (batch.len == 0) {
            self.exhausted = true;
            return false;
        }

        try self.buffer.appendSlice(batch);
        return true;
    }

    pub fn hasNext(self: *Self) bool {
        if (self.buffer.items.len > 0) return true;
        _ = self.fetchNext() catch return false;
        return self.buffer.items.len > 0;
    }

    pub fn next(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        if (self.buffer.items.len == 0) {
            if (!self.hasNext()) {
                return try allocator.alloc(u8, 0);
            }
        }

        const item = self.buffer.orderedRemove(0);
        if (allocator.ptr == self.allocator.ptr and allocator.vtable == self.allocator.vtable) {
            return item;
        }

        const copy = try allocator.dupe(u8, item);
        self.allocator.free(item);
        return copy;
    }
};

/// Token properties (converted from Swift token properties)
pub const TokenProperties = struct {
    name: ?[]const u8,
    description: ?[]const u8,
    image: ?[]const u8,
    custom_properties: std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates a properties container backed by a caller-provided allocator.
    pub fn initWithAllocator(allocator: std.mem.Allocator) Self {
        return Self{
            .name = null,
            .description = null,
            .image = null,
            .custom_properties = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn init() Self {
        return initWithAllocator(std.heap.page_allocator);
    }
    
    pub fn deinit(self: *Self) void {
        if (self.name) |name| self.allocator.free(name);
        if (self.description) |desc| self.allocator.free(desc);
        if (self.image) |img| self.allocator.free(img);

        var iter = self.custom_properties.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.custom_properties.deinit();
    }

    pub fn fromStackItem(stack_item: StackItem, allocator: std.mem.Allocator) !Self {
        var props = Self.initWithAllocator(allocator);

        if (stack_item != .Map) {
            return errors.SerializationError.InvalidFormat;
        }

        var it = stack_item.Map.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*.getString(allocator) catch continue;
            defer allocator.free(key);

            if (std.mem.eql(u8, key, "name")) {
                props.name = try entry.value_ptr.*.getString(allocator);
                continue;
            }

            if (std.mem.eql(u8, key, "description")) {
                props.description = try entry.value_ptr.*.getString(allocator);
                continue;
            }

            if (std.mem.eql(u8, key, "image")) {
                props.image = try entry.value_ptr.*.getString(allocator);
                continue;
            }

            const stored_key = try allocator.dupe(u8, key);
            errdefer allocator.free(stored_key);
            const stored_value = try entry.value_ptr.*.getString(allocator);
            errdefer allocator.free(stored_value);
            try props.custom_properties.put(stored_key, stored_value);
        }

        return props;
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
    try testing.expect(balance >= 0);
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
    var all_tokens_iter = try nft.tokens();
    defer all_tokens_iter.deinit();
    try testing.expect(!all_tokens_iter.hasNext()); // stub returns false
    
    var owner_tokens_iter = try nft.tokensOf(Hash160.ZERO);
    defer owner_tokens_iter.deinit();
    try testing.expect(!owner_tokens_iter.hasNext()); // stub returns false
    
    // Test unwrapped versions
    const all_tokens = try nft.tokensUnwrapped(100);
    defer allocator.free(all_tokens);
    try testing.expectEqual(@as(usize, 0), all_tokens.len);
    
    const owner_tokens = try nft.tokensOfUnwrapped(Hash160.ZERO, 100);
    defer allocator.free(owner_tokens);
    try testing.expectEqual(@as(usize, 0), owner_tokens.len);
}
