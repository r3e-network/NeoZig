//! NEO Token implementation
//!
//! Complete conversion from NeoSwift NeoToken.swift
//! Represents the native NEO token contract with governance features.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const FungibleToken = @import("fungible_token.zig").FungibleToken;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;
const NeoSwift = @import("../rpc/neo_client.zig").NeoSwift;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const StackItem = @import("../types/stack_item.zig").StackItem;

/// NEO token contract (converted from Swift NeoToken)
pub const NeoToken = struct {
    /// Contract name (matches Swift NAME)
    pub const NAME = "NeoToken";

    /// Script hash (matches Swift SCRIPT_HASH)
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.NEO_TOKEN };

    /// Token decimals (matches Swift DECIMALS)
    pub const DECIMALS: u8 = 0; // NEO is indivisible

    /// Token symbol (matches Swift SYMBOL)
    pub const SYMBOL = "NEO";

    /// Method names (match Swift constants)
    pub const GET_CANDIDATES = "getCandidates";
    pub const GET_COMMITTEE = "getCommittee";
    pub const GET_NEXT_BLOCK_VALIDATORS = "getNextBlockValidators";
    pub const REGISTER_CANDIDATE = "registerCandidate";
    pub const UNREGISTER_CANDIDATE = "unregisterCandidate";
    pub const VOTE = "vote";
    pub const GET_CANDIDATE_VOTE = "getCandidateVote";
    pub const GET_ACCOUNT_STATE = "getAccountState";
    pub const GET_GAS_PER_BLOCK = "getGasPerBlock";
    pub const SET_GAS_PER_BLOCK = "setGasPerBlock";
    pub const GET_REGISTER_PRICE = "getRegisterPrice";
    pub const SET_REGISTER_PRICE = "setRegisterPrice";

    /// Base fungible token
    fungible_token: FungibleToken,

    const Self = @This();

    /// Creates new NeoToken instance (equivalent to Swift init)
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
        data: ?ContractParameter,
    ) !TransactionBuilder {
        return try self.fungible_token.transfer(from, to, amount, data);
    }

    // ============================================================================
    // GOVERNANCE METHODS (converted from Swift governance functionality)
    // ============================================================================

    /// Gets all candidates (equivalent to Swift getCandidates)
    pub fn getCandidates(self: Self) ![]Candidate {
        const smart_contract = self.fungible_token.token.smart_contract;
        if (smart_contract.neo_swift == null) {
            return try smart_contract.allocator.alloc(Candidate, 0);
        }

        const neo_swift: *NeoSwift = @ptrCast(@alignCast(smart_contract.neo_swift.?));
        var request = try neo_swift.invokeFunction(SCRIPT_HASH, GET_CANDIDATES, &[_]ContractParameter{}, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        const items = try stack_item.getArray();
        var candidates = try smart_contract.allocator.alloc(Candidate, items.len);
        errdefer smart_contract.allocator.free(candidates);

        for (items, 0..) |item, i| {
            candidates[i] = try Candidate.fromStackItem(item);
        }

        return candidates;
    }

    /// Gets committee members (equivalent to Swift getCommittee)
    pub fn getCommittee(self: Self) ![][33]u8 {
        return try self.getPublicKeyList(GET_COMMITTEE);
    }

    /// Gets next block validators (equivalent to Swift getNextBlockValidators)
    pub fn getNextBlockValidators(self: Self) ![][33]u8 {
        return try self.getPublicKeyList(GET_NEXT_BLOCK_VALIDATORS);
    }

    /// Registers candidate (equivalent to Swift registerCandidate)
    pub fn registerCandidate(self: Self, public_key: [33]u8) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.publicKey(public_key[0..])};
        return try self.fungible_token.token.smart_contract.invokeFunction(REGISTER_CANDIDATE, &params);
    }

    /// Unregisters candidate (equivalent to Swift unregisterCandidate)
    pub fn unregisterCandidate(self: Self, public_key: [33]u8) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.publicKey(public_key[0..])};
        return try self.fungible_token.token.smart_contract.invokeFunction(UNREGISTER_CANDIDATE, &params);
    }

    /// Votes for candidate (equivalent to Swift vote)
    pub fn vote(self: Self, voter: Hash160, candidate: ?[33]u8) !TransactionBuilder {
        var params = ArrayList(ContractParameter).init(self.fungible_token.token.smart_contract.allocator);
        defer params.deinit();

        try params.append(ContractParameter.hash160(voter));

        if (candidate) |pub_key| {
            try params.append(ContractParameter.publicKey(pub_key[0..]));
        } else {
            try params.append(ContractParameter.void_param());
        }

        return try self.fungible_token.token.smart_contract.invokeFunction(VOTE, params.items);
    }

    /// Gets candidate vote count (equivalent to Swift getCandidateVote)
    pub fn getCandidateVote(self: Self, public_key: [33]u8) !i64 {
        const params = [_]ContractParameter{ContractParameter.publicKey(public_key[0..])};
        return try self.fungible_token.token.smart_contract.callFunctionReturningInt(GET_CANDIDATE_VOTE, &params);
    }

    /// Gets account state (equivalent to Swift getAccountState)
    pub fn getAccountState(self: Self, script_hash: Hash160) !AccountState {
        const params = [_]ContractParameter{ContractParameter.hash160(script_hash)};

        const smart_contract = self.fungible_token.token.smart_contract;
        if (smart_contract.neo_swift == null) {
            return AccountState.init();
        }

        const neo_swift: *NeoSwift = @ptrCast(@alignCast(smart_contract.neo_swift.?));
        var request = try neo_swift.invokeFunction(SCRIPT_HASH, GET_ACCOUNT_STATE, &params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        return try AccountState.fromStackItem(stack_item);
    }

    /// Gets GAS per block (equivalent to Swift getGasPerBlock)
    pub fn getGasPerBlock(self: Self) !i64 {
        return try self.fungible_token.token.smart_contract.callFunctionReturningInt(GET_GAS_PER_BLOCK, &[_]ContractParameter{});
    }

    /// Sets GAS per block (equivalent to Swift setGasPerBlock)
    pub fn setGasPerBlock(self: Self, gas_per_block: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(gas_per_block)};
        return try self.fungible_token.token.smart_contract.invokeFunction(SET_GAS_PER_BLOCK, &params);
    }

    /// Gets candidate registration price (equivalent to Swift getRegisterPrice)
    pub fn getRegisterPrice(self: Self) !i64 {
        return try self.fungible_token.token.smart_contract.callFunctionReturningInt(GET_REGISTER_PRICE, &[_]ContractParameter{});
    }

    /// Sets candidate registration price (equivalent to Swift setRegisterPrice)
    pub fn setRegisterPrice(self: Self, register_price: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(register_price)};
        return try self.fungible_token.token.smart_contract.invokeFunction(SET_REGISTER_PRICE, &params);
    }

    fn getPublicKeyList(self: Self, function_name: []const u8) ![][33]u8 {
        const smart_contract = self.fungible_token.token.smart_contract;
        if (smart_contract.neo_swift == null) {
            return try smart_contract.allocator.alloc([33]u8, 0);
        }

        const neo_swift: *NeoSwift = @ptrCast(@alignCast(smart_contract.neo_swift.?));
        var request = try neo_swift.invokeFunction(SCRIPT_HASH, function_name, &[_]ContractParameter{}, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        const items = try stack_item.getArray();

        var keys = try smart_contract.allocator.alloc([33]u8, items.len);
        errdefer smart_contract.allocator.free(keys);

        for (items, 0..) |item, i| {
            const bytes = switch (item) {
                .ByteString, .Buffer => |b| b,
                else => return errors.SerializationError.InvalidFormat,
            };
            if (bytes.len != 33) {
                return errors.SerializationError.InvalidFormat;
            }
            @memcpy(&keys[i], bytes);
        }

        return keys;
    }
};

/// Candidate structure (converted from Swift Candidate)
pub const Candidate = struct {
    public_key: [33]u8,
    votes: i64,

    const Self = @This();

    pub fn init(public_key: [33]u8, votes: i64) Self {
        return Self{
            .public_key = public_key,
            .votes = votes,
        };
    }

    pub fn fromStackItem(stack_item: StackItem) !Self {
        const values = try stack_item.getArray();
        if (values.len < 2) {
            return errors.SerializationError.InvalidFormat;
        }

        const key_bytes = switch (values[0]) {
            .ByteString, .Buffer => |bytes| bytes,
            else => return errors.SerializationError.InvalidFormat,
        };
        if (key_bytes.len != 33) {
            return errors.SerializationError.InvalidFormat;
        }

        var public_key: [33]u8 = undefined;
        @memcpy(&public_key, key_bytes);

        const votes = try values[1].getInteger();
        return Self.init(public_key, votes);
    }
};

/// Account state structure (converted from Swift account state)
pub const AccountState = struct {
    balance: i64,
    height: u32,
    vote_to: ?[33]u8,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .balance = 0,
            .height = 0,
            .vote_to = null,
        };
    }

    pub fn fromStackItem(stack_item: StackItem) !Self {
        if (stack_item == .Any) {
            return Self.init();
        }

        const values = try stack_item.getArray();
        if (values.len < 3) {
            return errors.throwIllegalState("Account State stack was malformed.");
        }

        const balance = try values[0].getInteger();
        const height_value = try values[1].getInteger();
        if (height_value < 0 or height_value > std.math.maxInt(u32)) {
            return errors.SerializationError.InvalidFormat;
        }

        var vote_to: ?[33]u8 = null;
        const vote_item = values[2];
        if (!vote_item.isNull()) {
            const vote_bytes = switch (vote_item) {
                .ByteString, .Buffer => |bytes| bytes,
                else => return errors.SerializationError.InvalidFormat,
            };
            if (vote_bytes.len != 33) {
                return errors.SerializationError.InvalidFormat;
            }

            var public_key: [33]u8 = undefined;
            @memcpy(&public_key, vote_bytes);
            vote_to = public_key;
        }

        return Self{
            .balance = balance,
            .height = @intCast(height_value),
            .vote_to = vote_to,
        };
    }
};

// Tests (converted from Swift NeoToken tests)
test "NeoToken constants and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const neo_token = NeoToken.init(allocator, null);

    // Test constant values (equivalent to Swift constant tests)
    try testing.expectEqualStrings("NeoToken", try neo_token.getName());
    try testing.expectEqualStrings("NEO", try neo_token.getSymbol());
    try testing.expectEqual(@as(u8, 0), try neo_token.getDecimals());

    // Test script hash (equivalent to Swift SCRIPT_HASH test)
    const script_hash = neo_token.fungible_token.token.getScriptHash();
    try testing.expect(std.mem.eql(u8, &constants.NativeContracts.NEO_TOKEN, &script_hash.toArray()));
}

test "NeoToken governance operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const neo_token = NeoToken.init(allocator, null);

    // Test candidate registration (equivalent to Swift registerCandidate tests)
    const test_public_key = [_]u8{0x02} ++ [_]u8{0xAB} ** 32;
    var register_tx = try neo_token.registerCandidate(test_public_key);
    defer register_tx.deinit();
    try testing.expect(register_tx.getScript() != null);

    var vote_tx = try neo_token.vote(Hash160.ZERO, test_public_key);
    defer vote_tx.deinit();
    try testing.expect(vote_tx.getScript() != null);

    var cancel_vote_tx = try neo_token.vote(Hash160.ZERO, null);
    defer cancel_vote_tx.deinit();
    try testing.expect(cancel_vote_tx.getScript() != null);
}

test "NeoToken fee and price operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const neo_token = NeoToken.init(allocator, null);

    // Test GAS per block operations (equivalent to Swift GAS per block tests)
    try testing.expect(try neo_token.getGasPerBlock() >= 0);
    var set_gas_tx = try neo_token.setGasPerBlock(500000000);
    defer set_gas_tx.deinit();
    try testing.expect(set_gas_tx.getScript() != null);

    try testing.expect(try neo_token.getRegisterPrice() >= 0);
    var set_price_tx = try neo_token.setRegisterPrice(100000000000);
    defer set_price_tx.deinit();
    try testing.expect(set_price_tx.getScript() != null);
}

test "AccountState and Candidate fromStackItem parsing" {
    const testing = std.testing;

    // No balance (Any)
    const no_balance_item = StackItem{ .Any = null };
    const no_balance_state = try AccountState.fromStackItem(no_balance_item);
    try testing.expectEqual(@as(i64, 0), no_balance_state.balance);
    try testing.expectEqual(@as(u32, 0), no_balance_state.height);
    try testing.expect(no_balance_state.vote_to == null);

    // No vote (third item Any)
    var no_vote_values = [_]StackItem{
        StackItem{ .Integer = 10 },
        StackItem{ .Integer = 42 },
        StackItem{ .Any = null },
    };
    const no_vote_item = StackItem{ .Struct = no_vote_values[0..] };
    const no_vote_state = try AccountState.fromStackItem(no_vote_item);
    try testing.expectEqual(@as(i64, 10), no_vote_state.balance);
    try testing.expectEqual(@as(u32, 42), no_vote_state.height);
    try testing.expect(no_vote_state.vote_to == null);

    // With vote public key
    const pub_key_bytes = [_]u8{0x02} ++ [_]u8{0xAB} ** 32;
    var with_vote_values = [_]StackItem{
        StackItem{ .Integer = 123 },
        StackItem{ .Integer = 7 },
        StackItem{ .ByteString = pub_key_bytes[0..] },
    };
    const with_vote_item = StackItem{ .Array = with_vote_values[0..] };
    const with_vote_state = try AccountState.fromStackItem(with_vote_item);
    try testing.expectEqual(@as(i64, 123), with_vote_state.balance);
    try testing.expectEqual(@as(u32, 7), with_vote_state.height);
    try testing.expect(with_vote_state.vote_to != null);
    try testing.expect(std.mem.eql(u8, with_vote_state.vote_to.?[0..], pub_key_bytes[0..]));

    // Candidate parsing
    var candidate_values = [_]StackItem{
        StackItem{ .ByteString = pub_key_bytes[0..] },
        StackItem{ .Integer = 999 },
    };
    const candidate_item = StackItem{ .Struct = candidate_values[0..] };
    const candidate = try Candidate.fromStackItem(candidate_item);
    try testing.expectEqual(@as(i64, 999), candidate.votes);
    try testing.expect(std.mem.eql(u8, candidate.public_key[0..], pub_key_bytes[0..]));
}
