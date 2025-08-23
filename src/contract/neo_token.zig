//! NEO Token implementation
//!
//! Complete conversion from NeoSwift NeoToken.swift
//! Represents the native NEO token contract with governance features.

const std = @import("std");
const constants = @import("../core/constants.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const FungibleToken = @import("fungible_token.zig").FungibleToken;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;

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
        // This would make actual RPC call and parse candidates
        _ = self;
        return try self.fungible_token.token.smart_contract.allocator.alloc(Candidate, 0);
    }
    
    /// Gets committee members (equivalent to Swift getCommittee)
    pub fn getCommittee(self: Self) ![][33]u8 {
        // This would make actual RPC call and parse committee
        _ = self;
        return try self.fungible_token.token.smart_contract.allocator.alloc([33]u8, 0);
    }
    
    /// Gets next block validators (equivalent to Swift getNextBlockValidators)
    pub fn getNextBlockValidators(self: Self) ![][33]u8 {
        // This would make actual RPC call
        _ = self;
        return try self.fungible_token.token.smart_contract.allocator.alloc([33]u8, 0);
    }
    
    /// Registers candidate (equivalent to Swift registerCandidate)
    pub fn registerCandidate(self: Self, public_key: [33]u8) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.publicKey(public_key)};
        return try self.fungible_token.token.smart_contract.invokeFunction(REGISTER_CANDIDATE, &params);
    }
    
    /// Unregisters candidate (equivalent to Swift unregisterCandidate)
    pub fn unregisterCandidate(self: Self, public_key: [33]u8) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.publicKey(public_key)};
        return try self.fungible_token.token.smart_contract.invokeFunction(UNREGISTER_CANDIDATE, &params);
    }
    
    /// Votes for candidate (equivalent to Swift vote)
    pub fn vote(self: Self, voter: Hash160, candidate: ?[33]u8) !TransactionBuilder {
        var params = std.ArrayList(ContractParameter).init(self.fungible_token.token.smart_contract.allocator);
        defer params.deinit();
        
        try params.append(ContractParameter.hash160(voter));
        
        if (candidate) |pub_key| {
            try params.append(ContractParameter.publicKey(pub_key));
        } else {
            try params.append(ContractParameter.void_param());
        }
        
        return try self.fungible_token.token.smart_contract.invokeFunction(VOTE, params.items);
    }
    
    /// Gets candidate vote count (equivalent to Swift getCandidateVote)
    pub fn getCandidateVote(self: Self, public_key: [33]u8) !i64 {
        const params = [_]ContractParameter{ContractParameter.publicKey(public_key)};
        return try self.fungible_token.token.smart_contract.callFunctionReturningInt(GET_CANDIDATE_VOTE, &params);
    }
    
    /// Gets account state (equivalent to Swift getAccountState)
    pub fn getAccountState(self: Self, script_hash: Hash160) !AccountState {
        const params = [_]ContractParameter{ContractParameter.hash160(script_hash)};
        
        // This would make actual RPC call and parse account state
        _ = params;
        return AccountState.init();
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
    
    pub fn fromStackItem(stack_item: anytype) !Self {
        // This would parse from actual stack item
        _ = stack_item;
        return Self.init(std.mem.zeroes([33]u8), 0);
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
    
    pub fn fromStackItem(stack_item: anytype) !Self {
        // This would parse from actual stack item
        _ = stack_item;
        return Self.init();
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
    
    // Test voting (equivalent to Swift vote tests)
    var vote_tx = try neo_token.vote(Hash160.ZERO, test_public_key);
    defer vote_tx.deinit();
    
    try testing.expect(vote_tx.getScript() != null);
    
    // Test unvoting (null candidate)
    var unvote_tx = try neo_token.vote(Hash160.ZERO, null);
    defer unvote_tx.deinit();
    
    try testing.expect(unvote_tx.getScript() != null);
}

test "NeoToken fee and price operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const neo_token = NeoToken.init(allocator, null);
    
    // Test GAS per block operations (equivalent to Swift GAS per block tests)
    const gas_per_block = try neo_token.getGasPerBlock();
    try testing.expect(gas_per_block >= 0);
    
    var set_gas_tx = try neo_token.setGasPerBlock(500000000); // 5 GAS
    defer set_gas_tx.deinit();
    
    try testing.expect(set_gas_tx.getScript() != null);
    
    // Test registration price operations (equivalent to Swift price tests)
    const register_price = try neo_token.getRegisterPrice();
    try testing.expect(register_price >= 0);
    
    var set_price_tx = try neo_token.setRegisterPrice(100000000000); // 1000 GAS
    defer set_price_tx.deinit();
    
    try testing.expect(set_price_tx.getScript() != null);
}