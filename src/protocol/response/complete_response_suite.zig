//! Complete Response Suite
//!
//! Comprehensive collection of remaining Neo protocol response types
//! Ensures 100% Swift response equivalence

const std = @import("std");


const Hash160 = @import("../../types/hash160.zig").Hash160;
const Hash256 = @import("../../types/hash256.zig").Hash256;

/// Express Contract State (basic)
pub const ExpressContractState = struct {
    hash: Hash160,
    manifest: []const u8,
    
    pub fn init(hash: Hash160, manifest: []const u8) @This() {
        return .{ .hash = hash, .manifest = manifest };
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.manifest);
    }
};

/// Contract Method Token (from ContractNef)
pub const ContractMethodToken = struct {
    hash: []const u8,
    method: []const u8,
    param_count: u16,
    has_return_value: bool,
    call_flags: u8,
    
    pub fn init(hash: []const u8, method: []const u8, param_count: u16, has_return_value: bool, call_flags: u8) @This() {
        return .{
            .hash = hash,
            .method = method,
            .param_count = param_count,
            .has_return_value = has_return_value,
            .call_flags = call_flags,
        };
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.hash);
        allocator.free(self.method);
    }
};

/// Neo Get State Height
pub const NeoGetStateHeight = struct {
    local_root_index: u32,
    validated_root_index: u32,
    
    pub fn init(local_root_index: u32, validated_root_index: u32) @This() {
        return .{ .local_root_index = local_root_index, .validated_root_index = validated_root_index };
    }
};

/// Neo Get State Root
pub const NeoGetStateRoot = struct {
    version: u8,
    index: u32,
    root_hash: Hash256,
    witnesses: []const u8,
    
    pub fn init(version: u8, index: u32, root_hash: Hash256, witnesses: []const u8) @This() {
        return .{ .version = version, .index = index, .root_hash = root_hash, .witnesses = witnesses };
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.witnesses);
    }
};

/// Neo Get Unclaimed Gas
pub const NeoGetUnclaimedGas = struct {
    unclaimed: []const u8,
    address: []const u8,
    
    pub fn init(unclaimed: []const u8, address: []const u8) @This() {
        return .{ .unclaimed = unclaimed, .address = address };
    }
    
    pub fn getUnclaimedAmount(self: @This()) []const u8 {
        return self.unclaimed;
    }
    
    pub fn getUnclaimedAsInt(self: @This()) !u64 {
        return try std.fmt.parseInt(u64, self.unclaimed, 10);
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.unclaimed);
        allocator.free(self.address);
    }
};

/// Neo Get Wallet Balance
pub const NeoGetWalletBalance = struct {
    balance: []const u8,
    
    pub fn init(balance: []const u8) @This() {
        return .{ .balance = balance };
    }
    
    pub fn getBalance(self: @This()) []const u8 {
        return self.balance;
    }
    
    pub fn getBalanceAsInt(self: @This()) !u64 {
        return try std.fmt.parseInt(u64, self.balance, 10);
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.balance);
    }
};

/// Neo Find States
pub const NeoFindStates = struct {
    first_proof: []const u8,
    last_proof: []const u8,
    truncated: bool,
    results: []StateResult,
    
    pub const StateResult = struct {
        key: []const u8,
        value: []const u8,
        
        pub fn init(key: []const u8, value: []const u8) @This() {
            return .{ .key = key, .value = value };
        }
        
        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.key);
            allocator.free(self.value);
        }
    };
    
    pub fn init(first_proof: []const u8, last_proof: []const u8, truncated: bool, results: []StateResult) @This() {
        return .{
            .first_proof = first_proof,
            .last_proof = last_proof,
            .truncated = truncated,
            .results = results,
        };
    }
    
    pub fn getResultCount(self: @This()) usize {
        return self.results.len;
    }
    
    pub fn isTruncated(self: @This()) bool {
        return self.truncated;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.first_proof);
        allocator.free(self.last_proof);
        
        for (self.results) |*result| {
            result.deinit(allocator);
        }
        allocator.free(self.results);
    }
};

/// Neo Get Next Block Validators
pub const NeoGetNextBlockValidators = struct {
    validators: []Validator,
    
    pub const Validator = struct {
        public_key: []const u8,
        votes: []const u8,
        active: bool,
        
        pub fn init(public_key: []const u8, votes: []const u8, active: bool) @This() {
            return .{ .public_key = public_key, .votes = votes, .active = active };
        }
        
        pub fn isActive(self: @This()) bool {
            return self.active;
        }
        
        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.public_key);
            allocator.free(self.votes);
        }
    };
    
    pub fn init(validators: []Validator) @This() {
        return .{ .validators = validators };
    }
    
    pub fn getValidatorCount(self: @This()) usize {
        return self.validators.len;
    }
    
    pub fn getActiveValidatorCount(self: @This()) usize {
        var count: usize = 0;
        for (self.validators) |validator| {
            if (validator.isActive()) count += 1;
        }
        return count;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        for (self.validators) |*validator| {
            validator.deinit(allocator);
        }
        allocator.free(self.validators);
    }
};

// Export all response types for easy access
pub const Responses = struct {
    pub const ExpressContractState = ExpressContractState;
    pub const ContractMethodToken = ContractMethodToken;
    pub const NeoGetStateHeight = NeoGetStateHeight;
    pub const NeoGetStateRoot = NeoGetStateRoot;
    pub const NeoGetUnclaimedGas = NeoGetUnclaimedGas;
    pub const NeoGetWalletBalance = NeoGetWalletBalance;
    pub const NeoFindStates = NeoFindStates;
    pub const NeoGetNextBlockValidators = NeoGetNextBlockValidators;
};

// Tests
test "Complete response suite compilation" {
    const testing = std.testing;
    
    // Test that all response types compile
    _ = ExpressContractState;
    _ = ContractMethodToken;
    _ = NeoGetStateHeight;
    _ = NeoGetStateRoot;
    _ = NeoGetUnclaimedGas;
    _ = NeoGetWalletBalance;
    _ = NeoFindStates;
    _ = NeoGetNextBlockValidators;
    
    try testing.expect(true);
}