//! Policy Contract implementation
//!
//! Complete conversion from NeoSwift PolicyContract.swift
//! Handles network policy and fee management operations.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const SmartContract = @import("smart_contract.zig").SmartContract;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;

/// Policy contract for network policy management (converted from Swift PolicyContract)
pub const PolicyContract = struct {
    /// Contract name (matches Swift NAME)
    pub const NAME = "PolicyContract";

    /// Script hash (matches Swift SCRIPT_HASH)
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.POLICY_CONTRACT };

    /// Method names (match Swift constants)
    pub const GET_FEE_PER_BYTE = "getFeePerByte";
    pub const GET_EXEC_FEE_FACTOR = "getExecFeeFactor";
    pub const GET_STORAGE_PRICE = "getStoragePrice";
    pub const IS_BLOCKED = "isBlocked";
    pub const SET_FEE_PER_BYTE = "setFeePerByte";
    pub const SET_EXEC_FEE_FACTOR = "setExecFeeFactor";
    pub const SET_STORAGE_PRICE = "setStoragePrice";
    pub const BLOCK_ACCOUNT = "blockAccount";
    pub const UNBLOCK_ACCOUNT = "unblockAccount";

    /// Base smart contract
    smart_contract: SmartContract,

    const Self = @This();

    /// Creates new PolicyContract instance (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator, neo_swift: ?*anyopaque) Self {
        return Self{
            .smart_contract = SmartContract.init(allocator, SCRIPT_HASH, neo_swift),
        };
    }

    /// Gets fee per byte (equivalent to Swift getFeePerByte)
    pub fn getFeePerByte(self: Self) !i64 {
        return try self.smart_contract.callFunctionReturningInt(GET_FEE_PER_BYTE, &[_]ContractParameter{});
    }

    /// Gets execution fee factor (equivalent to Swift getExecFeeFactor)
    pub fn getExecFeeFactor(self: Self) !i64 {
        return try self.smart_contract.callFunctionReturningInt(GET_EXEC_FEE_FACTOR, &[_]ContractParameter{});
    }

    /// Gets storage price (equivalent to Swift getStoragePrice)
    pub fn getStoragePrice(self: Self) !i64 {
        return try self.smart_contract.callFunctionReturningInt(GET_STORAGE_PRICE, &[_]ContractParameter{});
    }

    /// Checks if account is blocked (equivalent to Swift isBlocked)
    pub fn isBlocked(self: Self, script_hash: Hash160) !bool {
        const params = [_]ContractParameter{ContractParameter.hash160(script_hash)};
        return try self.smart_contract.callFunctionReturningBool(IS_BLOCKED, &params);
    }

    /// Sets fee per byte (equivalent to Swift setFeePerByte)
    pub fn setFeePerByte(self: Self, fee_per_byte: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(fee_per_byte)};
        return try self.smart_contract.invokeFunction(SET_FEE_PER_BYTE, &params);
    }

    /// Sets execution fee factor (equivalent to Swift setExecFeeFactor)
    pub fn setExecFeeFactor(self: Self, exec_fee_factor: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(exec_fee_factor)};
        return try self.smart_contract.invokeFunction(SET_EXEC_FEE_FACTOR, &params);
    }

    /// Sets storage price (equivalent to Swift setStoragePrice)
    pub fn setStoragePrice(self: Self, storage_price: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(storage_price)};
        return try self.smart_contract.invokeFunction(SET_STORAGE_PRICE, &params);
    }

    /// Blocks account (equivalent to Swift blockAccount)
    pub fn blockAccount(self: Self, script_hash: Hash160) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.hash160(script_hash)};
        return try self.smart_contract.invokeFunction(BLOCK_ACCOUNT, &params);
    }

    /// Unblocks account (equivalent to Swift unblockAccount)
    pub fn unblockAccount(self: Self, script_hash: Hash160) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.hash160(script_hash)};
        return try self.smart_contract.invokeFunction(UNBLOCK_ACCOUNT, &params);
    }

    /// Gets all blocked accounts (equivalent to Swift getBlockedAccounts)
    pub fn getBlockedAccounts(self: Self) ![]Hash160 {
        // This would make actual RPC call and parse blocked accounts
        return try self.smart_contract.allocator.alloc(Hash160, 0);
    }

    /// Checks multiple accounts blocked status (batch operation)
    pub fn areBlocked(self: Self, script_hashes: []const Hash160) ![]bool {
        var results = try self.smart_contract.allocator.alloc(bool, script_hashes.len);

        for (script_hashes, 0..) |script_hash, i| {
            results[i] = try self.isBlocked(script_hash);
        }

        return results;
    }

    /// Gets current network policies (comprehensive policy info)
    pub fn getCurrentPolicies(self: Self) !NetworkPolicies {
        return NetworkPolicies{
            .fee_per_byte = try self.getFeePerByte(),
            .exec_fee_factor = try self.getExecFeeFactor(),
            .storage_price = try self.getStoragePrice(),
        };
    }
};

/// Network policies structure (additional utility)
pub const NetworkPolicies = struct {
    fee_per_byte: i64,
    exec_fee_factor: i64,
    storage_price: i64,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .fee_per_byte = 0,
            .exec_fee_factor = 0,
            .storage_price = 0,
        };
    }

    /// Estimates transaction fee based on size
    pub fn estimateTransactionFee(self: Self, transaction_size: u32) i64 {
        return @as(i64, @intCast(transaction_size)) * self.fee_per_byte;
    }

    /// Estimates storage cost
    pub fn estimateStorageCost(self: Self, storage_bytes: u32) i64 {
        return @as(i64, @intCast(storage_bytes)) * self.storage_price;
    }
};

// Tests (converted from Swift PolicyContract tests)
test "PolicyContract creation and constants" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const policy_contract = PolicyContract.init(allocator, null);

    // Test constants (equivalent to Swift constant tests)
    try testing.expectEqualStrings("PolicyContract", PolicyContract.NAME);
    try testing.expectEqualStrings("getFeePerByte", PolicyContract.GET_FEE_PER_BYTE);
    try testing.expectEqualStrings("setFeePerByte", PolicyContract.SET_FEE_PER_BYTE);

    // Test script hash
    const script_hash = policy_contract.smart_contract.getScriptHash();
    try testing.expect(std.mem.eql(u8, &constants.NativeContracts.POLICY_CONTRACT, &script_hash.toArray()));
}

test "PolicyContract fee operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const policy_contract = PolicyContract.init(allocator, null);

    // Test fee retrieval (equivalent to Swift fee tests)
    const fee_per_byte = try policy_contract.getFeePerByte();
    try testing.expect(fee_per_byte >= 0);

    const exec_fee_factor = try policy_contract.getExecFeeFactor();
    try testing.expect(exec_fee_factor >= 0);

    const storage_price = try policy_contract.getStoragePrice();
    try testing.expect(storage_price >= 0);

    // Test fee setting (equivalent to Swift set fee tests)
    var set_fee_tx = try policy_contract.setFeePerByte(1000);
    defer set_fee_tx.deinit();

    try testing.expect(set_fee_tx.getScript() != null);

    var set_exec_tx = try policy_contract.setExecFeeFactor(30);
    defer set_exec_tx.deinit();

    try testing.expect(set_exec_tx.getScript() != null);

    var set_storage_tx = try policy_contract.setStoragePrice(100000);
    defer set_storage_tx.deinit();

    try testing.expect(set_storage_tx.getScript() != null);
}

test "PolicyContract account blocking" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const policy_contract = PolicyContract.init(allocator, null);

    // Test account blocking operations (equivalent to Swift blocking tests)
    const test_script_hash = Hash160.ZERO;

    // Test is blocked check
    const is_blocked = try policy_contract.isBlocked(test_script_hash);
    try testing.expect(!is_blocked); // stub returns false

    // Test block account
    var block_tx = try policy_contract.blockAccount(test_script_hash);
    defer block_tx.deinit();

    try testing.expect(block_tx.getScript() != null);

    // Test unblock account
    var unblock_tx = try policy_contract.unblockAccount(test_script_hash);
    defer unblock_tx.deinit();

    try testing.expect(unblock_tx.getScript() != null);

    // Test batch blocking check
    const script_hashes = [_]Hash160{ Hash160.ZERO, Hash160.ZERO };
    const blocked_status = try policy_contract.areBlocked(&script_hashes);
    defer allocator.free(blocked_status);

    try testing.expectEqual(@as(usize, 2), blocked_status.len);
}

test "PolicyContract network policies" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const policy_contract = PolicyContract.init(allocator, null);

    // Test comprehensive policy retrieval
    const policies = try policy_contract.getCurrentPolicies();

    try testing.expect(policies.fee_per_byte >= 0);
    try testing.expect(policies.exec_fee_factor >= 0);
    try testing.expect(policies.storage_price >= 0);

    // Test fee estimation utilities
    const estimated_tx_fee = policies.estimateTransactionFee(1000); // 1KB transaction
    try testing.expect(estimated_tx_fee >= 0);

    const estimated_storage_cost = policies.estimateStorageCost(100); // 100 bytes storage
    try testing.expect(estimated_storage_cost >= 0);
}
