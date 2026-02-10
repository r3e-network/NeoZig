//! Policy Contract implementation
//!
//! Neo N3 
//! Handles network policy and fee management operations.

const std = @import("std");

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const StackItem = @import("../types/stack_item.zig").StackItem;
const SmartContract = @import("smart_contract.zig").SmartContract;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;
const NeoClient = @import("../rpc/neo_client.zig").NeoClient;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const iterator_mod = @import("iterator.zig");

/// Policy contract for network policy management
pub const PolicyContract = struct {
    /// Contract name
    pub const NAME = "PolicyContract";

    /// Script hash
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.POLICY_CONTRACT };

    /// Method names
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

    /// Creates new PolicyContract instance
    pub fn init(allocator: std.mem.Allocator, client: ?*anyopaque) Self {
        return Self{
            .smart_contract = SmartContract.init(allocator, SCRIPT_HASH, client),
        };
    }

    /// Gets script hash for this contract.
    pub fn getScriptHash(self: Self) Hash160 {
        return self.smart_contract.getScriptHash();
    }

    /// Validates the underlying contract configuration.
    pub fn validate(self: Self) !void {
        try self.smart_contract.validate();
        if (!self.smart_contract.getScriptHash().eql(SCRIPT_HASH)) {
            return errors.ContractError.InvalidContract;
        }
    }

    /// Returns true if this contract is native.
    pub fn isNativeContract(self: Self) bool {
        return self.smart_contract.isNativeContract();
    }

    /// Gets fee per byte
    pub fn getFeePerByte(self: Self) !i64 {
        return try self.smart_contract.callFunctionReturningInt(GET_FEE_PER_BYTE, &[_]ContractParameter{});
    }

    /// Gets execution fee factor
    pub fn getExecFeeFactor(self: Self) !i64 {
        return try self.smart_contract.callFunctionReturningInt(GET_EXEC_FEE_FACTOR, &[_]ContractParameter{});
    }

    /// Gets storage price
    pub fn getStoragePrice(self: Self) !i64 {
        return try self.smart_contract.callFunctionReturningInt(GET_STORAGE_PRICE, &[_]ContractParameter{});
    }

    /// Checks if account is blocked
    pub fn isBlocked(self: Self, script_hash: Hash160) !bool {
        const params = [_]ContractParameter{ContractParameter.hash160(script_hash)};
        return try self.smart_contract.callFunctionReturningBool(IS_BLOCKED, &params);
    }

    /// Sets fee per byte
    pub fn setFeePerByte(self: Self, fee_per_byte: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(fee_per_byte)};
        return try self.smart_contract.invokeFunction(SET_FEE_PER_BYTE, &params);
    }

    /// Sets execution fee factor
    pub fn setExecFeeFactor(self: Self, exec_fee_factor: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(exec_fee_factor)};
        return try self.smart_contract.invokeFunction(SET_EXEC_FEE_FACTOR, &params);
    }

    /// Sets storage price
    pub fn setStoragePrice(self: Self, storage_price: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(storage_price)};
        return try self.smart_contract.invokeFunction(SET_STORAGE_PRICE, &params);
    }

    /// Blocks account
    pub fn blockAccount(self: Self, script_hash: Hash160) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.hash160(script_hash)};
        return try self.smart_contract.invokeFunction(BLOCK_ACCOUNT, &params);
    }

    /// Unblocks account
    pub fn unblockAccount(self: Self, script_hash: Hash160) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.hash160(script_hash)};
        return try self.smart_contract.invokeFunction(UNBLOCK_ACCOUNT, &params);
    }

    /// Gets all blocked accounts
    pub fn getBlockedAccounts(self: Self) ![]Hash160 {
        const smart_contract = self.smart_contract;
        if (smart_contract.client == null) return errors.NeoError.InvalidConfiguration;

        const client: *NeoClient = @ptrCast(@alignCast(smart_contract.client.?));
        var request = try client.invokeFunction(smart_contract.script_hash, "getBlockedAccounts", &[_]ContractParameter{}, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = client.getService().getAllocator();
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
            fn map(stack_item: StackItem, allocator: std.mem.Allocator) !Hash160 {
                const bytes = try stack_item.getByteArray(allocator);
                defer allocator.free(bytes);
                if (bytes.len != constants.HASH160_SIZE) return errors.SerializationError.InvalidFormat;
                var buf: [constants.HASH160_SIZE]u8 = undefined;
                @memcpy(&buf, bytes);
                std.mem.reverse(u8, &buf);
                return Hash160.fromArray(buf);
            }
        }.map;

        var iterator = try iterator_mod.Iterator(Hash160).init(
            smart_contract.allocator,
            smart_contract.client.?,
            session_id,
            interop.iterator_id,
            mapper,
        );
        defer iterator.deinit();

        const items = try iterator.traverseAll(SmartContract.DEFAULT_ITERATOR_COUNT);
        iterator.terminateSession() catch {};
        return items;
    }

    /// Checks multiple accounts blocked status (batch operation)
    pub fn areBlocked(self: Self, script_hashes: []const Hash160) ![]bool {
        const results = try self.smart_contract.allocator.alloc(bool, script_hashes.len);
        errdefer self.smart_contract.allocator.free(results);

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

// Tests
test "PolicyContract creation and constants" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const policy_contract = PolicyContract.init(allocator, null);

    // Test constants
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

    // Test fee retrieval
    try testing.expectError(errors.NeoError.InvalidConfiguration, policy_contract.getFeePerByte());
    try testing.expectError(errors.NeoError.InvalidConfiguration, policy_contract.getExecFeeFactor());
    try testing.expectError(errors.NeoError.InvalidConfiguration, policy_contract.getStoragePrice());

    // Test fee setting
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

    // Test account blocking operations
    const test_script_hash = Hash160.ZERO;

    // Test is blocked check
    try testing.expectError(errors.NeoError.InvalidConfiguration, policy_contract.isBlocked(test_script_hash));

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
    try testing.expectError(errors.NeoError.InvalidConfiguration, policy_contract.areBlocked(&script_hashes));
}

test "PolicyContract network policies" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const policy_contract = PolicyContract.init(allocator, null);

    // Test comprehensive policy retrieval
    try testing.expectError(errors.NeoError.InvalidConfiguration, policy_contract.getCurrentPolicies());
}
