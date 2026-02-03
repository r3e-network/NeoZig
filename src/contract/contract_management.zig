//! Contract Management implementation
//!
//! Complete conversion from NeoSwift ContractManagement.swift
//! Handles contract deployment, management, and state operations.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const StackItem = @import("../types/stack_item.zig").StackItem;
const SmartContract = @import("smart_contract.zig").SmartContract;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;
const NeoSwift = @import("../rpc/neo_client.zig").NeoSwift;
const NeoProtocol = @import("../protocol/neo_protocol.zig").NeoProtocol;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const iterator_mod = @import("iterator.zig");
const responses = @import("../rpc/responses.zig");

/// Contract Management contract (converted from Swift ContractManagement)
pub const ContractManagement = struct {
    /// Contract name (matches Swift NAME)
    pub const NAME = "ContractManagement";

    /// Method names (match Swift constants)
    pub const GET_MINIMUM_DEPLOYMENT_FEE = "getMinimumDeploymentFee";
    pub const SET_MINIMUM_DEPLOYMENT_FEE = "setMinimumDeploymentFee";
    pub const GET_CONTRACT_BY_ID = "getContractById";
    pub const GET_CONTRACT_HASHES = "getContractHashes";
    pub const HAS_METHOD = "hasMethod";
    pub const DEPLOY = "deploy";

    /// Script hash (matches Swift SCRIPT_HASH calculation)
    pub const SCRIPT_HASH: Hash160 = Hash160{ .bytes = constants.NativeContracts.CONTRACT_MANAGEMENT };

    /// Base smart contract
    smart_contract: SmartContract,

    const Self = @This();

    /// Creates new ContractManagement instance (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator, neo_swift: ?*anyopaque) Self {
        return Self{
            .smart_contract = SmartContract.init(allocator, SCRIPT_HASH, neo_swift),
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

    /// Gets minimum deployment fee (equivalent to Swift getMinimumDeploymentFee)
    pub fn getMinimumDeploymentFee(self: Self) !i64 {
        return try self.smart_contract.callFunctionReturningInt(GET_MINIMUM_DEPLOYMENT_FEE, &[_]ContractParameter{});
    }

    /// Sets minimum deployment fee (equivalent to Swift setMinimumDeploymentFee)
    pub fn setMinimumDeploymentFee(self: Self, minimum_fee: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(minimum_fee)};
        return try self.smart_contract.invokeFunction(SET_MINIMUM_DEPLOYMENT_FEE, &params);
    }

    /// Gets contract state by hash (equivalent to Swift getContract)
    pub fn getContract(self: Self, contract_hash: Hash160) !ContractState {
        const smart_contract = self.smart_contract;
        if (smart_contract.neo_swift == null) return errors.NeoError.InvalidConfiguration;

        const neo_swift: *NeoSwift = @ptrCast(@alignCast(smart_contract.neo_swift.?));
        var protocol = NeoProtocol.init(neo_swift.getService());
        var request = try protocol.getContractState(contract_hash);
        var response = try request.sendUsing(protocol.service);
        const service_allocator = neo_swift.getService().getAllocator();
        defer response.deinit(service_allocator);

        const state = response.result orelse return errors.ContractError.InvalidContractState;
        response.result = null;
        return state;
    }

    /// Gets contract by ID (equivalent to Swift getContractById)
    pub fn getContractById(self: Self, contract_id: i32) !ContractState {
        const contract_hash = try self.getContractHashById(contract_id);
        return try self.getContract(contract_hash);
    }

    /// Gets contract hash by ID (equivalent to Swift getContractHashById)
    fn getContractHashById(self: Self, contract_id: i32) !Hash160 {
        const params = [_]ContractParameter{ContractParameter.integer(contract_id)};

        // This would make actual RPC call and parse response
        return try self.smart_contract.callFunctionReturningHash160("getContract", &params);
    }

    /// Gets all contract hashes (equivalent to Swift getContractHashes)
    pub fn getContractHashes(self: Self) !ContractIterator {
        return try self.callFunctionReturningIterator(GET_CONTRACT_HASHES, &[_]ContractParameter{});
    }

    /// Gets contract hashes unwrapped (equivalent to Swift getContractHashesUnwrapped)
    pub fn getContractHashesUnwrapped(self: Self) ![]ContractIdentifiers {
        return try self.callFunctionAndUnwrapIterator(
            GET_CONTRACT_HASHES,
            &[_]ContractParameter{},
            SmartContract.DEFAULT_ITERATOR_COUNT,
        );
    }

    /// Checks if contract has method (equivalent to Swift hasMethod)
    pub fn hasMethod(self: Self, contract_hash: Hash160, method: []const u8, parameter_count: i32) !bool {
        const params = [_]ContractParameter{
            ContractParameter.hash160(contract_hash),
            ContractParameter.string(method),
            ContractParameter.integer(parameter_count),
        };

        return try self.smart_contract.callFunctionReturningBool(HAS_METHOD, &params);
    }

    /// Deploys contract (equivalent to Swift deploy)
    pub fn deploy(
        self: Self,
        nef_file: []const u8,
        manifest: []const u8,
        data: ?[]const u8,
    ) !TransactionBuilder {
        var params : ArrayList(ContractParameter) = .{ .allocator = self.smart_contract.allocator };
        defer params.deinit();

        try params.append(ContractParameter.byteArray(nef_file));
        try params.append(ContractParameter.string(manifest));

        if (data) |deployment_data| {
            try params.append(ContractParameter.byteArray(deployment_data));
        }

        return try self.smart_contract.invokeFunction(DEPLOY, params.items);
    }

    /// Updates contract (equivalent to Swift update)
    pub fn update(
        self: Self,
        nef_file: []const u8,
        manifest: []const u8,
        data: ?[]const u8,
    ) !TransactionBuilder {
        var params : ArrayList(ContractParameter) = .{ .allocator = self.smart_contract.allocator };
        defer params.deinit();

        try params.append(ContractParameter.byteArray(nef_file));
        try params.append(ContractParameter.string(manifest));

        if (data) |update_data| {
            try params.append(ContractParameter.byteArray(update_data));
        }

        return try self.smart_contract.invokeFunction("update", params.items);
    }

    /// Destroys contract (equivalent to Swift destroy)
    pub fn destroy(self: Self) !TransactionBuilder {
        return try self.smart_contract.invokeFunction("destroy", &[_]ContractParameter{});
    }

    /// Helper methods for iterator handling
    fn callFunctionReturningIterator(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) !ContractIterator {
        const smart_contract = self.smart_contract;
        if (smart_contract.neo_swift == null) return errors.NeoError.InvalidConfiguration;

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

        return try ContractIterator.initWithIterator(
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
    ) ![]ContractIdentifiers {
        const smart_contract = self.smart_contract;
        if (smart_contract.neo_swift == null) return errors.NeoError.InvalidConfiguration;

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
            fn map(stack_item: StackItem, allocator: std.mem.Allocator) !ContractIdentifiers {
                return try ContractIdentifiers.fromStackItem(stack_item, allocator);
            }
        }.map;

        var iterator = try iterator_mod.Iterator(ContractIdentifiers).init(
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

    fn unwrapIterator(self: Self, iterator: ContractIterator, max_items: u32) ![]ContractIdentifiers {
        var iter = iterator;
        defer iter.deinit();

        var items : ArrayList(ContractIdentifiers) = .{ .allocator = self.smart_contract.allocator };
        defer items.deinit();

        var retrieved: u32 = 0;
        while (retrieved < max_items and iter.hasNext()) {
            const entry = try iter.next();
            try items.append(entry);
            retrieved += 1;
        }

        return try items.toOwnedSlice();
    }
};

/// Contract iterator (converted from Swift Iterator pattern).
/// Iterator traversal is performed via the Neo RPC `traverseiterator` mechanism.
/// When constructed without a NeoSwift instance, this iterator is empty.
pub const ContractIterator = struct {
    session_id: []const u8,
    iterator_id: []const u8,
    allocator: std.mem.Allocator,
    inner: ?iterator_mod.Iterator(ContractIdentifiers),
    buffer: ArrayList(ContractIdentifiers),
    exhausted: bool,

    const Self = @This();

    pub fn init() Self {
        return initWithAllocator(std.heap.page_allocator);
    }

    pub fn initWithAllocator(allocator: std.mem.Allocator) Self {
        return Self{
            .session_id = "",
            .iterator_id = "",
            .allocator = allocator,
            .inner = null,
            .buffer = .{ .allocator = allocator },
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
            fn map(stack_item: StackItem, alloc: std.mem.Allocator) !ContractIdentifiers {
                return try ContractIdentifiers.fromStackItem(stack_item, alloc);
            }
        }.map;

        const inner_iter = try iterator_mod.Iterator(ContractIdentifiers).init(
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
            .buffer = .{ .allocator = allocator },
            .exhausted = false,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.inner) |*inner_iter| {
            inner_iter.terminateSession() catch {};
            inner_iter.deinit();
            self.inner = null;
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

    pub fn next(self: *Self) !ContractIdentifiers {
        if (self.buffer.items.len == 0) {
            if (!self.hasNext()) {
                return errors.throwIllegalState("Iterator exhausted");
            }
        }

        return self.buffer.orderedRemove(0);
    }
};

/// Contract identifiers (converted from Swift ContractState.ContractIdentifiers)
pub const ContractIdentifiers = struct {
    id: i32,
    hash: Hash160,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .id = 0,
            .hash = Hash160.ZERO,
        };
    }

    pub fn fromStackItem(stack_item: StackItem, allocator: std.mem.Allocator) !Self {
        const item = stack_item;
        const values = try item.getArray();
        if (values.len < 2) return errors.SerializationError.InvalidFormat;

        const id_value = try values[0].getInteger();
        if (id_value < std.math.minInt(i32) or id_value > std.math.maxInt(i32)) {
            return errors.SerializationError.InvalidFormat;
        }

        const hash_bytes = try values[1].getByteArray(allocator);
        defer allocator.free(hash_bytes);
        if (hash_bytes.len != constants.HASH160_SIZE) {
            return errors.SerializationError.InvalidFormat;
        }

        var buf: [constants.HASH160_SIZE]u8 = undefined;
        @memcpy(&buf, hash_bytes);
        std.mem.reverse(u8, &buf);

        return Self{
            .id = @intCast(id_value),
            .hash = Hash160.fromArray(buf),
        };
    }
};

pub const ContractState = responses.ContractState;
pub const ContractNef = responses.ContractNef;
pub const ContractManifest = responses.ContractManifest;
pub const ContractGroup = responses.ContractGroup;
pub const ContractFeatures = responses.ContractFeatures;
pub const ContractABI = responses.ContractABI;
pub const ContractMethod = responses.ContractMethod;
pub const ContractEvent = responses.ContractEvent;
pub const ContractPermission = responses.ContractPermission;

// Tests (converted from Swift ContractManagement tests)
test "ContractManagement creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_mgmt = ContractManagement.init(allocator, null);

    // Test script hash (equivalent to Swift SCRIPT_HASH test)
    try testing.expect(!contract_mgmt.smart_contract.getScriptHash().eql(Hash160.ZERO));

    // Test constant values
    try testing.expectEqualStrings("ContractManagement", ContractManagement.NAME);
    try testing.expectEqualStrings("getMinimumDeploymentFee", ContractManagement.GET_MINIMUM_DEPLOYMENT_FEE);
    try testing.expectEqualStrings("deploy", ContractManagement.DEPLOY);
}

test "ContractManagement deployment operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_mgmt = ContractManagement.init(allocator, null);

    // Test contract deployment (equivalent to Swift deploy tests)
    const nef_file = [_]u8{ 0x4E, 0x45, 0x46, 0x33 }; // Mock NEF file
    const manifest = "{}"; // Mock manifest JSON

    var deploy_tx = try contract_mgmt.deploy(&nef_file, manifest, null);
    defer deploy_tx.deinit();

    // Should have script
    try testing.expect(deploy_tx.getScript() != null);

    // Test with deployment data
    const deployment_data = [_]u8{ 0x01, 0x02, 0x03 };
    var deploy_with_data_tx = try contract_mgmt.deploy(&nef_file, manifest, &deployment_data);
    defer deploy_with_data_tx.deinit();

    try testing.expect(deploy_with_data_tx.getScript() != null);
}

test "ContractManagement method validation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_mgmt = ContractManagement.init(allocator, null);

    // Test hasMethod functionality (equivalent to Swift hasMethod tests)
    const test_hash = Hash160.ZERO;
    try testing.expectError(errors.NeoError.InvalidConfiguration, contract_mgmt.hasMethod(test_hash, "testMethod", 2));
}

test "ContractManagement fee operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_mgmt = ContractManagement.init(allocator, null);

    // Test minimum deployment fee operations (equivalent to Swift fee tests)
    try testing.expectError(errors.NeoError.InvalidConfiguration, contract_mgmt.getMinimumDeploymentFee());

    // Test setting minimum fee
    var set_fee_tx = try contract_mgmt.setMinimumDeploymentFee(1000000);
    defer set_fee_tx.deinit();

    try testing.expect(set_fee_tx.getScript() != null);
}
