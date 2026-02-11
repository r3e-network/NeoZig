//! Smart Contract implementation
//!
//! Neo N3 
//! Essential for contract interaction and deployment.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const ScriptBuilder = @import("../script/script_builder.zig").ScriptBuilder;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;
const NeoClient = @import("../rpc/neo_client.zig").NeoClient;
const NeoProtocol = @import("../protocol/neo_protocol.zig").NeoProtocol;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const responses = @import("../rpc/responses.zig");

/// Smart contract representation
pub const SmartContract = struct {
    /// Default iterator count
    pub const DEFAULT_ITERATOR_COUNT: u32 = 100;

    /// Contract script hash
    script_hash: Hash160,
    /// Neo client reference
    client: ?*anyopaque, // stub for NeoClient reference
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Creates smart contract instance
    pub fn init(allocator: std.mem.Allocator, script_hash: Hash160, client: ?*anyopaque) Self {
        return Self{
            .script_hash = script_hash,
            .client = client,
            .allocator = allocator,
        };
    }

    /// Gets contract script hash
    pub fn getScriptHash(self: Self) Hash160 {
        return self.script_hash;
    }

    /// Validates that the contract has a usable script hash.
    pub fn validate(self: Self) !void {
        if (self.script_hash.eql(Hash160.ZERO)) {
            return errors.ContractError.InvalidContract;
        }
    }

    /// Returns true if this script hash matches a native contract.
    pub fn isNativeContract(self: Self) bool {
        return isNativeScriptHash(self.script_hash);
    }

    /// Invokes contract function
    pub fn invokeFunction(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) !TransactionBuilder {
        const script = try self.buildInvokeFunctionScript(function_name, params);
        defer self.allocator.free(script);

        var tx_builder = TransactionBuilder.init(self.allocator);
        _ = try tx_builder.script(script);
        return tx_builder;
    }

    /// Builds invoke function script
    pub fn buildInvokeFunctionScript(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) ![]u8 {
        if (function_name.len == 0) {
            return errors.throwIllegalArgument("The invocation function must not be empty");
        }

        var builder = ScriptBuilder.init(self.allocator);
        defer builder.deinit();

        _ = try builder.contractCall(self.script_hash, function_name, params, null);
        return try self.allocator.dupe(u8, builder.toScript());
    }

    /// Validates invocation method name and parameters before building scripts.
    pub fn validateInvocation(self: Self, function_name: []const u8, params: []const ContractParameter) !void {
        _ = self;
        _ = params;

        if (function_name.len == 0) {
            return errors.throwIllegalArgument("The invocation function must not be empty");
        }

        for (function_name) |ch| {
            if (std.ascii.isWhitespace(ch)) {
                return errors.throwIllegalArgument("The invocation function must not contain whitespace");
            }
        }
    }

    /// Calls function returning string
    pub fn callFunctionReturningString(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) ![]u8 {
        const client = try self.getClient();
        var request = try client.invokeFunction(self.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = client.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        return try stack_item.getString(self.allocator);
    }

    /// Calls function returning integer
    pub fn callFunctionReturningInt(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) !i64 {
        const client = try self.getClient();
        var request = try client.invokeFunction(self.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = client.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        return try stack_item.getInteger();
    }

    /// Calls function returning boolean
    pub fn callFunctionReturningBool(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) !bool {
        const client = try self.getClient();
        var request = try client.invokeFunction(self.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = client.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        return try stack_item.getBoolean();
    }

    /// Calls function returning Hash160 (used by native contracts).
    /// If no RPC client is attached, returns `Hash160.ZERO`.
    pub fn callFunctionReturningHash160(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) !Hash160 {
        const client = try self.getClient();
        var request = try client.invokeFunction(self.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = client.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();

        // Neo nodes return script hashes as ByteString in little-endian order.
        const bytes = try stack_item.getByteArray(self.allocator);
        defer self.allocator.free(bytes);

        if (bytes.len == constants.HASH160_SIZE) {
            var buf: [constants.HASH160_SIZE]u8 = undefined;
            @memcpy(&buf, bytes);
            std.mem.reverse(u8, &buf);
            return Hash160.fromArray(buf);
        }

        // Fall back to interpreting the value as a hex string.
        const hex = try stack_item.getString(self.allocator);
        defer self.allocator.free(hex);
        return try Hash160.initWithString(hex);
    }

    /// Calls function returning byte array (used by CryptoLib hash operations).
    pub fn callFunctionReturningBytes(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) ![]u8 {
        const client = try self.getClient();
        var request = try client.invokeFunction(self.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = client.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        return try stack_item.getByteArray(self.allocator);
    }

    /// Gets contract manifest
    pub fn getManifest(self: Self) !ContractManifest {
        const client = try self.getClient();
        var protocol = NeoProtocol.init(client.getService());
        var request = try protocol.getContractState(self.script_hash);
        var response = try request.sendUsing(protocol.service);
        const service_allocator = client.getService().getAllocator();
        defer response.deinit(service_allocator);

        var state = response.result orelse return errors.ContractError.InvalidContractState;
        response.result = null;
        const manifest = state.manifest;
        state.manifest = ContractManifest.init();
        state.deinit(service_allocator);
        return manifest;
    }

    /// Gets contract state
    pub fn getContractState(self: Self) !ContractState {
        const client = try self.getClient();
        var protocol = NeoProtocol.init(client.getService());
        var request = try protocol.getContractState(self.script_hash);
        var response = try request.sendUsing(protocol.service);
        const service_allocator = client.getService().getAllocator();
        defer response.deinit(service_allocator);

        const state = response.result orelse return errors.ContractError.InvalidContractState;
        response.result = null;
        return state;
    }

    pub fn hasClient(self: Self) bool {
        return self.client != null;
    }

    fn getClient(self: Self) !*NeoClient {
        const ptr = self.client orelse return errors.NeoError.InvalidConfiguration;
        return @ptrCast(@alignCast(ptr));
    }
};

fn isNativeScriptHash(script_hash: Hash160) bool {
    return script_hash.eql(Hash160{ .bytes = constants.NativeContracts.CONTRACT_MANAGEMENT }) or
        script_hash.eql(Hash160{ .bytes = constants.NativeContracts.STD_LIB }) or
        script_hash.eql(Hash160{ .bytes = constants.NativeContracts.CRYPTO_LIB }) or
        script_hash.eql(Hash160{ .bytes = constants.NativeContracts.LEDGER_CONTRACT }) or
        script_hash.eql(Hash160{ .bytes = constants.NativeContracts.NEO_TOKEN }) or
        script_hash.eql(Hash160{ .bytes = constants.NativeContracts.GAS_TOKEN }) or
        script_hash.eql(Hash160{ .bytes = constants.NativeContracts.POLICY_CONTRACT }) or
        script_hash.eql(Hash160{ .bytes = constants.NativeContracts.ROLE_MANAGEMENT }) or
        script_hash.eql(Hash160{ .bytes = constants.NativeContracts.ORACLE_CONTRACT }) or
        script_hash.eql(Hash160{ .bytes = constants.NativeContracts.NOTARY }) or
        script_hash.eql(Hash160{ .bytes = constants.NativeContracts.TREASURY });
}

pub const ContractManifest = responses.ContractManifest;
pub const ContractState = responses.ContractState;
pub const ContractNef = responses.ContractNef;
pub const ContractGroup = responses.ContractGroup;
pub const ContractFeatures = responses.ContractFeatures;
pub const ContractABI = responses.ContractABI;
pub const ContractMethod = responses.ContractMethod;
pub const ContractEvent = responses.ContractEvent;
pub const ContractPermission = responses.ContractPermission;

// Tests
test "SmartContract creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const contract = SmartContract.init(allocator, contract_hash, null);

    // Test script hash retrieval
    try testing.expect(contract.getScriptHash().eql(contract_hash));
}

test "SmartContract function invocation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_hash = Hash160.ZERO;
    const contract = SmartContract.init(allocator, contract_hash, null);

    // Test function invocation
    const params = [_]ContractParameter{
        ContractParameter.string("test_param"),
        ContractParameter.integer(42),
    };

    var tx_builder = try contract.invokeFunction("testMethod", &params);
    defer tx_builder.deinit();

    // Should have script
    try testing.expect(tx_builder.getScript() != null);
    try testing.expect(tx_builder.getScript().?.len > 0);
}

test "SmartContract script building" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const contract_hash = Hash160.ZERO;
    const contract = SmartContract.init(allocator, contract_hash, null);

    // Test script building
    const params = [_]ContractParameter{ContractParameter.boolean(true)};
    const script = try contract.buildInvokeFunctionScript("testMethod", &params);
    defer allocator.free(script);

    try testing.expect(script.len > 0);

    // Test empty function name error
    try testing.expectError(errors.NeoError.IllegalArgument, contract.buildInvokeFunctionScript("", &params));
}
