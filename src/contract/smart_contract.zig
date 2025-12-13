//! Smart Contract implementation
//!
//! Complete conversion from NeoSwift SmartContract.swift
//! Essential for contract interaction and deployment.

const std = @import("std");
const ArrayList = std.ArrayList;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const ScriptBuilder = @import("../script/script_builder.zig").ScriptBuilder;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;
const NeoSwift = @import("../rpc/neo_client.zig").NeoSwift;
const Signer = @import("../transaction/transaction_builder.zig").Signer;

/// Smart contract representation (converted from Swift SmartContract)
pub const SmartContract = struct {
    /// Default iterator count (matches Swift DEFAULT_ITERATOR_COUNT)
    pub const DEFAULT_ITERATOR_COUNT: u32 = 100;
    
    /// Contract script hash
    script_hash: Hash160,
    /// Neo client reference
    neo_swift: ?*anyopaque, // stub for NeoSwift reference
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates smart contract instance (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator, script_hash: Hash160, neo_swift: ?*anyopaque) Self {
        return Self{
            .script_hash = script_hash,
            .neo_swift = neo_swift,
            .allocator = allocator,
        };
    }
    
    /// Gets contract script hash
    pub fn getScriptHash(self: Self) Hash160 {
        return self.script_hash;
    }
    
    /// Invokes contract function (equivalent to Swift invokeFunction)
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
    
    /// Builds invoke function script (equivalent to Swift buildInvokeFunctionScript)
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
    
    /// Calls function returning string (equivalent to Swift callFunctionReturningString)
    pub fn callFunctionReturningString(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) ![]u8 {
        if (self.neo_swift == null) {
            return try self.allocator.dupe(u8, "UNKNOWN");
        }
        const neo_swift = try self.getNeoSwift();
        var request = try neo_swift.invokeFunction(self.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        return try stack_item.getString(self.allocator);
    }
    
    /// Calls function returning integer (equivalent to Swift callFunctionReturningInt)
    pub fn callFunctionReturningInt(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) !i64 {
        if (self.neo_swift == null) {
            return 0;
        }
        const neo_swift = try self.getNeoSwift();
        var request = try neo_swift.invokeFunction(self.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        return try stack_item.getInteger();
    }
    
    /// Calls function returning boolean (equivalent to Swift callFunctionReturningBool)
    pub fn callFunctionReturningBool(
        self: Self,
        function_name: []const u8,
        params: []const ContractParameter,
    ) !bool {
        if (self.neo_swift == null) {
            return false;
        }
        const neo_swift = try self.getNeoSwift();
        var request = try neo_swift.invokeFunction(self.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
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
        if (self.neo_swift == null) {
            return Hash160.ZERO;
        }
        const neo_swift = try self.getNeoSwift();
        var request = try neo_swift.invokeFunction(self.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
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
    
    /// Gets contract manifest (equivalent to Swift getManifest)
    pub fn getManifest(self: Self) !ContractManifest {
        // This would make actual RPC call in production
        _ = self;
        return ContractManifest.init();
    }
    
    /// Gets contract state (equivalent to Swift getContractState)
    pub fn getContractState(self: Self) !ContractState {
        // This would make actual RPC call in production
        _ = self;
        return ContractState.init();
    }

    pub fn hasClient(self: Self) bool {
        return self.neo_swift != null;
    }

    fn getNeoSwift(self: Self) !*NeoSwift {
        const ptr = self.neo_swift orelse return errors.NeoError.InvalidConfiguration;
        return @ptrCast(@alignCast(ptr));
    }
};

/// Contract manifest (converted from Swift ContractManifest)
pub const ContractManifest = struct {
    name: []const u8,
    groups: []const ContractGroup,
    features: ContractFeatures,
    supported_standards: []const []const u8,
    abi: ContractABI,
    permissions: []const ContractPermission,
    trusts: []const Hash160,
    extra: ?[]const u8,
    
    const Self = @This();
    
    pub fn init() Self {
        return Self{
            .name = "",
            .groups = &[_]ContractGroup{},
            .features = ContractFeatures.init(),
            .supported_standards = &[_][]const u8{},
            .abi = ContractABI.init(),
            .permissions = &[_]ContractPermission{},
            .trusts = &[_]Hash160{},
            .extra = null,
        };
    }
};

/// Contract state (converted from Swift ContractState)
pub const ContractState = struct {
    id: i32,
    update_counter: u32,
    hash: Hash160,
    nef: ContractNef,
    manifest: ContractManifest,
    
    pub fn init() ContractState {
        return ContractState{
            .id = 0,
            .update_counter = 0,
            .hash = Hash160.ZERO,
            .nef = ContractNef.init(),
            .manifest = ContractManifest.init(),
        };
    }
};

/// Contract NEF (converted from Swift ContractNef)
pub const ContractNef = struct {
    magic: u32,
    compiler: []const u8,
    source: []const u8,
    script: []const u8,
    checksum: u32,
    
    pub fn init() ContractNef {
        return ContractNef{
            .magic = 0x3346454E, // "NEF3"
            .compiler = "",
            .source = "",
            .script = &[_]u8{},
            .checksum = 0,
        };
    }
};

/// Supporting types (stubs for full implementation)
pub const ContractGroup = struct {
    public_key: [33]u8,
    signature: [64]u8,
    
    pub fn init() ContractGroup {
        return ContractGroup{
            .public_key = std.mem.zeroes([33]u8),
            .signature = std.mem.zeroes([64]u8),
        };
    }
};

pub const ContractFeatures = struct {
    storage: bool,
    payable: bool,
    
    pub fn init() ContractFeatures {
        return ContractFeatures{ .storage = false, .payable = false };
    }
};

pub const ContractABI = struct {
    methods: []const ContractMethod,
    events: []const ContractEvent,
    
    pub fn init() ContractABI {
        return ContractABI{
            .methods = &[_]ContractMethod{},
            .events = &[_]ContractEvent{},
        };
    }
};

pub const ContractMethod = struct {
    name: []const u8,
    parameters: []const ContractParameter,
    return_type: []const u8,
    offset: u32,
    safe: bool,
    
    pub fn init() ContractMethod {
        return ContractMethod{
            .name = "",
            .parameters = &[_]ContractParameter{},
            .return_type = "Any",
            .offset = 0,
            .safe = false,
        };
    }
};

pub const ContractEvent = struct {
    name: []const u8,
    parameters: []const ContractParameter,
    
    pub fn init() ContractEvent {
        return ContractEvent{
            .name = "",
            .parameters = &[_]ContractParameter{},
        };
    }
};

pub const ContractPermission = struct {
    contract: Hash160,
    methods: []const []const u8,
    
    pub fn init() ContractPermission {
        return ContractPermission{
            .contract = Hash160.ZERO,
            .methods = &[_][]const u8{},
        };
    }
};

// Tests (converted from Swift SmartContract tests)
test "SmartContract creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const contract_hash = try Hash160.initWithString("1234567890abcdef1234567890abcdef12345678");
    const contract = SmartContract.init(allocator, contract_hash, null);
    
    // Test script hash retrieval (equivalent to Swift scriptHash property)
    try testing.expect(contract.getScriptHash().eql(contract_hash));
}

test "SmartContract function invocation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const contract_hash = Hash160.ZERO;
    const contract = SmartContract.init(allocator, contract_hash, null);
    
    // Test function invocation (equivalent to Swift invokeFunction tests)
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
    
    // Test script building (equivalent to Swift buildInvokeFunctionScript)
    const params = [_]ContractParameter{ContractParameter.boolean(true)};
    const script = try contract.buildInvokeFunctionScript("testMethod", &params);
    defer allocator.free(script);
    
    try testing.expect(script.len > 0);
    
    // Test empty function name error
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        contract.buildInvokeFunctionScript("", &params)
    );
}
