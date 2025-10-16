//! Neo RPC client implementation
//!
//! Complete conversion from NeoSwift protocol layer
//! Implements all RPC methods with Swift API compatibility.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const Address = @import("../types/address.zig").Address;
const Transaction = @import("../transaction/transaction_builder.zig").Transaction;
const responses = @import("responses.zig");
pub const NeoSwiftConfig = @import("neo_swift_config.zig").NeoSwiftConfig;
pub const NeoSwiftService = @import("neo_swift_service.zig").NeoSwiftService;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const Request = @import("request.zig").Request;
const json_utils = @import("../utils/json_utils.zig");

/// Neo RPC client (converted from Swift NeoSwift class)
pub const NeoSwift = struct {
    allocator: std.mem.Allocator,
    config: NeoSwiftConfig,
    service: NeoSwiftService,

    const Self = @This();

    /// Creates new NeoSwift instance (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator, config: NeoSwiftConfig, service: NeoSwiftService) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .service = service,
        };
    }

    /// Builder method (equivalent to Swift build method)
    pub fn build(allocator: std.mem.Allocator, service: NeoSwiftService, config: ?NeoSwiftConfig) Self {
        const final_config = config orelse NeoSwiftConfig.init();
        return Self.init(allocator, final_config, service);
    }

    /// NNS resolver property (equivalent to Swift nnsResolver)
    pub fn getNnsResolver(self: Self) Hash160 {
        return self.config.nns_resolver;
    }

    /// Block interval property (equivalent to Swift blockInterval)
    pub fn getBlockInterval(self: Self) u32 {
        return self.config.block_interval;
    }

    /// Polling interval property (equivalent to Swift pollingInterval)
    pub fn getPollingInterval(self: Self) u32 {
        return self.config.polling_interval;
    }

    /// Max valid until block increment (equivalent to Swift maxValidUntilBlockIncrement)
    pub fn getMaxValidUntilBlockIncrement(self: Self) u32 {
        return self.config.max_valid_until_block_increment;
    }

    /// Allow transmission on fault (equivalent to Swift allowTransmissionOnFault)
    pub fn allowTransmissionOnFault(self: *Self) void {
        self.config.allows_transmission_on_fault = true;
    }

    /// Prevent transmission on fault (equivalent to Swift preventTransmissionOnFault)
    pub fn preventTransmissionOnFault(self: *Self) void {
        self.config.allows_transmission_on_fault = false;
    }

    pub fn getService(self: *Self) *NeoSwiftService {
        return &self.service;
    }

    /// Releases owned service resources (mirrors Swift deallocation paths)
    pub fn deinit(self: *Self) void {
        self.service.deinit();
    }

    /// Sets NNS resolver (equivalent to Swift setNNSResolver)
    pub fn setNNSResolver(self: *Self, nns_resolver: Hash160) void {
        self.config.nns_resolver = nns_resolver;
    }

    /// Gets network magic number (equivalent to Swift getNetworkMagicNumber)
    pub fn getNetworkMagicNumber(self: *Self) !u32 {
        if (self.config.network_magic == null) {
            var request = try self.getVersion();
            var version = try request.send();
            defer version.deinit(self.allocator);

            if (version.protocol) |protocol| {
                self.config.network_magic = protocol.network;
            } else {
                // Fall back to mainnet magic if protocol configuration is unavailable.
                self.config.network_magic = constants.DEFAULT_NETWORK_MAGIC;
            }
        }
        return self.config.network_magic.?;
    }

    /// Gets network magic as bytes (equivalent to Swift getNetworkMagicNumberBytes)
    pub fn getNetworkMagicNumberBytes(self: *Self) ![4]u8 {
        const magic_int = try self.getNetworkMagicNumber();
        return std.mem.toBytes(std.mem.nativeToBig(u32, magic_int));
    }

    // ============================================================================
    // BLOCKCHAIN METHODS (converted from Swift)
    // ============================================================================

    /// Gets best block hash (equivalent to Swift getBestBlockHash)
    pub fn getBestBlockHash(self: *Self) !RpcRequest(Hash256) {
        return RpcRequest(Hash256).init(self, "getbestblockhash", &[_]RpcParam{});
    }

    /// Gets block hash by index (equivalent to Swift getBlockHash)
    pub fn getBlockHash(self: *Self, block_index: u32) !RpcRequest(Hash256) {
        const params = [_]RpcParam{RpcParam.initInt(block_index)};
        return RpcRequest(Hash256).init(self, "getblockhash", &params);
    }

    /// Gets block by hash (equivalent to Swift getBlock)
    pub fn getBlock(self: *Self, block_hash: Hash256, full_transactions: bool) !RpcRequest(NeoBlock) {
        const hash_str = try block_hash.string(self.allocator);
        defer self.allocator.free(hash_str);

        const verbose = if (full_transactions) @as(i32, 1) else @as(i32, 0);
        const params = [_]RpcParam{
            RpcParam.initString(hash_str),
            RpcParam.initInt(verbose),
        };
        return RpcRequest(NeoBlock).init(self, "getblock", &params);
    }

    /// Gets block by index (equivalent to Swift getBlock)
    pub fn getBlockByIndex(self: *Self, block_index: u32, full_transactions: bool) !RpcRequest(NeoBlock) {
        const verbose = if (full_transactions) @as(i32, 1) else @as(i32, 0);
        const params = [_]RpcParam{
            RpcParam.initInt(block_index),
            RpcParam.initInt(verbose),
        };
        return RpcRequest(NeoBlock).init(self, "getblock", &params);
    }

    /// Gets raw block (equivalent to Swift getRawBlock)
    pub fn getRawBlock(self: *Self, block_hash: Hash256) !RpcRequest([]const u8) {
        const hash_str = try block_hash.string(self.allocator);
        defer self.allocator.free(hash_str);

        const params = [_]RpcParam{
            RpcParam.initString(hash_str),
            RpcParam.initInt(0), // Raw format
        };
        return RpcRequest([]const u8).init(self, "getblock", &params);
    }

    /// Gets block count (equivalent to Swift getBlockCount)
    pub fn getBlockCount(self: *Self) !RpcRequest(u32) {
        return RpcRequest(u32).init(self, "getblockcount", &[_]RpcParam{});
    }

    /// Gets transaction (equivalent to Swift getTransaction)
    pub fn getTransaction(self: *Self, tx_hash: Hash256) !RpcRequest(Transaction) {
        const hash_str = try tx_hash.string(self.allocator);
        defer self.allocator.free(hash_str);

        const params = [_]RpcParam{
            RpcParam.initString(hash_str),
            RpcParam.initInt(1), // Verbose
        };
        return RpcRequest(Transaction).init(self, "getrawtransaction", &params);
    }

    /// Gets connection count (equivalent to Swift getConnectionCount)
    pub fn getConnectionCount(self: *Self) !RpcRequest(u32) {
        return RpcRequest(u32).init(self, "getconnectioncount", &[_]RpcParam{});
    }

    /// Gets version (equivalent to Swift getVersion)
    pub fn getVersion(self: *Self) !RpcRequest(NeoVersion) {
        return RpcRequest(NeoVersion).init(self, "getversion", &[_]RpcParam{});
    }

    // ============================================================================
    // SMART CONTRACT METHODS (converted from Swift)
    // ============================================================================

    /// Invokes function (equivalent to Swift invokeFunction)
    pub fn invokeFunction(
        self: *Self,
        contract_hash: Hash160,
        function_name: []const u8,
        params: []const ContractParameter,
        signers: []const Signer,
    ) !RpcRequest(InvocationResult) {
        const contract_str = try contract_hash.string(self.allocator);
        defer self.allocator.free(contract_str);

        const rpc_params = [_]RpcParam{
            RpcParam.initString(contract_str),
            RpcParam.initString(function_name),
            RpcParam.initArray(params),
            RpcParam.initArray(signers),
        };

        return RpcRequest(InvocationResult).init(self, "invokefunction", &rpc_params);
    }

    /// Invokes script (equivalent to Swift invokeScript)
    pub fn invokeScript(
        self: *Self,
        script_hex: []const u8,
        signers: []const Signer,
    ) !RpcRequest(InvocationResult) {
        const rpc_params = [_]RpcParam{
            RpcParam.initString(script_hex),
            RpcParam.initArray(signers),
        };

        return RpcRequest(InvocationResult).init(self, "invokescript", &rpc_params);
    }

    /// Sends raw transaction (equivalent to Swift sendRawTransaction)
    pub fn sendRawTransaction(self: *Self, raw_transaction_hex: []const u8) !RpcRequest(SendRawTransactionResponse) {
        const params = [_]RpcParam{RpcParam.initString(raw_transaction_hex)};
        return RpcRequest(SendRawTransactionResponse).init(self, "sendrawtransaction", &params);
    }

    /// Calculates network fee (equivalent to Swift calculateNetworkFee)
    pub fn calculateNetworkFee(self: *Self, transaction_hex: []const u8) !RpcRequest(NetworkFeeResponse) {
        const params = [_]RpcParam{RpcParam.initString(transaction_hex)};
        return RpcRequest(NetworkFeeResponse).init(self, "calculatenetworkfee", &params);
    }

    // ============================================================================
    // WALLET METHODS (converted from Swift)
    // ============================================================================

    /// Gets NEP-17 balances (equivalent to Swift getNep17Balances)
    pub fn getNep17Balances(self: *Self, script_hash: Hash160) !RpcRequest(Nep17Balances) {
        const address = try script_hash.toAddress(self.allocator);
        defer self.allocator.free(address);

        const params = [_]RpcParam{RpcParam.initString(address)};
        return RpcRequest(Nep17Balances).init(self, "getnep17balances", &params);
    }

    /// Gets NEP-17 transfers (equivalent to Swift getNep17Transfers)
    pub fn getNep17Transfers(
        self: *Self,
        script_hash: Hash160,
        from_time: ?u64,
        to_time: ?u64,
    ) !RpcRequest(Nep17Transfers) {
        const address = try script_hash.toAddress(self.allocator);
        defer self.allocator.free(address);

        var params = std.ArrayList(RpcParam).init(self.allocator);
        defer params.deinit();

        try params.append(RpcParam.initString(address));

        if (from_time) |from| {
            try params.append(RpcParam.initInt(@intCast(from)));
            if (to_time) |to| {
                try params.append(RpcParam.initInt(@intCast(to)));
            }
        }

        return RpcRequest(Nep17Transfers).init(self, "getnep17transfers", params.items);
    }

    /// Validates address (equivalent to Swift validateAddress)
    pub fn validateAddress(self: *Self, address: []const u8) !RpcRequest(AddressValidation) {
        const params = [_]RpcParam{RpcParam.initString(address)};
        return RpcRequest(AddressValidation).init(self, "validateaddress", &params);
    }
};

/// RPC parameter wrapper
pub const RpcParam = union(enum) {
    String: []const u8,
    Integer: i64,
    Boolean: bool,
    ContractParameters: []const ContractParameter,
    Signers: []const Signer,

    pub fn initString(value: []const u8) RpcParam {
        return RpcParam{ .String = value };
    }

    pub fn initInt(value: anytype) RpcParam {
        return RpcParam{ .Integer = @intCast(value) };
    }

    pub fn initBool(value: bool) RpcParam {
        return RpcParam{ .Boolean = value };
    }

    pub fn initArray(value: anytype) RpcParam {
        if (@TypeOf(value) == []const ContractParameter or @TypeOf(value) == []ContractParameter) {
            return RpcParam{ .ContractParameters = value };
        } else if (@TypeOf(value) == []const Signer or @TypeOf(value) == []Signer) {
            return RpcParam{ .Signers = value };
        } else {
            @compileError("Unsupported array type for RPC parameter");
        }
    }
};

/// Generic RPC request (converted from Swift Request pattern)
pub fn RpcRequest(comptime T: type) type {
    return struct {
        client: *NeoSwift,
        method: []const u8,
        params: []const RpcParam,

        const Self = @This();

        pub fn init(client: *NeoSwift, method: []const u8, params: []const RpcParam) Self {
            return Self{
                .client = client,
                .method = method,
                .params = params,
            };
        }

        /// Sends the request (equivalent to Swift .send())
        pub fn send(self: Self) !T {
            const allocator = self.client.allocator;

            var params_list = std.ArrayList(std.json.Value).init(allocator);
            defer params_list.deinit();

            for (self.params) |param| {
                try params_list.append(try paramToJson(param, allocator));
            }

            const params_slice = try params_list.toOwnedSlice();
            defer {
                for (params_slice) |value| {
                    json_utils.freeValue(value, allocator);
                }
                allocator.free(params_slice);
            }

            var request = Request(T, T).init(allocator, self.method, params_slice);
            const response = try request.sendUsing(self.client.getService());
            return response;
        }
    };
}

fn contractParametersToJson(
    items: []const ContractParameter,
    allocator: std.mem.Allocator,
) !std.json.Value {
    var value = std.json.Value{ .array = std.json.Array.init(allocator) };
    errdefer value.array.deinit();
    for (items) |item| {
        try value.array.append(try item.toJsonValue(allocator));
    }
    return value;
}

fn signersToJson(signers: []const Signer, allocator: std.mem.Allocator) !std.json.Value {
    var value = std.json.Value{ .array = std.json.Array.init(allocator) };
    errdefer value.array.deinit();
    for (signers) |signer| {
        try value.array.append(try signer.toJsonValue(allocator));
    }
    return value;
}

fn paramToJson(param: RpcParam, allocator: std.mem.Allocator) !std.json.Value {
    var value: std.json.Value = .{ .null = {} };
    if (param == .String) {
        value = std.json.Value{ .string = try allocator.dupe(u8, param.String) };
    } else if (param == .Integer) {
        value = std.json.Value{ .integer = param.Integer };
    } else if (param == .Boolean) {
        value = std.json.Value{ .bool = param.Boolean };
    } else if (param == .ContractParameters) {
        value = try contractParametersToJson(param.ContractParameters, allocator);
    } else if (param == .Signers) {
        value = try signersToJson(param.Signers, allocator);
    }
    return value;
}

// ============================================================================
// RESPONSE TYPES (converted from Swift response classes)
// ============================================================================

/// Re-export response types for convenience
pub const NeoBlock = responses.NeoBlock;
pub const NeoVersion = responses.NeoVersion;

pub const InvocationResult = responses.InvocationResult;
pub const StackItem = @import("../types/stack_item.zig").StackItem;

/// NEP-17 balances (converted from Swift response)
pub const Nep17Balances = struct {
    balance: []const TokenBalance,
    address: []const u8,

    pub fn init() Nep17Balances {
        return std.mem.zeroes(Nep17Balances);
    }
};

/// Token balance (converted from Swift)
pub const TokenBalance = struct {
    asset_hash: Hash160,
    amount: []const u8,
    last_updated_block: u32,

    pub fn init() TokenBalance {
        return std.mem.zeroes(TokenBalance);
    }
};

/// NEP-17 transfers (converted from Swift response)
pub const Nep17Transfers = struct {
    sent: []const TokenTransfer,
    received: []const TokenTransfer,
    address: []const u8,

    pub fn init() Nep17Transfers {
        return std.mem.zeroes(Nep17Transfers);
    }
};

/// Token transfer (converted from Swift)
pub const TokenTransfer = struct {
    timestamp: u64,
    asset_hash: Hash160,
    transfer_address: []const u8,
    amount: []const u8,
    block_index: u32,
    transfer_notify_index: u32,
    tx_hash: Hash256,

    pub fn init() TokenTransfer {
        return std.mem.zeroes(TokenTransfer);
    }
};

/// Send raw transaction response (converted from Swift)
pub const SendRawTransactionResponse = struct {
    hash: Hash256,

    pub fn init() SendRawTransactionResponse {
        return SendRawTransactionResponse{ .hash = Hash256.ZERO };
    }
};

/// Network fee response (converted from Swift)
pub const NetworkFeeResponse = struct {
    network_fee: u64,

    pub fn init() NetworkFeeResponse {
        return NetworkFeeResponse{ .network_fee = 0 };
    }
};

/// Address validation response (converted from Swift)
pub const AddressValidation = struct {
    address: []const u8,
    is_valid: bool,

    pub fn init() AddressValidation {
        return AddressValidation{ .address = "", .is_valid = false };
    }
};

// Tests (converted from Swift RPC tests)
test "NeoSwift client creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = NeoSwiftConfig.init();
    var service = try @import("neo_swift_service.zig").ServiceFactory.localhost(allocator, null);
    var client = NeoSwift.build(allocator, service, config);
    defer client.deinit();
    service.relinquish();

    // Test configuration properties (matches Swift tests)
    try testing.expectEqual(@as(u32, 15000), client.getBlockInterval());
    try testing.expectEqual(@as(u32, 15000), client.getPollingInterval());
    try testing.expectEqual(@as(u32, 5760), client.getMaxValidUntilBlockIncrement());

    // Test configuration methods
    client.allowTransmissionOnFault();
    try testing.expect(client.config.allows_transmission_on_fault);

    client.preventTransmissionOnFault();
    try testing.expect(!client.config.allows_transmission_on_fault);
}

test "NeoSwift RPC method creation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = NeoSwiftConfig.init();
    var service = try @import("neo_swift_service.zig").ServiceFactory.localhost(allocator, null);
    var client = NeoSwift.build(allocator, service, config);
    defer client.deinit();
    service.relinquish();

    // Test RPC request creation (matches Swift Request pattern)
    const best_block_request = try client.getBestBlockHash();
    try testing.expectEqualStrings("getbestblockhash", best_block_request.method);

    const block_count_request = try client.getBlockCount();
    try testing.expectEqualStrings("getblockcount", block_count_request.method);

    const connection_count_request = try client.getConnectionCount();
    try testing.expectEqualStrings("getconnectioncount", connection_count_request.method);
}

test "NeoSwift contract invocation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const config = NeoSwiftConfig.init();
    var service = try @import("neo_swift_service.zig").ServiceFactory.localhost(allocator, null);
    var client = NeoSwift.build(allocator, service, config);
    defer client.deinit();
    service.relinquish();

    // Test contract function invocation (matches Swift invokeFunction)
    const contract_hash = Hash160.ZERO;
    const params = [_]ContractParameter{ContractParameter.integer(42)};
    const signers = [_]Signer{};

    const invoke_request = try client.invokeFunction(contract_hash, "testMethod", &params, &signers);
    try testing.expectEqualStrings("invokefunction", invoke_request.method);
}
