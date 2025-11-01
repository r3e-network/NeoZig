//! Neo Protocol implementation
//!
//! Complete conversion from NeoSwift Neo.swift protocol
//! Provides complete Neo blockchain protocol interface.

const std = @import("std");
const base64 = std.base64;

const json_utils = @import("../utils/json_utils.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const Request = @import("../rpc/request.zig").Request;
const parameter_utils = @import("../contract/parameter_utils.zig");
const StringUtils = @import("../utils/string_extensions.zig").StringUtils;
const TransactionSendToken = @import("../rpc/complete_responses.zig").TransactionSendToken;

const JsonArrayHolder = struct {
    value: std.json.Value,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *JsonArrayHolder) void {
        json_utils.freeValue(self.value, self.allocator);
        self.value = std.json.Value{ .null = {} };
    }
};

fn encodeContractParameters(params: []const ContractParameter, allocator: std.mem.Allocator) !JsonArrayHolder {
    var array = std.json.Array.init(allocator);
    var cleanup_needed = true;
    errdefer if (cleanup_needed) {
        var tmp = std.json.Value{ .array = array };
        json_utils.freeValue(tmp, allocator);
    };

    try array.ensureTotalCapacity(params.len);
    for (params) |param| {
        const param_json = try parameter_utils.parameterToJson(param, allocator);
        array.appendAssumeCapacity(param_json);
    }

    cleanup_needed = false;
    return JsonArrayHolder{
        .value = std.json.Value{ .array = array },
        .allocator = allocator,
    };
}

fn encodeSigners(signers: []const Signer, allocator: std.mem.Allocator) !JsonArrayHolder {
    var array = std.json.Array.init(allocator);
    var cleanup_needed = true;
    errdefer if (cleanup_needed) {
        var tmp = std.json.Value{ .array = array };
        json_utils.freeValue(tmp, allocator);
    };

    try array.ensureTotalCapacity(signers.len);
    for (signers) |signer| {
        const signer_json = try signer.toJsonValue(allocator);
        array.appendAssumeCapacity(signer_json);
    }

    cleanup_needed = false;
    return JsonArrayHolder{
        .value = std.json.Value{ .array = array },
        .allocator = allocator,
    };
}

fn encodeScriptBase64(script_hex: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const script_bytes = try StringUtils.bytesFromHex(script_hex, allocator);
    defer allocator.free(script_bytes);
    return try base64.standard.Encoder.encodeAlloc(allocator, script_bytes);
}

fn hexToBase64(hex_str: []const u8, allocator: std.mem.Allocator) ![]u8 {
    return encodeScriptBase64(hex_str, allocator);
}

fn encodeTransactionSendTokens(tokens: []const TransactionSendToken, allocator: std.mem.Allocator) !JsonArrayHolder {
    var array = std.json.Array.init(allocator);
    var cleanup_needed = true;
    errdefer if (cleanup_needed) {
        var tmp = std.json.Value{ .array = array };
        json_utils.freeValue(tmp, allocator);
    };

    try array.ensureTotalCapacity(tokens.len);
    for (tokens) |token| {
        var asset_hex = try token.asset.string(allocator);
        var needs_asset_free = true;
        errdefer if (needs_asset_free) allocator.free(asset_hex);

        var address_dup = try allocator.dupe(u8, token.address);
        var needs_address_free = true;
        errdefer if (needs_address_free) allocator.free(address_dup);

        var obj = std.json.ObjectMap.init(allocator);
        errdefer {
            var tmp_obj = std.json.Value{ .object = obj };
            json_utils.freeValue(tmp_obj, allocator);
        }

        try obj.put("asset", std.json.Value{ .string = asset_hex });
        needs_asset_free = false;
        try obj.put("value", std.json.Value{ .integer = token.value });
        try obj.put("address", std.json.Value{ .string = address_dup });
        needs_address_free = false;

        array.appendAssumeCapacity(std.json.Value{ .object = obj });
    }

    cleanup_needed = false;
    return JsonArrayHolder{
        .value = std.json.Value{ .array = array },
        .allocator = allocator,
    };
}

/// Neo protocol interface (converted from Swift Neo protocol)
pub const NeoProtocol = struct {
    /// Service implementation
    service: *@import("../rpc/neo_swift_service.zig").NeoSwiftService,

    const Self = @This();

    /// Creates Neo protocol implementation
    pub fn init(service: *@import("../rpc/neo_swift_service.zig").NeoSwiftService) Self {
        return Self{ .service = service };
    }

    // ============================================================================
    // BLOCKCHAIN METHODS (converted from Swift blockchain methods)
    // ============================================================================

    /// Gets best block hash (equivalent to Swift getBestBlockHash())
    pub fn getBestBlockHash(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoBlockHash, Hash256) {
        return try Request(@import("../rpc/response_aliases.zig").NeoBlockHash, Hash256).withNoParams(
            self.service.allocator,
            "getbestblockhash",
        );
    }

    /// Gets block hash by index (equivalent to Swift getBlockHash(_ blockIndex: Int))
    pub fn getBlockHash(self: Self, block_index: u32) !Request(@import("../rpc/response_aliases.zig").NeoBlockHash, Hash256) {
        const int_params = [_]i64{@intCast(block_index)};
        return try Request(@import("../rpc/response_aliases.zig").NeoBlockHash, Hash256).withIntegerParams(
            self.service.allocator,
            "getblockhash",
            &int_params,
        );
    }

    /// Gets block by hash (equivalent to Swift getBlock(_ blockHash: Hash256, _ returnFullTransactionObjects: Bool))
    pub fn getBlock(
        self: Self,
        block_hash: Hash256,
        return_full_transaction_objects: bool,
    ) !Request(@import("../rpc/response_aliases.zig").NeoGetBlock, @import("../rpc/responses.zig").NeoBlock) {
        const hash_hex = try block_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);

        const verbose = if (return_full_transaction_objects) @as(i64, 1) else @as(i64, 0);
        const params = [_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            std.json.Value{ .integer = verbose },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetBlock, @import("../rpc/responses.zig").NeoBlock).init(
            self.service.allocator,
            "getblock",
            &params,
        );
    }

    /// Gets block by index (equivalent to Swift getBlock(_ blockIndex: Int, _ returnFullTransactionObjects: Bool))
    pub fn getBlockByIndex(
        self: Self,
        block_index: u32,
        return_full_transaction_objects: bool,
    ) !Request(@import("../rpc/response_aliases.zig").NeoGetBlock, @import("../rpc/responses.zig").NeoBlock) {
        const verbose = if (return_full_transaction_objects) @as(i64, 1) else @as(i64, 0);
        const params = [_]std.json.Value{
            std.json.Value{ .integer = @intCast(block_index) },
            std.json.Value{ .integer = verbose },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetBlock, @import("../rpc/responses.zig").NeoBlock).init(
            self.service.allocator,
            "getblock",
            &params,
        );
    }

    /// Gets raw block by hash (equivalent to Swift getRawBlock(_ blockHash: Hash256))
    pub fn getRawBlock(self: Self, block_hash: Hash256) !Request(@import("../rpc/response_aliases.zig").NeoGetRawBlock, []const u8) {
        const hash_hex = try block_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);

        const params = [_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            std.json.Value{ .integer = 0 }, // Raw format
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetRawBlock, []const u8).init(
            self.service.allocator,
            "getblock",
            &params,
        );
    }

    /// Gets block count (equivalent to Swift getBlockCount())
    pub fn getBlockCount(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoBlockCount, u32) {
        return try Request(@import("../rpc/response_aliases.zig").NeoBlockCount, u32).withNoParams(
            self.service.allocator,
            "getblockcount",
        );
    }

    /// Gets block header by hash
    pub fn getBlockHeaderByHash(self: Self, block_hash: Hash256) !Request(@import("../rpc/response_aliases.zig").NeoGetBlock, @import("../rpc/responses.zig").NeoBlock) {
        const hash_hex = try block_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);

        const params = [_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            std.json.Value{ .integer = 1 },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetBlock, @import("../rpc/responses.zig").NeoBlock).init(
            self.service.allocator,
            "getblockheader",
            &params,
        );
    }

    /// Gets block header by index
    pub fn getBlockHeaderByIndex(self: Self, block_index: u32) !Request(@import("../rpc/response_aliases.zig").NeoGetBlock, @import("../rpc/responses.zig").NeoBlock) {
        const params = [_]std.json.Value{
            std.json.Value{ .integer = @intCast(block_index) },
            std.json.Value{ .integer = 1 },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetBlock, @import("../rpc/responses.zig").NeoBlock).init(
            self.service.allocator,
            "getblockheader",
            &params,
        );
    }

    /// Gets raw block header by hash
    pub fn getRawBlockHeaderByHash(self: Self, block_hash: Hash256) !Request(@import("../rpc/response_aliases.zig").NeoGetRawBlock, []const u8) {
        const hash_hex = try block_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);

        const params = [_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            std.json.Value{ .integer = 0 },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetRawBlock, []const u8).init(
            self.service.allocator,
            "getblockheader",
            &params,
        );
    }

    /// Gets raw block header by index
    pub fn getRawBlockHeaderByIndex(self: Self, block_index: u32) !Request(@import("../rpc/response_aliases.zig").NeoGetRawBlock, []const u8) {
        const params = [_]std.json.Value{
            std.json.Value{ .integer = @intCast(block_index) },
            std.json.Value{ .integer = 0 },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetRawBlock, []const u8).init(
            self.service.allocator,
            "getblockheader",
            &params,
        );
    }

    /// Gets block header count (equivalent to Swift getBlockHeaderCount())
    pub fn getBlockHeaderCount(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoBlockHeaderCount, u32) {
        return try Request(@import("../rpc/response_aliases.zig").NeoBlockHeaderCount, u32).withNoParams(
            self.service.allocator,
            "getblockheadercount",
        );
    }

    /// Gets native contracts (equivalent to Swift getNativeContracts())
    pub fn getNativeContracts(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoGetNativeContracts, []const @import("../rpc/complete_responses.zig").NativeContractState) {
        return try Request(@import("../rpc/response_aliases.zig").NeoGetNativeContracts, []const @import("../rpc/complete_responses.zig").NativeContractState).withNoParams(
            self.service.allocator,
            "getnativecontracts",
        );
    }

    /// Gets contract state (equivalent to Swift getContractState(_ contractHash: Hash160))
    pub fn getContractState(self: Self, contract_hash: Hash160) !Request(@import("../rpc/response_aliases.zig").NeoGetContractState, @import("../rpc/responses.zig").ContractState) {
        const hash_hex = try contract_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);

        const string_params = [_][]const u8{hash_hex};
        return try Request(@import("../rpc/response_aliases.zig").NeoGetContractState, @import("../rpc/responses.zig").ContractState).withStringParams(
            self.service.allocator,
            "getcontractstate",
            &string_params,
        );
    }

    /// Gets native contract state by name
    pub fn getNativeContractState(self: Self, contract_name: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoGetContractState, @import("../rpc/responses.zig").ContractState) {
        const string_params = [_][]const u8{contract_name};
        return try Request(@import("../rpc/response_aliases.zig").NeoGetContractState, @import("../rpc/responses.zig").ContractState).withStringParams(
            self.service.allocator,
            "getcontractstate",
            &string_params,
        );
    }

    /// Gets memory pool (equivalent to Swift getMemPool())
    pub fn getMemPool(self: Self) !Request(@import("../rpc/complete_responses.zig").NeoGetMemPool, @import("../rpc/complete_responses.zig").NeoGetMemPool) {
        const verbose_params = [_]i64{1};
        return try Request(@import("../rpc/complete_responses.zig").NeoGetMemPool, @import("../rpc/complete_responses.zig").NeoGetMemPool).withIntegerParams(
            self.service.allocator,
            "getrawmempool",
            &verbose_params,
        );
    }

    /// Gets raw memory pool transactions
    pub fn getRawMemPool(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoGetRawMemPool, []Hash256) {
        return try Request(@import("../rpc/response_aliases.zig").NeoGetRawMemPool, []Hash256).withNoParams(
            self.service.allocator,
            "getrawmempool",
        );
    }

    /// Gets transaction (equivalent to Swift getTransaction(_ txHash: Hash256))
    pub fn getTransaction(self: Self, tx_hash: Hash256) !Request(@import("../rpc/response_aliases.zig").NeoGetTransaction, @import("../rpc/responses.zig").Transaction) {
        const hash_hex = try tx_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);

        const params = [_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            std.json.Value{ .integer = 1 }, // Verbose
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetTransaction, @import("../rpc/responses.zig").Transaction).init(
            self.service.allocator,
            "getrawtransaction",
            &params,
        );
    }

    /// Gets raw transaction hex
    pub fn getRawTransaction(self: Self, tx_hash: Hash256) !Request(@import("../rpc/response_aliases.zig").NeoGetRawTransaction, []const u8) {
        const hash_hex = try tx_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);

        const params = [_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            std.json.Value{ .integer = 0 },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetRawTransaction, []const u8).init(
            self.service.allocator,
            "getrawtransaction",
            &params,
        );
    }

    // ============================================================================
    // NODE METHODS (converted from Swift node methods)
    // ============================================================================

    /// Gets connection count (equivalent to Swift getConnectionCount())
    pub fn getConnectionCount(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoConnectionCount, u32) {
        return try Request(@import("../rpc/response_aliases.zig").NeoConnectionCount, u32).withNoParams(
            self.service.allocator,
            "getconnectioncount",
        );
    }

    /// Gets peers (equivalent to Swift getPeers())
    pub fn getPeers(self: Self) !Request(@import("../rpc/complete_responses.zig").NeoGetPeers, @import("../rpc/complete_responses.zig").NeoGetPeers) {
        return try Request(@import("../rpc/complete_responses.zig").NeoGetPeers, @import("../rpc/complete_responses.zig").NeoGetPeers).withNoParams(
            self.service.allocator,
            "getpeers",
        );
    }

    /// Gets version (equivalent to Swift getVersion())
    pub fn getVersion(self: Self) !Request(@import("../rpc/remaining_responses.zig").NeoGetVersion, @import("../rpc/remaining_responses.zig").NeoGetVersion) {
        return try Request(@import("../rpc/remaining_responses.zig").NeoGetVersion, @import("../rpc/remaining_responses.zig").NeoGetVersion).withNoParams(
            self.service.allocator,
            "getversion",
        );
    }

    /// Sends raw transaction (equivalent to Swift sendRawTransaction(_ rawTransactionHex: String))
    pub fn sendRawTransaction(self: Self, raw_transaction_hex: []const u8) !Request(@import("../rpc/remaining_responses.zig").NeoSendRawTransaction, @import("../rpc/remaining_responses.zig").NeoSendRawTransaction) {
        const string_params = [_][]const u8{raw_transaction_hex};
        return try Request(@import("../rpc/remaining_responses.zig").NeoSendRawTransaction, @import("../rpc/remaining_responses.zig").NeoSendRawTransaction).withStringParams(
            self.service.allocator,
            "sendrawtransaction",
            &string_params,
        );
    }

    /// Submits serialized block bytes
    pub fn submitBlock(self: Self, serialized_block_hex: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoSubmitBlock, bool) {
        const string_params = [_][]const u8{serialized_block_hex};
        return try Request(@import("../rpc/response_aliases.zig").NeoSubmitBlock, bool).withStringParams(
            self.service.allocator,
            "submitblock",
            &string_params,
        );
    }

    // ============================================================================
    // SMART CONTRACT METHODS (converted from Swift smart contract methods)
    // ============================================================================

    /// Invokes function (equivalent to Swift invokeFunction methods)
    pub fn invokeFunction(
        self: Self,
        contract_hash: Hash160,
        function_name: []const u8,
        params: []const ContractParameter,
        signers: []const Signer,
    ) !Request(@import("../rpc/response_aliases.zig").NeoInvokeFunction, @import("../rpc/responses.zig").InvocationResult) {
        const allocator = self.service.allocator;
        const hash_hex = try contract_hash.string(allocator);
        defer allocator.free(hash_hex);

        var params_json = try encodeContractParameters(params, allocator);
        defer params_json.deinit();
        var signers_json = try encodeSigners(signers, allocator);
        defer signers_json.deinit();

        const rpc_params = [_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            std.json.Value{ .string = function_name },
            params_json.value,
            signers_json.value,
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoInvokeFunction, @import("../rpc/responses.zig").InvocationResult).init(
            allocator,
            "invokefunction",
            &rpc_params,
        );
    }

    /// Convenience wrapper for invoking without parameters
    pub fn invokeFunctionNoParams(
        self: Self,
        contract_hash: Hash160,
        function_name: []const u8,
        signers: []const Signer,
    ) !Request(@import("../rpc/response_aliases.zig").NeoInvokeFunction, @import("../rpc/responses.zig").InvocationResult) {
        return self.invokeFunction(contract_hash, function_name, &[_]ContractParameter{}, signers);
    }

    /// Invokes function and collects diagnostics
    pub fn invokeFunctionDiagnostics(
        self: Self,
        contract_hash: Hash160,
        function_name: []const u8,
        params: []const ContractParameter,
        signers: []const Signer,
    ) !Request(@import("../rpc/response_aliases.zig").NeoInvokeFunction, @import("../rpc/responses.zig").InvocationResult) {
        const allocator = self.service.allocator;
        const hash_hex = try contract_hash.string(allocator);
        defer allocator.free(hash_hex);

        var params_json = try encodeContractParameters(params, allocator);
        defer params_json.deinit();
        var signers_json = try encodeSigners(signers, allocator);
        defer signers_json.deinit();

        const rpc_params = [_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            std.json.Value{ .string = function_name },
            params_json.value,
            signers_json.value,
            std.json.Value{ .bool = true },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoInvokeFunction, @import("../rpc/responses.zig").InvocationResult).init(
            allocator,
            "invokefunction",
            &rpc_params,
        );
    }

    /// Convenience wrapper for invoking a function without parameters while collecting diagnostics
    pub fn invokeFunctionDiagnosticsNoParams(
        self: Self,
        contract_hash: Hash160,
        function_name: []const u8,
        signers: []const Signer,
    ) !Request(@import("../rpc/response_aliases.zig").NeoInvokeFunction, @import("../rpc/responses.zig").InvocationResult) {
        return self.invokeFunctionDiagnostics(contract_hash, function_name, &[_]ContractParameter{}, signers);
    }

    /// Invokes contract verify method
    pub fn invokeContractVerify(
        self: Self,
        contract_hash: Hash160,
        method_parameters: []const ContractParameter,
        signers: []const Signer,
    ) !Request(@import("../rpc/response_aliases.zig").NeoInvokeContractVerify, @import("../rpc/responses.zig").InvocationResult) {
        const allocator = self.service.allocator;
        const hash_hex = try contract_hash.string(allocator);
        defer allocator.free(hash_hex);

        var params_json = try encodeContractParameters(method_parameters, allocator);
        defer params_json.deinit();
        var signers_json = try encodeSigners(signers, allocator);
        defer signers_json.deinit();

        const rpc_params = [_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            params_json.value,
            signers_json.value,
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoInvokeContractVerify, @import("../rpc/responses.zig").InvocationResult).init(
            allocator,
            "invokecontractverify",
            &rpc_params,
        );
    }

    /// Invokes script (equivalent to Swift invokeScript)
    pub fn invokeScript(
        self: Self,
        script_hex: []const u8,
        signers: []const Signer,
    ) !Request(@import("../rpc/response_aliases.zig").NeoInvokeScript, @import("../rpc/responses.zig").InvocationResult) {
        const allocator = self.service.allocator;

        const script_base64 = try encodeScriptBase64(script_hex, allocator);
        defer allocator.free(script_base64);

        var signers_json = try encodeSigners(signers, allocator);
        defer signers_json.deinit();

        const params = [_]std.json.Value{
            std.json.Value{ .string = script_base64 },
            signers_json.value,
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoInvokeScript, @import("../rpc/responses.zig").InvocationResult).init(
            allocator,
            "invokescript",
            &params,
        );
    }

    /// Invokes script and includes diagnostics in the result
    pub fn invokeScriptDiagnostics(
        self: Self,
        script_hex: []const u8,
        signers: []const Signer,
    ) !Request(@import("../rpc/response_aliases.zig").NeoInvokeScript, @import("../rpc/responses.zig").InvocationResult) {
        const allocator = self.service.allocator;

        const script_base64 = try encodeScriptBase64(script_hex, allocator);
        defer allocator.free(script_base64);

        var signers_json = try encodeSigners(signers, allocator);
        defer signers_json.deinit();

        const params = [_]std.json.Value{
            std.json.Value{ .string = script_base64 },
            signers_json.value,
            std.json.Value{ .bool = true },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoInvokeScript, @import("../rpc/responses.zig").InvocationResult).init(
            allocator,
            "invokescript",
            &params,
        );
    }

    /// Traverses iterator (equivalent to Swift traverseIterator)
    pub fn traverseIterator(
        self: Self,
        session_id: []const u8,
        iterator_id: []const u8,
        count: u32,
    ) !Request(@import("../rpc/response_aliases.zig").NeoTraverseIterator, []const @import("../rpc/responses.zig").StackItem) {
        const params = [_]std.json.Value{
            std.json.Value{ .string = session_id },
            std.json.Value{ .string = iterator_id },
            std.json.Value{ .integer = @intCast(count) },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoTraverseIterator, []const @import("../rpc/responses.zig").StackItem).init(
            self.service.allocator,
            "traverseiterator",
            &params,
        );
    }

    /// Terminates session (equivalent to Swift terminateSession)
    pub fn terminateSession(self: Self, session_id: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoTerminateSession, bool) {
        const string_params = [_][]const u8{session_id};
        return try Request(@import("../rpc/response_aliases.zig").NeoTerminateSession, bool).withStringParams(
            self.service.allocator,
            "terminatesession",
            &string_params,
        );
    }

    /// Gets unclaimed GAS (equivalent to Swift getUnclaimedGas)
    pub fn getUnclaimedGas(self: Self, script_hash: Hash160) !Request(@import("../rpc/complete_responses.zig").NeoGetUnclaimedGas, @import("../rpc/complete_responses.zig").NeoGetUnclaimedGas) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const string_params = [_][]const u8{address};
        return try Request(@import("../rpc/complete_responses.zig").NeoGetUnclaimedGas, @import("../rpc/complete_responses.zig").NeoGetUnclaimedGas).withStringParams(
            self.service.allocator,
            "getunclaimedgas",
            &string_params,
        );
    }

    // ============================================================================
    // UTILITY METHODS (converted from Swift utility methods)
    // ============================================================================

    /// Lists plugins (equivalent to Swift listPlugins())
    pub fn listPlugins(self: Self) !Request(@import("../rpc/complete_responses.zig").NeoListPlugins, @import("../rpc/complete_responses.zig").NeoListPlugins) {
        return try Request(@import("../rpc/complete_responses.zig").NeoListPlugins, @import("../rpc/complete_responses.zig").NeoListPlugins).withNoParams(
            self.service.allocator,
            "listplugins",
        );
    }

    /// Validates address (equivalent to Swift validateAddress)
    pub fn validateAddress(self: Self, address: []const u8) !Request(@import("../rpc/complete_responses.zig").NeoValidateAddress, @import("../rpc/complete_responses.zig").NeoValidateAddress) {
        const string_params = [_][]const u8{address};
        return try Request(@import("../rpc/complete_responses.zig").NeoValidateAddress, @import("../rpc/complete_responses.zig").NeoValidateAddress).withStringParams(
            self.service.allocator,
            "validateaddress",
            &string_params,
        );
    }

    // ============================================================================
    // WALLET METHODS (converted from Swift wallet methods)
    // ============================================================================

    /// Closes wallet (equivalent to Swift closeWallet())
    pub fn closeWallet(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoCloseWallet, bool) {
        return try Request(@import("../rpc/response_aliases.zig").NeoCloseWallet, bool).withNoParams(
            self.service.allocator,
            "closewallet",
        );
    }

    /// Dumps private key for account (equivalent to Swift dumpPrivKey)
    pub fn dumpPrivKey(self: Self, script_hash: Hash160) !Request(@import("../rpc/response_aliases.zig").NeoDumpPrivKey, []const u8) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const string_params = [_][]const u8{address};
        return try Request(@import("../rpc/response_aliases.zig").NeoDumpPrivKey, []const u8).withStringParams(
            self.service.allocator,
            "dumpprivkey",
            &string_params,
        );
    }

    /// Opens wallet (equivalent to Swift openWallet)
    pub fn openWallet(self: Self, wallet_path: []const u8, password: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoOpenWallet, bool) {
        const string_params = [_][]const u8{ wallet_path, password };
        return try Request(@import("../rpc/response_aliases.zig").NeoOpenWallet, bool).withStringParams(
            self.service.allocator,
            "openwallet",
            &string_params,
        );
    }

    /// Gets wallet balance for token (equivalent to Swift getWalletBalance)
    pub fn getWalletBalance(self: Self, token_hash: Hash160) !Request(@import("../rpc/protocol_responses.zig").NeoGetWalletBalance, @import("../rpc/protocol_responses.zig").NeoGetWalletBalance) {
        const token_hex = try token_hash.string(self.service.allocator);
        defer self.service.allocator.free(token_hex);

        const string_params = [_][]const u8{token_hex};
        return try Request(@import("../rpc/protocol_responses.zig").NeoGetWalletBalance, @import("../rpc/protocol_responses.zig").NeoGetWalletBalance).withStringParams(
            self.service.allocator,
            "getwalletbalance",
            &string_params,
        );
    }

    /// Gets new address (equivalent to Swift getNewAddress)
    pub fn getNewAddress(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoGetNewAddress, []const u8) {
        return try Request(@import("../rpc/response_aliases.zig").NeoGetNewAddress, []const u8).withNoParams(
            self.service.allocator,
            "getnewaddress",
        );
    }

    /// Gets unclaimed GAS for wallet (equivalent to Swift getWalletUnclaimedGas)
    pub fn getWalletUnclaimedGas(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoGetWalletUnclaimedGas, []const u8) {
        return try Request(@import("../rpc/response_aliases.zig").NeoGetWalletUnclaimedGas, []const u8).withNoParams(
            self.service.allocator,
            "getwalletunclaimedgas",
        );
    }

    /// Imports private key (equivalent to Swift importPrivKey)
    pub fn importPrivKey(self: Self, private_key_wif: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoImportPrivKey, @import("../rpc/complete_responses.zig").NeoAddress) {
        const string_params = [_][]const u8{private_key_wif};
        return try Request(@import("../rpc/response_aliases.zig").NeoImportPrivKey, @import("../rpc/complete_responses.zig").NeoAddress).withStringParams(
            self.service.allocator,
            "importprivkey",
            &string_params,
        );
    }

    /// Lists addresses (equivalent to Swift listAddresses)
    pub fn listAddresses(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoListAddress, []const @import("../rpc/complete_responses.zig").NeoAddress) {
        return try Request(@import("../rpc/response_aliases.zig").NeoListAddress, []const @import("../rpc/complete_responses.zig").NeoAddress).withNoParams(
            self.service.allocator,
            "listaddress",
        );
    }

    /// Sends token from specific account (equivalent to Swift sendFrom)
    pub fn sendFrom(self: Self, token_hash: Hash160, from: Hash160, to: Hash160, amount: i64) !Request(@import("../rpc/response_aliases.zig").NeoSendFrom, @import("../rpc/responses.zig").Transaction) {
        const allocator = self.service.allocator;

        const token_hex = try token_hash.string(allocator);
        defer allocator.free(token_hex);

        const from_address = try from.toAddress(allocator);
        defer allocator.free(from_address);

        const to_address = try to.toAddress(allocator);
        defer allocator.free(to_address);

        const params = [_]std.json.Value{
            std.json.Value{ .string = token_hex },
            std.json.Value{ .string = from_address },
            std.json.Value{ .string = to_address },
            std.json.Value{ .integer = amount },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoSendFrom, @import("../rpc/responses.zig").Transaction).init(
            allocator,
            "sendfrom",
            &params,
        );
    }

    /// Convenience overload using TransactionSendToken (equivalent to Swift sendFrom(_, _ txSendToken:))
    pub fn sendFromToken(self: Self, from: Hash160, token: TransactionSendToken) !Request(@import("../rpc/response_aliases.zig").NeoSendFrom, @import("../rpc/responses.zig").Transaction) {
        const allocator = self.service.allocator;
        const to_hash = try Hash160.fromAddress(token.address, allocator);
        return self.sendFrom(token.asset, from, to_hash, token.value);
    }

    /// Sends multiple transfers from wallet (equivalent to Swift sendMany)
    pub fn sendMany(self: Self, tokens: []const TransactionSendToken) !Request(@import("../rpc/response_aliases.zig").NeoSendMany, @import("../rpc/responses.zig").Transaction) {
        const allocator = self.service.allocator;
        var tokens_json = try encodeTransactionSendTokens(tokens, allocator);
        defer tokens_json.deinit();

        const params = [_]std.json.Value{
            tokens_json.value,
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoSendMany, @import("../rpc/responses.zig").Transaction).init(
            allocator,
            "sendmany",
            &params,
        );
    }

    /// Sends multiple transfers from specific account (equivalent to Swift sendMany(_:from:))
    pub fn sendManyFrom(self: Self, from: Hash160, tokens: []const TransactionSendToken) !Request(@import("../rpc/response_aliases.zig").NeoSendMany, @import("../rpc/responses.zig").Transaction) {
        const allocator = self.service.allocator;
        var tokens_json = try encodeTransactionSendTokens(tokens, allocator);
        defer tokens_json.deinit();

        const from_address = try from.toAddress(allocator);
        defer allocator.free(from_address);

        const params = [_]std.json.Value{
            std.json.Value{ .string = from_address },
            tokens_json.value,
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoSendMany, @import("../rpc/responses.zig").Transaction).init(
            allocator,
            "sendmany",
            &params,
        );
    }

    /// Sends token from wallet to address (equivalent to Swift sendToAddress)
    pub fn sendToAddress(self: Self, token_hash: Hash160, to: Hash160, amount: i64) !Request(@import("../rpc/response_aliases.zig").NeoSendToAddress, @import("../rpc/responses.zig").Transaction) {
        const allocator = self.service.allocator;

        const token_hex = try token_hash.string(allocator);
        defer allocator.free(token_hex);

        const to_address = try to.toAddress(allocator);
        defer allocator.free(to_address);

        const params = [_]std.json.Value{
            std.json.Value{ .string = token_hex },
            std.json.Value{ .string = to_address },
            std.json.Value{ .integer = amount },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoSendToAddress, @import("../rpc/responses.zig").Transaction).init(
            allocator,
            "sendtoaddress",
            &params,
        );
    }

    // ============================================================================
    // ADDITIONAL METHODS (converted from remaining Swift methods)
    // ============================================================================

    /// Gets storage (equivalent to Swift getStorage)
    pub fn getStorage(self: Self, contract_hash: Hash160, key_hex_string: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoGetStorage, []const u8) {
        const hash_hex = try contract_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);

        const string_params = [_][]const u8{ hash_hex, key_hex_string };
        return try Request(@import("../rpc/response_aliases.zig").NeoGetStorage, []const u8).withStringParams(
            self.service.allocator,
            "getstorage",
            &string_params,
        );
    }

    /// Gets NEP-17 balances
    pub fn getNep17Balances(self: Self, script_hash: Hash160) !Request(@import("../rpc/token_responses.zig").NeoGetNep17Balances, @import("../rpc/token_responses.zig").NeoGetNep17Balances) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const params = [_]std.json.Value{std.json.Value{ .string = address }};
        return try Request(@import("../rpc/token_responses.zig").NeoGetNep17Balances, @import("../rpc/token_responses.zig").NeoGetNep17Balances).init(
            self.service.allocator,
            "getnep17balances",
            &params,
        );
    }

    /// Gets NEP-17 transfers (all)
    pub fn getNep17Transfers(self: Self, script_hash: Hash160) !Request(@import("../rpc/token_responses.zig").NeoGetNep17Transfers, @import("../rpc/token_responses.zig").NeoGetNep17Transfers) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const params = [_]std.json.Value{std.json.Value{ .string = address }};
        return try Request(@import("../rpc/token_responses.zig").NeoGetNep17Transfers, @import("../rpc/token_responses.zig").NeoGetNep17Transfers).init(
            self.service.allocator,
            "getnep17transfers",
            &params,
        );
    }

    /// Gets NEP-17 transfers since timestamp (milliseconds)
    pub fn getNep17TransfersFrom(self: Self, script_hash: Hash160, from_timestamp_ms: i64) !Request(@import("../rpc/token_responses.zig").NeoGetNep17Transfers, @import("../rpc/token_responses.zig").NeoGetNep17Transfers) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const params = [_]std.json.Value{
            std.json.Value{ .string = address },
            std.json.Value{ .integer = from_timestamp_ms },
        };

        return try Request(@import("../rpc/token_responses.zig").NeoGetNep17Transfers, @import("../rpc/token_responses.zig").NeoGetNep17Transfers).init(
            self.service.allocator,
            "getnep17transfers",
            &params,
        );
    }

    /// Gets NEP-17 transfers in time range (milliseconds)
    pub fn getNep17TransfersRange(self: Self, script_hash: Hash160, from_timestamp_ms: i64, to_timestamp_ms: i64) !Request(@import("../rpc/token_responses.zig").NeoGetNep17Transfers, @import("../rpc/token_responses.zig").NeoGetNep17Transfers) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const params = [_]std.json.Value{
            std.json.Value{ .string = address },
            std.json.Value{ .integer = from_timestamp_ms },
            std.json.Value{ .integer = to_timestamp_ms },
        };

        return try Request(@import("../rpc/token_responses.zig").NeoGetNep17Transfers, @import("../rpc/token_responses.zig").NeoGetNep17Transfers).init(
            self.service.allocator,
            "getnep17transfers",
            &params,
        );
    }

    /// Gets NEP-11 balances
    pub fn getNep11Balances(self: Self, script_hash: Hash160) !Request(@import("../rpc/token_responses.zig").NeoGetNep11Balances, @import("../rpc/token_responses.zig").NeoGetNep11Balances) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const params = [_]std.json.Value{std.json.Value{ .string = address }};
        return try Request(@import("../rpc/token_responses.zig").NeoGetNep11Balances, @import("../rpc/token_responses.zig").NeoGetNep11Balances).init(
            self.service.allocator,
            "getnep11balances",
            &params,
        );
    }

    /// Gets NEP-11 transfers (all)
    pub fn getNep11Transfers(self: Self, script_hash: Hash160) !Request(@import("../rpc/token_responses.zig").NeoGetNep11Transfers, @import("../rpc/token_responses.zig").NeoGetNep11Transfers) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const params = [_]std.json.Value{std.json.Value{ .string = address }};
        return try Request(@import("../rpc/token_responses.zig").NeoGetNep11Transfers, @import("../rpc/token_responses.zig").NeoGetNep11Transfers).init(
            self.service.allocator,
            "getnep11transfers",
            &params,
        );
    }

    /// Gets NEP-11 transfers since timestamp (milliseconds)
    pub fn getNep11TransfersFrom(self: Self, script_hash: Hash160, from_timestamp_ms: i64) !Request(@import("../rpc/token_responses.zig").NeoGetNep11Transfers, @import("../rpc/token_responses.zig").NeoGetNep11Transfers) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const params = [_]std.json.Value{
            std.json.Value{ .string = address },
            std.json.Value{ .integer = from_timestamp_ms },
        };

        return try Request(@import("../rpc/token_responses.zig").NeoGetNep11Transfers, @import("../rpc/token_responses.zig").NeoGetNep11Transfers).init(
            self.service.allocator,
            "getnep11transfers",
            &params,
        );
    }

    /// Gets NEP-11 transfers in range (milliseconds)
    pub fn getNep11TransfersRange(self: Self, script_hash: Hash160, from_timestamp_ms: i64, to_timestamp_ms: i64) !Request(@import("../rpc/token_responses.zig").NeoGetNep11Transfers, @import("../rpc/token_responses.zig").NeoGetNep11Transfers) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const params = [_]std.json.Value{
            std.json.Value{ .string = address },
            std.json.Value{ .integer = from_timestamp_ms },
            std.json.Value{ .integer = to_timestamp_ms },
        };

        return try Request(@import("../rpc/token_responses.zig").NeoGetNep11Transfers, @import("../rpc/token_responses.zig").NeoGetNep11Transfers).init(
            self.service.allocator,
            "getnep11transfers",
            &params,
        );
    }

    /// Gets NEP-11 token properties (equivalent to Swift getNep11Properties)
    pub fn getNep11Properties(self: Self, script_hash: Hash160, token_id: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoGetNep11Properties, @import("../rpc/response_aliases.zig").NeoGetNep11Properties) {
        const address = try script_hash.toAddress(self.service.allocator);
        defer self.service.allocator.free(address);

        const params = [_]std.json.Value{
            std.json.Value{ .string = address },
            std.json.Value{ .string = token_id },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetNep11Properties, @import("../rpc/response_aliases.zig").NeoGetNep11Properties).init(
            self.service.allocator,
            "getnep11properties",
            &params,
        );
    }

    /// Gets transaction height (equivalent to Swift getTransactionHeight)
    pub fn getTransactionHeight(self: Self, tx_hash: Hash256) !Request(@import("../rpc/response_aliases.zig").NeoGetTransactionHeight, u32) {
        const hash_hex = try tx_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);

        const string_params = [_][]const u8{hash_hex};
        return try Request(@import("../rpc/response_aliases.zig").NeoGetTransactionHeight, u32).withStringParams(
            self.service.allocator,
            "gettransactionheight",
            &string_params,
        );
    }

    /// Gets next block validators
    pub fn getNextBlockValidators(self: Self) !Request(@import("../rpc/complete_responses.zig").NeoGetNextBlockValidators, @import("../rpc/complete_responses.zig").NeoGetNextBlockValidators) {
        return try Request(@import("../rpc/complete_responses.zig").NeoGetNextBlockValidators, @import("../rpc/complete_responses.zig").NeoGetNextBlockValidators).withNoParams(
            self.service.allocator,
            "getnextblockvalidators",
        );
    }

    /// Gets committee (equivalent to Swift getCommittee)
    pub fn getCommittee(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoGetCommittee, []const []const u8) {
        return try Request(@import("../rpc/response_aliases.zig").NeoGetCommittee, []const []const u8).withNoParams(
            self.service.allocator,
            "getcommittee",
        );
    }

    /// Calculates network fee (utility method)
    pub fn calculateNetworkFee(self: Self, raw_transaction_hex: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoCalculateNetworkFee, @import("../rpc/complete_responses.zig").NetworkFeeResponse) {
        const allocator = self.service.allocator;
        const tx_base64 = try hexToBase64(raw_transaction_hex, allocator);
        defer allocator.free(tx_base64);

        const params = [_]std.json.Value{std.json.Value{ .string = tx_base64 }};
        return try Request(@import("../rpc/response_aliases.zig").NeoCalculateNetworkFee, @import("../rpc/complete_responses.zig").NetworkFeeResponse).init(
            allocator,
            "calculatenetworkfee",
            &params,
        );
    }

    /// Gets state root (equivalent to Swift getStateRoot)
    pub fn getStateRoot(self: Self, block_index: u32) !Request(@import("../rpc/complete_responses.zig").NeoGetStateRoot, @import("../rpc/complete_responses.zig").NeoGetStateRoot) {
        const int_params = [_]i64{@intCast(block_index)};
        return try Request(@import("../rpc/complete_responses.zig").NeoGetStateRoot, @import("../rpc/complete_responses.zig").NeoGetStateRoot).withIntegerParams(
            self.service.allocator,
            "getstateroot",
            &int_params,
        );
    }

    /// Gets proof for state (equivalent to Swift getProof)
    pub fn getProof(self: Self, root_hash: Hash256, contract_hash: Hash160, storage_key_hex: []const u8) !Request(@import("../rpc/remaining_responses.zig").NeoGetProof, []const u8) {
        const allocator = self.service.allocator;

        const root_hex = try root_hash.string(allocator);
        defer allocator.free(root_hex);

        const contract_hex = try contract_hash.string(allocator);
        defer allocator.free(contract_hex);

        const key_base64 = try hexToBase64(storage_key_hex, allocator);
        defer allocator.free(key_base64);

        const params = [_]std.json.Value{
            std.json.Value{ .string = root_hex },
            std.json.Value{ .string = contract_hex },
            std.json.Value{ .string = key_base64 },
        };

        return try Request(@import("../rpc/remaining_responses.zig").NeoGetProof, []const u8).init(
            allocator,
            "getproof",
            &params,
        );
    }

    /// Verifies proof (equivalent to Swift verifyProof)
    pub fn verifyProof(self: Self, root_hash: Hash256, proof_data_hex: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoVerifyProof, []const u8) {
        const allocator = self.service.allocator;

        const root_hex = try root_hash.string(allocator);
        defer allocator.free(root_hex);

        const proof_base64 = try hexToBase64(proof_data_hex, allocator);
        defer allocator.free(proof_base64);

        const params = [_]std.json.Value{
            std.json.Value{ .string = root_hex },
            std.json.Value{ .string = proof_base64 },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoVerifyProof, []const u8).init(
            allocator,
            "verifyproof",
            &params,
        );
    }

    /// Gets state height (equivalent to Swift getStateHeight)
    pub fn getStateHeight(self: Self) !Request(@import("../rpc/complete_responses.zig").NeoGetStateHeight, @import("../rpc/complete_responses.zig").NeoGetStateHeight) {
        return try Request(@import("../rpc/complete_responses.zig").NeoGetStateHeight, @import("../rpc/complete_responses.zig").NeoGetStateHeight).withNoParams(
            self.service.allocator,
            "getstateheight",
        );
    }

    /// Gets state entry (equivalent to Swift getState)
    pub fn getState(self: Self, root_hash: Hash256, contract_hash: Hash160, key_hex: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoGetState, []const u8) {
        const allocator = self.service.allocator;

        const root_hex = try root_hash.string(allocator);
        defer allocator.free(root_hex);

        const contract_hex = try contract_hash.string(allocator);
        defer allocator.free(contract_hex);

        const key_base64 = try hexToBase64(key_hex, allocator);
        defer allocator.free(key_base64);

        const params = [_]std.json.Value{
            std.json.Value{ .string = root_hex },
            std.json.Value{ .string = contract_hex },
            std.json.Value{ .string = key_base64 },
        };

        return try Request(@import("../rpc/response_aliases.zig").NeoGetState, []const u8).init(
            allocator,
            "getstate",
            &params,
        );
    }

    /// Finds states (equivalent to Swift findStates)
    pub fn findStates(
        self: Self,
        root_hash: Hash256,
        contract_hash: Hash160,
        key_prefix_hex: []const u8,
        start_key_hex: ?[]const u8,
        count_find_result_items: ?u32,
    ) !Request(@import("../rpc/remaining_responses.zig").NeoFindStates, @import("../rpc/remaining_responses.zig").NeoFindStates) {
        const allocator = self.service.allocator;

        const root_hex = try root_hash.string(allocator);
        defer allocator.free(root_hex);

        const contract_hex = try contract_hash.string(allocator);
        defer allocator.free(contract_hex);

        const prefix_base64 = try hexToBase64(key_prefix_hex, allocator);
        defer allocator.free(prefix_base64);

        var params_list = std.ArrayList(std.json.Value).init(allocator);
        defer params_list.deinit();

        try params_list.append(std.json.Value{ .string = root_hex });
        try params_list.append(std.json.Value{ .string = contract_hex });
        try params_list.append(std.json.Value{ .string = prefix_base64 });

        if (start_key_hex) |start_hex| {
            const start_base64 = try hexToBase64(start_hex, allocator);
            defer allocator.free(start_base64);
            try params_list.append(std.json.Value{ .string = start_base64 });
        } else if (count_find_result_items != null) {
            try params_list.append(std.json.Value{ .string = "" });
        }

        if (count_find_result_items) |count| {
            try params_list.append(std.json.Value{ .integer = @intCast(count) });
        }

        const params_slice = try params_list.toOwnedSlice();
        defer allocator.free(params_slice);

        return try Request(@import("../rpc/remaining_responses.zig").NeoFindStates, @import("../rpc/remaining_responses.zig").NeoFindStates).init(
            allocator,
            "findstates",
            params_slice,
        );
    }

    /// Finds states with optional start key convenience wrapper
    pub fn findStatesWithStart(
        self: Self,
        root_hash: Hash256,
        contract_hash: Hash160,
        key_prefix_hex: []const u8,
        start_key_hex: []const u8,
    ) !Request(@import("../rpc/remaining_responses.zig").NeoFindStates, @import("../rpc/remaining_responses.zig").NeoFindStates) {
        return self.findStates(root_hash, contract_hash, key_prefix_hex, start_key_hex, null);
    }

    /// Finds states with count convenience wrapper
    pub fn findStatesWithCount(
        self: Self,
        root_hash: Hash256,
        contract_hash: Hash160,
        key_prefix_hex: []const u8,
        count_find_result_items: u32,
    ) !Request(@import("../rpc/remaining_responses.zig").NeoFindStates, @import("../rpc/remaining_responses.zig").NeoFindStates) {
        return self.findStates(root_hash, contract_hash, key_prefix_hex, null, count_find_result_items);
    }

    /// Finds states convenience wrapper without optional arguments
    pub fn findStatesSimple(
        self: Self,
        root_hash: Hash256,
        contract_hash: Hash160,
        key_prefix_hex: []const u8,
    ) !Request(@import("../rpc/remaining_responses.zig").NeoFindStates, @import("../rpc/remaining_responses.zig").NeoFindStates) {
        return self.findStates(root_hash, contract_hash, key_prefix_hex, null, null);
    }
};

/// Protocol implementation factory
pub const NeoProtocolFactory = struct {
    /// Creates protocol for MainNet
    pub fn mainnet(allocator: std.mem.Allocator) !NeoProtocol {
        var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.mainnet(allocator);
        return NeoProtocol.init(&service);
    }

    /// Creates protocol for TestNet
    pub fn testnet(allocator: std.mem.Allocator) !NeoProtocol {
        var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.testnet(allocator);
        return NeoProtocol.init(&service);
    }

    /// Creates protocol for local node
    pub fn localhost(allocator: std.mem.Allocator, port: ?u16) !NeoProtocol {
        var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.localhost(allocator, port);
        return NeoProtocol.init(&service);
    }

    /// Creates custom protocol
    pub fn custom(
        allocator: std.mem.Allocator,
        endpoint: []const u8,
        timeout_ms: u32,
        max_retries: u32,
    ) !NeoProtocol {
        var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.custom(
            allocator,
            endpoint,
            timeout_ms,
            max_retries,
        );
        return NeoProtocol.init(&service);
    }
};

// Tests (converted from Swift Neo protocol tests)
test "NeoProtocol creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test protocol creation
    var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.localhost(allocator, null);
    const protocol = NeoProtocol.init(&service);

    // Test blockchain method requests
    const best_block_request = try protocol.getBestBlockHash();
    try testing.expectEqualStrings("getbestblockhash", best_block_request.getMethod());

    const block_count_request = try protocol.getBlockCount();
    try testing.expectEqualStrings("getblockcount", block_count_request.getMethod());

    const connection_count_request = try protocol.getConnectionCount();
    try testing.expectEqualStrings("getconnectioncount", connection_count_request.getMethod());
}

test "NeoProtocol parameterized requests" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.localhost(allocator, null);
    const protocol = NeoProtocol.init(&service);

    // Test parameterized requests
    const block_hash_request = try protocol.getBlockHash(12345);
    try testing.expectEqualStrings("getblockhash", block_hash_request.getMethod());

    const test_hash = try Hash256.initWithString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const block_request = try protocol.getBlock(test_hash, true);
    try testing.expectEqualStrings("getblock", block_request.getMethod());

    const transaction_request = try protocol.getTransaction(test_hash);
    try testing.expectEqualStrings("getrawtransaction", transaction_request.getMethod());

    const block_header_request = try protocol.getBlockHeaderByIndex(12345);
    try testing.expectEqualStrings("getblockheader", block_header_request.getMethod());

    const raw_block_header_request = try protocol.getRawBlockHeaderByIndex(12345);
    try testing.expectEqualStrings("getblockheader", raw_block_header_request.getMethod());

    const raw_transaction_request = try protocol.getRawTransaction(test_hash);
    try testing.expectEqualStrings("getrawtransaction", raw_transaction_request.getMethod());

    const raw_mempool_request = try protocol.getRawMemPool();
    try testing.expectEqualStrings("getrawmempool", raw_mempool_request.getMethod());

    const native_contract_request = try protocol.getNativeContractState("GasToken");
    try testing.expectEqualStrings("getcontractstate", native_contract_request.getMethod());

    const submit_block_request = try protocol.submitBlock("deadbeef");
    try testing.expectEqualStrings("submitblock", submit_block_request.getMethod());

    const validators_request = try protocol.getNextBlockValidators();
    try testing.expectEqualStrings("getnextblockvalidators", validators_request.getMethod());

    const state_root_request = try protocol.getStateRoot(42);
    try testing.expectEqualStrings("getstateroot", state_root_request.getMethod());

    const proof_request = try protocol.getProof(test_hash, Hash160.ZERO, "00");
    try testing.expectEqualStrings("getproof", proof_request.getMethod());

    const verify_request = try protocol.verifyProof(test_hash, "00");
    try testing.expectEqualStrings("verifyproof", verify_request.getMethod());

    const state_height_request = try protocol.getStateHeight();
    try testing.expectEqualStrings("getstateheight", state_height_request.getMethod());

    const state_request = try protocol.getState(test_hash, Hash160.ZERO, "00");
    try testing.expectEqualStrings("getstate", state_request.getMethod());

    const find_states_request = try protocol.findStatesSimple(test_hash, Hash160.ZERO, "00");
    try testing.expectEqualStrings("findstates", find_states_request.getMethod());

    const find_states_with_start = try protocol.findStatesWithStart(test_hash, Hash160.ZERO, "00", "01");
    try testing.expectEqualStrings("findstates", find_states_with_start.getMethod());

    const find_states_with_count = try protocol.findStatesWithCount(test_hash, Hash160.ZERO, "00", 10);
    try testing.expectEqualStrings("findstates", find_states_with_count.getMethod());

    const from_address_str = "NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7";
    const to_address_str = "NWcx4EfYdfqn5jNjDz8AHE6hWtWdUGDdmy";
    const from_hash = try Hash160.fromAddress(from_address_str, allocator);
    const to_hash = try Hash160.fromAddress(to_address_str, allocator);

    const send_from_request = try protocol.sendFrom(Hash160.ZERO, from_hash, to_hash, 1);
    try testing.expectEqualStrings("sendfrom", send_from_request.getMethod());

    const send_from_token = TransactionSendToken.init(Hash160.ZERO, 1, to_address_str);
    const send_from_token_request = try protocol.sendFromToken(from_hash, send_from_token);
    try testing.expectEqualStrings("sendfrom", send_from_token_request.getMethod());

    const tokens = [_]TransactionSendToken{send_from_token};
    const send_many_request = try protocol.sendMany(&tokens);
    try testing.expectEqualStrings("sendmany", send_many_request.getMethod());

    const send_many_from_request = try protocol.sendManyFrom(from_hash, &tokens);
    try testing.expectEqualStrings("sendmany", send_many_from_request.getMethod());

    const send_to_address_request = try protocol.sendToAddress(Hash160.ZERO, to_hash, 1);
    try testing.expectEqualStrings("sendtoaddress", send_to_address_request.getMethod());

    const wallet_balance_request = try protocol.getWalletBalance(Hash160.ZERO);
    try testing.expectEqualStrings("getwalletbalance", wallet_balance_request.getMethod());

    const wallet_unclaimed_request = try protocol.getWalletUnclaimedGas();
    try testing.expectEqualStrings("getwalletunclaimedgas", wallet_unclaimed_request.getMethod());

    const dump_priv_request = try protocol.dumpPrivKey(from_hash);
    try testing.expectEqualStrings("dumpprivkey", dump_priv_request.getMethod());

    const calc_fee_request = try protocol.calculateNetworkFee("00");
    try testing.expectEqualStrings("calculatenetworkfee", calc_fee_request.getMethod());

    const nep17_balances_request = try protocol.getNep17Balances(from_hash);
    try testing.expectEqualStrings("getnep17balances", nep17_balances_request.getMethod());

    const nep17_transfers_request = try protocol.getNep17Transfers(from_hash);
    try testing.expectEqualStrings("getnep17transfers", nep17_transfers_request.getMethod());

    const nep17_from_request = try protocol.getNep17TransfersFrom(from_hash, 1);
    try testing.expectEqualStrings("getnep17transfers", nep17_from_request.getMethod());

    const nep17_range_request = try protocol.getNep17TransfersRange(from_hash, 1, 2);
    try testing.expectEqualStrings("getnep17transfers", nep17_range_request.getMethod());

    const nep11_balances_request = try protocol.getNep11Balances(from_hash);
    try testing.expectEqualStrings("getnep11balances", nep11_balances_request.getMethod());

    const nep11_transfers_request = try protocol.getNep11Transfers(from_hash);
    try testing.expectEqualStrings("getnep11transfers", nep11_transfers_request.getMethod());

    const nep11_from_request = try protocol.getNep11TransfersFrom(from_hash, 1);
    try testing.expectEqualStrings("getnep11transfers", nep11_from_request.getMethod());

    const nep11_range_request = try protocol.getNep11TransfersRange(from_hash, 1, 2);
    try testing.expectEqualStrings("getnep11transfers", nep11_range_request.getMethod());

    const nep11_properties_request = try protocol.getNep11Properties(from_hash, "0102");
    try testing.expectEqualStrings("getnep11properties", nep11_properties_request.getMethod());
}

test "NeoProtocol smart contract methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.localhost(allocator, null);
    const protocol = NeoProtocol.init(&service);

    // Test contract invocation
    const contract_hash = Hash160.ZERO;
    const params = [_]ContractParameter{
        ContractParameter.string("test_param"),
        ContractParameter.integer(42),
    };
    const signers = [_]Signer{
        Signer.init(Hash160.ZERO, @import("../transaction/transaction_builder.zig").WitnessScope.CalledByEntry),
    };

    const invoke_request = try protocol.invokeFunction(contract_hash, "testMethod", &params, &signers);
    try testing.expectEqualStrings("invokefunction", invoke_request.getMethod());

    const invoke_no_params_request = try protocol.invokeFunctionNoParams(contract_hash, "noParams", &signers);
    try testing.expectEqualStrings("invokefunction", invoke_no_params_request.getMethod());

    const invoke_diag_request = try protocol.invokeFunctionDiagnostics(contract_hash, "testMethod", &params, &signers);
    try testing.expectEqualStrings("invokefunction", invoke_diag_request.getMethod());

    const invoke_diag_no_params = try protocol.invokeFunctionDiagnosticsNoParams(contract_hash, "diagnosticsNoParams", &signers);
    try testing.expectEqualStrings("invokefunction", invoke_diag_no_params.getMethod());

    const verify_request = try protocol.invokeContractVerify(contract_hash, &params, &signers);
    try testing.expectEqualStrings("invokecontractverify", verify_request.getMethod());

    // Test script invocation
    const script_hex = "0c21036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29641419ed9d4";
    const script_request = try protocol.invokeScript(script_hex, &signers);
    try testing.expectEqualStrings("invokescript", script_request.getMethod());

    const script_diag_request = try protocol.invokeScriptDiagnostics(script_hex, &signers);
    try testing.expectEqualStrings("invokescript", script_diag_request.getMethod());
}

test "NeoProtocol utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var service = try @import("../rpc/neo_swift_service.zig").ServiceFactory.localhost(allocator, null);
    const protocol = NeoProtocol.init(&service);

    // Test utility methods
    const plugins_request = try protocol.listPlugins();
    try testing.expectEqualStrings("listplugins", plugins_request.getMethod());

    const validate_request = try protocol.validateAddress("NPeaW6X5q2p7BoP6hYpLYA6jBFhEL6n1A7");
    try testing.expectEqualStrings("validateaddress", validate_request.getMethod());

    // Test wallet methods
    const close_wallet_request = try protocol.closeWallet();
    try testing.expectEqualStrings("closewallet", close_wallet_request.getMethod());

    const new_address_request = try protocol.getNewAddress();
    try testing.expectEqualStrings("getnewaddress", new_address_request.getMethod());
}
