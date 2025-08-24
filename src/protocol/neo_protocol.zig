//! Neo Protocol implementation
//!
//! Complete conversion from NeoSwift Neo.swift protocol
//! Provides complete Neo blockchain protocol interface.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const Request = @import("../rpc/request.zig").Request;

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
        return Request(@import("../rpc/response_aliases.zig").NeoBlockHash, Hash256).withNoParams(
            self.service.allocator,
            "getbestblockhash",
            self.service,
        );
    }
    
    /// Gets block hash by index (equivalent to Swift getBlockHash(_ blockIndex: Int))
    pub fn getBlockHash(self: Self, block_index: u32) !Request(@import("../rpc/response_aliases.zig").NeoBlockHash, Hash256) {
        const int_params = [_]i64{@intCast(block_index)};
        return try Request(@import("../rpc/response_aliases.zig").NeoBlockHash, Hash256).withIntegerParams(
            self.service.allocator,
            "getblockhash",
            &int_params,
            self.service,
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
        
        return Request(@import("../rpc/response_aliases.zig").NeoGetBlock, @import("../rpc/responses.zig").NeoBlock).init(
            self.service.allocator,
            "getblock",
            &params,
            self.service,
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
        
        return Request(@import("../rpc/response_aliases.zig").NeoGetBlock, @import("../rpc/responses.zig").NeoBlock).init(
            self.service.allocator,
            "getblock",
            &params,
            self.service,
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
        
        return Request(@import("../rpc/response_aliases.zig").NeoGetRawBlock, []const u8).init(
            self.service.allocator,
            "getblock",
            &params,
            self.service,
        );
    }
    
    /// Gets block count (equivalent to Swift getBlockCount())
    pub fn getBlockCount(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoBlockCount, u32) {
        return Request(@import("../rpc/response_aliases.zig").NeoBlockCount, u32).withNoParams(
            self.service.allocator,
            "getblockcount",
            self.service,
        );
    }
    
    /// Gets block header count (equivalent to Swift getBlockHeaderCount())
    pub fn getBlockHeaderCount(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoBlockHeaderCount, u32) {
        return Request(@import("../rpc/response_aliases.zig").NeoBlockHeaderCount, u32).withNoParams(
            self.service.allocator,
            "getblockheadercount",
            self.service,
        );
    }
    
    /// Gets native contracts (equivalent to Swift getNativeContracts())
    pub fn getNativeContracts(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoGetNativeContracts, []const @import("../rpc/complete_responses.zig").NativeContractState) {
        return Request(@import("../rpc/response_aliases.zig").NeoGetNativeContracts, []const @import("../rpc/complete_responses.zig").NativeContractState).withNoParams(
            self.service.allocator,
            "getnativecontracts",
            self.service,
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
            self.service,
        );
    }
    
    /// Gets memory pool (equivalent to Swift getMemPool())
    pub fn getMemPool(self: Self) !Request(@import("../rpc/complete_responses.zig").NeoGetMemPool, @import("../rpc/complete_responses.zig").NeoGetMemPool) {
        return Request(@import("../rpc/complete_responses.zig").NeoGetMemPool, @import("../rpc/complete_responses.zig").NeoGetMemPool).withNoParams(
            self.service.allocator,
            "getrawmempool",
            self.service,
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
        
        return Request(@import("../rpc/response_aliases.zig").NeoGetTransaction, @import("../rpc/responses.zig").Transaction).init(
            self.service.allocator,
            "getrawtransaction",
            &params,
            self.service,
        );
    }
    
    // ============================================================================
    // NODE METHODS (converted from Swift node methods)
    // ============================================================================
    
    /// Gets connection count (equivalent to Swift getConnectionCount())
    pub fn getConnectionCount(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoConnectionCount, u32) {
        return Request(@import("../rpc/response_aliases.zig").NeoConnectionCount, u32).withNoParams(
            self.service.allocator,
            "getconnectioncount",
            self.service,
        );
    }
    
    /// Gets peers (equivalent to Swift getPeers())
    pub fn getPeers(self: Self) !Request(@import("../rpc/complete_responses.zig").NeoGetPeers, @import("../rpc/complete_responses.zig").NeoGetPeers) {
        return Request(@import("../rpc/complete_responses.zig").NeoGetPeers, @import("../rpc/complete_responses.zig").NeoGetPeers).withNoParams(
            self.service.allocator,
            "getpeers",
            self.service,
        );
    }
    
    /// Gets version (equivalent to Swift getVersion())
    pub fn getVersion(self: Self) !Request(@import("../rpc/remaining_responses.zig").NeoGetVersion, @import("../rpc/remaining_responses.zig").NeoGetVersion) {
        return Request(@import("../rpc/remaining_responses.zig").NeoGetVersion, @import("../rpc/remaining_responses.zig").NeoGetVersion).withNoParams(
            self.service.allocator,
            "getversion",
            self.service,
        );
    }
    
    /// Sends raw transaction (equivalent to Swift sendRawTransaction(_ rawTransactionHex: String))
    pub fn sendRawTransaction(self: Self, raw_transaction_hex: []const u8) !Request(@import("../rpc/remaining_responses.zig").NeoSendRawTransaction, @import("../rpc/remaining_responses.zig").NeoSendRawTransaction) {
        const string_params = [_][]const u8{raw_transaction_hex};
        return try Request(@import("../rpc/remaining_responses.zig").NeoSendRawTransaction, @import("../rpc/remaining_responses.zig").NeoSendRawTransaction).withStringParams(
            self.service.allocator,
            "sendrawtransaction",
            &string_params,
            self.service,
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
        const hash_hex = try contract_hash.string(self.service.allocator);
        defer self.service.allocator.free(hash_hex);
        
        // Build parameters
        var params_array = std.ArrayList(std.json.Value).init(self.service.allocator);
        defer params_array.deinit();
        
        for (params) |param| {
            const param_json = try @import("../contract/parameter_utils.zig").parameterToJson(param, self.service.allocator);
            try params_array.append(param_json);
        }
        
        // Build signers
        var signers_array = std.ArrayList(std.json.Value).init(self.service.allocator);
        defer signers_array.deinit();
        
        for (signers) |signer| {
            const signer_hex = try signer.signer_hash.string(self.service.allocator);
            defer self.service.allocator.free(signer_hex);
            try signers_array.append(std.json.Value{ .string = signer_hex });
        }
        
        const rpc_params = [_]std.json.Value{
            std.json.Value{ .string = hash_hex },
            std.json.Value{ .string = function_name },
            std.json.Value{ .array = params_array.items },
            std.json.Value{ .array = signers_array.items },
        };
        
        return Request(@import("../rpc/response_aliases.zig").NeoInvokeFunction, @import("../rpc/responses.zig").InvocationResult).init(
            self.service.allocator,
            "invokefunction",
            &rpc_params,
            self.service,
        );
    }
    
    /// Invokes script (equivalent to Swift invokeScript)
    pub fn invokeScript(
        self: Self,
        script_hex: []const u8,
        signers: []const Signer,
    ) !Request(@import("../rpc/response_aliases.zig").NeoInvokeScript, @import("../rpc/responses.zig").InvocationResult) {
        var signers_array = std.ArrayList(std.json.Value).init(self.service.allocator);
        defer signers_array.deinit();
        
        for (signers) |signer| {
            const signer_hex = try signer.signer_hash.string(self.service.allocator);
            defer self.service.allocator.free(signer_hex);
            try signers_array.append(std.json.Value{ .string = signer_hex });
        }
        
        const params = [_]std.json.Value{
            std.json.Value{ .string = script_hex },
            std.json.Value{ .array = signers_array.items },
        };
        
        return Request(@import("../rpc/response_aliases.zig").NeoInvokeScript, @import("../rpc/responses.zig").InvocationResult).init(
            self.service.allocator,
            "invokescript",
            &params,
            self.service,
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
        
        return Request(@import("../rpc/response_aliases.zig").NeoTraverseIterator, []const @import("../rpc/responses.zig").StackItem).init(
            self.service.allocator,
            "traverseiterator",
            &params,
            self.service,
        );
    }
    
    /// Terminates session (equivalent to Swift terminateSession)
    pub fn terminateSession(self: Self, session_id: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoTerminateSession, bool) {
        const string_params = [_][]const u8{session_id};
        return try Request(@import("../rpc/response_aliases.zig").NeoTerminateSession, bool).withStringParams(
            self.service.allocator,
            "terminatesession",
            &string_params,
            self.service,
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
            self.service,
        );
    }
    
    // ============================================================================
    // UTILITY METHODS (converted from Swift utility methods)
    // ============================================================================
    
    /// Lists plugins (equivalent to Swift listPlugins())
    pub fn listPlugins(self: Self) !Request(@import("../rpc/complete_responses.zig").NeoListPlugins, @import("../rpc/complete_responses.zig").NeoListPlugins) {
        return Request(@import("../rpc/complete_responses.zig").NeoListPlugins, @import("../rpc/complete_responses.zig").NeoListPlugins).withNoParams(
            self.service.allocator,
            "listplugins",
            self.service,
        );
    }
    
    /// Validates address (equivalent to Swift validateAddress)
    pub fn validateAddress(self: Self, address: []const u8) !Request(@import("../rpc/complete_responses.zig").NeoValidateAddress, @import("../rpc/complete_responses.zig").NeoValidateAddress) {
        const string_params = [_][]const u8{address};
        return try Request(@import("../rpc/complete_responses.zig").NeoValidateAddress, @import("../rpc/complete_responses.zig").NeoValidateAddress).withStringParams(
            self.service.allocator,
            "validateaddress",
            &string_params,
            self.service,
        );
    }
    
    // ============================================================================
    // WALLET METHODS (converted from Swift wallet methods)
    // ============================================================================
    
    /// Closes wallet (equivalent to Swift closeWallet())
    pub fn closeWallet(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoCloseWallet, bool) {
        return Request(@import("../rpc/response_aliases.zig").NeoCloseWallet, bool).withNoParams(
            self.service.allocator,
            "closewallet",
            self.service,
        );
    }
    
    /// Opens wallet (equivalent to Swift openWallet)
    pub fn openWallet(self: Self, wallet_path: []const u8, password: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoOpenWallet, bool) {
        const string_params = [_][]const u8{ wallet_path, password };
        return try Request(@import("../rpc/response_aliases.zig").NeoOpenWallet, bool).withStringParams(
            self.service.allocator,
            "openwallet",
            &string_params,
            self.service,
        );
    }
    
    /// Gets new address (equivalent to Swift getNewAddress)
    pub fn getNewAddress(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoGetNewAddress, []const u8) {
        return Request(@import("../rpc/response_aliases.zig").NeoGetNewAddress, []const u8).withNoParams(
            self.service.allocator,
            "getnewaddress",
            self.service,
        );
    }
    
    /// Imports private key (equivalent to Swift importPrivKey)
    pub fn importPrivKey(self: Self, private_key_wif: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoImportPrivKey, @import("../rpc/complete_responses.zig").NeoAddress) {
        const string_params = [_][]const u8{private_key_wif};
        return try Request(@import("../rpc/response_aliases.zig").NeoImportPrivKey, @import("../rpc/complete_responses.zig").NeoAddress).withStringParams(
            self.service.allocator,
            "importprivkey",
            &string_params,
            self.service,
        );
    }
    
    /// Lists addresses (equivalent to Swift listAddresses)
    pub fn listAddresses(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoListAddress, []const @import("../rpc/complete_responses.zig").NeoAddress) {
        return Request(@import("../rpc/response_aliases.zig").NeoListAddress, []const @import("../rpc/complete_responses.zig").NeoAddress).withNoParams(
            self.service.allocator,
            "listaddress",
            self.service,
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
            self.service,
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
            self.service,
        );
    }
    
    /// Gets committee (equivalent to Swift getCommittee)
    pub fn getCommittee(self: Self) !Request(@import("../rpc/response_aliases.zig").NeoGetCommittee, []const []const u8) {
        return Request(@import("../rpc/response_aliases.zig").NeoGetCommittee, []const []const u8).withNoParams(
            self.service.allocator,
            "getcommittee",
            self.service,
        );
    }
    
    /// Calculates network fee (utility method)
    pub fn calculateNetworkFee(self: Self, raw_transaction_hex: []const u8) !Request(@import("../rpc/response_aliases.zig").NeoCalculateNetworkFee, @import("../rpc/complete_responses.zig").NetworkFeeResponse) {
        const string_params = [_][]const u8{raw_transaction_hex};
        return try Request(@import("../rpc/response_aliases.zig").NeoCalculateNetworkFee, @import("../rpc/complete_responses.zig").NetworkFeeResponse).withStringParams(
            self.service.allocator,
            "calculatenetworkfee",
            &string_params,
            self.service,
        );
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
    
    // Test script invocation
    const script_hex = "0c21036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29641419ed9d4";
    const script_request = try protocol.invokeScript(script_hex, &signers);
    try testing.expectEqualStrings("invokescript", script_request.getMethod());
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