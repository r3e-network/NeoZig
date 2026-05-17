//! Neo N3 client — the primary entry point for interacting with a Neo node.
//!
//! Construct a client with the builder, configure transport options, and call
//! operation methods directly. Each operation returns its response value (no
//! intermediate request handle to invoke).
//!
//! Example:
//!
//! ```zig
//! var client = try neo.Client.builder(allocator)
//!     .endpoint("http://localhost:20332")
//!     .timeoutMs(30_000)
//!     .retryPolicy(.{ .max_attempts = 5 })
//!     .build();
//! defer client.deinit();
//!
//! const count = try client.getBlockCount();
//! var version = try client.getVersion();
//! defer version.deinit(allocator);
//! ```

const std = @import("std");

const constants = @import("core/constants.zig");
const core_errors = @import("core/errors.zig");

const Hash160 = @import("types/hash160.zig").Hash160;
const Hash256 = @import("types/hash256.zig").Hash256;
const ContractParameter = @import("types/contract_parameter.zig").ContractParameter;

const Signer = @import("transaction/transaction_builder.zig").Signer;

const NeoConfig = @import("rpc/neo_config.zig").NeoConfig;
const NeoService = @import("rpc/neo_service.zig").NeoService;
const ServiceImplementation = @import("rpc/neo_service.zig").ServiceImplementation;
const http_service_mod = @import("rpc/http_service.zig");
const HttpService = http_service_mod.HttpService;
const http_client_mod = @import("rpc/http_client.zig");
const HttpClient = http_client_mod.HttpClient;

/// Structured JSON-RPC error returned by the server (code + message + data).
/// Inspect via `Client.takeLastServerError` after an operation returns
/// `error.ServerError`.
pub const ServerError = http_client_mod.ServerError;

const RpcParam = @import("rpc/rpc_operation.zig").RpcParam;
const RpcRequest = @import("rpc/rpc_operation.zig").RpcRequest;

const responses = @import("rpc/responses.zig");
const extended = @import("rpc/extended_responses.zig");
const rpc_types = @import("rpc/types.zig");

// ---------------------------------------------------------------------------
// Re-exported response types (so callers do not need to import internal modules)
// ---------------------------------------------------------------------------

pub const NeoBlock = responses.NeoBlock;
pub const NeoVersion = responses.NeoVersion;
pub const InvocationResult = responses.InvocationResult;
pub const Transaction = responses.Transaction;
pub const Nep17Balances = responses.Nep17Balances;
pub const TokenBalance = responses.TokenBalance;
pub const Nep17Transfers = responses.Nep17Transfers;
pub const TokenTransfer = responses.TokenTransfer;
pub const SendRawTransactionResponse = responses.SendRawTransactionResponse;
pub const NetworkFeeResponse = responses.NetworkFeeResponse;
pub const NeoApplicationLog = responses.NeoApplicationLog;
pub const ContractState = responses.ContractState;
pub const ValidateAddressResult = extended.NeoValidateAddress;
pub const NativeContractState = rpc_types.NativeContractState;
pub const NeoGetMemPool = rpc_types.NeoGetMemPool;
pub const NeoGetPeers = rpc_types.NeoGetPeers;
pub const NeoGetNextBlockValidators = rpc_types.NeoGetNextBlockValidators;
pub const NeoListPlugins = rpc_types.NeoListPlugins;
pub const NeoGetStateRoot = rpc_types.NeoGetStateRoot;
pub const NeoGetStateHeight = rpc_types.NeoGetStateHeight;
pub const NeoFindStates = rpc_types.NeoFindStates;
pub const NeoGetUnclaimedGas = rpc_types.NeoGetUnclaimedGas;
pub const NeoGetNep11Balances = rpc_types.NeoGetNep11Balances;

// ---------------------------------------------------------------------------
// Network presets
// ---------------------------------------------------------------------------

/// Well-known Neo networks.
///
/// Passing a preset to `Builder.network` selects a default endpoint when no
/// explicit endpoint has been set. The selected network does not validate
/// against the chain; use `Client.getNetworkMagic` to read the magic from the
/// connected node.
pub const Network = enum {
    mainnet,
    testnet,
    private,

    pub fn defaultEndpoint(self: Network) []const u8 {
        return switch (self) {
            .mainnet => "https://mainnet1.neo.coz.io:443",
            .testnet => "https://testnet1.neo.coz.io:443",
            .private => "http://localhost:20332",
        };
    }
};

/// Retry policy for transport-level failures.
///
/// Only transport errors and 5xx responses are retried. Successful JSON-RPC
/// error responses (the server returned a structured `error` object) are
/// surfaced immediately and never retried.
pub const RetryPolicy = struct {
    /// Total request attempts, including the initial one. 1 disables retry.
    max_attempts: u32 = 3,
    /// Initial backoff between attempts, in milliseconds.
    initial_backoff_ms: u32 = 500,
    /// Backoff growth factor applied between attempts.
    multiplier: f32 = 2.0,
    /// Upper bound on backoff between attempts, in milliseconds.
    max_backoff_ms: u32 = 30_000,
};

// ---------------------------------------------------------------------------
// Operation option structs
// ---------------------------------------------------------------------------

pub const GetBlockOptions = struct {
    /// When true, the block is returned with full transaction objects.
    /// When false, only transaction hashes are included.
    full_transactions: bool = false,
};

pub const InvokeOptions = struct {
    /// Signers that should be attached for verification. Empty by default.
    signers: []const Signer = &.{},
};

pub const TransferRangeOptions = struct {
    /// Lower-bound timestamp (UNIX ms). When null, no lower bound.
    from_time: ?u64 = null,
    /// Upper-bound timestamp (UNIX ms). Ignored when `from_time` is null.
    to_time: ?u64 = null,
};

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// High-level Neo N3 client.
///
/// Owns the underlying transport and configuration. Construct via
/// `Client.builder(allocator)`; release with `deinit`.
///
/// Methods are safe to call concurrently only if the underlying HTTP transport
/// is; the bundled HTTP transport is not thread-safe and must be wrapped if
/// shared across threads.
pub const Client = struct {
    allocator: std.mem.Allocator,
    config: NeoConfig,
    service: NeoService,
    retry: RetryPolicy,

    const Self = @This();

    /// Returns a new client builder bound to `allocator`.
    pub fn builder(allocator: std.mem.Allocator) Builder {
        return Builder.init(allocator);
    }

    /// Fluent client builder. Each setter returns a new builder value.
    pub const Builder = struct {
        allocator: std.mem.Allocator,
        endpoint_value: ?[]const u8 = null,
        network_preset: Network = .private,
        timeout_ms: u32 = 30_000,
        include_raw_responses: bool = false,
        max_response_bytes: usize = HttpClient.DEFAULT_MAX_RESPONSE_BYTES,
        retry: RetryPolicy = .{},
        config: NeoConfig = NeoConfig.init(),

        pub fn init(allocator: std.mem.Allocator) Builder {
            return .{ .allocator = allocator };
        }

        /// Sets the JSON-RPC endpoint URL. Overrides any `network` preset.
        pub fn endpoint(self: Builder, value: []const u8) Builder {
            var next = self;
            next.endpoint_value = value;
            return next;
        }

        /// Selects a network preset. The preset's default endpoint is used
        /// only when `endpoint` is not set.
        pub fn network(self: Builder, value: Network) Builder {
            var next = self;
            next.network_preset = value;
            return next;
        }

        /// Per-request timeout in milliseconds. The underlying stdlib http
        /// client honors this as a best-effort total, not a socket deadline.
        pub fn timeoutMs(self: Builder, ms: u32) Builder {
            var next = self;
            next.timeout_ms = ms;
            return next;
        }

        /// Configures retry behavior for transport-level failures.
        pub fn retryPolicy(self: Builder, value: RetryPolicy) Builder {
            var next = self;
            next.retry = value;
            return next;
        }

        /// When true, every response is captured as a raw string in addition
        /// to being parsed. Useful for debugging; off by default.
        pub fn includeRawResponses(self: Builder, enabled: bool) Builder {
            var next = self;
            next.include_raw_responses = enabled;
            return next;
        }

        /// Caps the size of a response body read into memory. 0 = default cap.
        pub fn maxResponseBytes(self: Builder, bytes: usize) Builder {
            var next = self;
            next.max_response_bytes = bytes;
            return next;
        }

        /// Overrides the NNS resolver contract hash. Default is the mainnet NNS.
        pub fn nnsResolver(self: Builder, hash: Hash160) Builder {
            var next = self;
            next.config.nns_resolver = hash;
            return next;
        }

        /// Block production interval in ms. Defaults to 15000 (Neo N3 mainnet).
        pub fn blockIntervalMs(self: Builder, ms: u32) Builder {
            var next = self;
            _ = next.config.setBlockInterval(ms);
            return next;
        }

        /// Block polling interval in ms. Defaults to the block interval.
        pub fn pollingIntervalMs(self: Builder, ms: u32) Builder {
            var next = self;
            next.config.polling_interval = ms;
            return next;
        }

        /// When true, transactions are still transmitted to the network even
        /// if their test invocation reports FAULT. Off by default.
        pub fn allowTransmissionOnFault(self: Builder, enabled: bool) Builder {
            var next = self;
            next.config.allows_transmission_on_fault = enabled;
            return next;
        }

        /// Builds the client. Allocates the transport; the caller owns
        /// the returned client and must call `deinit`.
        pub fn build(self: Builder) !Client {
            try self.config.validate();
            const resolved_endpoint = self.endpoint_value orelse self.network_preset.defaultEndpoint();

            const http_service = try self.allocator.create(HttpService);
            errdefer self.allocator.destroy(http_service);

            http_service.* = HttpService.init(
                self.allocator,
                resolved_endpoint,
                self.include_raw_responses,
            );
            http_service.setTimeout(self.timeout_ms);
            http_service.setMaxRetries(self.retry.max_attempts);
            http_service.setMaxResponseBytes(self.max_response_bytes);

            const impl = ServiceImplementation.init(http_service, self.allocator, true);
            return Client{
                .allocator = self.allocator,
                .config = self.config,
                .service = NeoService.init(impl),
                .retry = self.retry,
            };
        }
    };

    /// Releases the underlying transport and any owned resources.
    pub fn deinit(self: *Self) void {
        self.service.deinit();
    }

    // ----- Internal helper ------------------------------------------------

    fn rpcCall(
        self: *Self,
        comptime T: type,
        method: []const u8,
        params: []const RpcParam,
    ) !T {
        var req = try RpcRequest(T).init(self.allocator, &self.service, method, params);
        return try req.send();
    }

    // ----- Blockchain queries --------------------------------------------

    /// Returns the hash of the highest known block.
    pub fn getBestBlockHash(self: *Self) !Hash256 {
        return self.rpcCall(Hash256, "getbestblockhash", &.{});
    }

    /// Returns the hash of the block at `index`.
    pub fn getBlockHash(self: *Self, index: u32) !Hash256 {
        const params = [_]RpcParam{RpcParam.initInt(index)};
        return self.rpcCall(Hash256, "getblockhash", &params);
    }

    /// Returns the block identified by `hash`. Caller owns the returned value
    /// and must call its `deinit(allocator)`.
    pub fn getBlock(self: *Self, hash: Hash256, opts: GetBlockOptions) !NeoBlock {
        const hash_str = try hash.string(self.allocator);
        defer self.allocator.free(hash_str);
        const params = [_]RpcParam{
            RpcParam.initString(hash_str),
            RpcParam.initInt(@as(i32, if (opts.full_transactions) 1 else 0)),
        };
        return self.rpcCall(NeoBlock, "getblock", &params);
    }

    /// Returns the block at `index`. Caller owns the returned value.
    pub fn getBlockByIndex(self: *Self, index: u32, opts: GetBlockOptions) !NeoBlock {
        const params = [_]RpcParam{
            RpcParam.initInt(index),
            RpcParam.initInt(@as(i32, if (opts.full_transactions) 1 else 0)),
        };
        return self.rpcCall(NeoBlock, "getblock", &params);
    }

    /// Returns the current block count.
    pub fn getBlockCount(self: *Self) !u32 {
        return self.rpcCall(u32, "getblockcount", &.{});
    }

    /// Returns the count of currently connected peers.
    pub fn getConnectionCount(self: *Self) !u32 {
        return self.rpcCall(u32, "getconnectioncount", &.{});
    }

    /// Returns the connected node's version and protocol settings.
    pub fn getVersion(self: *Self) !NeoVersion {
        return self.rpcCall(NeoVersion, "getversion", &.{});
    }

    /// Returns a transaction by hash (verbose form). Caller owns the value.
    pub fn getTransaction(self: *Self, hash: Hash256) !Transaction {
        const hash_str = try hash.string(self.allocator);
        defer self.allocator.free(hash_str);
        const params = [_]RpcParam{
            RpcParam.initString(hash_str),
            RpcParam.initInt(@as(i32, 1)),
        };
        return self.rpcCall(Transaction, "getrawtransaction", &params);
    }

    /// Returns the block index containing the given transaction.
    pub fn getTransactionHeight(self: *Self, hash: Hash256) !u32 {
        const hash_str = try hash.string(self.allocator);
        defer self.allocator.free(hash_str);
        const params = [_]RpcParam{RpcParam.initString(hash_str)};
        return self.rpcCall(u32, "gettransactionheight", &params);
    }

    /// Returns the header for the block identified by `hash`.
    /// Caller owns the returned value.
    pub fn getBlockHeader(self: *Self, hash: Hash256) !NeoBlock {
        const hash_str = try hash.string(self.allocator);
        defer self.allocator.free(hash_str);
        const params = [_]RpcParam{
            RpcParam.initString(hash_str),
            RpcParam.initInt(@as(i32, 1)),
        };
        return self.rpcCall(NeoBlock, "getblockheader", &params);
    }

    /// Returns the header for the block at `index`. Caller owns the value.
    pub fn getBlockHeaderByIndex(self: *Self, index: u32) !NeoBlock {
        const params = [_]RpcParam{
            RpcParam.initInt(index),
            RpcParam.initInt(@as(i32, 1)),
        };
        return self.rpcCall(NeoBlock, "getblockheader", &params);
    }

    /// Returns the count of available block headers.
    pub fn getBlockHeaderCount(self: *Self) !u32 {
        return self.rpcCall(u32, "getblockheadercount", &.{});
    }

    /// Returns the verified and unverified hashes in the node's mempool.
    /// Caller owns the returned value.
    pub fn getMemPool(self: *Self) !NeoGetMemPool {
        const params = [_]RpcParam{RpcParam.initInt(@as(i32, 1))};
        return self.rpcCall(NeoGetMemPool, "getrawmempool", &params);
    }

    /// Returns just the verified hashes in the node's mempool.
    /// Caller owns the returned slice and each Hash256 (no per-element deinit needed).
    pub fn getRawMemPool(self: *Self) ![]Hash256 {
        return self.rpcCall([]Hash256, "getrawmempool", &.{});
    }

    /// Returns the node's peer list.
    /// Caller owns the returned value.
    pub fn getPeers(self: *Self) !NeoGetPeers {
        return self.rpcCall(NeoGetPeers, "getpeers", &.{});
    }

    /// Returns the next block validators (committee subset that will produce
    /// the next block). Caller owns the returned value.
    pub fn getNextBlockValidators(self: *Self) !NeoGetNextBlockValidators {
        return self.rpcCall(NeoGetNextBlockValidators, "getnextblockvalidators", &.{});
    }

    /// Returns the list of native contracts deployed on the network.
    /// Caller owns the returned slice and each element's allocated fields.
    pub fn getNativeContracts(self: *Self) ![]NativeContractState {
        return self.rpcCall([]NativeContractState, "getnativecontracts", &.{});
    }

    /// Lists the RPC plugins loaded on the node. Caller owns the value.
    pub fn listPlugins(self: *Self) !NeoListPlugins {
        return self.rpcCall(NeoListPlugins, "listplugins", &.{});
    }

    /// Reads a single storage entry from the contract's persistent state.
    /// `key_base64` is the base64-encoded storage key.
    /// Returns the value as a base64-encoded byte string; caller owns it.
    pub fn getStorage(self: *Self, contract: Hash160, key_base64: []const u8) ![]const u8 {
        const contract_str = try contract.string(self.allocator);
        defer self.allocator.free(contract_str);
        const params = [_]RpcParam{
            RpcParam.initString(contract_str),
            RpcParam.initString(key_base64),
        };
        return self.rpcCall([]const u8, "getstorage", &params);
    }

    /// Submits a fully constructed block (hex-encoded) for the node to relay.
    /// Returns the block hash on success.
    pub fn submitBlock(self: *Self, block_hex: []const u8) !Hash256 {
        const params = [_]RpcParam{RpcParam.initString(block_hex)};
        return self.rpcCall(Hash256, "submitblock", &params);
    }

    // ----- Contract operations (additions) -------------------------------

    /// Calls a contract's `verify` entry point (used for witness-based
    /// authorization). Returns an InvocationResult; caller owns it.
    pub fn invokeContractVerify(
        self: *Self,
        contract: Hash160,
        method: []const u8,
        params: []const ContractParameter,
        opts: InvokeOptions,
    ) !InvocationResult {
        const contract_str = try contract.string(self.allocator);
        defer self.allocator.free(contract_str);
        const rpc_params = [_]RpcParam{
            RpcParam.initString(contract_str),
            RpcParam.initString(method),
            RpcParam.initArray(params),
            RpcParam.initArray(opts.signers),
        };
        return self.rpcCall(InvocationResult, "invokecontractverify", &rpc_params);
    }

    /// Returns the unclaimed GAS for `script_hash`. Caller owns the value.
    pub fn getUnclaimedGas(self: *Self, script_hash: Hash160) !NeoGetUnclaimedGas {
        const address = try script_hash.toAddress(self.allocator);
        defer self.allocator.free(address);
        const params = [_]RpcParam{RpcParam.initString(address)};
        return self.rpcCall(NeoGetUnclaimedGas, "getunclaimedgas", &params);
    }

    // ----- NEP-11 (non-fungible token) operations ------------------------

    /// Returns the NEP-11 balances for `script_hash`. Caller owns the value.
    pub fn getNep11Balances(self: *Self, script_hash: Hash160) !NeoGetNep11Balances {
        const address = try script_hash.toAddress(self.allocator);
        defer self.allocator.free(address);
        const params = [_]RpcParam{RpcParam.initString(address)};
        return self.rpcCall(NeoGetNep11Balances, "getnep11balances", &params);
    }

    // ----- State service operations --------------------------------------

    /// Returns the state root at the given block index. Caller owns the value.
    pub fn getStateRoot(self: *Self, index: u32) !NeoGetStateRoot {
        const params = [_]RpcParam{RpcParam.initInt(index)};
        return self.rpcCall(NeoGetStateRoot, "getstateroot", &params);
    }

    /// Returns the local and validated state heights. Caller owns the value.
    pub fn getStateHeight(self: *Self) !NeoGetStateHeight {
        return self.rpcCall(NeoGetStateHeight, "getstateheight", &.{});
    }

    // ----- Contract operations -------------------------------------------

    /// Returns the state of a deployed contract.
    pub fn getContractState(self: *Self, contract: Hash160) !ContractState {
        const contract_str = try contract.string(self.allocator);
        defer self.allocator.free(contract_str);
        const params = [_]RpcParam{RpcParam.initString(contract_str)};
        return self.rpcCall(ContractState, "getcontractstate", &params);
    }

    /// Invokes a contract method without broadcasting (test invocation).
    pub fn invokeFunction(
        self: *Self,
        contract: Hash160,
        method: []const u8,
        params: []const ContractParameter,
        opts: InvokeOptions,
    ) !InvocationResult {
        const contract_str = try contract.string(self.allocator);
        defer self.allocator.free(contract_str);
        const rpc_params = [_]RpcParam{
            RpcParam.initString(contract_str),
            RpcParam.initString(method),
            RpcParam.initArray(params),
            RpcParam.initArray(opts.signers),
        };
        return self.rpcCall(InvocationResult, "invokefunction", &rpc_params);
    }

    /// Test-invokes a raw script.
    pub fn invokeScript(
        self: *Self,
        script_hex: []const u8,
        opts: InvokeOptions,
    ) !InvocationResult {
        const rpc_params = [_]RpcParam{
            RpcParam.initString(script_hex),
            RpcParam.initArray(opts.signers),
        };
        return self.rpcCall(InvocationResult, "invokescript", &rpc_params);
    }

    /// Broadcasts a signed, serialized transaction (hex-encoded).
    /// Returns the server's send response (transaction hash on success).
    pub fn sendRawTransaction(self: *Self, raw_tx_hex: []const u8) !SendRawTransactionResponse {
        const params = [_]RpcParam{RpcParam.initString(raw_tx_hex)};
        return self.rpcCall(SendRawTransactionResponse, "sendrawtransaction", &params);
    }

    /// Computes the network fee for a serialized transaction (hex-encoded).
    pub fn calculateNetworkFee(self: *Self, tx_hex: []const u8) !NetworkFeeResponse {
        const params = [_]RpcParam{RpcParam.initString(tx_hex)};
        return self.rpcCall(NetworkFeeResponse, "calculatenetworkfee", &params);
    }

    // ----- NEP-17 token operations ---------------------------------------

    /// Returns the NEP-17 balances for `script_hash`.
    pub fn getNep17Balances(self: *Self, script_hash: Hash160) !Nep17Balances {
        const address = try script_hash.toAddress(self.allocator);
        defer self.allocator.free(address);
        const params = [_]RpcParam{RpcParam.initString(address)};
        return self.rpcCall(Nep17Balances, "getnep17balances", &params);
    }

    /// Returns the NEP-17 transfer history for `script_hash`, optionally
    /// bounded by `from_time` and `to_time`.
    pub fn getNep17Transfers(
        self: *Self,
        script_hash: Hash160,
        opts: TransferRangeOptions,
    ) !Nep17Transfers {
        const address = try script_hash.toAddress(self.allocator);
        defer self.allocator.free(address);

        var params = std.ArrayList(RpcParam).init(self.allocator);
        defer params.deinit();
        try params.append(RpcParam.initString(address));
        if (opts.from_time) |from| {
            try params.append(RpcParam.initInt(from));
            if (opts.to_time) |to| try params.append(RpcParam.initInt(to));
        }
        return self.rpcCall(Nep17Transfers, "getnep17transfers", params.items);
    }

    /// Validates a Neo address string against the connected network's rules.
    pub fn validateAddress(self: *Self, address: []const u8) !ValidateAddressResult {
        const params = [_]RpcParam{RpcParam.initString(address)};
        return self.rpcCall(ValidateAddressResult, "validateaddress", &params);
    }

    // ----- Configuration accessors ---------------------------------------

    /// Returns the network magic number for the connected node. If the value
    /// has not yet been fetched, calls `getVersion` to populate it.
    pub fn getNetworkMagic(self: *Self) !u32 {
        if (self.config.network_magic) |magic| return magic;
        var version = try self.getVersion();
        defer version.deinit(self.allocator);
        if (version.protocol) |proto| {
            _ = self.config.setNetworkMagic(proto.network);
            NeoConfig.setAddressVersion(@intCast(proto.address_version));
            if (proto.ms_per_block) |ms| self.config.block_interval = ms;
            if (proto.max_valid_until_block_increment) |mvubi|
                self.config.max_valid_until_block_increment = mvubi;
            return proto.network;
        }
        return core_errors.NeoError.InvalidConfiguration;
    }

    pub fn isMainnet(self: Self) bool {
        return self.config.isMainnet();
    }

    pub fn isTestnet(self: Self) bool {
        return self.config.isTestnet();
    }

    pub fn getNnsResolver(self: Self) Hash160 {
        return self.config.nns_resolver;
    }

    pub fn getBlockInterval(self: Self) u32 {
        return self.config.block_interval;
    }

    pub fn getPollingInterval(self: Self) u32 {
        return self.config.polling_interval;
    }

    /// Consumes and returns the structured JSON-RPC error from the most recent
    /// operation, if one was captured. Use after a method returns
    /// `error.ServerError` to inspect the server's `code`/`message`/`data`.
    /// Caller owns the returned value and must call `deinit(allocator)`.
    pub fn takeLastServerError(self: *Self) ?ServerError {
        return self.service.service_impl.http_service.http_client.takeLastServerError();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Client.builder applies endpoint and retry defaults" {
    const testing = std.testing;
    var client = try Client.builder(testing.allocator)
        .endpoint("http://127.0.0.1:20332")
        .timeoutMs(5_000)
        .retryPolicy(.{ .max_attempts = 7, .initial_backoff_ms = 100 })
        .build();
    defer client.deinit();

    try testing.expectEqual(@as(u32, 7), client.retry.max_attempts);
    try testing.expectEqual(@as(u32, 100), client.retry.initial_backoff_ms);
    try testing.expectEqual(NeoConfig.DEFAULT_BLOCK_TIME, client.getBlockInterval());
}

test "Client.builder honors network preset when endpoint is omitted" {
    const testing = std.testing;
    var client = try Client.builder(testing.allocator)
        .network(.testnet)
        .build();
    defer client.deinit();

    try testing.expect(!client.isMainnet());
    try testing.expect(!client.isTestnet()); // magic not yet fetched
}

test "Client.builder overrides config via fluent setters" {
    const testing = std.testing;
    var client = try Client.builder(testing.allocator)
        .endpoint("http://127.0.0.1:20332")
        .blockIntervalMs(5_000)
        .pollingIntervalMs(2_500)
        .allowTransmissionOnFault(true)
        .build();
    defer client.deinit();

    try testing.expectEqual(@as(u32, 5_000), client.getBlockInterval());
    try testing.expectEqual(@as(u32, 2_500), client.getPollingInterval());
    try testing.expect(client.config.allows_transmission_on_fault);
}

test "Network.defaultEndpoint returns expected presets" {
    const testing = std.testing;
    try testing.expectEqualStrings("http://localhost:20332", Network.private.defaultEndpoint());
    try testing.expect(std.mem.indexOf(u8, Network.mainnet.defaultEndpoint(), "mainnet") != null);
    try testing.expect(std.mem.indexOf(u8, Network.testnet.defaultEndpoint(), "testnet") != null);
}

// Sanity check that every named operation has a callable method on Client.
// This catches accidental method-name typos by exercising the symbol table.
test "Client exposes the full v2.0 operation surface" {
    const testing = std.testing;
    _ = testing;
    const C = Client;
    // Blockchain
    _ = @TypeOf(C.getBestBlockHash);
    _ = @TypeOf(C.getBlockHash);
    _ = @TypeOf(C.getBlock);
    _ = @TypeOf(C.getBlockByIndex);
    _ = @TypeOf(C.getBlockCount);
    _ = @TypeOf(C.getBlockHeader);
    _ = @TypeOf(C.getBlockHeaderByIndex);
    _ = @TypeOf(C.getBlockHeaderCount);
    _ = @TypeOf(C.getConnectionCount);
    _ = @TypeOf(C.getVersion);
    _ = @TypeOf(C.getTransaction);
    _ = @TypeOf(C.getTransactionHeight);
    _ = @TypeOf(C.getNativeContracts);
    _ = @TypeOf(C.getMemPool);
    _ = @TypeOf(C.getRawMemPool);
    _ = @TypeOf(C.getPeers);
    _ = @TypeOf(C.getNextBlockValidators);
    _ = @TypeOf(C.listPlugins);
    _ = @TypeOf(C.submitBlock);
    // Contract
    _ = @TypeOf(C.getContractState);
    _ = @TypeOf(C.invokeFunction);
    _ = @TypeOf(C.invokeScript);
    _ = @TypeOf(C.invokeContractVerify);
    _ = @TypeOf(C.sendRawTransaction);
    _ = @TypeOf(C.calculateNetworkFee);
    _ = @TypeOf(C.getStorage);
    _ = @TypeOf(C.getUnclaimedGas);
    // NEP-17 / NEP-11
    _ = @TypeOf(C.getNep17Balances);
    _ = @TypeOf(C.getNep17Transfers);
    _ = @TypeOf(C.getNep11Balances);
    // State service
    _ = @TypeOf(C.getStateRoot);
    _ = @TypeOf(C.getStateHeight);
    // Utility
    _ = @TypeOf(C.validateAddress);
    _ = @TypeOf(C.getNetworkMagic);
    _ = @TypeOf(C.takeLastServerError);
}
