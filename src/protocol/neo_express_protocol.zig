//! Neo Express Protocol Facade
//!
//! Provides a high-level wrapper around the Neo Express helper so callers can
//! access express-specific RPC requests without dealing with the lower-level
//! request builders directly.

const std = @import("std");

const NeoExpress = @import("neo_express.zig").NeoExpress;
const NeoSwiftService = @import("../rpc/neo_swift_service.zig").NeoSwiftService;
const Request = @import("../rpc/request.zig").Request;
const response_aliases = @import("../rpc/response_aliases.zig");
const complete_responses = @import("../rpc/complete_responses.zig");
const TransactionAttribute = @import("../transaction/transaction_builder.zig").TransactionAttribute;
const Hash160 = @import("../types/hash160.zig").Hash160;

/// High-level Neo Express protocol wrapper.
pub const NeoExpressProtocol = struct {
    express: NeoExpress,

    const Self = @This();

    /// Builds a protocol wrapper from an existing NeoSwift service.
    pub fn init(service: *NeoSwiftService) Self {
        return Self{ .express = NeoExpress.init(service) };
    }

    /// Returns a request builder for `expressgetpopulatedblocks`.
    pub fn expressGetPopulatedBlocks(self: Self) !Request(response_aliases.NeoExpressGetPopulatedBlocks, complete_responses.PopulatedBlocks) {
        return try self.express.expressGetPopulatedBlocks();
    }

    /// Returns a request builder for `expressgetnep17contracts`.
    pub fn expressGetNep17Contracts(self: Self) !Request(response_aliases.NeoExpressGetNep17Contracts, []const complete_responses.Nep17Contract) {
        return try self.express.expressGetNep17Contracts();
    }

    /// Returns a request builder for `expressgetcontractstorage`.
    pub fn expressGetContractStorage(
        self: Self,
        contract_hash: Hash160,
    ) !Request(response_aliases.NeoExpressGetContractStorage, []const complete_responses.ContractStorageEntry) {
        return try self.express.expressGetContractStorage(contract_hash);
    }

    /// Returns a request builder for `expresslistcontracts`.
    pub fn expressListContracts(self: Self) !Request(response_aliases.NeoExpressListContracts, []const complete_responses.ExpressContractState) {
        return try self.express.expressListContracts();
    }

    /// Returns a request builder for `expresscreatecheckpoint`.
    pub fn expressCreateCheckpoint(
        self: Self,
        filename: []const u8,
    ) !Request(response_aliases.NeoExpressCreateCheckpoint, []const u8) {
        return try self.express.expressCreateCheckpoint(filename);
    }

    /// Returns a request builder for `expresslistoraclerequests`.
    pub fn expressListOracleRequests(self: Self) !Request(response_aliases.NeoExpressListOracleRequests, []const complete_responses.OracleRequest) {
        return try self.express.expressListOracleRequests();
    }

    /// Returns a request builder for `expresscreateoracleresponsetx`.
    pub fn expressCreateOracleResponseTx(
        self: Self,
        attribute: TransactionAttribute,
    ) !Request(response_aliases.NeoExpressCreateOracleResponseTx, []const u8) {
        return try self.express.expressCreateOracleResponseTx(attribute);
    }

    /// Returns a request builder for `expressshutdown`.
    pub fn expressShutdown(self: Self) !Request(response_aliases.NeoExpressShutdown, complete_responses.ExpressShutdown) {
        return try self.express.expressShutdown();
    }
};

test "NeoExpressProtocol builds express requests" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create an HTTP service with a mocked HTTP client so no network is used.
    var http_service = @import("../rpc/http_service.zig").HttpService.init(allocator, null, false);
    defer http_service.deinit();

    const MockContext = struct { response: []const u8 };
    var mock_context = MockContext{ .response = "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":1}" };

    const mock_send = struct {
        fn send(
            ctx_ptr: ?*anyopaque,
            alloc: std.mem.Allocator,
            endpoint: []const u8,
            payload: []const u8,
            timeout_ms: u32,
        ) @import("../core/errors.zig").NetworkError![]u8 {
            _ = endpoint;
            _ = payload;
            _ = timeout_ms;
            const ctx = @ptrCast(*MockContext, ctx_ptr.?);
            return try alloc.dupe(u8, ctx.response);
        }
    }.send;

    http_service.http_client.withSender(mock_send, &mock_context);

    var neo_service = NeoSwiftService.init(&http_service);
    var protocol = NeoExpressProtocol.init(&neo_service);

    const populated = try protocol.expressGetPopulatedBlocks();
    try testing.expectEqualStrings("expressgetpopulatedblocks", populated.method);

    const nep17 = try protocol.expressGetNep17Contracts();
    try testing.expectEqualStrings("expressgetnep17contracts", nep17.method);

    const checkpoint = try protocol.expressCreateCheckpoint("checkpoint.neoexpress", allocator);
    try testing.expectEqualStrings("expresscreatecheckpoint", checkpoint.method);
}
