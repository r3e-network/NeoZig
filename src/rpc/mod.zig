//! RPC module
//!
//! Complete RPC system.

const std = @import("std");

// Export RPC components
pub const NeoClient = @import("neo_client.zig").NeoClient;
pub const NeoConfig = @import("neo_client.zig").NeoConfig;
pub const NeoService = @import("neo_client.zig").NeoService;
pub const RpcRequest = @import("neo_client.zig").RpcRequest;
pub const RpcParam = @import("neo_client.zig").RpcParam;
pub const ServiceFactory = @import("neo_service.zig").ServiceFactory;
pub const ServiceImplementation = @import("neo_service.zig").ServiceImplementation;
pub const HttpService = @import("http_service.zig").HttpService;
pub const HttpServiceFactory = @import("http_service.zig").HttpServiceFactory;
pub const HttpClient = @import("http_client.zig").HttpClient;
pub const HttpClientFactory = @import("http_client.zig").HttpClientFactory;
pub const Request = @import("request.zig").Request;
pub const RequestUtils = @import("request.zig").RequestUtils;
pub const Response = @import("response.zig").Response;
pub const ResponseError = @import("response.zig").ResponseError;

// Export complete response types
pub const NeoBlock = @import("responses.zig").NeoBlock;
pub const NeoVersion = @import("responses.zig").NeoVersion;
pub const InvocationResult = @import("responses.zig").InvocationResult;
pub const StackItem = @import("../types/stack_item.zig").StackItem;
pub const Nep17Balances = @import("responses.zig").Nep17Balances;
pub const Nep17Transfers = @import("responses.zig").Nep17Transfers;
pub const TokenBalance = @import("responses.zig").TokenBalance;
pub const TokenTransfer = @import("responses.zig").TokenTransfer;
pub const NeoApplicationLog = @import("responses.zig").NeoApplicationLog;
pub const Execution = @import("responses.zig").Execution;
pub const Notification = @import("responses.zig").Notification;
pub const ContractState = @import("responses.zig").ContractState;
pub const NeoAccountState = @import("extended_responses.zig").NeoAccountState;
pub const NeoGetNextBlockValidators = @import("extended_responses.zig").NeoGetNextBlockValidators;
pub const NeoGetStateHeight = @import("extended_responses.zig").NeoGetStateHeight;
pub const NeoGetStateRoot = @import("extended_responses.zig").NeoGetStateRoot;
pub const NeoListPlugins = @import("extended_responses.zig").NeoListPlugins;
pub const OracleRequest = @import("extended_responses.zig").OracleRequest;
pub const OracleResponseCode = @import("extended_responses.zig").OracleResponseCode;
pub const NeoGetNep17Balances = @import("token_responses.zig").NeoGetNep17Balances;
pub const NeoGetNep17Transfers = @import("token_responses.zig").NeoGetNep17Transfers;
pub const NeoGetNep11Balances = @import("token_responses.zig").NeoGetNep11Balances;
pub const NeoGetPeers = @import("protocol_responses.zig").NeoGetPeers;
pub const NetworkFeeResponse = @import("responses.zig").NetworkFeeResponse;
pub const SendRawTransactionResponse = @import("responses.zig").SendRawTransactionResponse;

test "rpc module" {
    std.testing.refAllDecls(@This());
}
