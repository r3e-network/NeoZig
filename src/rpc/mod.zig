//! Low-level RPC types and transport.
//!
//! Most applications should use `neo.Client` instead. This module is the
//! escape hatch for callers that need the legacy `NeoClient` builder, the
//! response-type catalog (`rpc.types`), or direct access to the HTTP
//! transport for embedding/testing.

const std = @import("std");

pub const types = @import("types.zig");

pub const NeoClient = @import("neo_client.zig").NeoClient;
pub const NeoConfig = @import("neo_config.zig").NeoConfig;
pub const NeoService = @import("neo_service.zig").NeoService;
pub const Client = NeoClient;
pub const Config = NeoConfig;
pub const Service = NeoService;
pub const NeoClientBuilder = NeoClient.Builder;
pub const NeoConfigBuilder = NeoConfig.Builder;
pub const RpcRequest = @import("rpc_operation.zig").RpcRequest;
pub const RpcParam = @import("rpc_operation.zig").RpcParam;
pub const ServiceFactory = @import("neo_service.zig").ServiceFactory;
pub const ServiceImplementation = @import("neo_service.zig").ServiceImplementation;
pub const HttpService = @import("http_service.zig").HttpService;
pub const HttpServiceFactory = @import("http_service.zig").HttpServiceFactory;
pub const HttpClient = @import("http_client.zig").HttpClient;
pub const HttpClientFactory = @import("http_client.zig").HttpClientFactory;
pub const Backoff = @import("http_client.zig").Backoff;
pub const ServerError = @import("http_client.zig").ServerError;
pub const Request = @import("request.zig").Request;
pub const RequestUtils = @import("request.zig").RequestUtils;
pub const Response = @import("response.zig").Response;
pub const ResponseError = @import("response.zig").ResponseError;

pub const NeoBlock = types.NeoBlock;
pub const NeoVersion = types.NeoVersion;
pub const InvocationResult = types.InvocationResult;
pub const StackItem = types.StackItem;
pub const Nep17Balances = types.Nep17Balances;
pub const Nep17Transfers = types.Nep17Transfers;
pub const TokenBalance = types.TokenBalance;
pub const TokenTransfer = types.TokenTransfer;
pub const NeoApplicationLog = types.NeoApplicationLog;
pub const Execution = types.Execution;
pub const Notification = types.Notification;
pub const ContractState = types.ContractState;
pub const NeoAccountState = types.NeoAccountState;
pub const NeoGetNextBlockValidators = types.NeoGetNextBlockValidators;
pub const NeoGetStateHeight = types.NeoGetStateHeight;
pub const NeoGetStateRoot = types.NeoGetStateRoot;
pub const NeoListPlugins = types.NeoListPlugins;
pub const OracleRequest = types.OracleRequest;
pub const OracleResponseCode = types.OracleResponseCode;
pub const NeoGetNep17Balances = types.NeoGetNep17Balances;
pub const NeoGetNep17Transfers = types.NeoGetNep17Transfers;
pub const NeoGetNep11Balances = types.NeoGetNep11Balances;
pub const NeoGetPeers = types.NeoGetPeers;
pub const NetworkFeeResponse = types.NetworkFeeResponse;
pub const SendRawTransactionResponse = types.SendRawTransactionResponse;
pub const NeoAddress = types.NeoAddress;
pub const ContractMethodToken = types.ContractMethodToken;
pub const NameState = types.NameState;
pub const TransactionSendToken = types.TransactionSendToken;
pub const NeoGetUnclaimedGas = types.NeoGetUnclaimedGas;
pub const Nep17Contract = types.Nep17Contract;
pub const NeoNetworkFee = types.NeoNetworkFee;
pub const NeoValidateAddress = types.NeoValidateAddress;
pub const PopulatedBlocks = types.PopulatedBlocks;
pub const RecordState = types.RecordState;
pub const NativeContractState = types.NativeContractState;
pub const ExpressContractState = types.ExpressContractState;
pub const ExpressShutdown = types.ExpressShutdown;
pub const Diagnostics = types.Diagnostics;
pub const ContractStorageEntry = types.ContractStorageEntry;
pub const NeoGetMemPool = types.NeoGetMemPool;
pub const Peer = types.Peer;
pub const NeoGetWalletBalance = types.NeoGetWalletBalance;
pub const NeoGetClaimable = types.NeoGetClaimable;
pub const ClaimableTransaction = types.ClaimableTransaction;
pub const NeoGetTokenTransfers = types.NeoGetTokenTransfers;
pub const NeoGetWalletUnclaimedGas = types.NeoGetWalletUnclaimedGas;
pub const NeoGetProof = types.NeoGetProof;
pub const NeoGetVersion = types.NeoGetVersion;
pub const NeoSendRawTransaction = types.NeoSendRawTransaction;
pub const NeoFindStates = types.NeoFindStates;
pub const NeoGetUnspents = types.NeoGetUnspents;
pub const TransactionAttributeResponse = types.TransactionAttributeResponse;
pub const NotificationResponse = types.NotificationResponse;
pub const ResponseAliases = types.ResponseAliases;
pub const ExpressShutdownResponse = types.ExpressShutdownResponse;
pub const DiagnosticsResponse = types.DiagnosticsResponse;

test "rpc module" {
    std.testing.refAllDecls(@This());
}
