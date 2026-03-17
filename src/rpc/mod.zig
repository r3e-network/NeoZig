//! RPC module
//!
//! Complete RPC system.

const std = @import("std");

pub const client = @import("client_namespace.zig");
pub const config = @import("config_namespace.zig");
pub const service = @import("service_namespace.zig");
pub const transport = @import("transport_namespace.zig");
pub const operation = @import("operation_namespace.zig");
pub const types = @import("types.zig");

// Backward-compatible flat exports
pub const NeoClient = client.Client;
pub const NeoConfig = config.Config;
pub const NeoService = service.Service;
pub const Client = NeoClient;
pub const Config = NeoConfig;
pub const Service = NeoService;
pub const NeoClientBuilder = client.Builder;
pub const NeoConfigBuilder = config.Builder;
pub const RpcRequest = operation.Request;
pub const RpcParam = operation.Param;
pub const ServiceFactory = service.Factory;
pub const ServiceImplementation = service.Implementation;
pub const HttpService = transport.Service;
pub const HttpServiceFactory = transport.ServiceFactory;
pub const HttpClient = transport.Client;
pub const HttpClientFactory = transport.ClientFactory;
pub const Request = operation.JsonRequest;
pub const RequestUtils = operation.RequestUtils;
pub const Response = operation.Response;
pub const ResponseError = operation.ResponseError;

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

test "rpc module mirrors unique catalog aliases" {
    const testing = std.testing;

    try testing.expect(NeoGetClaimable == types.NeoGetClaimable);
    try testing.expect(NeoFindStates == types.NeoFindStates);
    try testing.expect(DiagnosticsResponse == types.DiagnosticsResponse);
}
