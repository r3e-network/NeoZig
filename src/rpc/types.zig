const std = @import("std");

pub const core = @import("responses.zig");
pub const extended = @import("extended_responses.zig");
pub const protocol = @import("protocol_responses.zig");
pub const remaining = @import("remaining_responses.zig");

pub const NeoBlock = core.NeoBlock;
pub const NeoVersion = core.NeoVersion;
pub const InvocationResult = core.InvocationResult;
pub const StackItem = @import("../types/stack_item.zig").StackItem;
pub const Nep17Balances = core.Nep17Balances;
pub const Nep17Transfers = core.Nep17Transfers;
pub const TokenBalance = core.TokenBalance;
pub const TokenTransfer = core.TokenTransfer;
pub const NeoApplicationLog = core.NeoApplicationLog;
pub const Execution = core.Execution;
pub const Notification = core.Notification;
pub const ContractState = core.ContractState;
pub const NetworkFeeResponse = core.NetworkFeeResponse;
pub const SendRawTransactionResponse = core.SendRawTransactionResponse;

pub const NeoAccountState = extended.NeoAccountState;
pub const NeoAddress = extended.NeoAddress;
pub const OracleRequest = extended.OracleRequest;
pub const ContractMethodToken = extended.ContractMethodToken;
pub const NameState = extended.NameState;
pub const NeoListPlugins = extended.NeoListPlugins;
pub const TransactionSendToken = extended.TransactionSendToken;
pub const NeoGetUnclaimedGas = extended.NeoGetUnclaimedGas;
pub const NeoGetNextBlockValidators = extended.NeoGetNextBlockValidators;
pub const NeoGetStateHeight = extended.NeoGetStateHeight;
pub const NeoGetStateRoot = extended.NeoGetStateRoot;
pub const Nep17Contract = extended.Nep17Contract;
pub const OracleResponseCode = extended.OracleResponseCode;
pub const NeoNetworkFee = extended.NeoNetworkFee;
pub const NeoValidateAddress = extended.NeoValidateAddress;
pub const PopulatedBlocks = extended.PopulatedBlocks;
pub const RecordState = extended.RecordState;
pub const NativeContractState = extended.NativeContractState;
pub const ExpressContractState = extended.ExpressContractState;
pub const ExpressShutdown = extended.ExpressShutdown;
pub const Diagnostics = extended.Diagnostics;
pub const ContractStorageEntry = extended.ContractStorageEntry;

pub const NeoGetMemPool = protocol.NeoGetMemPool;
pub const NeoGetPeers = protocol.NeoGetPeers;
pub const Peer = protocol.Peer;
pub const NeoGetWalletBalance = protocol.NeoGetWalletBalance;
pub const NeoGetClaimable = protocol.NeoGetClaimable;
pub const ClaimableTransaction = protocol.ClaimableTransaction;

pub const NeoGetNep17Balances = @import("token_responses.zig").NeoGetNep17Balances;
pub const NeoGetNep17Transfers = @import("token_responses.zig").NeoGetNep17Transfers;
pub const NeoGetNep11Balances = @import("token_responses.zig").NeoGetNep11Balances;

pub const NeoGetTokenTransfers = remaining.NeoGetTokenTransfers;
pub const NeoGetWalletUnclaimedGas = remaining.NeoGetWalletUnclaimedGas;
pub const NeoGetProof = remaining.NeoGetProof;
pub const NeoGetVersion = remaining.NeoGetVersion;
pub const NeoSendRawTransaction = remaining.NeoSendRawTransaction;
pub const NeoFindStates = remaining.NeoFindStates;
pub const NeoGetUnspents = remaining.NeoGetUnspents;
pub const TransactionAttributeResponse = remaining.TransactionAttributeResponse;
pub const NotificationResponse = remaining.NotificationResponse;
pub const ResponseAliases = remaining.ResponseAliases;
pub const ExpressShutdownResponse = remaining.ExpressShutdownResponse;
pub const DiagnosticsResponse = remaining.DiagnosticsResponse;

test "rpc types exposes complete catalog namespaces" {
    const testing = std.testing;

    try testing.expect(core.blockchain.NeoBlock == NeoBlock);
    try testing.expect(extended.network.NeoGetStateRoot == NeoGetStateRoot);
    try testing.expect(protocol.wallet.NeoGetClaimable == NeoGetClaimable);
    try testing.expect(remaining.state.NeoFindStates == NeoFindStates);
    try testing.expect(remaining.misc.DiagnosticsResponse == DiagnosticsResponse);
}
