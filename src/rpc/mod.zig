//! RPC module
//!
//! Complete RPC system converted from Swift implementation.

const std = @import("std");

// Export RPC components
pub const NeoSwift = @import("neo_client.zig").NeoSwift;
pub const NeoSwiftConfig = @import("neo_client.zig").NeoSwiftConfig;
pub const NeoSwiftService = @import("neo_client.zig").NeoSwiftService;
pub const RpcRequest = @import("neo_client.zig").RpcRequest;
pub const RpcParam = @import("neo_client.zig").RpcParam;

// Export complete response types
pub const NeoBlock = @import("responses.zig").NeoBlock;
pub const NeoVersion = @import("responses.zig").NeoVersion;
pub const InvocationResult = @import("responses.zig").InvocationResult;
pub const StackItem = @import("responses.zig").StackItem;
pub const Nep17Balances = @import("responses.zig").Nep17Balances;
pub const Nep17Transfers = @import("responses.zig").Nep17Transfers;
pub const TokenBalance = @import("responses.zig").TokenBalance;
pub const TokenTransfer = @import("responses.zig").TokenTransfer;
pub const NeoApplicationLog = @import("responses.zig").NeoApplicationLog;
pub const Execution = @import("responses.zig").Execution;
pub const Notification = @import("responses.zig").Notification;
pub const ContractState = @import("responses.zig").ContractState;
pub const NetworkFeeResponse = @import("responses.zig").NetworkFeeResponse;
pub const SendRawTransactionResponse = @import("responses.zig").SendRawTransactionResponse;

test "rpc module" {
    std.testing.refAllDecls(@This());
}