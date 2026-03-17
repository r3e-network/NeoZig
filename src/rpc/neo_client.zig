//! Neo RPC client implementation
//!
//! Neo N3
//! Implements all RPC methods.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const ArrayList = std.ArrayList;
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const Address = @import("../types/address.zig").Address;
const Transaction = @import("../transaction/transaction_builder.zig").Transaction;
const responses = @import("responses.zig");
pub const NeoConfig = @import("neo_config.zig").NeoConfig;
pub const NeoService = @import("neo_service.zig").NeoService;
const ServiceImplementation = @import("neo_service.zig").ServiceImplementation;
pub const RpcRequest = @import("rpc_operation.zig").RpcRequest;
pub const RpcParam = @import("rpc_operation.zig").RpcParam;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const ServiceFactory = @import("neo_service.zig").ServiceFactory;
const HttpService = @import("http_service.zig").HttpService;
const HttpClient = @import("http_client.zig").HttpClient;
const blockchain_methods = @import("neo_client_blockchain.zig");
const contract_methods = @import("neo_client_contract.zig");
const wallet_methods = @import("neo_client_wallet.zig");
const core_methods = @import("neo_client_core.zig");

/// Neo RPC client
pub const NeoClient = struct {
    allocator: std.mem.Allocator,
    config: NeoConfig,
    service: NeoService,

    const Self = @This();

    pub usingnamespace core_methods.mixin(Self);
    pub usingnamespace blockchain_methods.mixin(Self);
    pub usingnamespace contract_methods.mixin(Self);
    pub usingnamespace wallet_methods.mixin(Self);
};

// ============================================================================
// RESPONSE TYPES
// ============================================================================

/// Re-export response types for convenience
pub const NeoBlock = responses.NeoBlock;
pub const NeoVersion = responses.NeoVersion;

pub const InvocationResult = responses.InvocationResult;
pub const StackItem = @import("../types/stack_item.zig").StackItem;

/// NEP-17 balances (RPC response).
pub const Nep17Balances = responses.Nep17Balances;
pub const TokenBalance = responses.TokenBalance;

/// NEP-17 transfers (RPC response).
pub const Nep17Transfers = responses.Nep17Transfers;
pub const TokenTransfer = responses.TokenTransfer;

/// Send raw transaction response.
pub const SendRawTransactionResponse = responses.SendRawTransactionResponse;

/// Network fee response.
pub const NetworkFeeResponse = responses.NetworkFeeResponse;

/// Address validation response.
pub const AddressValidation = @import("extended_responses.zig").NeoValidateAddress;
