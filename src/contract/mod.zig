//! Contract module
//!
//! Complete smart contract system converted from Swift.

const std = @import("std");

// Export contract components
pub const SmartContract = @import("smart_contract.zig").SmartContract;
pub const ContractManagement = @import("contract_management.zig").ContractManagement;
pub const FungibleToken = @import("fungible_token.zig").FungibleToken;
pub const NonFungibleToken = @import("non_fungible_token.zig").NonFungibleToken;
pub const GasToken = @import("gas_token.zig").GasToken;
pub const NeoToken = @import("neo_token.zig").NeoToken;
pub const Token = @import("token.zig").Token;
pub const TransferRecipient = @import("fungible_token.zig").TransferRecipient;

// Export contract data structures
pub const ContractManifest = @import("smart_contract.zig").ContractManifest;
pub const ContractState = @import("smart_contract.zig").ContractState;
pub const ContractNef = @import("smart_contract.zig").ContractNef;
pub const ContractGroup = @import("smart_contract.zig").ContractGroup;
pub const ContractFeatures = @import("smart_contract.zig").ContractFeatures;
pub const ContractABI = @import("smart_contract.zig").ContractABI;
pub const ContractMethod = @import("smart_contract.zig").ContractMethod;
pub const ContractEvent = @import("smart_contract.zig").ContractEvent;
pub const ContractPermission = @import("smart_contract.zig").ContractPermission;

test "contract module" {
    std.testing.refAllDecls(@This());
}