//! Contract module — smart contract interaction surface.

const std = @import("std");

pub const SmartContract = @import("smart_contract.zig").SmartContract;
pub const Token = @import("token.zig").Token;
pub const FungibleToken = @import("fungible_token.zig").FungibleToken;
pub const NonFungibleToken = @import("non_fungible_token.zig").NonFungibleToken;
pub const GasToken = @import("gas_token.zig").GasToken;
pub const NeoToken = @import("neo_token.zig").NeoToken;
pub const TransferRecipient = @import("fungible_token.zig").TransferRecipient;

pub const ContractManagement = @import("contract_management.zig").ContractManagement;
pub const PolicyContract = @import("policy_contract.zig").PolicyContract;
pub const RoleManagement = @import("role_management.zig").RoleManagement;
pub const Role = @import("../types/role.zig").Role;
pub const Treasury = @import("treasury.zig").Treasury;
pub const Notary = @import("notary.zig").Notary;
pub const CryptoLib = @import("crypto_lib.zig").CryptoLib;
pub const NamedCurveHash = @import("crypto_lib.zig").NamedCurveHash;

pub const NeoURI = @import("neo_uri.zig").NeoURI;
pub const NeoURIBuilder = @import("neo_uri.zig").NeoURIBuilder;
pub const URIUtils = @import("neo_uri.zig").URIUtils;
pub const NNSName = @import("nns_name.zig").NNSName;
pub const NeoNameService = @import("neo_name_service.zig").NeoNameService;
pub const NefFile = @import("nef_file.zig").NefFile;
pub const MethodToken = @import("nef_file.zig").MethodToken;

pub const ContractManifest = @import("smart_contract.zig").ContractManifest;
pub const ContractState = @import("smart_contract.zig").ContractState;
pub const ContractNef = @import("smart_contract.zig").ContractNef;
pub const ContractGroup = @import("smart_contract.zig").ContractGroup;
pub const ContractFeatures = @import("smart_contract.zig").ContractFeatures;
pub const ContractABI = @import("smart_contract.zig").ContractABI;
pub const ContractMethod = @import("smart_contract.zig").ContractMethod;
pub const ContractEvent = @import("smart_contract.zig").ContractEvent;
pub const ContractPermission = @import("smart_contract.zig").ContractPermission;
pub const ContractError = @import("contract_error.zig").ContractError;
pub const ContractErrorUtils = @import("contract_error.zig").ContractErrorUtils;

test "contract module" {
    std.testing.refAllDecls(@This());
}
