//! Contract module
//!
//! Complete smart contract system.

const std = @import("std");

pub const base = @import("base_namespace.zig");
pub const tokens = @import("token_namespace.zig");
pub const native = @import("native_namespace.zig");
pub const naming = @import("naming_namespace.zig");
pub const artifacts = @import("artifact_namespace.zig");
pub const types = @import("type_namespace.zig");

// Export contract components
pub const SmartContract = base.SmartContract;
pub const Token = base.Token;
pub const FungibleToken = tokens.FungibleToken;
pub const NonFungibleToken = tokens.NonFungibleToken;
pub const GasToken = tokens.GasToken;
pub const NeoToken = tokens.NeoToken;
pub const TransferRecipient = tokens.TransferRecipient;
pub const ContractManagement = native.ContractManagement;
pub const PolicyContract = native.PolicyContract;
pub const RoleManagement = native.RoleManagement;
pub const Role = native.Role;
pub const Treasury = native.Treasury;
pub const Notary = native.Notary;
pub const CryptoLib = native.CryptoLib;
pub const NamedCurveHash = native.NamedCurveHash;
pub const NeoURI = naming.NeoURI;
pub const NeoURIBuilder = naming.NeoURIBuilder;
pub const URIUtils = naming.URIUtils;
pub const NNSName = naming.NNSName;
pub const NeoNameService = naming.NeoNameService;
pub const NefFile = artifacts.NefFile;
pub const MethodToken = artifacts.MethodToken;

// Export contract data structures
pub const ContractManifest = types.ContractManifest;
pub const ContractState = types.ContractState;
pub const ContractNef = types.ContractNef;
pub const ContractGroup = types.ContractGroup;
pub const ContractFeatures = types.ContractFeatures;
pub const ContractABI = types.ContractABI;
pub const ContractMethod = types.ContractMethod;
pub const ContractEvent = types.ContractEvent;
pub const ContractPermission = types.ContractPermission;
pub const ContractError = types.ContractError;
pub const ContractErrorUtils = types.ContractErrorUtils;

test "contract module" {
    std.testing.refAllDecls(@This());
}
