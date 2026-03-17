const std = @import("std");

pub const state = @import("responses_contract_state.zig");
pub const manifest = @import("responses_contract_manifest.zig");
pub const abi = @import("responses_contract_abi.zig");

pub const ContractState = state.ContractState;
pub const ContractNef = state.ContractNef;
pub const ContractFeatures = manifest.ContractFeatures;
pub const ContractManifest = manifest.ContractManifest;
pub const ContractGroup = manifest.ContractGroup;
pub const ContractParameterDefinition = abi.ContractParameterDefinition;
pub const ContractMethod = abi.ContractMethod;
pub const ContractEvent = abi.ContractEvent;
pub const ContractABI = abi.ContractABI;
pub const ContractPermission = abi.ContractPermission;

test "contract responses module exposes submodule namespaces" {
    const testing = std.testing;

    try testing.expect(state.ContractState == ContractState);
    try testing.expect(manifest.ContractManifest == ContractManifest);
    try testing.expect(abi.ContractABI == ContractABI);
}
