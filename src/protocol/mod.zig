//! Protocol module
//!
//! Internal protocol helpers and response models.

const std = @import("std");

pub const JsonRpc2_0Rx = @import("json_rpc_2_0_rx.zig").JsonRpc2_0Rx;

// Response models used by protocol helpers.
pub const ContractManifest = @import("response/contract_manifest.zig").ContractManifest;
pub const ContractGroup = @import("response/contract_manifest.zig").ContractGroup;
pub const ContractPermission = @import("response/contract_manifest.zig").ContractPermission;

test "protocol module" {
    std.testing.refAllDecls(@This());
}
