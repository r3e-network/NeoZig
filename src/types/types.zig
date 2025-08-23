//! Core Neo types module
//!
//! Exports all Neo blockchain types with Swift API compatibility.

const std = @import("std");

pub const Hash160 = @import("hash160.zig").Hash160;
pub const Hash256 = @import("hash256.zig").Hash256;
pub const Address = @import("address.zig").Address;
pub const ContractParameter = @import("contract_parameter.zig").ContractParameter;
pub const ContractParameterType = @import("contract_parameter.zig").ContractParameterType;
pub const CallFlags = @import("call_flags.zig").CallFlags;

test "types module" {
    std.testing.refAllDecls(@This());
}