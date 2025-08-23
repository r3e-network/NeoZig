//! Wallet module
//!
//! Complete wallet system converted from Swift implementation.

const std = @import("std");

// Export wallet components
pub const Wallet = @import("neo_wallet.zig").Wallet;
pub const Account = @import("neo_wallet.zig").Account;
pub const ScryptParams = @import("neo_wallet.zig").ScryptParams;
pub const ContractInfo = @import("neo_wallet.zig").ContractInfo;
pub const Hash160Context = @import("neo_wallet.zig").Hash160Context;

test "wallet module" {
    std.testing.refAllDecls(@This());
}