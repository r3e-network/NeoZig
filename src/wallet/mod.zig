//! Wallet module
//!
//! Complete wallet system.

const std = @import("std");

// Export wallet components
pub const Wallet = @import("neo_wallet.zig").Wallet;
// WalletAccount is the NEP-6 wallet entry managed by Wallet.
pub const WalletAccount = @import("neo_wallet.zig").Account;
pub const Account = @import("account.zig").Account;
pub const ScryptParams = @import("neo_wallet.zig").ScryptParams;
pub const ContractInfo = @import("neo_wallet.zig").ContractInfo;
pub const Hash160Context = @import("neo_wallet.zig").Hash160Context;
pub const Bip39Account = @import("bip39_account.zig").Bip39Account;
pub const validateMnemonic = @import("bip39_account.zig").validateMnemonic;
pub const NEP6Wallet = @import("nep6_wallet.zig").NEP6Wallet;
pub const NEP6Account = @import("nep6_wallet.zig").NEP6Account;
pub const NEP6Contract = @import("nep6_wallet.zig").NEP6Contract;
pub const CompleteNEP6Wallet = @import("nep6_extended.zig").CompleteNEP6Wallet;

test "wallet module" {
    std.testing.refAllDecls(@This());
}
