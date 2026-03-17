//! Wallet module
//!
//! Complete wallet system.

const std = @import("std");

pub const accounts = @import("account_namespace.zig");
pub const nep6 = @import("nep6_namespace.zig");
pub const support = @import("support_namespace.zig");

// Export wallet components
pub const Wallet = accounts.Wallet;
pub const StoredAccount = accounts.StoredAccount;
pub const SignerAccount = accounts.SignerAccount;
pub const WalletAccount = StoredAccount;
pub const Account = SignerAccount;
pub const Bip39Account = accounts.Bip39Account;
pub const VerificationScript = accounts.VerificationScript;
pub const validateMnemonic = accounts.validateMnemonic;
pub const NEP6Wallet = nep6.NEP6Wallet;
pub const NEP6Account = nep6.NEP6Account;
pub const NEP6Contract = nep6.NEP6Contract;
pub const CompleteNEP6Wallet = nep6.CompleteNEP6Wallet;
pub const ScryptParams = support.ScryptParams;
pub const ContractInfo = support.ContractInfo;
pub const Hash160Context = support.Hash160Context;
pub const WalletError = support.WalletError;

test "wallet module" {
    std.testing.refAllDecls(@This());
}

test "wallet module exposes canonical account aliases" {
    const testing = std.testing;

    try testing.expect(StoredAccount == WalletAccount);
    try testing.expect(SignerAccount == Account);
}
