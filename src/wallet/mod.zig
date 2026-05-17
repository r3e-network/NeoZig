//! Wallet module — NEP-6 wallets, accounts, BIP-39 mnemonics.

const std = @import("std");

pub const Wallet = @import("neo_wallet.zig").Wallet;
pub const StoredAccount = @import("neo_wallet.zig").Account;
pub const SignerAccount = @import("account.zig").Account;
pub const WalletAccount = StoredAccount;
pub const Account = SignerAccount;
pub const Bip39Account = @import("bip39_account.zig").Bip39Account;
pub const VerificationScript = @import("verification_script.zig").VerificationScript;
pub const validateMnemonic = @import("bip39_account.zig").validateMnemonic;

pub const NEP6Wallet = @import("nep6_wallet.zig").NEP6Wallet;
pub const NEP6Account = @import("nep6_wallet.zig").NEP6Account;
pub const NEP6Contract = @import("nep6_wallet.zig").NEP6Contract;
pub const CompleteNEP6Wallet = @import("nep6_extended.zig").CompleteNEP6Wallet;

pub const ScryptParams = @import("neo_wallet.zig").ScryptParams;
pub const ContractInfo = @import("neo_wallet.zig").ContractInfo;
pub const Hash160Context = @import("neo_wallet.zig").Hash160Context;
pub const WalletError = @import("wallet_error.zig").WalletError;

test "wallet module" {
    std.testing.refAllDecls(@This());
}
