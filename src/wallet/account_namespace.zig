pub const Wallet = @import("neo_wallet.zig").Wallet;
pub const StoredAccount = @import("neo_wallet.zig").Account;
pub const SignerAccount = @import("account.zig").Account;
pub const WalletAccount = StoredAccount;
pub const Account = SignerAccount;
pub const Bip39Account = @import("bip39_account.zig").Bip39Account;
pub const VerificationScript = @import("verification_script.zig").VerificationScript;
pub const validateMnemonic = @import("bip39_account.zig").validateMnemonic;
