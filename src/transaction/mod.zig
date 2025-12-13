//! Transaction module
//!
//! Complete transaction system converted from Swift implementation.

const std = @import("std");



// Export transaction components
pub const TransactionBuilder = @import("transaction_builder.zig").TransactionBuilder;
pub const Transaction = @import("transaction_builder.zig").Transaction;
pub const Signer = @import("transaction_builder.zig").Signer;
pub const Witness = @import("transaction_builder.zig").Witness;
pub const TransactionAttribute = @import("transaction_builder.zig").TransactionAttribute;
pub const AttributeType = @import("transaction_builder.zig").AttributeType;
pub const WitnessScope = @import("transaction_builder.zig").WitnessScope;
pub const CompleteWitnessScope = @import("witness_scope_complete.zig").CompleteWitnessScope;
pub const WitnessRule = @import("transaction_builder.zig").WitnessRule;
pub const WitnessAction = @import("transaction_builder.zig").WitnessAction;
pub const WitnessCondition = @import("transaction_builder.zig").WitnessCondition;
pub const WitnessContext = @import("witness_rule.zig").WitnessContext;
pub const Account = @import("transaction_builder.zig").Account;
pub const AccountSigner = @import("account_signer.zig").AccountSigner;
pub const NeoTransaction = @import("neo_transaction.zig").NeoTransaction;
pub const InvocationScript = @import("witness.zig").InvocationScript;
pub const VerificationScript = @import("witness.zig").VerificationScript;
pub const WitnessScripts = @import("witness.zig").Witness;

test "transaction module" {
    std.testing.refAllDecls(@This());
}
