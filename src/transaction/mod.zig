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
pub const WitnessRule = @import("transaction_builder.zig").WitnessRule;
pub const WitnessAction = @import("transaction_builder.zig").WitnessAction;
pub const WitnessCondition = @import("transaction_builder.zig").WitnessCondition;
pub const Account = @import("transaction_builder.zig").Account;

test "transaction module" {
    std.testing.refAllDecls(@This());
}