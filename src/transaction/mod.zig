//! Transaction module — transaction building, signing, and broadcasting.

const std = @import("std");

pub const TransactionBuilder = @import("transaction_builder.zig").TransactionBuilder;
pub const Transaction = @import("transaction_builder.zig").Transaction;
pub const Signer = @import("transaction_builder.zig").Signer;
pub const TransactionAttribute = @import("transaction_builder.zig").TransactionAttribute;
pub const AttributeType = @import("transaction_builder.zig").AttributeType;
pub const WitnessScope = @import("transaction_builder.zig").WitnessScope;
pub const Account = @import("transaction_builder.zig").Account;

pub const TransactionWitness = @import("transaction_builder.zig").Witness;
pub const ScriptWitness = @import("witness.zig").Witness;
pub const Witness = TransactionWitness;
pub const CompleteWitness = ScriptWitness;
pub const InvocationScript = @import("witness.zig").InvocationScript;
pub const VerificationScript = @import("witness.zig").VerificationScript;
pub const WitnessScripts = ScriptWitness;
pub const WitnessScopeSet = @import("witness_scope.zig").CompleteWitnessScope;
pub const CompleteWitnessScope = @import("witness_scope.zig").CompleteWitnessScope;
pub const WitnessRule = @import("transaction_builder.zig").WitnessRule;
pub const WitnessAction = @import("transaction_builder.zig").WitnessAction;
pub const WitnessCondition = @import("transaction_builder.zig").WitnessCondition;
pub const WitnessContext = @import("witness_rule.zig").WitnessContext;

pub const AccountSigner = @import("account_signer.zig").AccountSigner;
pub const ContractSigner = @import("contract_signer.zig").ContractSigner;
pub const ContractVerificationContext = @import("contract_signer.zig").ContractVerificationContext;
pub const ContractSignerFactory = @import("contract_signer.zig").ContractSignerFactory;
pub const TokenOperation = @import("contract_signer.zig").TokenOperation;

pub const NeoTransaction = @import("neo_transaction.zig").NeoTransaction;
pub const TransactionBroadcaster = @import("transaction_broadcast.zig").TransactionBroadcaster;
pub const TransactionFees = @import("transaction_broadcast.zig").TransactionFees;
pub const TransactionFeesFormatted = @import("transaction_broadcast.zig").TransactionFeesFormatted;
pub const TransactionStatus = @import("transaction_broadcast.zig").TransactionStatus;
pub const BroadcastUtils = @import("transaction_broadcast.zig").BroadcastUtils;

test "transaction module" {
    std.testing.refAllDecls(@This());
}
