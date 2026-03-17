//! Transaction module
//!
//! Complete transaction system.

const std = @import("std");

pub const builder = @import("builder_namespace.zig");
pub const witnesses = @import("witness_namespace.zig");
pub const signers = @import("signer_namespace.zig");
pub const broadcast = @import("broadcast_namespace.zig");

// Export transaction components
pub const TransactionBuilder = builder.TransactionBuilder;
pub const Transaction = builder.Transaction;
pub const Signer = builder.Signer;
pub const TransactionAttribute = builder.TransactionAttribute;
pub const AttributeType = builder.AttributeType;
pub const WitnessScope = builder.WitnessScope;
pub const Account = builder.Account;
pub const TransactionWitness = witnesses.TransactionWitness;
pub const ScriptWitness = witnesses.ScriptWitness;
pub const Witness = TransactionWitness;
pub const CompleteWitness = witnesses.CompleteWitness;
pub const InvocationScript = witnesses.InvocationScript;
pub const VerificationScript = witnesses.VerificationScript;
pub const WitnessScripts = witnesses.WitnessScripts;
pub const WitnessScopeSet = witnesses.WitnessScopeSet;
pub const CompleteWitnessScope = witnesses.CompleteWitnessScope;
pub const WitnessRule = witnesses.WitnessRule;
pub const WitnessAction = witnesses.WitnessAction;
pub const WitnessCondition = witnesses.WitnessCondition;
pub const WitnessContext = witnesses.WitnessContext;
pub const AccountSigner = signers.AccountSigner;
pub const ContractSigner = signers.ContractSigner;
pub const ContractVerificationContext = signers.ContractVerificationContext;
pub const ContractSignerFactory = signers.ContractSignerFactory;
pub const TokenOperation = signers.TokenOperation;
pub const NeoTransaction = broadcast.NeoTransaction;
pub const TransactionBroadcaster = broadcast.TransactionBroadcaster;
pub const TransactionFees = broadcast.TransactionFees;
pub const TransactionFeesFormatted = broadcast.TransactionFeesFormatted;
pub const TransactionStatus = broadcast.TransactionStatus;
pub const BroadcastUtils = broadcast.BroadcastUtils;

test "transaction module" {
    std.testing.refAllDecls(@This());
}

test "transaction module exposes canonical witness aliases" {
    const testing = std.testing;

    try testing.expect(TransactionWitness == Witness);
    try testing.expect(ScriptWitness == CompleteWitness);
    try testing.expect(ScriptWitness == WitnessScripts);
    try testing.expect(WitnessScopeSet == CompleteWitnessScope);
}
