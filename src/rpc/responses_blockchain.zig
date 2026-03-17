const std = @import("std");

pub const block = @import("responses_blockchain_block.zig");
pub const transaction = @import("responses_blockchain_transaction.zig");
pub const network = @import("responses_blockchain_network.zig");

pub const NeoBlock = block.NeoBlock;
pub const NeoWitness = transaction.NeoWitness;
pub const Transaction = transaction.Transaction;
pub const TransactionSigner = transaction.TransactionSigner;
pub const WitnessRule = transaction.WitnessRule;
pub const WitnessCondition = transaction.WitnessCondition;
pub const NeoVersion = network.NeoVersion;
pub const HardforkInfo = network.HardforkInfo;
pub const ProtocolConfiguration = network.ProtocolConfiguration;
pub const NetworkFeeResponse = network.NetworkFeeResponse;
pub const SendRawTransactionResponse = network.SendRawTransactionResponse;

test "blockchain responses module exposes submodule namespaces" {
    const testing = std.testing;

    try testing.expect(block.NeoBlock == NeoBlock);
    try testing.expect(transaction.Transaction == Transaction);
    try testing.expect(network.NeoVersion == NeoVersion);
}
