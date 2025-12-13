//! Transaction tests converted from Swift
//!
//! Complete conversion of NeoSwift transaction test suite.

const std = @import("std");


const neo = @import("neo-zig");

// Tests transaction builder (converted from Swift TransactionBuilderTests)
test "transaction builder creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();
    
    // Test version setting (matches Swift test)
    _ = builder.version(1);
    try testing.expectEqual(@as(u8, 1), builder.version_field);
    
    // Test nonce setting (matches Swift test)
    _ = try builder.nonce(12345);
    try testing.expectEqual(@as(u32, 12345), builder.nonce_field);
    
    // Test valid until block
    _ = try builder.validUntilBlock(1000000);
    try testing.expectEqual(@as(u32, 1000000), builder.valid_until_block_field.?);
    
    // Test additional fees
    _ = builder.additionalNetworkFee(500000);
    try testing.expectEqual(@as(u64, 500000), builder.additional_network_fee);
    
    _ = builder.additionalSystemFee(1000000);
    try testing.expectEqual(@as(u64, 1000000), builder.additional_system_fee);
}

// Tests signer management (converted from Swift signer tests)
test "transaction builder signer management" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();
    
    // Create test signer (matches Swift Signer creation)
    const test_signer = neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CalledByEntry);
    
    // Add signer (equivalent to Swift signer(_ signer: Signer))
    _ = try builder.signer(test_signer);
    
    const signers = builder.getSigners();
    try testing.expectEqual(@as(usize, 1), signers.len);
    try testing.expect(signers[0].signer_hash.eql(neo.Hash160.ZERO));
    try testing.expectEqual(neo.transaction.WitnessScope.CalledByEntry, signers[0].scopes);
}

// Tests token transfer (converted from Swift token transfer tests)
test "transaction builder token transfer" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();
    
    // Build GAS token transfer (matches Swift transferToken functionality)
    const amount: u64 = 100000000; // 1 GAS (8 decimals)
    _ = try builder.transferToken(
        neo.transaction.TransactionBuilder.GAS_TOKEN_HASH,
        neo.Hash160.ZERO, // from
        neo.Hash160.ZERO, // to
        amount,
    );
    
    // Verify script was created (equivalent to Swift script validation)
    const script = builder.getScript();
    try testing.expect(script != null);
    try testing.expect(script.?.len > 0);
    
    // Script should contain contract call elements
    try testing.expect(std.mem.indexOf(u8, script.?, &[_]u8{0x41}) != null); // SYSCALL opcode

    // Verify full script matches ScriptBuilder output.
    const params = [_]neo.ContractParameter{
        neo.ContractParameter.hash160(neo.Hash160.ZERO),
        neo.ContractParameter.hash160(neo.Hash160.ZERO),
        neo.ContractParameter.integer(@intCast(amount)),
    };
    var expected = neo.script.ScriptBuilder.init(allocator);
    defer expected.deinit();
    _ = try expected.contractCall(neo.transaction.TransactionBuilder.GAS_TOKEN_HASH, "transfer", &params, null);
    try testing.expectEqualSlices(u8, expected.toScript(), script.?);
}

// Tests contract function invocation (converted from Swift contract tests)
test "transaction builder contract invocation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();
    
    // Create test parameters (matches Swift ContractParameter creation)
    const params = [_]neo.ContractParameter{
        neo.ContractParameter.string("test_parameter"),
        neo.ContractParameter.integer(42),
        neo.ContractParameter.boolean(true),
    };
    
    // Invoke function (equivalent to Swift invokeFunction)
    _ = try builder.invokeFunction(neo.Hash160.ZERO, "testMethod", &params);
    
    const script = builder.getScript();
    try testing.expect(script != null);
    try testing.expect(script.?.len > 0);

    // Verify full script matches ScriptBuilder output.
    var expected = neo.script.ScriptBuilder.init(allocator);
    defer expected.deinit();
    _ = try expected.contractCall(neo.Hash160.ZERO, "testMethod", &params, null);
    try testing.expectEqualSlices(u8, expected.toScript(), script.?);
}

test "transaction hash matches NeoTransaction with attributes" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();

    const signer = neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CalledByEntry);
    _ = try builder.signer(signer);
    _ = try builder.script(&[_]u8{0x51});
    _ = try builder.highPriority();

    const transaction = try builder.build();
    defer {
        allocator.free(transaction.signers);
        allocator.free(transaction.attributes);
        allocator.free(transaction.script);
        allocator.free(transaction.witnesses);
    }

    const tx_hash = try transaction.getHash(allocator);

    const neo_transaction = neo.transaction.NeoTransaction.init(
        null,
        transaction.version,
        transaction.nonce,
        transaction.valid_until_block,
        transaction.signers,
        transaction.system_fee,
        transaction.network_fee,
        transaction.attributes,
        transaction.script,
        transaction.witnesses,
        null,
    );
    const neo_hash = try neo_transaction.getHash(allocator);
    try testing.expect(tx_hash.eql(neo_hash));
}

comptime {
    // Additional transaction-focused tests live under `tests/transaction/`.
    _ = @import("transaction/witness_scope_tests.zig");
    _ = @import("transaction/serializable_transaction_tests.zig");
    _ = @import("transaction/witness_tests.zig");
    _ = @import("transaction/signer_tests.zig");
    _ = @import("transaction/transaction_builder_tests.zig");
}

// Tests transaction building (converted from Swift build tests)
test "transaction builder complete workflow" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();
    
    // Configure transaction (matches Swift configuration)
    _ = builder.version(0)
        .additionalNetworkFee(500000)
        .additionalSystemFee(1000000);
    
    // Add signer
    const signer = neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CalledByEntry);
    _ = try builder.signer(signer);
    
    // Add script
    _ = try builder.script(&[_]u8{ 0x41, 0x56, 0xE7, 0xB3, 0x27 }); // SYSCALL CheckSig
    
    // Build transaction (equivalent to Swift build())
    const transaction = try builder.build();
    defer {
        allocator.free(transaction.signers);
        allocator.free(transaction.attributes);
        allocator.free(transaction.script);
        allocator.free(transaction.witnesses);
    }
    
    // Validate transaction (equivalent to Swift validation)
    try transaction.validate();
    
    // Test transaction properties
    try testing.expectEqual(@as(u8, 0), transaction.version);
    try testing.expectEqual(@as(u64, 1000000), transaction.system_fee);
    try testing.expectEqual(@as(u64, 500000), transaction.network_fee);
    try testing.expectEqual(@as(usize, 1), transaction.signers.len);
    
    // Test transaction hash calculation (equivalent to Swift getHash)
    const tx_hash = try transaction.getHash(allocator);
    try testing.expect(!tx_hash.eql(neo.Hash256.ZERO));
}

// Tests high priority attribute (converted from Swift attribute tests)
test "transaction builder high priority attribute" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();
    
    // Add high priority (equivalent to Swift highPriority())
    _ = try builder.highPriority();
    
    // Check if high priority is set (equivalent to Swift isHighPriority)
    try testing.expect(builder.isHighPriority());
}

// Tests witness scope validation (converted from Swift witness tests)
test "witness scope validation" {
    const testing = std.testing;
    
    // Test witness scope values (matches Swift WitnessScope enum)
    try testing.expectEqual(@as(u8, 0x00), @intFromEnum(neo.transaction.WitnessScope.None));
    try testing.expectEqual(@as(u8, 0x01), @intFromEnum(neo.transaction.WitnessScope.CalledByEntry));
    try testing.expectEqual(@as(u8, 0x10), @intFromEnum(neo.transaction.WitnessScope.CustomContracts));
    try testing.expectEqual(@as(u8, 0x20), @intFromEnum(neo.transaction.WitnessScope.CustomGroups));
    try testing.expectEqual(@as(u8, 0x40), @intFromEnum(neo.transaction.WitnessScope.WitnessRules));
    try testing.expectEqual(@as(u8, 0x80), @intFromEnum(neo.transaction.WitnessScope.Global));
}
