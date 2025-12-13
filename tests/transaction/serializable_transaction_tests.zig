//! Serializable Transaction Tests
//!
//! Complete conversion from NeoSwift SerializableTransactionTest.swift
//! Tests transaction serialization and deserialization.

const std = @import("std");


const testing = std.testing;
const neo = @import("neo-zig");
const NeoTransaction = neo.transaction.NeoTransaction;

test "Transaction serialization roundtrip" {
    const allocator = testing.allocator;
    
    const signers = [_]neo.transaction.Signer{
        neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CalledByEntry),
    };
    const attributes = [_]neo.transaction.TransactionAttribute{};
    const script = [_]u8{ 0x10, 0x11, 0x40 };
    var witnesses = [_]neo.transaction.Witness{
        neo.transaction.Witness.init(&[_]u8{}, &[_]u8{}),
    };

    const transaction = NeoTransaction.init(
        null,
        0,
        12345,
        1000,
        &signers,
        100000,
        50000,
        &attributes,
        &script,
        &witnesses,
        null,
    );

    const serialized = try transaction.serialize(allocator);
    defer allocator.free(serialized);

    var deserialized = try NeoTransaction.deserialize(serialized, allocator);
    defer deserialized.deinit(allocator);

    try testing.expectEqual(transaction.version, deserialized.version);
    try testing.expectEqual(transaction.nonce, deserialized.nonce);
    try testing.expectEqual(transaction.system_fee, deserialized.system_fee);
    try testing.expectEqual(transaction.network_fee, deserialized.network_fee);
    try testing.expectEqual(transaction.valid_until_block, deserialized.valid_until_block);
    try testing.expectEqualSlices(u8, transaction.script, deserialized.script);
}
