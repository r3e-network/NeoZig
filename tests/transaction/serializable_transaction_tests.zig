//! Serializable Transaction Tests
//!
//! Complete conversion from NeoSwift SerializableTransactionTest.swift
//! Tests transaction serialization and deserialization.

const std = @import("std");
const testing = std.testing;
const NeoTransaction = @import("../../src/transaction/neo_transaction.zig").NeoTransaction;
const BinaryWriter = @import("../../src/serialization/binary_writer_complete.zig").CompleteBinaryWriter;
const BinaryReader = @import("../../src/serialization/binary_reader_complete.zig").CompleteBinaryReader;

test "Transaction serialization roundtrip" {
    const allocator = testing.allocator;
    
    // Create test transaction
    var transaction = try NeoTransaction.init(allocator);
    defer transaction.deinit(allocator);
    
    transaction.version = 0;
    transaction.nonce = 12345;
    transaction.system_fee = 100000;
    transaction.network_fee = 50000;
    transaction.valid_until_block = 1000;
    
    const test_script = [_]u8{ 0x10, 0x11, 0x40 };
    try transaction.setScript(&test_script, allocator);
    
    // Serialize transaction
    var writer = BinaryWriter.init(allocator);
    defer writer.deinit();
    
    try transaction.serialize(&writer);
    const serialized_data = writer.toArray();
    
    try testing.expect(serialized_data.len > 0);
    
    // Deserialize transaction
    var reader = BinaryReader.init(serialized_data);
    var deserialized_tx = try NeoTransaction.deserialize(&reader, allocator);
    defer deserialized_tx.deinit(allocator);
    
    // Verify roundtrip
    try testing.expectEqual(transaction.version, deserialized_tx.version);
    try testing.expectEqual(transaction.nonce, deserialized_tx.nonce);
    try testing.expectEqual(transaction.system_fee, deserialized_tx.system_fee);
    try testing.expectEqual(transaction.network_fee, deserialized_tx.network_fee);
    try testing.expectEqual(transaction.valid_until_block, deserialized_tx.valid_until_block);
}