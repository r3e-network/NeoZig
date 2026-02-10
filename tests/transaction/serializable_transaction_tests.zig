//! Serializable Transaction Tests
//!
//! Serializable transaction tests
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

test "Transaction serialization roundtrip with extended attributes" {
    const allocator = testing.allocator;

    const signers = [_]neo.transaction.Signer{
        neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CalledByEntry),
    };

    const height_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, 42));
    const conflict_hash = try neo.Hash256.initWithString("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const conflict_bytes = conflict_hash.toLittleEndianArray();
    const notary_bytes = [_]u8{2};

    const attributes = [_]neo.transaction.TransactionAttribute{
        neo.transaction.TransactionAttribute.init(.NotValidBefore, height_bytes[0..]),
        neo.transaction.TransactionAttribute.init(.Conflicts, conflict_bytes[0..]),
        neo.transaction.TransactionAttribute.init(.NotaryAssisted, notary_bytes[0..]),
    };
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

    try testing.expectEqual(@as(usize, 3), deserialized.attributes.len);
    try testing.expectEqual(neo.transaction.AttributeType.NotValidBefore, deserialized.attributes[0].attribute_type);
    try testing.expectEqualSlices(u8, height_bytes[0..], deserialized.attributes[0].data);
    try testing.expectEqual(neo.transaction.AttributeType.Conflicts, deserialized.attributes[1].attribute_type);
    try testing.expectEqualSlices(u8, conflict_bytes[0..], deserialized.attributes[1].data);
    try testing.expectEqual(neo.transaction.AttributeType.NotaryAssisted, deserialized.attributes[2].attribute_type);
    try testing.expectEqualSlices(u8, notary_bytes[0..], deserialized.attributes[2].data);
}
