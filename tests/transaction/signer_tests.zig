//! Signer tests
//!
//! This file validates the currently-exposed transaction signer APIs.

const std = @import("std");
const neo = @import("neo-zig");

const testing = std.testing;

test "Signer validates scope payload requirements" {
    // CustomContracts requires at least one allowed contract.
    var signer_contracts = neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CustomContracts);
    try testing.expectError(neo.errors.TransactionError.InvalidSigner, signer_contracts.validate());

    var allowed_contracts = [_]neo.Hash160{
        try neo.Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678"),
    };
    signer_contracts.allowed_contracts = allowed_contracts[0..];
    try signer_contracts.validate();

    // CustomGroups requires at least one allowed group.
    var signer_groups = neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CustomGroups);
    try testing.expectError(neo.errors.TransactionError.InvalidSigner, signer_groups.validate());

    var group: [33]u8 = [_]u8{0} ** 33;
    group[0] = 0x02; // compressed key prefix (not a full validation here)
    var allowed_groups = [_][33]u8{group};
    signer_groups.allowed_groups = allowed_groups[0..];
    try signer_groups.validate();

    // WitnessRules requires at least one rule.
    var signer_rules = neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.WitnessRules);
    try testing.expectError(neo.errors.TransactionError.InvalidSigner, signer_rules.validate());

    var rules = [_]neo.transaction.WitnessRule{
        neo.transaction.WitnessRule.init(.Allow, neo.transaction.WitnessCondition.boolean(true)),
    };
    signer_rules.rules = rules[0..];
    try signer_rules.validate();
}

test "Signer serialize/deserialize roundtrip can deinit owned memory" {
    const allocator = testing.allocator;

    const signer_hash = try neo.Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    var contracts = [_]neo.Hash160{
        try neo.Hash160.initWithString("0xabcdef1234567890abcdef1234567890abcdef12"),
        try neo.Hash160.initWithString("0x9876543210fedcba9876543210fedcba98765432"),
    };

    var signer = neo.transaction.Signer.init(signer_hash, neo.transaction.WitnessScope.CustomContracts);
    signer.allowed_contracts = contracts[0..];

    var writer = neo.BinaryWriter.init(allocator);
    defer writer.deinit();
    try signer.serialize(&writer);

    var reader = neo.BinaryReader.init(writer.toSlice());
    var decoded = try neo.transaction.Signer.deserialize(&reader, allocator);
    defer decoded.deinit(allocator);

    try decoded.validate();
    try testing.expect(decoded.signer_hash.eql(signer_hash));
    try testing.expectEqual(neo.transaction.WitnessScope.CustomContracts, decoded.scopes);
    try testing.expectEqual(@as(usize, 2), decoded.allowed_contracts.len);
    try testing.expect(decoded.allowed_contracts[0].eql(contracts[0]));
    try testing.expect(decoded.allowed_contracts[1].eql(contracts[1]));
}

test "AccountSigner produces consistent base signer" {
    const allocator = testing.allocator;

    const private_key = neo.crypto.PrivateKey.generate();
    const account = try neo.transaction.Account.initWithPrivateKey(private_key, true, allocator);

    const entry_signer = try neo.transaction.AccountSigner.calledByEntry(account);
    try entry_signer.validate();
    try testing.expectEqual(neo.transaction.WitnessScope.CalledByEntry, entry_signer.getWitnessScope());
    try testing.expect(entry_signer.getScriptHash().eql(account.getScriptHash()));

    const global_signer = try neo.transaction.AccountSigner.global(account);
    try global_signer.validate();
    try testing.expectEqual(neo.transaction.WitnessScope.Global, global_signer.getWitnessScope());
    try testing.expect(global_signer.getScriptHash().eql(account.getScriptHash()));

    var allowed_contracts = [_]neo.Hash160{
        try neo.Hash160.initWithString("0xabcdef1234567890abcdef1234567890abcdef12"),
    };
    const custom_contracts = try neo.transaction.AccountSigner.customContracts(account, allowed_contracts[0..]);
    try custom_contracts.validate();
    try testing.expectEqual(neo.transaction.WitnessScope.CustomContracts, custom_contracts.getWitnessScope());
    try testing.expectEqual(@as(usize, 1), custom_contracts.getSigner().allowed_contracts.len);

    const pub_key = try account.getPublicKey();
    var group: [33]u8 = undefined;
    @memcpy(&group, pub_key.toSlice());
    var allowed_groups = [_][33]u8{group};
    const custom_groups = try neo.transaction.AccountSigner.customGroups(account, allowed_groups[0..]);
    try custom_groups.validate();
    try testing.expectEqual(neo.transaction.WitnessScope.CustomGroups, custom_groups.getWitnessScope());
    try testing.expectEqual(@as(usize, 1), custom_groups.getSigner().allowed_groups.len);
}
