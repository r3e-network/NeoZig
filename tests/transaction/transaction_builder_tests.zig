//! TransactionBuilder tests
//!
//! Focused coverage for the currently-exposed transaction builder and signing APIs.

const std = @import("std");
const neo = @import("neo-zig");

const testing = std.testing;

test "TransactionBuilder firstSigner reorders signers" {
    const allocator = testing.allocator;

    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();

    const signer_a = neo.transaction.Signer.init(neo.Hash160.ZERO, neo.transaction.WitnessScope.CalledByEntry);
    const signer_b = neo.transaction.Signer.init(
        try neo.Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678"),
        neo.transaction.WitnessScope.CalledByEntry,
    );

    _ = try builder.signers(&[_]neo.transaction.Signer{ signer_a, signer_b });
    try testing.expectEqual(@as(usize, 2), builder.getSigners().len);

    _ = try builder.firstSigner(signer_b.signer_hash);
    try testing.expect(builder.getSigners()[0].signer_hash.eql(signer_b.signer_hash));
}

test "TransactionBuilder.sign creates witness scripts" {
    const allocator = testing.allocator;

    var builder = neo.transaction.TransactionBuilder.init(allocator);
    defer builder.deinit();

    const private_key = neo.crypto.PrivateKey.generate();
    const account = try neo.transaction.Account.initWithPrivateKey(private_key, true, allocator);

    _ = try builder.validUntilBlock(1234);
    _ = try builder.signer(neo.transaction.Signer.init(account.getScriptHash(), neo.transaction.WitnessScope.CalledByEntry));
    _ = try builder.script(&[_]u8{ 0x01, 0x02, 0x03 });

    var tx = try builder.sign(&[_]neo.transaction.Account{account}, 5195086);
    defer tx.deinit(allocator);

    try tx.validate();
    try testing.expectEqual(@as(usize, 1), tx.signers.len);
    try testing.expectEqual(@as(usize, 1), tx.witnesses.len);

    const witness = tx.witnesses[0];
    try testing.expectEqual(@as(usize, 66), witness.invocation_script.len);
    try testing.expectEqual(@as(u8, 0x0C), witness.invocation_script[0]); // PUSHDATA1
    try testing.expectEqual(@as(u8, 64), witness.invocation_script[1]); // signature length

    const expected_pub = try private_key.getPublicKey(true);
    const expected_verification = try neo.script.ScriptBuilder.buildVerificationScript(expected_pub.toSlice(), allocator);
    defer allocator.free(expected_verification);
    try testing.expectEqualSlices(u8, expected_verification, witness.verification_script);
}

test "TransactionBuilder.sign rejects signer/account mismatches" {
    const allocator = testing.allocator;

    const private_key_a = neo.crypto.PrivateKey.generate();
    const account_a = try neo.transaction.Account.initWithPrivateKey(private_key_a, true, allocator);
    const private_key_b = neo.crypto.PrivateKey.generate();
    const account_b = try neo.transaction.Account.initWithPrivateKey(private_key_b, true, allocator);

    {
        var builder = neo.transaction.TransactionBuilder.init(allocator);
        defer builder.deinit();

        _ = try builder.signer(neo.transaction.Signer.init(account_a.getScriptHash(), neo.transaction.WitnessScope.CalledByEntry));
        _ = try builder.script(&[_]u8{0x01});

        try testing.expectError(neo.errors.TransactionError.InvalidSigner, builder.sign(&[_]neo.transaction.Account{account_b}, 1));
    }

    {
        var builder = neo.transaction.TransactionBuilder.init(allocator);
        defer builder.deinit();

        _ = try builder.signer(neo.transaction.Signer.init(account_a.getScriptHash(), neo.transaction.WitnessScope.CalledByEntry));
        _ = try builder.script(&[_]u8{0x01});

        try testing.expectError(neo.errors.TransactionError.InvalidSigner, builder.sign(&[_]neo.transaction.Account{}, 1));
    }
}
