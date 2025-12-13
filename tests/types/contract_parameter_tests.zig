//! Contract Parameter Tests
//!
//! Updated for the current `neo.types.ContractParameter` value-type API.

const std = @import("std");

const testing = std.testing;
const neo = @import("neo-zig");

const ContractParameter = neo.types.ContractParameter;
const ContractParameterType = neo.types.ContractParameterType;

test "ContractParameter type tags and equality" {
    const bytes_a = [_]u8{ 0x01, 0x02, 0x03 };
    const bytes_b = [_]u8{ 0x01, 0x02, 0x03 };
    const bytes_c = [_]u8{ 0x01, 0x02, 0x04 };

    try testing.expectEqual(ContractParameterType.Boolean, ContractParameter.boolean(true).getType());
    try testing.expectEqual(ContractParameterType.Integer, ContractParameter.integer(42).getType());
    try testing.expectEqual(ContractParameterType.ByteArray, ContractParameter.byteArray(&bytes_a).getType());
    try testing.expectEqual(ContractParameterType.String, ContractParameter.string("hello").getType());
    try testing.expectEqual(ContractParameterType.Hash160, ContractParameter.hash160(neo.Hash160.ZERO).getType());
    try testing.expectEqual(ContractParameterType.Hash256, ContractParameter.hash256(neo.Hash256.ZERO).getType());

    try testing.expect(ContractParameter.boolean(true).eql(ContractParameter.boolean(true)));
    try testing.expect(!ContractParameter.boolean(true).eql(ContractParameter.boolean(false)));

    try testing.expect(ContractParameter.integer(123).eql(ContractParameter.integer(123)));
    try testing.expect(!ContractParameter.integer(123).eql(ContractParameter.integer(124)));

    try testing.expect(ContractParameter.byteArray(&bytes_a).eql(ContractParameter.byteArray(&bytes_b)));
    try testing.expect(!ContractParameter.byteArray(&bytes_a).eql(ContractParameter.byteArray(&bytes_c)));

    try testing.expect(ContractParameter.string("neo").eql(ContractParameter.string("neo")));
    try testing.expect(!ContractParameter.string("neo").eql(ContractParameter.string("zig")));
}

test "ContractParameter public key validation" {
    const valid_pubkey = [_]u8{0x02} ++ [_]u8{0xAB} ** 32;
    try ContractParameter.publicKey(&valid_pubkey).validate();

    var invalid_pubkey = valid_pubkey;
    invalid_pubkey[0] = 0x04;
    try testing.expectError(
        neo.ValidationError.InvalidParameter,
        ContractParameter.publicKey(&invalid_pubkey).validate(),
    );
}

test "ContractParameter public key and signature length checks" {
    const too_short_pubkey = [_]u8{0x02} ++ [_]u8{0xAB} ** 31;
    try testing.expectError(
        neo.ValidationError.InvalidLength,
        ContractParameter.publicKeyChecked(&too_short_pubkey),
    );

    const valid_sig = [_]u8{0xAA} ** neo.constants.SIGNATURE_SIZE;
    _ = try ContractParameter.signatureChecked(&valid_sig);

    const too_short_sig = [_]u8{0xAA} ** (neo.constants.SIGNATURE_SIZE - 1);
    try testing.expectError(
        neo.ValidationError.InvalidLength,
        ContractParameter.signatureChecked(&too_short_sig),
    );
}

test "ContractParameter array equality" {
    const a_items = [_]ContractParameter{
        ContractParameter.integer(1),
        ContractParameter.boolean(true),
        ContractParameter.string("hello"),
    };
    const b_items = [_]ContractParameter{
        ContractParameter.integer(1),
        ContractParameter.boolean(true),
        ContractParameter.string("hello"),
    };
    const c_items = [_]ContractParameter{
        ContractParameter.integer(1),
        ContractParameter.boolean(false),
        ContractParameter.string("hello"),
    };

    const a = ContractParameter.array(&a_items);
    const b = ContractParameter.array(&b_items);
    const c = ContractParameter.array(&c_items);

    try testing.expect(a.eql(b));
    try testing.expect(!a.eql(c));
}

test "ContractParameter JSON encoding" {
    const allocator = testing.allocator;

    const param = ContractParameter.integer(42);
    const json_value = try param.toJsonValue(allocator);
    defer neo.utils.json_utils.freeValue(json_value, allocator);

    try testing.expect(json_value == .object);
    const obj = json_value.object;

    try testing.expectEqualStrings("Integer", obj.get("type").?.string);
    try testing.expectEqualStrings("42", obj.get("value").?.string);
}
