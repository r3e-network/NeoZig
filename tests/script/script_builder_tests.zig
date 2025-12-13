//! Script Builder Tests
//!
//! Complete conversion from NeoSwift ScriptBuilderTests.swift
//! Tests script building, opcode generation, and parameter handling.

const std = @import("std");

const testing = std.testing;
const neo = @import("neo-zig");
const ScriptBuilder = neo.script.ScriptBuilder;
const OpCode = neo.script.OpCode;
const ContractParameter = neo.types.ContractParameter;
const Hash160 = neo.Hash160;
const InteropService = neo.script.InteropService;

/// Helper function to create byte arrays (equivalent to Swift byteArray helper)
fn createByteArray(size: usize, allocator: std.mem.Allocator) ![]u8 {
    const result = try allocator.alloc(u8, size);
    for (result, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }
    return result;
}

/// Helper function to verify script builder output (equivalent to Swift assertBuilder)
fn assertBuilderBytes(builder: *ScriptBuilder, expected: []const u8) !void {
    const script = builder.toScript();
    
    if (expected.len <= script.len) {
        try testing.expectEqualSlices(u8, expected, script[0..expected.len]);
    } else {
        try testing.expectEqualSlices(u8, expected, script);
    }
}

fn assertBuilderLastBytes(builder: *ScriptBuilder, expected: []const u8, total_length: usize) !void {
    const script = builder.toScript();
    try testing.expectEqual(total_length, script.len);
    
    const start_idx = script.len - expected.len;
    try testing.expectEqualSlices(u8, expected, script[start_idx..]);
}

// Test pushing empty array (converted from Swift testPushArrayEmpty)
test "Push empty array" {
    const allocator = testing.allocator;
    
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Push empty array (equivalent to Swift pushArray([]))
    const empty_array = [_]ContractParameter{};
    _ = try builder.pushArray(&empty_array);
    
    // Should generate NEWARRAY0 opcode (equivalent to Swift OpCode.newArray0.opcode)
    const expected = [_]u8{@intFromEnum(OpCode.NEWARRAY0)};
    try assertBuilderBytes(&builder, &expected);
}

// Test pushing empty array parameter (converted from Swift testPushParamEmptyArray)
test "Push empty array parameter" {
    const allocator = testing.allocator;
    
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Create empty array parameter (equivalent to Swift ContractParameter(type: .array, value: []))
    const empty_array_param = ContractParameter.array(&[_]ContractParameter{});
    
    _ = try builder.pushParam(empty_array_param);
    
    // Should generate NEWARRAY0 opcode
    const expected = [_]u8{@intFromEnum(OpCode.NEWARRAY0)};
    try assertBuilderBytes(&builder, &expected);
}

// Test pushing byte arrays (converted from Swift testPushByteArray)
test "Push byte arrays" {
    const allocator = testing.allocator;
    
    // Test different byte array sizes (equivalent to Swift pushData tests)
    const test_cases = [_]struct {
        size: usize,
        expected_prefix: []const u8,
    }{
        .{ .size = 1, .expected_prefix = &[_]u8{ 0x0C, 0x01 } },     // PUSHDATA1, length 1
        .{ .size = 75, .expected_prefix = &[_]u8{ 0x0C, 0x4B } },    // PUSHDATA1, length 75
        .{ .size = 256, .expected_prefix = &[_]u8{ 0x0D, 0x00, 0x01 } }, // PUSHDATA2, length 256
        .{ .size = 65536, .expected_prefix = &[_]u8{ 0x0E, 0x00, 0x00, 0x01, 0x00 } }, // PUSHDATA4, length 65536
    };
    
    for (test_cases) |case| {
        var builder = ScriptBuilder.init(allocator);
        defer builder.deinit();
        
        const byte_array = try createByteArray(case.size, allocator);
        defer allocator.free(byte_array);
        
        _ = try builder.pushData(byte_array);
        
        // Verify expected prefix (equivalent to Swift assertBuilder)
        try assertBuilderBytes(&builder, case.expected_prefix);
        
        // Verify total length is prefix + data
        const script = builder.toScript();
        try testing.expectEqual(case.expected_prefix.len + case.size, script.len);
    }
}

// Test pushing strings (converted from Swift testPushString)
test "Push strings" {
    const allocator = testing.allocator;
    
    // Test empty string (equivalent to Swift pushData(""))
    var builder1 = ScriptBuilder.init(allocator);
    defer builder1.deinit();
    
    _ = try builder1.pushData("");
    const expected_empty = [_]u8{ 0x0C, 0x00 }; // PUSHDATA1, length 0
    try assertBuilderBytes(&builder1, &expected_empty);
    
    // Test single character (equivalent to Swift pushData("a"))
    var builder2 = ScriptBuilder.init(allocator);
    defer builder2.deinit();
    
    _ = try builder2.pushData("a");
    const expected_single = [_]u8{ 0x0C, 0x01, 0x61 }; // PUSHDATA1, length 1, 'a'
    try assertBuilderBytes(&builder2, &expected_single);
    
    // Test large string (equivalent to Swift 10000 character string)
    var builder3 = ScriptBuilder.init(allocator);
    defer builder3.deinit();
    
    const large_string = try allocator.alloc(u8, 10000);
    defer allocator.free(large_string);
    @memset(large_string, 'a');
    
    _ = try builder3.pushData(large_string);
    const expected_large_prefix = [_]u8{ 0x0D, 0x10, 0x27 }; // PUSHDATA2, length 10000 (0x2710)
    try assertBuilderBytes(&builder3, &expected_large_prefix);
}

// Test pushing integers (converted from Swift testPushInteger)
test "Push integers" {
    const allocator = testing.allocator;
    
    // Test special integer opcodes (equivalent to Swift pushInteger tests)
    const integer_test_cases = [_]struct {
        value: i64,
        expected: []const u8,
    }{
        .{ .value = -1, .expected = &[_]u8{@intFromEnum(OpCode.PUSHM1)} },
        .{ .value = 0, .expected = &[_]u8{@intFromEnum(OpCode.PUSH0)} },
        .{ .value = 1, .expected = &[_]u8{@intFromEnum(OpCode.PUSH1)} },
        .{ .value = 16, .expected = &[_]u8{@intFromEnum(OpCode.PUSH16)} },
        .{ .value = 17, .expected = &[_]u8{ @intFromEnum(OpCode.PUSHINT8), 0x11 } },
        .{ .value = -800000, .expected = &[_]u8{ @intFromEnum(OpCode.PUSHINT32), 0x00, 0xCB, 0xF3, 0xFF } },
        .{ .value = -100000000000, .expected = &[_]u8{ @intFromEnum(OpCode.PUSHINT64), 0x00, 0x18, 0x89, 0xB7, 0xE8, 0xFF, 0xFF, 0xFF } },
        .{ .value = 100000000000, .expected = &[_]u8{ @intFromEnum(OpCode.PUSHINT64), 0x00, 0xE8, 0x76, 0x48, 0x17, 0x00, 0x00, 0x00 } },
    };
    
    for (integer_test_cases) |case| {
        var builder = ScriptBuilder.init(allocator);
        defer builder.deinit();
        
        _ = try builder.pushInteger(case.value);

        try assertBuilderBytes(&builder, case.expected);
    }
}

// Test pushing boolean values
test "Push boolean values" {
    const allocator = testing.allocator;
    
    // Test true value
    var builder_true = ScriptBuilder.init(allocator);
    defer builder_true.deinit();
    
    _ = try builder_true.pushBoolean(true);
    const expected_true = [_]u8{@intFromEnum(OpCode.PUSH1)}; // TRUE = PUSH1
    try assertBuilderBytes(&builder_true, &expected_true);
    
    // Test false value
    var builder_false = ScriptBuilder.init(allocator);
    defer builder_false.deinit();
    
    _ = try builder_false.pushBoolean(false);
    const expected_false = [_]u8{@intFromEnum(OpCode.PUSH0)}; // FALSE = PUSH0
    try assertBuilderBytes(&builder_false, &expected_false);
}

// Test contract calls
test "Contract call script generation" {
    const allocator = testing.allocator;
    
    // Test contract call (equivalent to Swift contractCall tests)
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const method_name = "testMethod";
    
    // Create test parameters
    const params = [_]ContractParameter{
        ContractParameter.integer(42),
        ContractParameter.string("test"),
    };

    _ = try builder.contractCall(contract_hash, method_name, &params, null);
    
    const contract_script = builder.toScript();
    try testing.expect(contract_script.len > 0);
    try testing.expect(contract_script.len > 30); // Should be substantial with parameters + contract call
}

// Test syscall generation
test "Syscall generation" {
    const allocator = testing.allocator;
    
    // Test syscall (equivalent to Swift sysCall tests)
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    _ = try builder.sysCall(InteropService.SystemContractCall);
    
    const syscall_script = builder.toScript();
    try testing.expect(syscall_script.len > 0);
    try testing.expect(syscall_script.len >= 5); // SYSCALL opcode + 4-byte hash
    
    // First byte should be SYSCALL opcode
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.SYSCALL)), syscall_script[0]);
}

test "Multi-sig verification script sorts public keys" {
    const allocator = testing.allocator;

    // Matches NeoSwift ScriptBuilderTests.testVerificationScriptFromPublicKeys
    const key1_hex = "035fdb1d1f06759547020891ae97c729327853aeb1256b6fe0473bc2e9fa42ff50";
    const key2_hex = "03eda286d19f7ee0b472afd1163d803d620a961e1581a8f2704b52c0285f6e022d";
    const key3_hex = "03ac81ec17f2f15fd6d193182f927c5971559c2a32b9408a06fec9e711fb7ca02e";

    var key1: [33]u8 = undefined;
    var key2: [33]u8 = undefined;
    var key3: [33]u8 = undefined;
    _ = try std.fmt.hexToBytes(&key1, key1_hex);
    _ = try std.fmt.hexToBytes(&key2, key2_hex);
    _ = try std.fmt.hexToBytes(&key3, key3_hex);

    const pub_keys = [_][]const u8{ &key1, &key2, &key3 };
    const script = try ScriptBuilder.buildMultiSigVerificationScript(&pub_keys, 2, allocator);
    defer allocator.free(script);

    // Expected order after sorting: key1, key3, key2.
    const expected_hex = "12" ++
        "0c21" ++ key1_hex ++
        "0c21" ++ key3_hex ++
        "0c21" ++ key2_hex ++
        "13" ++
        "41" ++
        "9ed0dc3a";

    var expected: [112]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, script);
}

// Test opcode sequences
test "OpCode sequence generation" {
    const allocator = testing.allocator;
    
    // Test multiple opcodes (equivalent to Swift opCode tests)
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    const opcodes = [_]OpCode{ OpCode.PUSH1, OpCode.PUSH2, OpCode.ADD, OpCode.RET };
    _ = try builder.opCode(&opcodes);
    
    const opcode_script = builder.toScript();
    try testing.expectEqual(@as(usize, 4), opcode_script.len);
    
    // Verify each opcode is present
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.PUSH1)), opcode_script[0]);
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.PUSH2)), opcode_script[1]);
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.ADD)), opcode_script[2]);
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.RET)), opcode_script[3]);
}

// Test script builder chaining
test "Script builder method chaining" {
    const allocator = testing.allocator;
    
    // Test method chaining (equivalent to Swift fluent interface)
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Chain multiple operations
    _ = try builder.pushInteger(1);
    _ = try builder.pushInteger(2);
    _ = try builder.opCode(&[_]OpCode{OpCode.ADD});
    _ = try builder.pushData("result");
    _ = try builder.opCode(&[_]OpCode{OpCode.RET});
    
    const chained_script = builder.toScript();
    try testing.expect(chained_script.len > 0);
    try testing.expect(chained_script.len >= 5); // Should have multiple operations
    
    // Last byte should be RET
    try testing.expectEqual(@as(u8, @intFromEnum(OpCode.RET)), chained_script[chained_script.len - 1]);
}

// Test parameter pushing with different types
test "Parameter pushing with different types" {
    const allocator = testing.allocator;
    
    // Test different contract parameter types
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Integer parameter
    _ = try builder.pushParam(ContractParameter.integer(123));
    
    // String parameter
    _ = try builder.pushParam(ContractParameter.string("hello"));
    
    // Boolean parameter
    _ = try builder.pushParam(ContractParameter.boolean(true));
    
    // Hash160 parameter
    const test_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    _ = try builder.pushParam(ContractParameter.hash160(test_hash));
    
    const param_script = builder.toScript();
    try testing.expect(param_script.len > 0);
    try testing.expect(param_script.len > 30); // Integer + string + bool + hash160
}

// Test script size calculations
test "Script size calculations and limits" {
    const allocator = testing.allocator;
    
    // Test script with known size
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Add operations with predictable sizes
    _ = try builder.pushInteger(0);        // 1 byte (PUSH0)
    _ = try builder.pushInteger(1);        // 1 byte (PUSH1)
    _ = try builder.pushData("test");      // 6 bytes (PUSHDATA1 + length + data)
    _ = try builder.opCode(&[_]OpCode{OpCode.ADD}); // 1 byte
    
    const sized_script = builder.toScript();
    try testing.expectEqual(@as(usize, 9), sized_script.len);
    
    // Test empty script
    var empty_builder = ScriptBuilder.init(allocator);
    defer empty_builder.deinit();
    
    const empty_script = empty_builder.toScript();
    try testing.expectEqual(@as(usize, 0), empty_script.len);
}

// Test complex script building scenarios
test "Complex script building scenarios" {
    const allocator = testing.allocator;
    
    // Build a complex script with multiple operations (similar to NEP-17 transfer)
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    const contract_hash = try Hash160.initWithString("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5"); // NEO token
    const sender_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const recipient_hash = try Hash160.initWithString("0x969a77db482f74ce27105f760efa139223431394");
    
    // Create transfer parameters
    const transfer_params = [_]ContractParameter{
        ContractParameter.hash160(sender_hash),
        ContractParameter.hash160(recipient_hash),
        ContractParameter.integer(1000000),
        ContractParameter{ .Any = {} },
    };

    _ = try builder.contractCall(contract_hash, "transfer", &transfer_params, null);
    
    const complex_script = builder.toScript();
    try testing.expect(complex_script.len > 0);
    try testing.expect(complex_script.len > 80); // Parameters + contract call should be substantial
    
    // Verify script ends with expected elements (syscall)
    try testing.expect(complex_script.len >= 5); // At minimum should have syscall at end
}

// Test script builder error conditions
test "Script builder error conditions" {
    const allocator = testing.allocator;
    
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Test invalid contract call (empty method name)
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const empty_params = [_]ContractParameter{};
    
    try testing.expectError(
        neo.NeoError.IllegalArgument,
        builder.contractCall(contract_hash, "", &empty_params, null)
    );
    
    // Test valid contract call works
    _ = try builder.contractCall(contract_hash, "validMethod", &empty_params, null);
    
    const valid_script = builder.toScript();
    try testing.expect(valid_script.len > 0);
}

// Test script builder reset and reuse
test "Script builder reset and reuse" {
    const allocator = testing.allocator;
    
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Build first script
    _ = try builder.pushInteger(1);
    _ = try builder.pushInteger(2);
    _ = try builder.opCode(&[_]OpCode{OpCode.ADD});
    
    const first_script = builder.toScript();
    try testing.expect(first_script.len > 0);
    
    // Reset and build second script
    builder.reset();
    
    _ = try builder.pushData("hello");
    _ = try builder.opCode(&[_]OpCode{OpCode.RET});
    
    const second_script = builder.toScript();
    try testing.expect(second_script.len > 0);
    try testing.expect(second_script.len != first_script.len); // Should be different
}
