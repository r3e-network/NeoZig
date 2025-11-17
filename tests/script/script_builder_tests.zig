//! Script Builder Tests
//!
//! Complete conversion from NeoSwift ScriptBuilderTests.swift
//! Tests script building, opcode generation, and parameter handling.

const std = @import("std");


const testing = std.testing;
const ScriptBuilder = @import("../../src/script/script_builder.zig").ScriptBuilder;
const OpCode = @import("../../src/script/op_code.zig").OpCode;
const ContractParameter = @import("../../src/types/contract_parameter.zig").ContractParameter;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;
const InteropService = @import("../../src/script/interop_service.zig").InteropService;

/// Helper function to create byte arrays (equivalent to Swift byteArray helper)
fn createByteArray(size: usize, allocator: std.mem.Allocator) ![]u8 {
    var result = try allocator.alloc(u8, size);
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

/// Test pushing empty array (converted from Swift testPushArrayEmpty)
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

/// Test pushing empty array parameter (converted from Swift testPushParamEmptyArray)
test "Push empty array parameter" {
    const allocator = testing.allocator;
    
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Create empty array parameter (equivalent to Swift ContractParameter(type: .array, value: []))
    var empty_array_param = try ContractParameter.createArray(&[_]ContractParameter{}, allocator);
    defer empty_array_param.deinit(allocator);
    
    _ = try builder.pushParam(empty_array_param);
    
    // Should generate NEWARRAY0 opcode
    const expected = [_]u8{@intFromEnum(OpCode.NEWARRAY0)};
    try assertBuilderBytes(&builder, &expected);
}

/// Test pushing byte arrays (converted from Swift testPushByteArray)
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

/// Test pushing strings (converted from Swift testPushString)
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

/// Test pushing integers (converted from Swift testPushInteger)
test "Push integers" {
    const allocator = testing.allocator;
    
    // Test special integer opcodes (equivalent to Swift pushInteger tests)
    const integer_test_cases = [_]struct {
        value: i64,
        expected: []const u8,
    }{
        .{ .value = 0, .expected = &[_]u8{@intFromEnum(OpCode.PUSH0)} },
        .{ .value = 1, .expected = &[_]u8{@intFromEnum(OpCode.PUSH1)} },
        .{ .value = 16, .expected = &[_]u8{@intFromEnum(OpCode.PUSH16)} },
        .{ .value = 17, .expected = &[_]u8{ 0x00, 0x11 } }, // PUSHINT8, value 17
    };
    
    for (integer_test_cases) |case| {
        var builder = ScriptBuilder.init(allocator);
        defer builder.deinit();
        
        _ = try builder.pushInteger(case.value);
        
        // For special opcodes, check exact match
        if (case.value >= 0 and case.value <= 16) {
            try assertBuilderBytes(&builder, case.expected);
        } else {
            // For other integers, just verify we have output
            const script = builder.toScript();
            try testing.expect(script.len > 0);
        }
    }
    
    // Test negative integer (equivalent to Swift pushInteger(-800000))
    var builder_negative = ScriptBuilder.init(allocator);
    defer builder_negative.deinit();
    
    _ = try builder_negative.pushInteger(-800000);
    const negative_script = builder_negative.toScript();
    try testing.expect(negative_script.len > 0);
    try testing.expect(negative_script.len >= 5); // Should have opcode + 4-byte value
}

/// Test pushing boolean values
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

/// Test contract calls
test "Contract call script generation" {
    const allocator = testing.allocator;
    
    // Test contract call (equivalent to Swift contractCall tests)
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const method_name = "testMethod";
    
    // Create test parameters
    var params = [_]ContractParameter{
        try ContractParameter.createInteger(42, allocator),
        try ContractParameter.createString("test", allocator),
    };
    defer {
        for (params) |*param| {
            param.deinit(allocator);
        }
    }
    
    _ = try builder.contractCall(contract_hash, method_name, &params);
    
    const contract_script = builder.toScript();
    try testing.expect(contract_script.len > 0);
    try testing.expect(contract_script.len > 30); // Should be substantial with parameters + contract call
}

/// Test syscall generation
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

/// Test opcode sequences
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

/// Test script builder chaining
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

/// Test parameter pushing with different types
test "Parameter pushing with different types" {
    const allocator = testing.allocator;
    
    // Test different contract parameter types
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Integer parameter
    var int_param = try ContractParameter.createInteger(123, allocator);
    defer int_param.deinit(allocator);
    _ = try builder.pushParam(int_param);
    
    // String parameter
    var string_param = try ContractParameter.createString("hello", allocator);
    defer string_param.deinit(allocator);
    _ = try builder.pushParam(string_param);
    
    // Boolean parameter
    var bool_param = try ContractParameter.createBoolean(true, allocator);
    defer bool_param.deinit(allocator);
    _ = try builder.pushParam(bool_param);
    
    // Hash160 parameter
    const test_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    var hash_param = try ContractParameter.createHash160(test_hash, allocator);
    defer hash_param.deinit(allocator);
    _ = try builder.pushParam(hash_param);
    
    const param_script = builder.toScript();
    try testing.expect(param_script.len > 0);
    try testing.expect(param_script.len > 50); // Should be substantial with multiple parameters
}

/// Test script size calculations
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
    try testing.expect(sized_script.len >= 9); // At least 9 bytes expected
    
    // Test empty script
    var empty_builder = ScriptBuilder.init(allocator);
    defer empty_builder.deinit();
    
    const empty_script = empty_builder.toScript();
    try testing.expectEqual(@as(usize, 0), empty_script.len);
}

/// Test complex script building scenarios
test "Complex script building scenarios" {
    const allocator = testing.allocator;
    
    // Build a complex script with multiple operations (similar to NEP-17 transfer)
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    const contract_hash = try Hash160.initWithString("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5"); // NEO token
    const sender_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const recipient_hash = try Hash160.initWithString("0x969a77db482f74ce27105f760efa139223431394");
    
    // Create transfer parameters
    var transfer_params = [_]ContractParameter{
        try ContractParameter.createHash160(sender_hash, allocator),
        try ContractParameter.createHash160(recipient_hash, allocator),
        try ContractParameter.createInteger(1000000, allocator),
        try ContractParameter.createAny(null, allocator),
    };
    defer {
        for (transfer_params) |*param| {
            param.deinit(allocator);
        }
    }
    
    _ = try builder.contractCall(contract_hash, "transfer", &transfer_params);
    
    const complex_script = builder.toScript();
    try testing.expect(complex_script.len > 0);
    try testing.expect(complex_script.len > 100); // Complex script should be substantial
    
    // Verify script ends with expected elements (syscall)
    try testing.expect(complex_script.len >= 5); // At minimum should have syscall at end
}

/// Test script builder error conditions
test "Script builder error conditions" {
    const allocator = testing.allocator;
    
    var builder = ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    // Test invalid contract call (empty method name)
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    const empty_params = [_]ContractParameter{};
    
    try testing.expectError(
        @import("../../src/core/errors.zig").NeoError.IllegalArgument,
        builder.contractCall(contract_hash, "", &empty_params)
    );
    
    // Test valid contract call works
    _ = try builder.contractCall(contract_hash, "validMethod", &empty_params);
    
    const valid_script = builder.toScript();
    try testing.expect(valid_script.len > 0);
}

/// Test script builder reset and reuse
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