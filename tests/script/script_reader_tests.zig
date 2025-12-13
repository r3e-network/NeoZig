//! Script Reader Tests
//!
//! Complete conversion from NeoSwift ScriptReaderTests.swift
//! Tests script analysis and opcode conversion.

const std = @import("std");

const testing = std.testing;
const neo = @import("neo-zig");
const ScriptReader = neo.script.ScriptReader;

test "Script reader opcode conversion" {
    const allocator = testing.allocator;
    
    const simple_script = [_]u8{ 0x10, 0x11, 0x9E, 0x40 }; // PUSH0, PUSH1, ADD, RET
    
    const opcode_string = try ScriptReader.convertToOpCodeStringFromBytes(&simple_script, allocator);
    defer allocator.free(opcode_string);
    
    try testing.expect(std.mem.indexOf(u8, opcode_string, "PUSH0") != null);
    try testing.expect(std.mem.indexOf(u8, opcode_string, "PUSH1") != null);
    try testing.expect(std.mem.indexOf(u8, opcode_string, "ADD") != null);
    try testing.expect(std.mem.indexOf(u8, opcode_string, "RET") != null);
}

test "Script analysis" {
    const allocator = testing.allocator;
    
    const test_script = [_]u8{ 0x10, 0x11, 0x9E, 0x0C, 0x02, 0xAB, 0xCD };
    
    var analysis = try ScriptReader.analyzeScript(&test_script, allocator);
    defer analysis.deinit();
    
    try testing.expectEqual(@as(usize, test_script.len), analysis.total_bytes);
    try testing.expect(analysis.opcodes.items.len > 0);
    try testing.expect(analysis.push_operations >= 2);
}
