//! NEF File Tests
//!
//! Complete conversion from NeoSwift NefFileTests.swift
//! Tests NEF (Neo Executable Format) file handling.

const std = @import("std");


const testing = std.testing;
const NefFile = @import("../../src/contract/nef_file.zig").NefFile;

test "NEF file creation and validation" {
    const allocator = testing.allocator;
    
    const compiler = "neon";
    const script_bytes = [_]u8{ 0x10, 0x11, 0x40 }; // PUSH0, PUSH1, RET
    const checksum: u32 = 0x12345678;
    
    var nef_file = try NefFile.create(compiler, &script_bytes, checksum, allocator);
    defer nef_file.deinit(allocator);
    
    try testing.expectEqualStrings(compiler, nef_file.getCompiler());
    try testing.expectEqualSlices(u8, &script_bytes, nef_file.getScript());
    try testing.expectEqual(checksum, nef_file.getChecksum());
    
    try nef_file.validate();
}

test "NEF file magic number validation" {
    const allocator = testing.allocator;
    
    var nef_file = try NefFile.create("neon", &[_]u8{0x40}, 0x12345678, allocator);
    defer nef_file.deinit(allocator);
    
    try testing.expectEqual(NefFile.NEF_MAGIC, nef_file.getMagic());
    try testing.expect(nef_file.isValidMagic());
}