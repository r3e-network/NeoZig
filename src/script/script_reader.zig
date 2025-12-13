//! Script Reader implementation
//!
//! Complete conversion from NeoSwift ScriptReader.swift
//! Provides script analysis and human-readable conversion capabilities.

const std = @import("std");
const ArrayList = std.ArrayList;


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const OpCode = @import("op_code.zig").OpCode;
const InteropService = @import("script_builder.zig").InteropService;
const BinaryReader = @import("../serialization/binary_reader_complete.zig").CompleteBinaryReader;
const PublicKey = @import("../crypto/keys.zig").PublicKey;

/// Script reader for NeoVM script analysis (converted from Swift ScriptReader)
pub const ScriptReader = struct {
    /// Gets interop service by hash (equivalent to Swift getInteropServiceCode)
    pub fn getInteropServiceCode(hash_string: []const u8) ?InteropService {
        if (hash_string.len != 8) return null;

        var target: [4]u8 = undefined;
        _ = std.fmt.hexToBytes(&target, hash_string) catch return null;

        for (InteropService.getAllServices()) |service| {
            var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(service.toString(), &digest, .{});
            if (std.mem.eql(u8, digest[0..4], &target)) {
                return service;
            }
        }

        return null;
    }
    
    /// Converts script to OpCode string (equivalent to Swift convertToOpCodeString(_ script: String))
    pub fn convertToOpCodeString(script_hex: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const script_bytes = try @import("../utils/string_extensions.zig").StringUtils.bytesFromHex(script_hex, allocator);
        defer allocator.free(script_bytes);
        
        return try convertToOpCodeStringFromBytes(script_bytes, allocator);
    }
    
    /// Converts script bytes to OpCode string (equivalent to Swift convertToOpCodeString(_ script: Bytes))
    pub fn convertToOpCodeStringFromBytes(script: []const u8, allocator: std.mem.Allocator) ![]u8 {
        var reader = BinaryReader.init(script);
        var result = ArrayList(u8).init(allocator);
        defer result.deinit();
        
        while (reader.hasMore()) {
            const opcode_byte = reader.readByte() catch break;
            
            // Convert byte to OpCode if possible
            if (OpCode.fromByte(opcode_byte)) |opcode| {
                const opcode_name = opcode.getName();
                try result.appendSlice(opcode_name);
                
                // Handle operands
                const operand_info = getOperandInfo(opcode);
                if (operand_info.size > 0) {
                    // Fixed size operand
                    const operand_bytes = reader.readBytes(operand_info.size, allocator) catch break;
                    defer allocator.free(operand_bytes);
                    
                    const operand_hex = try @import("../utils/bytes_extensions.zig").BytesUtils.toHexString(operand_bytes, allocator);
                    defer allocator.free(operand_hex);
                    
                    try result.appendSlice(" ");
                    try result.appendSlice(operand_hex);
                } else if (operand_info.prefix_size > 0) {
                    // Variable size operand with prefix
                    const prefix_size = try getPrefixSize(&reader, operand_info);
                    const operand_bytes = reader.readBytes(prefix_size, allocator) catch break;
                    defer allocator.free(operand_bytes);
                    
                    const operand_hex = try @import("../utils/bytes_extensions.zig").BytesUtils.toHexString(operand_bytes, allocator);
                    defer allocator.free(operand_hex);
                    
                    try result.appendSlice(" ");
                    try result.appendSlice(operand_hex);
                }
                
                try result.append('\n');
            } else {
                // Unknown opcode - show as hex
                const unknown_hex = try std.fmt.allocPrint(allocator, "UNKNOWN_0x{X:0>2}\n", .{opcode_byte});
                defer allocator.free(unknown_hex);
                try result.appendSlice(unknown_hex);
            }
        }
        
        return try result.toOwnedSlice();
    }
    
    /// Analyzes script structure (utility method)
    pub fn analyzeScript(script: []const u8, allocator: std.mem.Allocator) !ScriptAnalysis {
        var analysis = ScriptAnalysis{
            .total_bytes = script.len,
            .opcodes = ArrayList(OpCodeInfo).init(allocator),
            .push_operations = 0,
            .syscall_operations = 0,
            .jump_operations = 0,
            .arithmetic_operations = 0,
        };
        
        var reader = BinaryReader.init(script);
        
        while (reader.hasMore()) {
            const opcode_byte = reader.readByte() catch break;
            
            if (OpCode.fromByte(opcode_byte)) |opcode| {
                const operand_info = getOperandInfo(opcode);
                var operand_data: ?[]u8 = null;
                
                if (operand_info.size > 0) {
                    operand_data = reader.readBytes(operand_info.size, allocator) catch null;
                } else if (operand_info.prefix_size > 0) {
                    const prefix_size = getPrefixSize(&reader, operand_info) catch 0;
                    operand_data = reader.readBytes(prefix_size, allocator) catch null;
                }
                
                try analysis.opcodes.append(OpCodeInfo{
                    .opcode = opcode,
                    .operand = operand_data,
                    .position = reader.getPosition() - 1,
                });
                
                // Classify operations
                if (opcode.isPush()) {
                    analysis.push_operations += 1;
                } else if (opcode == .SYSCALL) {
                    analysis.syscall_operations += 1;
                } else if (opcode.isJump()) {
                    analysis.jump_operations += 1;
                } else if (isArithmeticOpCode(opcode)) {
                    analysis.arithmetic_operations += 1;
                }
            }
        }
        
        return analysis;
    }
    
    /// Validates script structure (utility method)
    pub fn validateScriptStructure(script: []const u8, allocator: std.mem.Allocator) !void {
        var analysis = try analyzeScript(script, allocator);
        defer analysis.deinit();
        
        // Basic validation rules
        if (analysis.total_bytes > constants.MAX_TRANSACTION_SIZE) {
            return errors.ValidationError.InvalidScript;
        }
        
        if (analysis.opcodes.items.len == 0 and script.len > 0) {
            return errors.ValidationError.InvalidScript;
        }
    }
    
    /// Extracts public keys from verification script (utility method)
    pub fn extractPublicKeys(script: []const u8, allocator: std.mem.Allocator) ![]PublicKey {
        var public_keys = ArrayList(PublicKey).init(allocator);
        defer public_keys.deinit();
        
        var reader = BinaryReader.init(script);
        
        while (reader.hasMore()) {
            const opcode_byte = reader.readByte() catch break;
            
            if (opcode_byte == 0x0C) { // PUSHDATA1
                const data_len = reader.readByte() catch break;
                
                if (data_len == 33) { // Compressed public key
                    const key_bytes = reader.readBytes(33, allocator) catch break;
                    defer allocator.free(key_bytes);
                    
                    if (PublicKey.init(key_bytes, true)) |pub_key| {
                        try public_keys.append(pub_key);
                    } else |_| {
                        // Not a valid public key, continue
                        continue;
                    }
                }
            }
        }
        
        return try public_keys.toOwnedSlice();
    }
};

/// Operand information for opcodes
pub const OperandInfo = struct {
    size: usize,
    prefix_size: usize,
    
    pub fn init(size: usize, prefix_size: usize) OperandInfo {
        return OperandInfo{ .size = size, .prefix_size = prefix_size };
    }
};

/// OpCode information for analysis
pub const OpCodeInfo = struct {
    opcode: OpCode,
    operand: ?[]u8,
    position: usize,
    
    pub fn deinit(self: *OpCodeInfo, allocator: std.mem.Allocator) void {
        if (self.operand) |operand| {
            allocator.free(operand);
        }
    }
};

/// Script analysis results
pub const ScriptAnalysis = struct {
    total_bytes: usize,
    opcodes: ArrayList(OpCodeInfo),
    push_operations: u32,
    syscall_operations: u32,
    jump_operations: u32,
    arithmetic_operations: u32,
    
    pub fn deinit(self: *ScriptAnalysis) void {
        for (self.opcodes.items) |*opcode_info| {
            opcode_info.deinit(self.opcodes.allocator);
        }
        self.opcodes.deinit();
    }
    
    pub fn format(self: ScriptAnalysis, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "Script Analysis: {} bytes, {} opcodes (Push: {}, Syscall: {}, Jump: {}, Arithmetic: {})",
            .{ self.total_bytes, self.opcodes.items.len, self.push_operations, self.syscall_operations, self.jump_operations, self.arithmetic_operations }
        );
    }
};

/// Gets operand information for opcode
fn getOperandInfo(opcode: OpCode) OperandInfo {
    return switch (opcode) {
        .PUSHDATA1 => OperandInfo.init(0, 1),
        .PUSHDATA2 => OperandInfo.init(0, 2),
        .PUSHDATA4 => OperandInfo.init(0, 4),
        .SYSCALL => OperandInfo.init(4, 0),
        .JMP => OperandInfo.init(1, 0),
        .JMPIF => OperandInfo.init(1, 0),
        .JMPIFNOT => OperandInfo.init(1, 0),
        else => OperandInfo.init(0, 0),
    };
}

/// Gets prefix size for variable-length operands
fn getPrefixSize(reader: *BinaryReader, operand_info: OperandInfo) !usize {
    return switch (operand_info.prefix_size) {
        1 => @intCast(try reader.readByte()),
        2 => @intCast(try reader.readUInt16()),
        4 => @intCast(try reader.readUInt32()),
        else => 0,
    };
}

/// Checks if opcode is arithmetic
fn isArithmeticOpCode(opcode: OpCode) bool {
    return switch (opcode) {
        .ADD, .SUB, .MUL, .DIV, .MOD, .POW => true,
        else => false,
    };
}

// Tests (converted from Swift ScriptReader tests)
test "ScriptReader opcode conversion" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test OpCode string conversion (equivalent to Swift convertToOpCodeString tests)
    const simple_script_hex = "1011"; // PUSH0, PUSH1
    const opcode_string = try ScriptReader.convertToOpCodeString(simple_script_hex, allocator);
    defer allocator.free(opcode_string);
    
    try testing.expect(std.mem.indexOf(u8, opcode_string, "PUSH0") != null);
    try testing.expect(std.mem.indexOf(u8, opcode_string, "PUSH1") != null);
    
    // Test script with data
    const script_with_data = [_]u8{ 0x0C, 0x04, 0x01, 0x02, 0x03, 0x04, 0x40 }; // PUSHDATA1, 4 bytes, data, RET
    const detailed_string = try ScriptReader.convertToOpCodeStringFromBytes(&script_with_data, allocator);
    defer allocator.free(detailed_string);
    
    try testing.expect(std.mem.indexOf(u8, detailed_string, "PUSHDATA1") != null);
    try testing.expect(std.mem.indexOf(u8, detailed_string, "RET") != null);
}

test "ScriptReader interop service detection" {
    const testing = std.testing;
    
    // Test interop service detection (equivalent to Swift getInteropServiceCode tests)
    const contract_call_hash = "627d5b52"; // SYSTEM_CONTRACT_CALL
    const service = ScriptReader.getInteropServiceCode(contract_call_hash);
    try testing.expect(service != null);
    try testing.expectEqual(InteropService.SystemContractCall, service.?);
    
    const check_sig_hash = "56e7b327"; // SYSTEM_CRYPTO_CHECK_SIG
    const check_sig_service = ScriptReader.getInteropServiceCode(check_sig_hash);
    try testing.expect(check_sig_service != null);
    try testing.expectEqual(InteropService.SystemCryptoCheckSig, check_sig_service.?);
    
    // Test unknown hash
    const unknown_service = ScriptReader.getInteropServiceCode("00000000");
    try testing.expect(unknown_service == null);
}

test "ScriptReader script analysis" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test script analysis (equivalent to Swift script analysis tests)
    const test_script = [_]u8{
        0x10,       // PUSH0
        0x11,       // PUSH1
        0x9E,       // ADD
        0x0C, 0x02, 0xAB, 0xCD, // PUSHDATA1, 2 bytes, data
        0x41, 0x52, 0x5b, 0x7d, 0x62, // SYSCALL, contract call hash
        0x40,       // RET
    };
    
    var analysis = try ScriptReader.analyzeScript(&test_script, allocator);
    defer analysis.deinit();
    
    try testing.expectEqual(@as(usize, test_script.len), analysis.total_bytes);
    try testing.expect(analysis.opcodes.items.len > 0);
    try testing.expect(analysis.push_operations >= 3); // PUSH0, PUSH1, PUSHDATA1
    try testing.expect(analysis.syscall_operations >= 1); // SYSCALL
    try testing.expect(analysis.arithmetic_operations >= 1); // ADD
    
    const formatted_analysis = try analysis.format(allocator);
    defer allocator.free(formatted_analysis);
    
    try testing.expect(std.mem.indexOf(u8, formatted_analysis, "opcodes") != null);
    try testing.expect(std.mem.indexOf(u8, formatted_analysis, "Push") != null);
}

test "ScriptReader public key extraction" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test public key extraction from verification script
    const key_pair = try @import("../crypto/ec_key_pair.zig").ECKeyPair.createRandom();
    defer {
        var mutable_kp = key_pair;
        mutable_kp.zeroize();
    }
    
    // Create verification script
    var builder = @import("script_builder.zig").ScriptBuilder.init(allocator);
    defer builder.deinit();
    
    const public_key = key_pair.getPublicKey();
    _ = try builder.pushData(public_key.toSlice());
    _ = try builder.sysCall(.SystemCryptoCheckSig);
    
    const script = builder.toScript();
    
    // Extract public keys
    const extracted_keys = try ScriptReader.extractPublicKeys(script, allocator);
    defer allocator.free(extracted_keys);
    
    try testing.expectEqual(@as(usize, 1), extracted_keys.len);
    try testing.expect(extracted_keys[0].eql(public_key));
}

test "ScriptReader validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test script structure validation
    const valid_script = [_]u8{ 0x10, 0x11, 0x9E, 0x40 }; // PUSH0, PUSH1, ADD, RET
    try ScriptReader.validateScriptStructure(&valid_script, allocator);
    
    // Test invalid script (too large)
    const large_script = [_]u8{0x40} ** (constants.MAX_TRANSACTION_SIZE + 1);
    try testing.expectError(
        errors.ValidationError.InvalidScript,
        ScriptReader.validateScriptStructure(&large_script, allocator)
    );
    
    // Test empty script validation
    const empty_script = [_]u8{};
    try ScriptReader.validateScriptStructure(&empty_script, allocator); // Should pass
}
