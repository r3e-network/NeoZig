//! NEF (Neo Executable Format) File implementation
//!
//! Complete conversion from NeoSwift NefFile.swift
//! Handles NEF3 file format for smart contract deployment.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash256 = @import("../types/hash256.zig").Hash256;
const BinaryWriter = @import("../serialization/binary_writer.zig").BinaryWriter;
const BinaryReader = @import("../serialization/binary_reader.zig").BinaryReader;

/// NEF file structure (converted from Swift NefFile)
pub const NefFile = struct {
    /// Magic header constant (matches Swift MAGIC)
    pub const MAGIC: u32 = 0x3346454E; // "NEF3"
    
    /// Size constants (match Swift constants)
    pub const MAGIC_SIZE: u32 = 4;
    pub const COMPILER_SIZE: u32 = 64;
    pub const MAX_SOURCE_URL_SIZE: u32 = 256;
    pub const MAX_SCRIPT_LENGTH: u32 = 512 * 1024; // 512KB
    pub const CHECKSUM_SIZE: u32 = 4;
    pub const HEADER_SIZE: u32 = MAGIC_SIZE + COMPILER_SIZE;
    
    /// Compiler name and version
    compiler: ?[]const u8,
    /// Source code URL
    source_url: []const u8,
    /// Contract method tokens
    method_tokens: []const MethodToken,
    /// Contract script
    script: []const u8,
    /// Checksum bytes
    checksum: [4]u8,
    
    const Self = @This();
    
    /// Creates NEF file (equivalent to Swift init)
    pub fn init(
        compiler: ?[]const u8,
        source_url: []const u8,
        method_tokens: []const MethodToken,
        script: []const u8,
    ) !Self {
        // Validate constraints
        if (source_url.len > MAX_SOURCE_URL_SIZE) {
            return errors.throwIllegalArgument("Source URL too long");
        }
        
        if (script.len > MAX_SCRIPT_LENGTH) {
            return errors.throwIllegalArgument("Script too long");
        }
        
        // Calculate checksum
        const checksum = try calculateChecksum(compiler, source_url, method_tokens, script);
        
        return Self{
            .compiler = compiler,
            .source_url = source_url,
            .method_tokens = method_tokens,
            .script = script,
            .checksum = checksum,
        };
    }
    
    /// Gets checksum as integer (equivalent to Swift .checksumInteger property)
    pub fn getChecksumAsInteger(self: Self) u32 {
        return std.mem.littleToNative(u32, std.mem.bytesToValue(u32, &self.checksum));
    }
    
    /// Calculates checksum from bytes (equivalent to Swift getChecksumAsInteger)
    pub fn getChecksumAsIntegerFromBytes(checksum_bytes: [4]u8) u32 {
        return std.mem.littleToNative(u32, std.mem.bytesToValue(u32, &checksum_bytes));
    }
    
    /// Serializes NEF file (equivalent to Swift serialization)
    pub fn serialize(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var writer = BinaryWriter.init(allocator);
        defer writer.deinit();
        
        // Write magic
        try writer.writeU32(MAGIC);
        
        // Write compiler (64 bytes, null-padded)
        var compiler_bytes: [COMPILER_SIZE]u8 = std.mem.zeroes([COMPILER_SIZE]u8);
        if (self.compiler) |comp| {
            const copy_len = @min(comp.len, COMPILER_SIZE - 1); // Reserve 1 byte for null terminator
            @memcpy(compiler_bytes[0..copy_len], comp[0..copy_len]);
        }
        try writer.writeBytes(&compiler_bytes);
        
        // Write source URL with length prefix
        try writer.writeVarInt(self.source_url.len);
        try writer.writeBytes(self.source_url);
        
        // Write reserved bytes (2 bytes)
        try writer.writeBytes(&[_]u8{ 0x00, 0x00 });
        
        // Write method tokens
        try writer.writeVarInt(self.method_tokens.len);
        for (self.method_tokens) |token| {
            try token.serialize(&writer);
        }
        
        // Write reserved bytes (2 bytes)
        try writer.writeBytes(&[_]u8{ 0x00, 0x00 });
        
        // Write script
        try writer.writeVarInt(self.script.len);
        try writer.writeBytes(self.script);
        
        // Write checksum
        try writer.writeBytes(&self.checksum);
        
        return try allocator.dupe(u8, writer.toSlice());
    }
    
    /// Deserializes NEF file (equivalent to Swift deserialization)
    pub fn deserialize(data: []const u8, allocator: std.mem.Allocator) !Self {
        var reader = BinaryReader.init(data);
        
        // Read magic
        const magic = try reader.readU32();
        if (magic != MAGIC) {
            return errors.throwIllegalArgument("Invalid NEF magic number");
        }
        
        // Read compiler (64 bytes)
        var compiler_bytes: [COMPILER_SIZE]u8 = undefined;
        try reader.readBytes(&compiler_bytes);
        
        // Extract compiler string (null-terminated)
        var compiler_len: usize = 0;
        while (compiler_len < COMPILER_SIZE and compiler_bytes[compiler_len] != 0) {
            compiler_len += 1;
        }
        
        const compiler = if (compiler_len > 0) 
            try allocator.dupe(u8, compiler_bytes[0..compiler_len])
        else 
            null;
        
        // Read source URL
        const source_url_len = try reader.readVarInt();
        if (source_url_len > MAX_SOURCE_URL_SIZE) {
            return errors.throwIllegalArgument("Source URL too long");
        }
        
        const source_url = try allocator.alloc(u8, @intCast(source_url_len));
        try reader.readBytes(source_url);
        
        // Read reserved bytes (2 bytes)
        var reserved1: [2]u8 = undefined;
        try reader.readBytes(&reserved1);
        
        // Read method tokens
        const tokens_count = try reader.readVarInt();
        var method_tokens = try allocator.alloc(MethodToken, @intCast(tokens_count));
        for (method_tokens) |*token| {
            token.* = try MethodToken.deserialize(&reader, allocator);
        }
        
        // Read reserved bytes (2 bytes)
        var reserved2: [2]u8 = undefined;
        try reader.readBytes(&reserved2);
        
        // Read script
        const script_len = try reader.readVarInt();
        if (script_len > MAX_SCRIPT_LENGTH) {
            return errors.throwIllegalArgument("Script too long");
        }
        
        const script = try allocator.alloc(u8, @intCast(script_len));
        try reader.readBytes(script);
        
        // Read checksum
        var checksum: [4]u8 = undefined;
        try reader.readBytes(&checksum);
        
        return Self{
            .compiler = compiler,
            .source_url = source_url,
            .method_tokens = method_tokens,
            .script = script,
            .checksum = checksum,
        };
    }
    
    /// Validates NEF file integrity (equivalent to Swift validation)
    pub fn validate(self: Self, allocator: std.mem.Allocator) !void {
        // Recalculate checksum and verify
        const calculated_checksum = try calculateChecksum(
            self.compiler,
            self.source_url,
            self.method_tokens,
            self.script,
        );
        
        if (!std.mem.eql(u8, &self.checksum, &calculated_checksum)) {
            return errors.throwIllegalArgument("NEF file checksum validation failed");
        }
        
        // Validate constraints
        if (self.source_url.len > MAX_SOURCE_URL_SIZE) {
            return errors.throwIllegalArgument("Source URL too long");
        }
        
        if (self.script.len > MAX_SCRIPT_LENGTH) {
            return errors.throwIllegalArgument("Script too long");
        }
        
        // Validate method tokens
        for (self.method_tokens) |token| {
            try token.validate();
        }
    }
    
    /// Gets NEF size (equivalent to Swift size calculation)
    pub fn getSize(self: Self) usize {
        var size: usize = HEADER_SIZE; // Magic + compiler
        
        size += getVarIntSize(self.source_url.len) + self.source_url.len; // Source URL
        size += 2; // Reserved
        size += getVarIntSize(self.method_tokens.len); // Method tokens count
        
        for (self.method_tokens) |token| {
            size += token.getSize();
        }
        
        size += 2; // Reserved
        size += getVarIntSize(self.script.len) + self.script.len; // Script
        size += CHECKSUM_SIZE; // Checksum
        
        return size;
    }
};

/// Method token (converted from Swift MethodToken)
pub const MethodToken = struct {
    hash: @import("../types/hash160.zig").Hash160,
    method: []const u8,
    parameters_count: u16,
    has_return_value: bool,
    call_flags: u8,
    
    const Self = @This();
    
    pub fn init(
        hash: @import("../types/hash160.zig").Hash160,
        method: []const u8,
        parameters_count: u16,
        has_return_value: bool,
        call_flags: u8,
    ) Self {
        return Self{
            .hash = hash,
            .method = method,
            .parameters_count = parameters_count,
            .has_return_value = has_return_value,
            .call_flags = call_flags,
        };
    }
    
    pub fn serialize(self: Self, writer: *BinaryWriter) !void {
        try writer.writeBytes(&self.hash.toArray());
        try writer.writeVarInt(self.method.len);
        try writer.writeBytes(self.method);
        try writer.writeU32(@as(u16, self.parameters_count));
        try writer.writeByte(if (self.has_return_value) 1 else 0);
        try writer.writeByte(self.call_flags);
    }
    
    pub fn deserialize(reader: *BinaryReader, allocator: std.mem.Allocator) !Self {
        var hash_bytes: [20]u8 = undefined;
        try reader.readBytes(&hash_bytes);
        const hash = @import("../types/hash160.zig").Hash160.init(hash_bytes);
        
        const method_len = try reader.readVarInt();
        const method = try allocator.alloc(u8, @intCast(method_len));
        try reader.readBytes(method);
        
        const parameters_count = @as(u16, @intCast(try reader.readU32()));
        const has_return_value = (try reader.readByte()) != 0;
        const call_flags = try reader.readByte();
        
        return Self.init(hash, method, parameters_count, has_return_value, call_flags);
    }
    
    pub fn validate(self: Self) !void {
        if (self.method.len == 0) {
            return errors.throwIllegalArgument("Method name cannot be empty");
        }
        
        if (self.method.len > 255) {
            return errors.throwIllegalArgument("Method name too long");
        }
    }
    
    pub fn getSize(self: Self) usize {
        return 20 + // Hash160
               getVarIntSize(self.method.len) + self.method.len + // Method
               4 + // Parameters count (u32)
               1 + // Has return value
               1;  // Call flags
    }
};

/// Calculates NEF file checksum (equivalent to Swift checksum calculation)
fn calculateChecksum(
    compiler: ?[]const u8,
    source_url: []const u8,
    method_tokens: []const MethodToken,
    script: []const u8,
) ![4]u8 {
    // Build data for checksum calculation (everything except checksum itself)
    var data = std.ArrayList(u8).init(std.heap.page_allocator);
    defer data.deinit();
    
    // Magic
    const magic_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, NefFile.MAGIC));
    try data.appendSlice(&magic_bytes);
    
    // Compiler (64 bytes, null-padded)
    var compiler_bytes: [NefFile.COMPILER_SIZE]u8 = std.mem.zeroes([NefFile.COMPILER_SIZE]u8);
    if (compiler) |comp| {
        const copy_len = @min(comp.len, NefFile.COMPILER_SIZE - 1);
        @memcpy(compiler_bytes[0..copy_len], comp[0..copy_len]);
    }
    try data.appendSlice(&compiler_bytes);
    
    // Source URL with length
    const source_len_bytes = getVarIntBytes(source_url.len);
    try data.appendSlice(&source_len_bytes);
    try data.appendSlice(source_url);
    
    // Reserved (2 bytes)
    try data.appendSlice(&[_]u8{ 0x00, 0x00 });
    
    // Method tokens
    const tokens_len_bytes = getVarIntBytes(method_tokens.len);
    try data.appendSlice(&tokens_len_bytes);
    
    for (method_tokens) |token| {
        try data.appendSlice(&token.hash.toArray());
        
        const method_len_bytes = getVarIntBytes(token.method.len);
        try data.appendSlice(&method_len_bytes);
        try data.appendSlice(token.method);
        
        const params_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, token.parameters_count));
        try data.appendSlice(&params_bytes);
        
        try data.append(if (token.has_return_value) 1 else 0);
        try data.append(token.call_flags);
    }
    
    // Reserved (2 bytes)
    try data.appendSlice(&[_]u8{ 0x00, 0x00 });
    
    // Script with length
    const script_len_bytes = getVarIntBytes(script.len);
    try data.appendSlice(&script_len_bytes);
    try data.appendSlice(script);
    
    // Calculate double SHA256
    const first_hash = Hash256.sha256(data.items);
    const second_hash = Hash256.sha256(first_hash.toSlice());
    
    // Return first 4 bytes as checksum
    var checksum: [4]u8 = undefined;
    @memcpy(&checksum, second_hash.toSlice()[0..4]);
    
    return checksum;
}

/// Gets VarInt bytes for serialization
fn getVarIntBytes(value: usize) [9]u8 {
    var bytes: [9]u8 = undefined;
    var len: usize = 0;
    
    if (value < 0xFC) {
        bytes[0] = @intCast(value);
        len = 1;
    } else if (value <= 0xFFFF) {
        bytes[0] = 0xFD;
        const value_bytes = std.mem.toBytes(std.mem.nativeToLittle(u16, @intCast(value)));
        @memcpy(bytes[1..3], &value_bytes);
        len = 3;
    } else if (value <= 0xFFFFFFFF) {
        bytes[0] = 0xFE;
        const value_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(value)));
        @memcpy(bytes[1..5], &value_bytes);
        len = 5;
    } else {
        bytes[0] = 0xFF;
        const value_bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, value));
        @memcpy(bytes[1..9], &value_bytes);
        len = 9;
    }
    
    return bytes;
}

/// Gets VarInt size
fn getVarIntSize(value: usize) usize {
    if (value < 0xFC) return 1;
    if (value <= 0xFFFF) return 3;
    if (value <= 0xFFFFFFFF) return 5;
    return 9;
}

// Tests (converted from Swift NefFile tests)
test "NefFile creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test NEF file creation (equivalent to Swift NefFile tests)
    const method_tokens = [_]MethodToken{};
    const script = [_]u8{ 0x41, 0x9D, 0x42 }; // Simple test script
    
    const nef_file = try NefFile.init(
        "neo-zig-compiler-v1.0",
        "https://github.com/neo-project/neo-zig",
        &method_tokens,
        &script,
    );
    
    // Test properties
    try testing.expectEqualStrings("neo-zig-compiler-v1.0", nef_file.compiler.?);
    try testing.expectEqualStrings("https://github.com/neo-project/neo-zig", nef_file.source_url);
    try testing.expectEqual(@as(usize, 0), nef_file.method_tokens.len);
    try testing.expectEqualSlices(u8, &script, nef_file.script);
    
    // Test checksum calculation
    const checksum_int = nef_file.getChecksumAsInteger();
    try testing.expect(checksum_int != 0);
    
    // Test constants
    try testing.expectEqual(@as(u32, 0x3346454E), NefFile.MAGIC);
    try testing.expectEqual(@as(u32, 4), NefFile.MAGIC_SIZE);
    try testing.expectEqual(@as(u32, 64), NefFile.COMPILER_SIZE);
    try testing.expectEqual(@as(u32, 256), NefFile.MAX_SOURCE_URL_SIZE);
}

test "NefFile serialization and deserialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Create test NEF file
    const method_tokens = [_]MethodToken{};
    const script = [_]u8{ 0x10, 0x11, 0x9E }; // PUSH0, PUSH1, ADD
    
    const original_nef = try NefFile.init(
        "test-compiler",
        "test-source.neo",
        &method_tokens,
        &script,
    );
    
    // Test serialization
    const serialized = try original_nef.serialize(allocator);
    defer allocator.free(serialized);
    
    try testing.expect(serialized.len > 0);
    try testing.expect(serialized.len >= NefFile.HEADER_SIZE);
    
    // Test deserialization
    const deserialized_nef = try NefFile.deserialize(serialized, allocator);
    defer {
        if (deserialized_nef.compiler) |comp| allocator.free(comp);
        allocator.free(deserialized_nef.source_url);
        allocator.free(deserialized_nef.method_tokens);
        allocator.free(deserialized_nef.script);
    }
    
    // Verify round-trip
    try testing.expectEqualStrings("test-compiler", deserialized_nef.compiler.?);
    try testing.expectEqualStrings("test-source.neo", deserialized_nef.source_url);
    try testing.expectEqualSlices(u8, original_nef.script, deserialized_nef.script);
    try testing.expectEqual(original_nef.getChecksumAsInteger(), deserialized_nef.getChecksumAsInteger());
}

test "NefFile validation and constraints" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test source URL length constraint
    const long_url = "x" ** (NefFile.MAX_SOURCE_URL_SIZE + 1);
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        NefFile.init("compiler", long_url, &[_]MethodToken{}, &[_]u8{0x40})
    );
    
    // Test script length constraint
    const long_script = [_]u8{0} ** (NefFile.MAX_SCRIPT_LENGTH + 1);
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        NefFile.init("compiler", "source.neo", &[_]MethodToken{}, &long_script)
    );
    
    // Test valid NEF file validation
    const valid_nef = try NefFile.init(
        "valid-compiler",
        "valid-source.neo",
        &[_]MethodToken{},
        &[_]u8{ 0x40 }, // RET
    );
    
    try valid_nef.validate(allocator);
}

test "MethodToken operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test method token creation
    const method_token = MethodToken.init(
        @import("../types/hash160.zig").Hash160.ZERO,
        "testMethod",
        2, // parameters count
        true, // has return value
        0x0F, // call flags
    );
    
    try testing.expect(method_token.hash.eql(@import("../types/hash160.zig").Hash160.ZERO));
    try testing.expectEqualStrings("testMethod", method_token.method);
    try testing.expectEqual(@as(u16, 2), method_token.parameters_count);
    try testing.expect(method_token.has_return_value);
    try testing.expectEqual(@as(u8, 0x0F), method_token.call_flags);
    
    // Test validation
    try method_token.validate();
    
    // Test invalid method token
    const invalid_token = MethodToken.init(
        @import("../types/hash160.zig").Hash160.ZERO,
        "", // Empty method name
        0,
        false,
        0,
    );
    
    try testing.expectError(errors.NeoError.IllegalArgument, invalid_token.validate());
    
    // Test method token size calculation
    const size = method_token.getSize();
    try testing.expect(size >= 26); // Minimum size for valid token
}

test "NefFile with method tokens" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test NEF file with method tokens
    const method_tokens = [_]MethodToken{
        MethodToken.init(
            @import("../types/hash160.zig").Hash160.ZERO,
            "balanceOf",
            1,
            true,
            0x01,
        ),
        MethodToken.init(
            @import("../types/hash160.zig").Hash160.ZERO,
            "transfer",
            3,
            true,
            0x0F,
        ),
    };
    
    const script = [_]u8{ 0x10, 0x40 }; // PUSH0, RET
    
    const nef_with_tokens = try NefFile.init(
        "token-test-compiler",
        "token-test.neo",
        &method_tokens,
        &script,
    );
    
    try testing.expectEqual(@as(usize, 2), nef_with_tokens.method_tokens.len);
    try testing.expectEqualStrings("balanceOf", nef_with_tokens.method_tokens[0].method);
    try testing.expectEqualStrings("transfer", nef_with_tokens.method_tokens[1].method);
    
    // Test validation
    try nef_with_tokens.validate(allocator);
    
    // Test size calculation includes method tokens
    const size = nef_with_tokens.getSize();
    try testing.expect(size > NefFile.HEADER_SIZE + script.len);
}