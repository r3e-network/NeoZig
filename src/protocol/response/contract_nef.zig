//! Contract NEF Implementation
//!
//! Complete conversion from NeoSwift ContractNef.swift
//! Provides contract NEF (Neo Executable Format) representation.

const std = @import("std");

/// Contract method token (referenced in ContractNef)
pub const ContractMethodToken = struct {
    /// Method hash
    hash: []const u8,
    /// Method name
    method: []const u8,
    /// Parameter count
    param_count: u16,
    /// Has return value
    has_return_value: bool,
    /// Call flags
    call_flags: u8,
    
    const Self = @This();
    
    /// Creates new ContractMethodToken
    pub fn init(hash: []const u8, method: []const u8, param_count: u16, has_return_value: bool, call_flags: u8) Self {
        return Self{
            .hash = hash,
            .method = method,
            .param_count = param_count,
            .has_return_value = has_return_value,
            .call_flags = call_flags,
        };
    }
    
    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.hash, other.hash) and
               std.mem.eql(u8, self.method, other.method) and
               self.param_count == other.param_count and
               self.has_return_value == other.has_return_value and
               self.call_flags == other.call_flags;
    }
    
    /// Hash function
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.hash);
        hasher.update(self.method);
        hasher.update(std.mem.asBytes(&self.param_count));
        hasher.update(&[_]u8{if (self.has_return_value) 1 else 0});
        hasher.update(&[_]u8{self.call_flags});
        return hasher.final();
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.hash);
        allocator.free(self.method);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const hash_copy = try allocator.dupe(u8, self.hash);
        const method_copy = try allocator.dupe(u8, self.method);
        return Self.init(hash_copy, method_copy, self.param_count, self.has_return_value, self.call_flags);
    }
};

/// Contract NEF (Neo Executable Format) (converted from Swift ContractNef)
pub const ContractNef = struct {
    /// NEF magic number
    magic: u32,
    /// Compiler information
    compiler: []const u8,
    /// Source information (optional)
    source: ?[]const u8,
    /// Contract method tokens
    tokens: []ContractMethodToken,
    /// Contract script (base64 encoded)
    script: []const u8,
    /// Checksum
    checksum: u32,
    
    const Self = @This();
    
    /// NEF magic number constant
    pub const NEF_MAGIC: u32 = 0x3346454E; // "NEF3" in little-endian
    
    /// Creates new ContractNef (equivalent to Swift init)
    pub fn init(
        magic: u32,
        compiler: []const u8,
        source: ?[]const u8,
        tokens: []ContractMethodToken,
        script: []const u8,
        checksum: u32,
    ) Self {
        return Self{
            .magic = magic,
            .compiler = compiler,
            .source = source,
            .tokens = tokens,
            .script = script,
            .checksum = checksum,
        };
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        if (self.magic != other.magic or
            self.checksum != other.checksum or
            !std.mem.eql(u8, self.compiler, other.compiler) or
            !std.mem.eql(u8, self.script, other.script) or
            self.tokens.len != other.tokens.len) {
            return false;
        }
        
        // Compare source (handling null values)
        if (self.source == null and other.source == null) {
            // Both null - OK
        } else if (self.source == null or other.source == null) {
            return false; // One null, one not
        } else {
            if (!std.mem.eql(u8, self.source.?, other.source.?)) {
                return false;
            }
        }
        
        // Compare tokens
        for (self.tokens, 0..) |token, i| {
            if (!token.eql(other.tokens[i])) {
                return false;
            }
        }
        
        return true;
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&self.magic));
        hasher.update(self.compiler);
        
        if (self.source) |source| {
            hasher.update(source);
        }
        
        for (self.tokens) |token| {
            const token_hash = token.hash();
            hasher.update(std.mem.asBytes(&token_hash));
        }
        
        hasher.update(self.script);
        hasher.update(std.mem.asBytes(&self.checksum));
        return hasher.final();
    }
    
    /// Validates NEF format
    pub fn validate(self: Self) !void {
        if (self.magic != NEF_MAGIC) {
            return error.InvalidNefMagic;
        }
        
        if (self.compiler.len == 0) {
            return error.EmptyCompilerInfo;
        }
        
        if (self.script.len == 0) {
            return error.EmptyScript;
        }
        
        // Validate script is valid base64
        if (!isValidBase64(self.script)) {
            return error.InvalidScriptFormat;
        }
    }
    
    /// Checks if NEF is valid
    pub fn isValid(self: Self) bool {
        self.validate() catch return false;
        return true;
    }
    
    /// Gets script as bytes
    pub fn getScriptBytes(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try base64Decode(self.script, allocator);
    }
    
    /// Gets script size in bytes
    pub fn getScriptSize(self: Self, allocator: std.mem.Allocator) !usize {
        const script_bytes = try self.getScriptBytes(allocator);
        defer allocator.free(script_bytes);
        return script_bytes.len;
    }
    
    /// Checks if has method tokens
    pub fn hasMethodTokens(self: Self) bool {
        return self.tokens.len > 0;
    }
    
    /// Gets method token by name
    pub fn getMethodToken(self: Self, method_name: []const u8) ?ContractMethodToken {
        for (self.tokens) |token| {
            if (std.mem.eql(u8, token.method, method_name)) {
                return token;
            }
        }
        return null;
    }
    
    /// Gets all method names
    pub fn getMethodNames(self: Self, allocator: std.mem.Allocator) ![][]const u8 {
        var method_names = try std.ArrayList([]const u8).initCapacity(allocator, self.tokens.len);
        defer method_names.deinit();
        
        for (self.tokens) |token| {
            try method_names.append(token.method);
        }
        
        return try method_names.toOwnedSlice();
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const source_str = if (self.source) |source|
            try std.fmt.allocPrint(allocator, "\"{s}\"", .{source})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(source_str);
        
        // Encode tokens array
        var tokens_json = std.ArrayList(u8).init(allocator);
        defer tokens_json.deinit();
        
        try tokens_json.appendSlice("[");
        for (self.tokens, 0..) |token, i| {
            if (i > 0) try tokens_json.appendSlice(",");
            
            const token_json = try std.fmt.allocPrint(
                allocator,
                "{{\"hash\":\"{s}\",\"method\":\"{s}\",\"paramcount\":{},\"hasreturnvalue\":{},\"callflags\":{}}}",
                .{ token.hash, token.method, token.param_count, token.has_return_value, token.call_flags }
            );
            defer allocator.free(token_json);
            try tokens_json.appendSlice(token_json);
        }
        try tokens_json.appendSlice("]");
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"magic\":{},\"compiler\":\"{s}\",\"source\":{s},\"tokens\":{s},\"script\":\"{s}\",\"checksum\":{}}}",
            .{ self.magic, self.compiler, source_str, tokens_json.items, self.script, self.checksum }
        );
    }
    
    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        const magic = @as(u32, @intCast(json_obj.get("magic").?.integer));
        const compiler = try allocator.dupe(u8, json_obj.get("compiler").?.string);
        
        const source = if (json_obj.get("source")) |source_value|
            switch (source_value) {
                .string => |s| try allocator.dupe(u8, s),
                .null => null,
                else => null,
            }
        else
            null;
        
        // Parse tokens array
        const tokens_array = json_obj.get("tokens").?.array;
        var tokens = try std.ArrayList(ContractMethodToken).initCapacity(allocator, tokens_array.items.len);
        defer tokens.deinit();
        
        for (tokens_array.items) |token_value| {
            const token_obj = token_value.object;
            const hash = try allocator.dupe(u8, token_obj.get("hash").?.string);
            const method = try allocator.dupe(u8, token_obj.get("method").?.string);
            const param_count = @as(u16, @intCast(token_obj.get("paramcount").?.integer));
            const has_return_value = token_obj.get("hasreturnvalue").?.bool;
            const call_flags = @as(u8, @intCast(token_obj.get("callflags").?.integer));
            
            try tokens.append(ContractMethodToken.init(hash, method, param_count, has_return_value, call_flags));
        }
        
        const script = try allocator.dupe(u8, json_obj.get("script").?.string);
        const checksum = @as(u32, @intCast(json_obj.get("checksum").?.integer));
        
        return Self.init(magic, compiler, source, try tokens.toOwnedSlice(), script, checksum);
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.compiler);
        
        if (self.source) |source| {
            allocator.free(source);
        }
        
        for (self.tokens) |*token| {
            token.deinit(allocator);
        }
        allocator.free(self.tokens);
        
        allocator.free(self.script);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const compiler_copy = try allocator.dupe(u8, self.compiler);
        
        const source_copy = if (self.source) |source|
            try allocator.dupe(u8, source)
        else
            null;
        
        var tokens_copy = try std.ArrayList(ContractMethodToken).initCapacity(allocator, self.tokens.len);
        defer tokens_copy.deinit();
        
        for (self.tokens) |token| {
            try tokens_copy.append(try token.clone(allocator));
        }
        
        const script_copy = try allocator.dupe(u8, self.script);
        
        return Self.init(
            self.magic,
            compiler_copy,
            source_copy,
            try tokens_copy.toOwnedSlice(),
            script_copy,
            self.checksum
        );
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const script_size = self.getScriptSize(allocator) catch 0;
        
        return try std.fmt.allocPrint(
            allocator,
            "ContractNef(compiler: {s}, script: {} bytes, methods: {}, checksum: 0x{X})",
            .{ self.compiler, script_size, self.tokens.len, self.checksum }
        );
    }
};

/// Helper functions
fn isValidBase64(data: []const u8) bool {
    if (data.len == 0) return false;
    if (data.len % 4 != 0) return false;
    
    for (data) |char| {
        if (!std.base64.standard.Decoder.isValidChar(char) and char != '=') {
            return false;
        }
    }
    
    return true;
}

fn base64Decode(encoded: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(encoded);
    const decoded = try allocator.alloc(u8, decoded_len);
    try decoder.decode(decoded, encoded);
    return decoded;
}

// Tests (converted from Swift ContractNef tests)
test "ContractMethodToken creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test method token creation
    const hash = try allocator.dupe(u8, "0x1234567890abcdef");
    var token = ContractMethodToken.init(hash, "testMethod", 2, true, 0x01);
    defer token.deinit(allocator);
    
    try testing.expectEqualStrings("0x1234567890abcdef", token.hash);
    try testing.expectEqualStrings("testMethod", token.method);
    try testing.expectEqual(@as(u16, 2), token.param_count);
    try testing.expect(token.has_return_value);
    try testing.expectEqual(@as(u8, 0x01), token.call_flags);
    
    // Test cloning
    var cloned_token = try token.clone(allocator);
    defer cloned_token.deinit(allocator);
    
    try testing.expect(token.eql(cloned_token));
}

test "ContractNef creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test NEF creation (equivalent to Swift tests)
    const compiler = try allocator.dupe(u8, "neon");
    const source = try allocator.dupe(u8, "test.neo");
    const script = try allocator.dupe(u8, "VgEMDEhlbGxvIFdvcmxkIQ=="); // "Hello World!" in base64
    
    var nef = ContractNef.init(
        ContractNef.NEF_MAGIC,
        compiler,
        source,
        &[_]ContractMethodToken{},
        script,
        0x12345678
    );
    defer nef.deinit(allocator);
    
    try testing.expectEqual(ContractNef.NEF_MAGIC, nef.magic);
    try testing.expectEqualStrings("neon", nef.compiler);
    try testing.expectEqualStrings("test.neo", nef.source.?);
    try testing.expectEqual(@as(u32, 0x12345678), nef.checksum);
    try testing.expect(!nef.hasMethodTokens());
    
    // Test validation
    try nef.validate();
    try testing.expect(nef.isValid());
}

test "ContractNef with method tokens" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test NEF with method tokens
    const compiler = try allocator.dupe(u8, "neon");
    const script = try allocator.dupe(u8, "VgEMDEhlbGxvIFdvcmxkIQ==");
    
    const hash1 = try allocator.dupe(u8, "0x1111111111111111");
    const hash2 = try allocator.dupe(u8, "0x2222222222222222");
    const method1 = try allocator.dupe(u8, "method1");
    const method2 = try allocator.dupe(u8, "method2");
    
    var tokens = [_]ContractMethodToken{
        ContractMethodToken.init(hash1, method1, 1, true, 0x01),
        ContractMethodToken.init(hash2, method2, 2, false, 0x02),
    };
    defer {
        for (tokens) |*token| {
            token.deinit(allocator);
        }
    }
    
    var nef = ContractNef.init(
        ContractNef.NEF_MAGIC,
        compiler,
        null,
        &tokens,
        script,
        0xABCDEF00
    );
    defer nef.deinit(allocator);
    
    try testing.expect(nef.hasMethodTokens());
    try testing.expectEqual(@as(usize, 2), nef.tokens.len);
    
    // Test method lookup
    const found_method = nef.getMethodToken("method1").?;
    try testing.expectEqualStrings("method1", found_method.method);
    try testing.expectEqual(@as(u16, 1), found_method.param_count);
    
    const not_found = nef.getMethodToken("nonexistent");
    try testing.expect(not_found == null);
    
    // Test method names
    const method_names = try nef.getMethodNames(allocator);
    defer allocator.free(method_names);
    
    try testing.expectEqual(@as(usize, 2), method_names.len);
}

test "ContractNef validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test valid NEF
    const compiler = try allocator.dupe(u8, "neon");
    const script = try allocator.dupe(u8, "VgEMDEhlbGxvIFdvcmxkIQ==");
    
    var valid_nef = ContractNef.init(
        ContractNef.NEF_MAGIC,
        compiler,
        null,
        &[_]ContractMethodToken{},
        script,
        0x12345678
    );
    defer valid_nef.deinit(allocator);
    
    try valid_nef.validate();
    
    // Test invalid magic
    const invalid_compiler = try allocator.dupe(u8, "neon");
    const invalid_script = try allocator.dupe(u8, "VgEMDEhlbGxvIFdvcmxkIQ==");
    
    var invalid_nef = ContractNef.init(
        0x12345678, // Wrong magic
        invalid_compiler,
        null,
        &[_]ContractMethodToken{},
        invalid_script,
        0x12345678
    );
    defer invalid_nef.deinit(allocator);
    
    try testing.expectError(error.InvalidNefMagic, invalid_nef.validate());
    
    // Test empty compiler
    const empty_compiler = try allocator.dupe(u8, "");
    const empty_script = try allocator.dupe(u8, "VgEMDEhlbGxvIFdvcmxkIQ==");
    
    var empty_compiler_nef = ContractNef.init(
        ContractNef.NEF_MAGIC,
        empty_compiler,
        null,
        &[_]ContractMethodToken{},
        empty_script,
        0x12345678
    );
    defer empty_compiler_nef.deinit(allocator);
    
    try testing.expectError(error.EmptyCompilerInfo, empty_compiler_nef.validate());
}

test "ContractNef JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON encoding/decoding (equivalent to Swift Codable tests)
    const compiler = try allocator.dupe(u8, "neon");
    const source = try allocator.dupe(u8, "test.neo");
    const script = try allocator.dupe(u8, "VgEMDEhlbGxvIFdvcmxkIQ==");
    
    var original_nef = ContractNef.init(
        ContractNef.NEF_MAGIC,
        compiler,
        source,
        &[_]ContractMethodToken{},
        script,
        0x12345678
    );
    defer original_nef.deinit(allocator);
    
    const json_str = try original_nef.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(json_str.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_str, "neon") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "test.neo") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "VgEMDEhlbGxvIFdvcmxkIQ==") != null);
    
    var decoded_nef = try ContractNef.decodeFromJson(json_str, allocator);
    defer decoded_nef.deinit(allocator);
    
    try testing.expect(original_nef.eql(decoded_nef));
}

test "ContractNef utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test script bytes
    const compiler = try allocator.dupe(u8, "neon");
    const script = try allocator.dupe(u8, "VgEMDEhlbGxvIFdvcmxkIQ=="); // "Hello World!" in base64
    
    var nef = ContractNef.init(
        ContractNef.NEF_MAGIC,
        compiler,
        null,
        &[_]ContractMethodToken{},
        script,
        0x12345678
    );
    defer nef.deinit(allocator);
    
    const script_bytes = try nef.getScriptBytes(allocator);
    defer allocator.free(script_bytes);
    
    try testing.expect(script_bytes.len > 0);
    
    const script_size = try nef.getScriptSize(allocator);
    try testing.expectEqual(script_bytes.len, script_size);
    
    // Test formatting
    const formatted = try nef.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "ContractNef") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "neon") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "bytes") != null);
}