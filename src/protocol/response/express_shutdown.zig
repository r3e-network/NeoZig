//! Express Shutdown Implementation
//!
//! Complete conversion from NeoSwift ExpressShutdown.swift
//! Provides shutdown response for Neo-express development nodes.

const std = @import("std");

/// Express shutdown response (converted from Swift ExpressShutdown)
pub const ExpressShutdown = struct {
    /// Process ID of the shutdown node
    process_id: u32,
    
    const Self = @This();
    
    /// Creates new ExpressShutdown (equivalent to Swift init)
    pub fn init(process_id: u32) Self {
        return Self{
            .process_id = process_id,
        };
    }
    
    /// Gets process ID
    pub fn getProcessId(self: Self) u32 {
        return self.process_id;
    }
    
    /// Checks if shutdown was successful (process ID > 0)
    pub fn isSuccessful(self: Self) bool {
        return self.process_id > 0;
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return self.process_id == other.process_id;
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&self.process_id));
        return hasher.final();
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "{{\"process-id\":{}}}",
            .{self.process_id}
        );
    }
    
    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        // Handle both "process-id" and "processId" for compatibility
        const process_id = if (json_obj.get("process-id")) |value|
            @as(u32, @intCast(value.integer))
        else if (json_obj.get("processId")) |value|
            @as(u32, @intCast(value.integer))
        else
            return error.MissingProcessId;
        
        return Self.init(process_id);
    }
    
    /// Decodes from string (equivalent to Swift StringDecode property wrapper)
    pub fn decodeFromString(process_id_str: []const u8) !Self {
        const process_id = try std.fmt.parseInt(u32, process_id_str, 10);
        return Self.init(process_id);
    }
    
    /// Encodes to string (equivalent to Swift StringDecode property wrapper)
    pub fn encodeToString(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "{}", .{self.process_id});
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const status = if (self.isSuccessful()) "successful" else "failed";
        
        return try std.fmt.allocPrint(
            allocator,
            "ExpressShutdown(process_id: {}, status: {s})",
            .{ self.process_id, status }
        );
    }
    
    /// Creates from shutdown result
    pub fn fromShutdownResult(success: bool) Self {
        return Self.init(if (success) 1 else 0);
    }
    
    /// Creates success response
    pub fn success(process_id: u32) Self {
        return Self.init(process_id);
    }
    
    /// Creates failure response
    pub fn failure() Self {
        return Self.init(0);
    }
    
    /// Validates shutdown response
    pub fn validate(self: Self) !void {
        // Basic validation - process IDs should be reasonable
        if (self.process_id > 999999) {
            return error.InvalidProcessId;
        }
    }
    
    /// Gets shutdown status message
    pub fn getStatusMessage(self: Self, allocator: std.mem.Allocator) ![]u8 {
        if (self.isSuccessful()) {
            return try std.fmt.allocPrint(
                allocator,
                "Neo-express node shutdown successfully (process ID: {})",
                .{self.process_id}
            );
        } else {
            return try allocator.dupe(u8, "Neo-express node shutdown failed");
        }
    }
};

// Tests (converted from Swift ExpressShutdown tests)
test "ExpressShutdown creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test shutdown creation (equivalent to Swift tests)
    const shutdown = ExpressShutdown.init(12345);
    
    try testing.expectEqual(@as(u32, 12345), shutdown.getProcessId());
    try testing.expect(shutdown.isSuccessful());
    
    // Test validation
    try shutdown.validate();
    
    // Test failed shutdown
    const failed_shutdown = ExpressShutdown.failure();
    try testing.expectEqual(@as(u32, 0), failed_shutdown.getProcessId());
    try testing.expect(!failed_shutdown.isSuccessful());
    
    // Test success factory
    const success_shutdown = ExpressShutdown.success(9999);
    try testing.expect(success_shutdown.isSuccessful());
    try testing.expectEqual(@as(u32, 9999), success_shutdown.getProcessId());
}

test "ExpressShutdown equality and hashing" {
    const testing = std.testing;
    
    // Test equality (equivalent to Swift Hashable tests)
    const shutdown1 = ExpressShutdown.init(111);
    const shutdown2 = ExpressShutdown.init(111);
    const shutdown3 = ExpressShutdown.init(222);
    
    try testing.expect(shutdown1.eql(shutdown2));
    try testing.expect(!shutdown1.eql(shutdown3));
    
    // Test hashing
    const hash1 = shutdown1.hash();
    const hash2 = shutdown2.hash();
    const hash3 = shutdown3.hash();
    
    try testing.expectEqual(hash1, hash2); // Same shutdowns should have same hash
    try testing.expectNotEqual(hash1, hash3); // Different shutdowns should have different hash
}

test "ExpressShutdown JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON encoding/decoding (equivalent to Swift Codable tests)
    const original_shutdown = ExpressShutdown.init(54321);
    
    const json_str = try original_shutdown.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(json_str.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_str, "54321") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "process-id") != null);
    
    const decoded_shutdown = try ExpressShutdown.decodeFromJson(json_str, allocator);
    try testing.expect(original_shutdown.eql(decoded_shutdown));
}

test "ExpressShutdown string conversion" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test string encoding/decoding (equivalent to Swift StringDecode tests)
    const shutdown = ExpressShutdown.init(67890);
    
    const string_value = try shutdown.encodeToString(allocator);
    defer allocator.free(string_value);
    
    try testing.expectEqualStrings("67890", string_value);
    
    const decoded_shutdown = try ExpressShutdown.decodeFromString(string_value);
    try testing.expect(shutdown.eql(decoded_shutdown));
}

test "ExpressShutdown utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test formatting
    const shutdown = ExpressShutdown.init(13579);
    
    const formatted = try shutdown.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "ExpressShutdown") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "13579") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "successful") != null);
    
    // Test status message
    const status_message = try shutdown.getStatusMessage(allocator);
    defer allocator.free(status_message);
    
    try testing.expect(std.mem.indexOf(u8, status_message, "shutdown successfully") != null);
    try testing.expect(std.mem.indexOf(u8, status_message, "13579") != null);
    
    // Test failed shutdown status
    const failed_shutdown = ExpressShutdown.failure();
    const failed_message = try failed_shutdown.getStatusMessage(allocator);
    defer allocator.free(failed_message);
    
    try testing.expect(std.mem.indexOf(u8, failed_message, "shutdown failed") != null);
}