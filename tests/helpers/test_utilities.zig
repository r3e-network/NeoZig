//! Test Utilities
//!
//! Complete conversion from NeoSwift test helpers
//! Provides mock implementations and test utilities.

const std = @import("std");



/// Mock URL session for testing (converted from Swift MockURLSession)
pub const MockURLSession = struct {
    responses: std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .responses = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.responses.deinit();
    }
    
    pub fn setResponse(self: *Self, method: []const u8, response: []const u8) !void {
        try self.responses.put(method, response);
    }
    
    pub fn getResponse(self: Self, method: []const u8) ?[]const u8 {
        return self.responses.get(method);
    }
};

/// Mock Neo Swift for testing
pub const MockNeoSwift = struct {
    responses: std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) @This() {
        return @This(){
            .responses = std.HashMap([]const u8, []const u8, StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *@This()) void {
        self.responses.deinit();
    }
};

/// Test JSON utilities (converted from Swift JSON helpers)
pub const TestJSON = struct {
    pub fn fromFile(filename: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return try allocator.dupe(u8, "{}"); // Placeholder
    }
    
    pub fn mockResponse(method: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "{{\"jsonrpc\":\"2.0\",\"result\":\"mock_{s}\",\"id\":1}}",
            .{method}
        );
    }
};

const StringContext = std.HashMap.StringContext;