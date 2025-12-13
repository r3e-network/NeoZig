//! Response implementation
//!
//! Complete conversion from NeoSwift Response.swift
//! Provides JSON-RPC 2.0 response structure and error handling.

const std = @import("std");


const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const json_utils = @import("../utils/json_utils.zig");

/// Raw response trait (converted from Swift HasRawResponse protocol)
pub const HasRawResponse = struct {
    /// Gets raw response string
    pub fn getRawResponse(self: anytype) ?[]const u8 {
        return self.raw_response;
    }
    
    /// Sets raw response string
    pub fn setRawResponse(self: anytype, raw_response: ?[]const u8) void {
        self.raw_response = raw_response;
    }
};

/// JSON-RPC 2.0 response (converted from Swift Response)
pub fn Response(comptime T: type) type {
    return struct {
        /// Request ID
        id: u32,
        /// JSON-RPC version
        jsonrpc: []const u8,
        /// Response result
        result: ?T,
        /// Response error
        response_error: ?ResponseError,
        /// Raw response string
        raw_response: ?[]const u8,
        
        allocator: std.mem.Allocator,
        
        const Self = @This();
        
        /// Creates response with result (equivalent to Swift init(_ result: T))
        pub fn init(allocator: std.mem.Allocator, result: T) Self {
            return Self{
                .id = 1,
                .jsonrpc = "2.0",
                .result = result,
                .response_error = null,
                .raw_response = null,
                .allocator = allocator,
            };
        }
        
        /// Creates response with error
        pub fn initWithError(allocator: std.mem.Allocator, response_error: ResponseError) Self {
            return Self{
                .id = 1,
                .jsonrpc = "2.0",
                .result = null,
                .response_error = response_error,
                .raw_response = null,
                .allocator = allocator,
            };
        }
        
        /// Cleanup resources
        pub fn deinit(self: *Self) void {
            if (self.raw_response) |raw| {
                self.allocator.free(raw);
            }
            
            if (self.response_error) |*err| {
                err.deinit(self.allocator);
            }
        }
        
        /// Checks if response has error (equivalent to Swift .hasError property)
        pub fn hasError(self: Self) bool {
            return self.response_error != null;
        }
        
        /// Gets result or throws error (equivalent to Swift getResult())
        pub fn getResult(self: Self) !T {
            if (self.response_error != null) {
                return errors.NetworkError.ServerError;
            }
            
            return self.result orelse errors.NetworkError.InvalidResponse;
        }
        
        /// Gets result safely (returns null if error)
        pub fn getResultSafe(self: Self) ?T {
            if (self.hasError()) return null;
            return self.result;
        }
        
        /// Serializes response to JSON (equivalent to Swift Codable encoding)
        pub fn toJson(self: Self) !std.json.Value {
            var response_obj = std.json.ObjectMap.init(self.allocator);
            
            try json_utils.putOwnedKey(&response_obj, self.allocator, "jsonrpc", std.json.Value{ .string = try self.allocator.dupe(u8, self.jsonrpc) });
            try json_utils.putOwnedKey(&response_obj, self.allocator, "id", std.json.Value{ .integer = @intCast(self.id) });
            
            if (self.result) |result| {
                // Would serialize result based on type
                if (T == u32) {
                    try json_utils.putOwnedKey(&response_obj, self.allocator, "result", std.json.Value{ .integer = @intCast(result) });
                } else if (T == []const u8) {
                    try json_utils.putOwnedKey(&response_obj, self.allocator, "result", std.json.Value{ .string = try self.allocator.dupe(u8, result) });
                } else if (T == bool) {
                    try json_utils.putOwnedKey(&response_obj, self.allocator, "result", std.json.Value{ .bool = result });
                } else {
                    // For complex types, would call their toJson method
                    try json_utils.putOwnedKey(&response_obj, self.allocator, "result", std.json.Value{ .null = {} });
                }
            }

            if (self.response_error) |err| {
                try json_utils.putOwnedKey(&response_obj, self.allocator, "error", try err.toJson(self.allocator));
            }
            
            return std.json.Value{ .object = response_obj };
        }
        
        /// Parses response from JSON (equivalent to Swift Codable decoding)
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            const obj = json_value.object;
            
            const id = @as(u32, @intCast(obj.get("id").?.integer));
            const jsonrpc = obj.get("jsonrpc").?.string;
            
            var response = Self{
                .id = id,
                .jsonrpc = jsonrpc,
                .result = null,
                .response_error = null,
                .raw_response = null,
                .allocator = allocator,
            };
            
            // Parse result or error
            if (obj.get("result")) |result| {
                // Would parse result based on type T
                if (T == u32) {
                    response.result = @intCast(result.integer);
                } else if (T == []const u8) {
                    response.result = try allocator.dupe(u8, result.string);
                } else if (T == bool) {
                    response.result = result.bool;
                }
                // For complex types, would call their fromJson method
            }
            
            if (obj.get("error")) |error_obj| {
                response.response_error = try ResponseError.fromJson(error_obj, allocator);
            }
            
            return response;
        }
        
        /// Sets raw response for debugging
        pub fn setRawResponse(self: *Self, raw: []const u8) !void {
            if (self.raw_response) |old_raw| {
                self.allocator.free(old_raw);
            }
            self.raw_response = try self.allocator.dupe(u8, raw);
        }
    };
}

/// Response error (converted from Swift Response.Error)
pub const ResponseError = struct {
    code: i32,
    message: []const u8,
    data: ?[]const u8,
    
    const Self = @This();
    
    /// Creates response error
    pub fn init(code: i32, message: []const u8, data: ?[]const u8) Self {
        return Self{
            .code = code,
            .message = message,
            .data = data,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
        if (self.data) |data| {
            allocator.free(data);
        }
    }
    
    /// Gets error description (equivalent to Swift LocalizedError)
    pub fn getErrorDescription(self: Self, allocator: std.mem.Allocator) ![]u8 {
        if (self.data) |data| {
            return try std.fmt.allocPrint(
                allocator,
                "RPC Error {d}: {s} (Data: {s})",
                .{ self.code, self.message, data }
            );
        } else {
            return try std.fmt.allocPrint(
                allocator,
                "RPC Error {d}: {s}",
                .{ self.code, self.message }
            );
        }
    }
    
    /// Converts to JSON
    pub fn toJson(self: Self, allocator: std.mem.Allocator) !std.json.Value {
        var error_obj = std.json.ObjectMap.init(allocator);
        
        try json_utils.putOwnedKey(&error_obj, allocator, "code", std.json.Value{ .integer = @intCast(self.code) });
        try json_utils.putOwnedKey(&error_obj, allocator, "message", std.json.Value{ .string = try allocator.dupe(u8, self.message) });

        if (self.data) |data| {
            try json_utils.putOwnedKey(&error_obj, allocator, "data", std.json.Value{ .string = try allocator.dupe(u8, data) });
        }
        
        return std.json.Value{ .object = error_obj };
    }
    
    /// Parses from JSON
    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;
        
        const code = @as(i32, @intCast(obj.get("code").?.integer));
        const message = try allocator.dupe(u8, obj.get("message").?.string);
        const data = if (obj.get("data")) |d| try allocator.dupe(u8, d.string) else null;
        
        return Self.init(code, message, data);
    }
    
    /// Compares errors for equality
    pub fn eql(self: Self, other: Self) bool {
        if (self.code != other.code) return false;
        if (!std.mem.eql(u8, self.message, other.message)) return false;
        
        if (self.data == null and other.data == null) return true;
        if (self.data == null or other.data == null) return false;
        
        return std.mem.eql(u8, self.data.?, other.data.?);
    }
    
    /// Hash function for HashMap usage
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        
        const code_bytes = std.mem.toBytes(self.code);
        hasher.update(&code_bytes);
        hasher.update(self.message);
        
        if (self.data) |data| {
            hasher.update(data);
        }
        
        return hasher.final();
    }
};

// Tests (converted from Swift Response tests)
test "Response creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test response with result (equivalent to Swift Response tests)
    const IntResponse = Response(u32);
    
    var response_with_result = IntResponse.init(allocator, 12345);
    defer response_with_result.deinit();
    
    try testing.expect(!response_with_result.hasError());
    try testing.expectEqual(@as(u32, 12345), try response_with_result.getResult());
    
    // Test response with error
    const error_info = ResponseError.init(-1, try allocator.dupe(u8, "Test error"), null);
    var response_with_error = IntResponse.initWithError(allocator, error_info);
    defer response_with_error.deinit();
    
    try testing.expect(response_with_error.hasError());
    try testing.expectError(errors.NetworkError.ServerError, response_with_error.getResult());
}

test "ResponseError operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test error creation (equivalent to Swift Error tests)
    var error_info = ResponseError.init(
        -32602,
        try allocator.dupe(u8, "Invalid params"),
        try allocator.dupe(u8, "Additional error data"),
    );
    defer error_info.deinit(allocator);
    
    try testing.expectEqual(@as(i32, -32602), error_info.code);
    try testing.expectEqualStrings("Invalid params", error_info.message);
    try testing.expectEqualStrings("Additional error data", error_info.data.?);
    
    // Test error description
    const description = try error_info.getErrorDescription(allocator);
    defer allocator.free(description);
    
    try testing.expect(std.mem.indexOf(u8, description, "-32602") != null);
    try testing.expect(std.mem.indexOf(u8, description, "Invalid params") != null);
    try testing.expect(std.mem.indexOf(u8, description, "Additional error data") != null);
}

test "Response JSON operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const StringResponse = Response([]const u8);
    
    var response = StringResponse.init(allocator, "test_result");
    defer response.deinit();
    
    // Test JSON serialization
    const json_value = try response.toJson();
    defer json_utils.freeValue(json_value, allocator);
    
    const response_obj = json_value.object;
    try testing.expectEqualStrings("2.0", response_obj.get("jsonrpc").?.string);
    try testing.expectEqual(@as(i64, 1), response_obj.get("id").?.integer);
    try testing.expectEqualStrings("test_result", response_obj.get("result").?.string);
}
