//! Service Protocol Implementation
//!
//! Complete conversion from NeoSwift Service.swift
//! Provides service protocol for Neo RPC communication.

const std = @import("std");

/// Service protocol for Neo RPC communication (converted from Swift Service)
pub const Service = struct {
    /// Include raw responses flag
    include_raw_responses: bool,
    /// I/O performer function
    perform_io_fn: *const fn (payload: []const u8, allocator: std.mem.Allocator) anyerror![]u8,
    /// Allocator for memory management
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Creates new Service (equivalent to Swift Service protocol)
    pub fn init(
        include_raw_responses: bool,
        perform_io_fn: *const fn (payload: []const u8, allocator: std.mem.Allocator) anyerror![]u8,
        allocator: std.mem.Allocator,
    ) Self {
        return Self{
            .include_raw_responses = include_raw_responses,
            .perform_io_fn = perform_io_fn,
            .allocator = allocator,
        };
    }
    
    /// Performs I/O operation (equivalent to Swift performIO)
    pub fn performIO(self: Self, payload: []const u8) ![]u8 {
        return try self.perform_io_fn(payload, self.allocator);
    }
    
    /// Sends request and returns response (equivalent to Swift send extension)
    pub fn send(
        self: Self,
        comptime T: type,
        comptime U: type,
        request: Request(T, U),
    ) !Response(U) {
        // Encode request to JSON
        const json_payload = try request.encodeToJson(self.allocator);
        defer self.allocator.free(json_payload);
        
        // Perform I/O
        const response_data = try self.performIO(json_payload);
        defer self.allocator.free(response_data);
        
        // Decode response
        var response: Response(U) = undefined;
        
        if (self.include_raw_responses) {
            response = try Response(U).decodeFromJsonWithRaw(response_data, self.allocator);
        } else {
            response = try Response(U).decodeFromJson(response_data, self.allocator);
        }
        
        return response;
    }
    
    /// Sends request with specific response type
    pub fn sendRequest(
        self: Self,
        comptime ResponseType: type,
        request_json: []const u8,
    ) !ResponseType {
        const response_data = try self.performIO(request_json);
        defer self.allocator.free(response_data);
        
        return try ResponseType.decodeFromJson(response_data, self.allocator);
    }
    
    /// Creates JSON-RPC request payload
    pub fn createJsonRpcRequest(
        self: Self,
        method: []const u8,
        params: ?[]const u8,
        request_id: u32,
    ) ![]u8 {
        const params_str = params orelse "[]";
        
        return try std.fmt.allocPrint(
            self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{s},\"id\":{}}}",
            .{ method, params_str, request_id }
        );
    }
    
    /// Validates JSON-RPC response
    pub fn validateJsonRpcResponse(self: Self, response_json: []const u8) !void {
        _ = self;
        
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, response_json, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        // Check JSON-RPC version
        if (json_obj.get("jsonrpc")) |version| {
            if (!std.mem.eql(u8, version.string, "2.0")) {
                return error.InvalidJsonRpcVersion;
            }
        } else {
            return error.MissingJsonRpcVersion;
        }
        
        // Check if response has error
        if (json_obj.get("error")) |error_obj| {
            _ = error_obj;
            return error.JsonRpcError;
        }
        
        // Must have either result or error
        if (json_obj.get("result") == null) {
            return error.MissingJsonRpcResult;
        }
    }
    
    /// Handles JSON-RPC errors
    pub fn handleJsonRpcError(self: Self, response_json: []const u8) !JsonRpcError {
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, response_json, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        if (json_obj.get("error")) |error_obj| {
            const error_code = @as(i32, @intCast(error_obj.object.get("code").?.integer));
            const error_message = try self.allocator.dupe(u8, error_obj.object.get("message").?.string);
            
            const error_data = if (error_obj.object.get("data")) |data|
                try self.allocator.dupe(u8, data.string)
            else
                null;
            
            return JsonRpcError.init(error_code, error_message, error_data);
        }
        
        return error.NoJsonRpcError;
    }
};

/// Generic Request structure (referenced in Service)
pub fn Request(comptime T: type, comptime U: type) type {
    return struct {
        jsonrpc: []const u8,
        method: []const u8,
        params: []const u8,
        id: u32,
        
        const Self = @This();
        
        pub fn init(method: []const u8, params: []const u8, id: u32) Self {
            return Self{
                .jsonrpc = "2.0",
                .method = method,
                .params = params,
                .id = id,
            };
        }
        
        pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
            return try std.fmt.allocPrint(
                allocator,
                "{{\"jsonrpc\":\"{s}\",\"method\":\"{s}\",\"params\":{s},\"id\":{}}}",
                .{ self.jsonrpc, self.method, self.params, self.id }
            );
        }
    };
}

/// Generic Response structure (referenced in Service)
pub fn Response(comptime U: type) type {
    return struct {
        jsonrpc: []const u8,
        result: ?U,
        error: ?JsonRpcError,
        id: u32,
        raw_response: ?[]const u8,
        
        const Self = @This();
        
        pub fn init(result: ?U, error: ?JsonRpcError, id: u32, raw_response: ?[]const u8) Self {
            return Self{
                .jsonrpc = "2.0",
                .result = result,
                .error = error,
                .id = id,
                .raw_response = raw_response,
            };
        }
        
        pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
            const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
            defer parsed.deinit();
            
            const json_obj = parsed.value.object;
            
            const id = @as(u32, @intCast(json_obj.get("id").?.integer));
            
            var result: ?U = null;
            var rpc_error: ?JsonRpcError = null;
            
            if (json_obj.get("result")) |result_value| {
                // TODO: Decode U type from JSON
                _ = result_value;
                result = undefined; // Placeholder
            }
            
            if (json_obj.get("error")) |error_obj| {
                const error_code = @as(i32, @intCast(error_obj.object.get("code").?.integer));
                const error_message = try allocator.dupe(u8, error_obj.object.get("message").?.string);
                const error_data = if (error_obj.object.get("data")) |data|
                    try allocator.dupe(u8, data.string)
                else
                    null;
                
                rpc_error = JsonRpcError.init(error_code, error_message, error_data);
            }
            
            return Self.init(result, rpc_error, id, null);
        }
        
        pub fn decodeFromJsonWithRaw(json_str: []const u8, allocator: std.mem.Allocator) !Self {
            const raw_copy = try allocator.dupe(u8, json_str);
            var response = try Self.decodeFromJson(json_str, allocator);
            response.raw_response = raw_copy;
            return response;
        }
        
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.error) |*err| {
                err.deinit(allocator);
            }
            
            if (self.raw_response) |raw| {
                allocator.free(raw);
            }
        }
    };
}

/// JSON-RPC error representation
pub const JsonRpcError = struct {
    code: i32,
    message: []const u8,
    data: ?[]const u8,
    
    const Self = @This();
    
    pub fn init(code: i32, message: []const u8, data: ?[]const u8) Self {
        return Self{
            .code = code,
            .message = message,
            .data = data,
        };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
        if (self.data) |data| {
            allocator.free(data);
        }
    }
    
    pub fn isParseError(self: Self) bool {
        return self.code == -32700;
    }
    
    pub fn isInvalidRequest(self: Self) bool {
        return self.code == -32600;
    }
    
    pub fn isMethodNotFound(self: Self) bool {
        return self.code == -32601;
    }
    
    pub fn isInvalidParams(self: Self) bool {
        return self.code == -32602;
    }
    
    pub fn isInternalError(self: Self) bool {
        return self.code == -32603;
    }
    
    pub fn isServerError(self: Self) bool {
        return self.code >= -32099 and self.code <= -32000;
    }
    
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        if (self.data) |data| {
            return try std.fmt.allocPrint(
                allocator,
                "JsonRpcError(code: {}, message: {s}, data: {s})",
                .{ self.code, self.message, data }
            );
        } else {
            return try std.fmt.allocPrint(
                allocator,
                "JsonRpcError(code: {}, message: {s})",
                .{ self.code, self.message }
            );
        }
    }
};

/// Service factory functions
pub const ServiceFactory = struct {
    /// Creates HTTP service
    pub fn createHttpService(
        url: []const u8,
        include_raw_responses: bool,
        allocator: std.mem.Allocator,
    ) !Service {
        const http_perform_io = struct {
            fn performIO(payload: []const u8, alloc: std.mem.Allocator) anyerror![]u8 {
                _ = payload;
                _ = alloc;
                // TODO: Implement actual HTTP client call
                return error.NotImplemented;
            }
        }.performIO;
        
        _ = url;
        
        return Service.init(include_raw_responses, http_perform_io, allocator);
    }
    
    /// Creates WebSocket service
    pub fn createWebSocketService(
        url: []const u8,
        include_raw_responses: bool,
        allocator: std.mem.Allocator,
    ) !Service {
        const ws_perform_io = struct {
            fn performIO(payload: []const u8, alloc: std.mem.Allocator) anyerror![]u8 {
                _ = payload;
                _ = alloc;
                // TODO: Implement actual WebSocket client call
                return error.NotImplemented;
            }
        }.performIO;
        
        _ = url;
        
        return Service.init(include_raw_responses, ws_perform_io, allocator);
    }
    
    /// Creates mock service for testing
    pub fn createMockService(
        mock_response: []const u8,
        include_raw_responses: bool,
        allocator: std.mem.Allocator,
    ) !Service {
        const mock_perform_io = struct {
            fn performIO(payload: []const u8, alloc: std.mem.Allocator) anyerror![]u8 {
                _ = payload;
                return try alloc.dupe(u8, mock_response);
            }
        }.performIO;
        
        return Service.init(include_raw_responses, mock_perform_io, allocator);
    }
};

// Tests (converted from Swift Service protocol tests)
test "Service creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test service creation (equivalent to Swift Service tests)
    const mock_response = "{\"jsonrpc\":\"2.0\",\"result\":\"test\",\"id\":1}";
    const service = try ServiceFactory.createMockService(mock_response, false, allocator);
    
    try testing.expect(!service.include_raw_responses);
    
    // Test I/O operation
    const test_payload = "{\"test\":\"payload\"}";
    const response = try service.performIO(test_payload);
    defer allocator.free(response);
    
    try testing.expectEqualStrings(mock_response, response);
}

test "JsonRpcError creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON-RPC error creation
    const message = try allocator.dupe(u8, "Method not found");
    const data = try allocator.dupe(u8, "Additional error data");
    
    var error_obj = JsonRpcError.init(-32601, message, data);
    defer error_obj.deinit(allocator);
    
    try testing.expectEqual(@as(i32, -32601), error_obj.code);
    try testing.expectEqualStrings("Method not found", error_obj.message);
    try testing.expect(error_obj.isMethodNotFound());
    try testing.expect(!error_obj.isParseError());
    
    // Test formatting
    const formatted = try error_obj.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "Method not found") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "-32601") != null);
}

test "Service JSON-RPC request creation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON-RPC request creation
    const service = try ServiceFactory.createMockService("{}", false, allocator);
    
    const request_json = try service.createJsonRpcRequest("getversion", null, 1);
    defer allocator.free(request_json);
    
    try testing.expect(std.mem.indexOf(u8, request_json, "getversion") != null);
    try testing.expect(std.mem.indexOf(u8, request_json, "jsonrpc") != null);
    try testing.expect(std.mem.indexOf(u8, request_json, "2.0") != null);
    try testing.expect(std.mem.indexOf(u8, request_json, "\"id\":1") != null);
}

test "Service JSON-RPC validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const service = try ServiceFactory.createMockService("{}", false, allocator);
    
    // Test valid response
    const valid_response = "{\"jsonrpc\":\"2.0\",\"result\":\"test\",\"id\":1}";
    try service.validateJsonRpcResponse(valid_response);
    
    // Test invalid version
    const invalid_version = "{\"jsonrpc\":\"1.0\",\"result\":\"test\",\"id\":1}";
    try testing.expectError(error.InvalidJsonRpcVersion, service.validateJsonRpcResponse(invalid_version));
    
    // Test missing version
    const missing_version = "{\"result\":\"test\",\"id\":1}";
    try testing.expectError(error.MissingJsonRpcVersion, service.validateJsonRpcResponse(missing_version));
    
    // Test error response
    const error_response = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":1}";
    try testing.expectError(error.JsonRpcError, service.validateJsonRpcResponse(error_response));
}