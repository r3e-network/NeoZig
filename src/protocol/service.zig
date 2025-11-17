//! Service Protocol Implementation
//!
//! Complete conversion from NeoSwift Service.swift
//! Provides service protocol for Neo RPC communication.

const std = @import("std");
const ArrayList = std.array_list.Managed;
const meta = std.meta;
const json_utils = @import("../utils/json_utils.zig");

const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const HttpClient = @import("../rpc/http_client.zig").HttpClient;

const HttpContext = struct {
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    client: HttpClient,
};

const WebSocketContext = struct {
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    client: HttpClient,
};

const MockContext = struct {
    allocator: std.mem.Allocator,
    response: []const u8,
};

fn stringifyJsonValue(value: std.json.Value, allocator: std.mem.Allocator) ![]u8 {
    var buffer = ArrayList(u8).init(allocator);
    defer buffer.deinit();

    var stringify = std.json.Stringify{ .writer = buffer.writer(), .options = .{} };
    try stringify.write(value);

    return try buffer.toOwnedSlice();
}

fn decodeResultValue(comptime U: type, value: std.json.Value, allocator: std.mem.Allocator) !U {
    if (comptime U == std.json.Value) {
        return try json_utils.cloneValue(value, allocator);
    }

    if (comptime meta.trait.isUnsignedInt(U) or meta.trait.isSignedInt(U)) {
        switch (value) {
            .integer => |int_value| return @as(U, @intCast(int_value)),
            .string => |str| return std.fmt.parseInt(U, str, 10) catch return error.InvalidJsonRpcResult,
            else => return error.InvalidJsonRpcResult,
        }
    }

    if (comptime meta.trait.isFloat(U)) {
        switch (value) {
            .float => |float_value| return @floatCast(U, float_value),
            .integer => |int_value| return @floatFromInt(U, int_value),
            .string => |str| return std.fmt.parseFloat(U, str) catch return error.InvalidJsonRpcResult,
            else => return error.InvalidJsonRpcResult,
        }
    }

    if (comptime U == bool) {
        switch (value) {
            .bool => |b| return b,
            .integer => |i| return i != 0,
            .string => |s| return std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "1"),
            else => return error.InvalidJsonRpcResult,
        }
    }

    if (comptime meta.trait.isSlice(U) and meta.Child(U) == u8) {
        return switch (value) {
            .string => |s| try allocator.dupe(u8, s),
            else => blk: {
                const rendered = try stringifyJsonValue(value, allocator);
                break :blk rendered;
            },
        };
    }

    if (comptime U == Hash160) {
        if (value != .string) return error.InvalidJsonRpcResult;
        return try Hash160.initWithString(value.string);
    }

    if (comptime U == Hash256) {
        if (value != .string) return error.InvalidJsonRpcResult;
        return try Hash256.initWithString(value.string);
    }

    if (comptime @hasDecl(U, "fromJson")) {
        const func = U.fromJson;
        const info = @typeInfo(@TypeOf(func)).Fn;
        if (info.params.len == 2) {
            const param0 = info.params[0].type.?;
            const param1 = info.params[1].type.?;
            if (param0 == std.json.Value and param1 == std.mem.Allocator) {
                return try func(value, allocator);
            }
            if (param0 == []const u8 and param1 == std.mem.Allocator) {
                const rendered = try stringifyJsonValue(value, allocator);
                defer allocator.free(rendered);
                return try func(rendered, allocator);
            }
        } else if (info.params.len == 1 and info.params[0].type.? == std.json.Value) {
            return try func(value);
        }
    }

    if (comptime @hasDecl(U, "decodeFromJson")) {
        const func = U.decodeFromJson;
        const info = @typeInfo(@TypeOf(func)).Fn;
        if (info.params.len == 2) {
            const param0 = info.params[0].type.?;
            const param1 = info.params[1].type.?;
            if (param0 == std.json.Value and param1 == std.mem.Allocator) {
                return try func(value, allocator);
            }
            if (param0 == []const u8 and param1 == std.mem.Allocator) {
                const rendered = try stringifyJsonValue(value, allocator);
                defer allocator.free(rendered);
                return try func(rendered, allocator);
            }
        }
    }

    return error.UnsupportedResultType;
}

fn httpPerformIO(context_ptr: ?*anyopaque, payload: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const ctx = @ptrCast(*HttpContext, context_ptr.?);
    _ = allocator; // HttpClient manages allocations internally
    return ctx.client.post(payload);
}

fn normalizeWebSocketEndpoint(url: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    if (std.mem.startsWith(u8, url, "ws://")) {
        const remainder = url[5..];
        return try std.fmt.allocPrint(allocator, "http://{s}", .{remainder});
    }
    if (std.mem.startsWith(u8, url, "wss://")) {
        const remainder = url[6..];
        return try std.fmt.allocPrint(allocator, "https://{s}", .{remainder});
    }
    return try allocator.dupe(u8, url);
}

fn httpContextCleanup(context_ptr: ?*anyopaque, allocator: std.mem.Allocator) void {
    _ = allocator;
    if (context_ptr) |ptr| {
        const ctx = @ptrCast(*HttpContext, ptr);
        if (ctx.endpoint.len > 0) ctx.allocator.free(ctx.endpoint);
        ctx.allocator.destroy(ctx);
    }
}

fn websocketPerformIO(context_ptr: ?*anyopaque, payload: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const ctx = @ptrCast(*WebSocketContext, context_ptr.?);
    _ = allocator; // HttpClient manages its own allocator usage
    return ctx.client.post(payload);
}

fn websocketContextCleanup(context_ptr: ?*anyopaque, allocator: std.mem.Allocator) void {
    _ = allocator;
    if (context_ptr) |ptr| {
        const ctx = @ptrCast(*WebSocketContext, ptr);
        if (ctx.endpoint.len > 0) ctx.allocator.free(ctx.endpoint);
        ctx.allocator.destroy(ctx);
    }
}

fn mockPerformIO(context_ptr: ?*anyopaque, payload: []const u8, allocator: std.mem.Allocator) ![]u8 {
    _ = payload;
    const ctx = @ptrCast(*MockContext, context_ptr.?);
    return try allocator.dupe(u8, ctx.response);
}

fn mockContextCleanup(context_ptr: ?*anyopaque, allocator: std.mem.Allocator) void {
    _ = allocator;
    if (context_ptr) |ptr| {
        const ctx = @ptrCast(*MockContext, ptr);
        if (ctx.response.len > 0) ctx.allocator.free(ctx.response);
        ctx.allocator.destroy(ctx);
    }
}
/// Service protocol for Neo RPC communication (converted from Swift Service)
pub const Service = struct {
    /// Include raw responses flag
    include_raw_responses: bool,
    /// I/O performer function
    perform_io_fn: *const fn (context: ?*anyopaque, payload: []const u8, allocator: std.mem.Allocator) anyerror![]u8,
    /// Optional context passed to perform function
    perform_context: ?*anyopaque,
    /// Allocator for memory management
    allocator: std.mem.Allocator,
    /// Optional cleanup hook for custom contexts
    cleanup_fn: ?*const fn (context: ?*anyopaque, allocator: std.mem.Allocator) void,

    const Self = @This();

    /// Creates new Service (equivalent to Swift Service protocol)
    pub fn init(
        include_raw_responses: bool,
        perform_io_fn: *const fn (context: ?*anyopaque, payload: []const u8, allocator: std.mem.Allocator) anyerror![]u8,
        perform_context: ?*anyopaque,
        allocator: std.mem.Allocator,
        cleanup_fn: ?*const fn (context: ?*anyopaque, allocator: std.mem.Allocator) void,
    ) Self {
        return Self{
            .include_raw_responses = include_raw_responses,
            .perform_io_fn = perform_io_fn,
            .perform_context = perform_context,
            .allocator = allocator,
            .cleanup_fn = cleanup_fn,
        };
    }

    /// Performs I/O operation (equivalent to Swift performIO)
    pub fn performIO(self: Self, payload: []const u8) ![]u8 {
        return try self.perform_io_fn(self.perform_context, payload, self.allocator);
    }

    /// Releases any resources owned by the service instance
    pub fn deinit(self: *Self) void {
        if (self.cleanup_fn) |cleanup| {
            cleanup(self.perform_context, self.allocator);
        }
        self.perform_context = null;
        self.cleanup_fn = null;
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

        return try std.fmt.allocPrint(self.allocator, "{{\"jsonrpc\":\"2.0\",\"method\":\"{s}\",\"params\":{s},\"id\":{}}}", .{ method, params_str, request_id });
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
    _ = T;
    _ = U;
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
            return try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"{s}\",\"method\":\"{s}\",\"params\":{s},\"id\":{}}}", .{ self.jsonrpc, self.method, self.params, self.id });
        }
    };
}

/// Generic Response structure (referenced in Service)
pub fn Response(comptime U: type) type {
    return struct {
        jsonrpc: []const u8,
        owns_jsonrpc: bool,
        result: ?U,
        rpc_error: ?JsonRpcError,
        id: u32,
        raw_response: ?[]const u8,

        const Self = @This();

        pub fn init(result: ?U, rpc_error: ?JsonRpcError, id: u32, raw_response: ?[]const u8) Self {
            return Self{
                .jsonrpc = "2.0",
                .owns_jsonrpc = false,
                .result = result,
                .rpc_error = rpc_error,
                .id = id,
                .raw_response = raw_response,
            };
        }

        pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
            const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
            defer parsed.deinit();

            const json_obj = parsed.value.object;

            const jsonrpc_field = json_obj.get("jsonrpc") orelse return error.MissingJsonRpcVersion;
            const id = @as(u32, @intCast(json_obj.get("id").?.integer));

            var result: ?U = null;
            var response_error: ?JsonRpcError = null;

            if (json_obj.get("result")) |result_value| {
                if (result_value == .null) {
                    result = null;
                } else {
                    result = try decodeResultValue(U, result_value, allocator);
                }
            }

            if (json_obj.get("error")) |error_obj| {
                const error_code = @as(i32, @intCast(error_obj.object.get("code").?.integer));
                const error_message = try allocator.dupe(u8, error_obj.object.get("message").?.string);
                const error_data = if (error_obj.object.get("data")) |data|
                    try allocator.dupe(u8, data.string)
                else
                    null;

                response_error = JsonRpcError.init(error_code, error_message, error_data);
            }

            const jsonrpc_copy = try allocator.dupe(u8, jsonrpc_field.string);

            return Self{
                .jsonrpc = jsonrpc_copy,
                .owns_jsonrpc = true,
                .result = result,
                .rpc_error = response_error,
                .id = id,
                .raw_response = null,
            };
        }

        pub fn decodeFromJsonWithRaw(json_str: []const u8, allocator: std.mem.Allocator) !Self {
            const raw_copy = try allocator.dupe(u8, json_str);
            var response = try Self.decodeFromJson(json_str, allocator);
            response.raw_response = raw_copy;
            return response;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.owns_jsonrpc and self.jsonrpc.len > 0) allocator.free(self.jsonrpc);
            if (self.rpc_error) |*err| {
                err.deinit(allocator);
            }

            if (self.result) |*res| {
                if (comptime @hasDecl(U, "deinit")) {
                    res.deinit(allocator);
                } else if (comptime meta.trait.isSlice(U) and meta.Child(U) == u8) {
                    if (res.len > 0) allocator.free(@constCast(res.*));
                }
                self.result = null;
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
            return try std.fmt.allocPrint(allocator, "JsonRpcError(code: {}, message: {s}, data: {s})", .{ self.code, self.message, data });
        } else {
            return try std.fmt.allocPrint(allocator, "JsonRpcError(code: {}, message: {s})", .{ self.code, self.message });
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
        const endpoint = try allocator.dupe(u8, url);
        errdefer allocator.free(endpoint);
        const context = try allocator.create(HttpContext);
        context.* = .{
            .allocator = allocator,
            .endpoint = endpoint,
            .client = HttpClient.init(allocator, endpoint),
        };

        return Service.init(include_raw_responses, httpPerformIO, context, allocator, httpContextCleanup);
    }

    /// Creates WebSocket service
    pub fn createWebSocketService(
        url: []const u8,
        include_raw_responses: bool,
        allocator: std.mem.Allocator,
    ) !Service {
        const endpoint = try normalizeWebSocketEndpoint(url, allocator);
        errdefer allocator.free(endpoint);
        const context = try allocator.create(WebSocketContext);
        context.* = .{ .allocator = allocator, .endpoint = endpoint };

        context.client = HttpClient.init(allocator, endpoint);

        return Service.init(include_raw_responses, websocketPerformIO, context, allocator, websocketContextCleanup);
    }

    /// Creates mock service for testing
    pub fn createMockService(
        mock_response: []const u8,
        include_raw_responses: bool,
        allocator: std.mem.Allocator,
    ) !Service {
        const response_copy = try allocator.dupe(u8, mock_response);
        errdefer allocator.free(response_copy);
        const context = try allocator.create(MockContext);
        context.* = .{
            .allocator = allocator,
            .response = response_copy,
        };

        return Service.init(include_raw_responses, mockPerformIO, context, allocator, mockContextCleanup);
    }
};

// Tests (converted from Swift Service protocol tests)
test "Service creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test service creation (equivalent to Swift Service tests)
    const mock_response = "{\"jsonrpc\":\"2.0\",\"result\":\"test\",\"id\":1}";
    var service = try ServiceFactory.createMockService(mock_response, false, allocator);
    defer service.deinit();

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

test "Response decode basic types" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const json = "{\"jsonrpc\":\"2.0\",\"result\":42,\"id\":1}";
    var response_u32 = try Response(u32).decodeFromJson(json, allocator);
    defer response_u32.deinit(allocator);
    try testing.expectEqual(@as(u32, 42), response_u32.result.?);

    const json_bool = "{\"jsonrpc\":\"2.0\",\"result\":true,\"id\":2}";
    var response_bool = try Response(bool).decodeFromJson(json_bool, allocator);
    defer response_bool.deinit(allocator);
    try testing.expect(response_bool.result.?);
}

test "Response decode using fromJson" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Sample = struct {
        value: i32,

        pub fn fromJson(json_value: std.json.Value, allocator2: std.mem.Allocator) !Sample {
            _ = allocator2;
            return Sample{ .value = @as(i32, @intCast(json_value.object.get("value").?.integer)) };
        }

        pub fn deinit(self: *Sample, allocator2: std.mem.Allocator) void {
            _ = self;
            _ = allocator2;
        }
    };

    const json = "{\"jsonrpc\":\"2.0\",\"result\":{\"value\":99},\"id\":3}";
    var response_struct = try Response(Sample).decodeFromJson(json, allocator);
    defer response_struct.deinit(allocator);
    try testing.expectEqual(@as(i32, 99), response_struct.result.?.value);
}

test "Service JSON-RPC request creation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test JSON-RPC request creation
    var service = try ServiceFactory.createMockService("{}", false, allocator);
    defer service.deinit();

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

    var service = try ServiceFactory.createMockService("{}", false, allocator);
    defer service.deinit();

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
