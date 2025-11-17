//! Request implementation
//!
//! Complete conversion from NeoSwift Request.swift
//! Provides JSON-RPC 2.0 request structure and handling.

const std = @import("std");
const ArrayList = std.array_list.Managed;
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const json_utils = @import("../utils/json_utils.zig");

/// Request counter for generating unique IDs
var request_counter = std.atomic.Value(u32).init(1);

/// Gets and increments request counter (thread-safe)
pub fn getAndIncrementRequestId() u32 {
    return request_counter.fetchAdd(1, .seq_cst);
}

/// JSON-RPC 2.0 request (converted from Swift Request)
pub fn Request(comptime T: type, comptime U: type) type {
    return struct {
        /// JSON-RPC version (constant)
        jsonrpc: []const u8 = "2.0",
        /// RPC method name
        method: []const u8,
        /// Whether the method string is heap allocated
        owns_method: bool,
        /// RPC parameters
        params: std.json.Array,
        /// Request ID
        id: u32,
        allocator: std.mem.Allocator,

        const Self = @This();

        /// Creates request (equivalent to Swift init)
        pub fn init(
            allocator: std.mem.Allocator,
            method: []const u8,
            params: []const std.json.Value,
        ) !Self {
            var params_array = std.json.Array.init(allocator);
            errdefer {
                for (params_array.items) |value| {
                    json_utils.freeValue(value, allocator);
                }
                params_array.deinit();
            }

            try params_array.ensureTotalCapacity(params.len);
            for (params) |param| {
                const cloned = try json_utils.cloneValue(param, allocator);
                try params_array.append(cloned);
            }

            const method_copy = try allocator.dupe(u8, method);

            return Self{
                .method = method_copy,
                .owns_method = true,
                .params = params_array,
                .id = getAndIncrementRequestId(),
                .allocator = allocator,
            };
        }

        /// Releases resources owned by the request
        pub fn deinit(self: *Self) void {
            var array = self.params;
            for (array.items) |value| {
                json_utils.freeValue(value, self.allocator);
            }
            array.deinit();
            self.params = std.json.Array.init(self.allocator);

            if (self.owns_method) {
                self.allocator.free(@constCast(self.method));
                self.owns_method = false;
            }
            self.method = "";
        }

        /// Sends request (equivalent to Swift send())
        pub fn sendUsing(self: *Self, service: anytype) !T {
            defer self.deinit();
            return try service.send(T, U, self);
        }

        /// Serializes request to JSON (equivalent to Swift Codable encoding)
        pub fn toJson(self: *const Self) !std.json.Value {
            var request_obj = std.json.ObjectMap.init(self.allocator);
            errdefer {
                const cleanup_value = std.json.Value{ .object = request_obj };
                json_utils.freeValue(cleanup_value, self.allocator);
            }

            const jsonrpc_key = try self.allocator.dupe(u8, "jsonrpc");
            var jsonrpc_key_inserted = false;
            errdefer if (!jsonrpc_key_inserted) self.allocator.free(jsonrpc_key);
            const jsonrpc_copy = try self.allocator.dupe(u8, self.jsonrpc);
            var jsonrpc_inserted = false;
            errdefer if (!jsonrpc_inserted) self.allocator.free(jsonrpc_copy);
            try request_obj.put(jsonrpc_key, std.json.Value{ .string = jsonrpc_copy });
            jsonrpc_key_inserted = true;
            jsonrpc_inserted = true;

            const method_key = try self.allocator.dupe(u8, "method");
            var method_key_inserted = false;
            errdefer if (!method_key_inserted) self.allocator.free(method_key);
            const method_copy = try self.allocator.dupe(u8, self.method);
            var method_inserted = false;
            errdefer if (!method_inserted) self.allocator.free(method_copy);
            try request_obj.put(method_key, std.json.Value{ .string = method_copy });
            method_key_inserted = true;
            method_inserted = true;

            var params_copy = std.json.Array.init(self.allocator);
            var params_owned = false;
            errdefer if (!params_owned) {
                const cleanup = std.json.Value{ .array = params_copy };
                json_utils.freeValue(cleanup, self.allocator);
            };

            try params_copy.ensureTotalCapacity(self.params.items.len);
            for (self.params.items) |param| {
                try params_copy.append(try json_utils.cloneValue(param, self.allocator));
            }

            const params_key = try self.allocator.dupe(u8, "params");
            var params_key_inserted = false;
            errdefer if (!params_key_inserted) self.allocator.free(params_key);
            try request_obj.put(params_key, std.json.Value{ .array = params_copy });
            params_key_inserted = true;
            params_owned = true;

            const id_key = try self.allocator.dupe(u8, "id");
            var id_key_inserted = false;
            errdefer if (!id_key_inserted) self.allocator.free(id_key);
            try request_obj.put(id_key, std.json.Value{ .integer = @intCast(self.id) });
            id_key_inserted = true;

            return std.json.Value{ .object = request_obj };
        }

        /// Parses request from JSON (equivalent to Swift Codable decoding)
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
            const obj = json_value.object;

            const method = try allocator.dupe(u8, obj.get("method").?.string);
            const id = @as(u32, @intCast(obj.get("id").?.integer));

            var params = ArrayList(std.json.Value).init(allocator);
            if (obj.get("params")) |params_array| {
                for (params_array.array) |param| {
                    try params.append(param);
                }
            }

            const params_slice = try params.toOwnedSlice();
            defer allocator.free(params_slice);

            var self_instance = try Self.init(allocator, method, params_slice);
            self_instance.id = id;
            // Self.init duplicated method already; free the temporary duplicate.
            allocator.free(method);
            return self_instance;
        }

        /// Gets method name
        pub fn getMethod(self: Self) []const u8 {
            return self.method;
        }

        /// Gets parameters
        pub fn getParams(self: Self) []const std.json.Value {
            return self.params.items;
        }

        /// Gets request ID
        pub fn getId(self: Self) u32 {
            return self.id;
        }

        /// Validates request structure
        pub fn validate(self: Self) !void {
            if (self.method.len == 0) {
                return errors.ValidationError.InvalidParameter;
            }

            if (!std.mem.eql(u8, self.jsonrpc, "2.0")) {
                return errors.ValidationError.InvalidParameter;
            }
        }

        /// Creates request with string parameters (utility method)
        pub fn withStringParams(
            allocator: std.mem.Allocator,
            method: []const u8,
            string_params: []const []const u8,
        ) !Self {
            var params = try allocator.alloc(std.json.Value, string_params.len);
            defer allocator.free(params);

            for (string_params, 0..) |param, i| {
                params[i] = std.json.Value{ .string = param };
            }

            return try Self.init(allocator, method, params);
        }

        /// Creates request with integer parameters (utility method)
        pub fn withIntegerParams(
            allocator: std.mem.Allocator,
            method: []const u8,
            int_params: []const i64,
        ) !Self {
            var params = try allocator.alloc(std.json.Value, int_params.len);
            defer allocator.free(params);

            for (int_params, 0..) |param, i| {
                params[i] = std.json.Value{ .integer = param };
            }

            return try Self.init(allocator, method, params);
        }

        /// Creates request with no parameters (utility method)
        pub fn withNoParams(
            allocator: std.mem.Allocator,
            method: []const u8,
        ) !Self {
            return try Self.init(allocator, method, &[_]std.json.Value{});
        }
    };
}

/// Request utilities
pub const RequestUtils = struct {
    /// Validates JSON-RPC request format
    pub fn validateJsonRpcRequest(json_str: []const u8, allocator: std.mem.Allocator) !void {
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch {
            return errors.ValidationError.InvalidFormat;
        };
        defer parsed.deinit();

        if (parsed.value != .object) {
            return errors.ValidationError.InvalidFormat;
        }

        const obj = parsed.value.object;

        // Check required fields
        const jsonrpc = obj.get("jsonrpc") orelse return errors.ValidationError.InvalidFormat;
        if (!std.mem.eql(u8, jsonrpc.string, "2.0")) {
            return errors.ValidationError.InvalidFormat;
        }

        _ = obj.get("method") orelse return errors.ValidationError.InvalidFormat;
        _ = obj.get("id") orelse return errors.ValidationError.InvalidFormat;

        // params is optional but should be array if present
        if (obj.get("params")) |params| {
            if (params != .array) {
                return errors.ValidationError.InvalidFormat;
            }
        }
    }

    /// Creates batch request
    pub fn createBatchRequest(
        requests: []const std.json.Value,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        var batch_array = std.json.Array.init(allocator);
        errdefer batch_array.deinit();

        try batch_array.ensureTotalCapacity(requests.len);
        for (requests) |value| {
            try batch_array.append(try json_utils.cloneValue(value, allocator));
        }

        const batch_json = std.json.Value{ .array = batch_array };
        var writer_state = std.Io.Writer.Allocating.init(allocator);
        defer writer_state.deinit();

        var stringify = std.json.Stringify{ .writer = &writer_state.writer, .options = .{} };
        try stringify.write(batch_json);

        const result = try writer_state.toOwnedSlice();

        for (batch_array.items) |entry| {
            json_utils.freeValue(entry, allocator);
        }
        batch_array.deinit();

        return result;
    }

    /// Parses batch response
    pub fn parseBatchResponse(response_body: []const u8, allocator: std.mem.Allocator) ![]std.json.Value {
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, response_body, .{});
        defer parsed.deinit();

        if (parsed.value != .array) {
            return errors.ValidationError.InvalidFormat;
        }

        const response_array = parsed.value.array;
        var results = try allocator.alloc(std.json.Value, response_array.items.len);
        errdefer allocator.free(results);

        for (response_array.items, 0..) |item, i| {
            results[i] = try json_utils.cloneValue(item, allocator);
        }

        return results;
    }
};

// Tests (converted from Swift Request tests)
test "Request creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Create test service

    // Test request creation (equivalent to Swift Request tests)
    const TestResponse = struct {
        result: ?u32,

        pub fn init() @This() {
            return @This(){ .result = null };
        }
    };

    const TestRequest = Request(TestResponse, u32);

    const params = [_]std.json.Value{
        std.json.Value{ .integer = 12345 },
    };

    var request = try TestRequest.init(allocator, "getblockcount", &params);
    defer request.deinit();

    try testing.expectEqualStrings("2.0", request.jsonrpc);
    try testing.expectEqualStrings("getblockcount", request.method);
    try testing.expectEqual(@as(usize, 1), request.getParams().len);
    try testing.expect(request.id > 0);

    // Test request validation
    try request.validate();
}

test "Request JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const TestResponse = struct {
        result: ?[]const u8,
        pub fn init() @This() {
            return @This(){ .result = null };
        }
    };

    const TestRequest = Request(TestResponse, []const u8);

    const params = [_]std.json.Value{
        std.json.Value{ .string = "test_param" },
    };

    var request = try TestRequest.init(allocator, "testmethod", &params);
    defer request.deinit();

    // Test JSON conversion
    const json_value = try request.toJson();
    defer json_utils.freeValue(json_value, allocator);

    const request_obj = json_value.object;
    try testing.expectEqualStrings("2.0", request_obj.get("jsonrpc").?.string);
    try testing.expectEqualStrings("testmethod", request_obj.get("method").?.string);

    const params_array = request_obj.get("params").?.array;
    try testing.expectEqual(@as(usize, 1), params_array.items.len);
    try testing.expectEqualStrings("test_param", params_array.items[0].string);
}

test "Request utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test JSON-RPC validation (equivalent to Swift validation tests)
    const valid_request =
        \\{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}
    ;
    try RequestUtils.validateJsonRpcRequest(valid_request, allocator);

    // Test invalid requests
    const invalid_version =
        \\{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}
    ;
    try testing.expectError(errors.ValidationError.InvalidFormat, RequestUtils.validateJsonRpcRequest(invalid_version, allocator));

    const missing_method =
        \\{"jsonrpc":"2.0","params":[],"id":1}
    ;
    try testing.expectError(errors.ValidationError.InvalidFormat, RequestUtils.validateJsonRpcRequest(missing_method, allocator));

    // Test batch request creation
    const requests = [_]std.json.Value{
        std.json.Value{ .object = std.json.ObjectMap.init(allocator) },
        std.json.Value{ .object = std.json.ObjectMap.init(allocator) },
    };

    const batch_json = try RequestUtils.createBatchRequest(&requests, allocator);
    defer allocator.free(batch_json);

    try testing.expect(batch_json.len > 0);
    try testing.expect(std.mem.startsWith(u8, batch_json, "["));
    try testing.expect(std.mem.endsWith(u8, batch_json, "]"));
}
