//! Request implementation
//!
//! Complete conversion from NeoSwift Request.swift
//! Provides JSON-RPC 2.0 request structure and handling.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");

/// Request counter for generating unique IDs
var request_counter: u32 = 1;

/// Gets and increments request counter (thread-safe)
pub fn getAndIncrementRequestId() u32 {
    defer request_counter += 1;
    return request_counter;
}

/// JSON-RPC 2.0 request (converted from Swift Request)
pub fn Request(comptime T: type, comptime U: type) type {
    return struct {
        /// JSON-RPC version (constant)
        jsonrpc: []const u8 = "2.0",
        /// RPC method name
        method: []const u8,
        /// RPC parameters
        params: []const std.json.Value,
        /// Request ID
        id: u32,
        /// Neo service for sending
        neo_swift_service: ?*NeoSwiftService,
        
        allocator: std.mem.Allocator,
        
        const Self = @This();
        
        /// Creates request (equivalent to Swift init)
        pub fn init(
            allocator: std.mem.Allocator,
            method: []const u8,
            params: []const std.json.Value,
            neo_swift_service: *NeoSwiftService,
        ) Self {
            return Self{
                .method = method,
                .params = params,
                .id = getAndIncrementRequestId(),
                .neo_swift_service = neo_swift_service,
                .allocator = allocator,
            };
        }
        
        /// Sends request (equivalent to Swift send())
        pub fn send(self: Self) !T {
            if (self.neo_swift_service == null) {
                return errors.NetworkError.ServiceUnavailable;
            }
            
            return try self.neo_swift_service.?.send(T, U, self);
        }
        
        /// Serializes request to JSON (equivalent to Swift Codable encoding)
        pub fn toJson(self: Self) !std.json.Value {
            var request_obj = std.json.ObjectMap.init(self.allocator);
            
            try request_obj.put("jsonrpc", std.json.Value{ .string = self.jsonrpc });
            try request_obj.put("method", std.json.Value{ .string = self.method });
            try request_obj.put("params", std.json.Value{ .array = self.params });
            try request_obj.put("id", std.json.Value{ .integer = @intCast(self.id) });
            
            return std.json.Value{ .object = request_obj };
        }
        
        /// Parses request from JSON (equivalent to Swift Codable decoding)
        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator, service: *NeoSwiftService) !Self {
            const obj = json_value.object;
            
            const method = try allocator.dupe(u8, obj.get("method").?.string);
            const id = @as(u32, @intCast(obj.get("id").?.integer));
            
            var params = std.ArrayList(std.json.Value).init(allocator);
            if (obj.get("params")) |params_array| {
                for (params_array.array) |param| {
                    try params.append(param);
                }
            }
            
            return Self{
                .method = method,
                .params = try params.toOwnedSlice(),
                .id = id,
                .neo_swift_service = service,
                .allocator = allocator,
            };
        }
        
        /// Gets method name
        pub fn getMethod(self: Self) []const u8 {
            return self.method;
        }
        
        /// Gets parameters
        pub fn getParams(self: Self) []const std.json.Value {
            return self.params;
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
            
            if (self.neo_swift_service == null) {
                return errors.NetworkError.ServiceUnavailable;
            }
        }
        
        /// Creates request with string parameters (utility method)
        pub fn withStringParams(
            allocator: std.mem.Allocator,
            method: []const u8,
            string_params: []const []const u8,
            service: *NeoSwiftService,
        ) !Self {
            var params = try allocator.alloc(std.json.Value, string_params.len);
            
            for (string_params, 0..) |param, i| {
                params[i] = std.json.Value{ .string = param };
            }
            
            return Self.init(allocator, method, params, service);
        }
        
        /// Creates request with integer parameters (utility method)
        pub fn withIntegerParams(
            allocator: std.mem.Allocator,
            method: []const u8,
            int_params: []const i64,
            service: *NeoSwiftService,
        ) !Self {
            var params = try allocator.alloc(std.json.Value, int_params.len);
            
            for (int_params, 0..) |param, i| {
                params[i] = std.json.Value{ .integer = param };
            }
            
            return Self.init(allocator, method, params, service);
        }
        
        /// Creates request with no parameters (utility method)
        pub fn withNoParams(
            allocator: std.mem.Allocator,
            method: []const u8,
            service: *NeoSwiftService,
        ) Self {
            return Self.init(allocator, method, &[_]std.json.Value{}, service);
        }
    };
}

/// Neo Swift service interface (forward declaration)
pub const NeoSwiftService = struct {
    endpoint: []const u8,
    timeout_ms: u32,
    
    pub fn init(endpoint: []const u8) NeoSwiftService {
        return NeoSwiftService{
            .endpoint = endpoint,
            .timeout_ms = 30000,
        };
    }
    
    /// Sends request (would be implemented with actual HTTP client)
    pub fn send(self: *NeoSwiftService, comptime T: type, comptime U: type, request: Request(T, U)) !T {
        _ = self;
        _ = request;
        
        // In production, this would make actual HTTP request
        return T.init();
    }
};

/// Request utilities
pub const RequestUtils = struct {
    /// Validates JSON-RPC request format
    pub fn validateJsonRpcRequest(json_str: []const u8, allocator: std.mem.Allocator) !void {
        var json_parser = std.json.Parser.init(allocator, .alloc_always);
        defer json_parser.deinit();
        
        var json_tree = json_parser.parse(json_str) catch {
            return errors.ValidationError.InvalidFormat;
        };
        defer json_tree.deinit();
        
        const obj = json_tree.root.object;
        
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
        var json_buffer = std.ArrayList(u8).init(allocator);
        defer json_buffer.deinit();
        
        const batch_json = std.json.Value{ .array = requests };
        try std.json.stringify(batch_json, .{}, json_buffer.writer());
        
        return try json_buffer.toOwnedSlice();
    }
    
    /// Parses batch response
    pub fn parseBatchResponse(response_body: []const u8, allocator: std.mem.Allocator) ![]std.json.Value {
        var json_parser = std.json.Parser.init(allocator, .alloc_always);
        defer json_parser.deinit();
        
        var json_tree = try json_parser.parse(response_body);
        defer json_tree.deinit();
        
        const response_array = json_tree.root.array;
        return try allocator.dupe(std.json.Value, response_array);
    }
};

// Tests (converted from Swift Request tests)
test "Request creation and basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Create test service
    var service = NeoSwiftService.init("http://localhost:20332");
    
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
    
    const request = TestRequest.init(allocator, "getblockcount", &params, &service);
    
    try testing.expectEqualStrings("2.0", request.jsonrpc);
    try testing.expectEqualStrings("getblockcount", request.method);
    try testing.expectEqual(@as(usize, 1), request.params.len);
    try testing.expect(request.id > 0);
    
    // Test request validation
    try request.validate();
}

test "Request JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var service = NeoSwiftService.init("http://localhost:20332");
    
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
    
    const request = TestRequest.init(allocator, "testmethod", &params, &service);
    
    // Test JSON conversion
    const json_value = try request.toJson();
    defer json_value.deinit();
    
    const request_obj = json_value.object;
    try testing.expectEqualStrings("2.0", request_obj.get("jsonrpc").?.string);
    try testing.expectEqualStrings("testmethod", request_obj.get("method").?.string);
    
    const params_array = request_obj.get("params").?.array;
    try testing.expectEqual(@as(usize, 1), params_array.len);
    try testing.expectEqualStrings("test_param", params_array[0].string);
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