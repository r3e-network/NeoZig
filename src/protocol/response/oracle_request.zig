//! Oracle Request Implementation
//!
//! Complete conversion from NeoSwift OracleRequest.swift
//! Provides oracle request structure for Neo blockchain oracles.

const std = @import("std");


const Hash160 = @import("../../types/hash160.zig").Hash160;
const Hash256 = @import("../../types/hash256.zig").Hash256;

/// Oracle request structure (converted from Swift OracleRequest)
pub const OracleRequest = struct {
    /// Request ID
    request_id: u64,
    /// Original transaction hash that created this request
    original_transaction_hash: Hash256,
    /// Gas allocated for response
    gas_for_response: u64,
    /// URL to fetch data from
    url: []const u8,
    /// JSONPath filter for response data
    filter: []const u8,
    /// Callback contract hash
    callback_contract: Hash160,
    /// Callback method name
    callback_method: []const u8,
    /// User data (base64 encoded)
    user_data: []const u8,
    
    const Self = @This();
    
    /// Creates new oracle request (equivalent to Swift init)
    pub fn init(
        request_id: u64,
        original_transaction_hash: Hash256,
        gas_for_response: u64,
        url: []const u8,
        filter: []const u8,
        callback_contract: Hash160,
        callback_method: []const u8,
        user_data: []const u8,
    ) Self {
        return Self{
            .request_id = request_id,
            .original_transaction_hash = original_transaction_hash,
            .gas_for_response = gas_for_response,
            .url = url,
            .filter = filter,
            .callback_contract = callback_contract,
            .callback_method = callback_method,
            .user_data = user_data,
        };
    }
    
    /// Gets request ID
    pub fn getRequestId(self: Self) u64 {
        return self.request_id;
    }
    
    /// Gets original transaction hash
    pub fn getOriginalTransactionHash(self: Self) Hash256 {
        return self.original_transaction_hash;
    }
    
    /// Gets gas for response
    pub fn getGasForResponse(self: Self) u64 {
        return self.gas_for_response;
    }
    
    /// Gets URL
    pub fn getUrl(self: Self) []const u8 {
        return self.url;
    }
    
    /// Gets filter
    pub fn getFilter(self: Self) []const u8 {
        return self.filter;
    }
    
    /// Gets callback contract
    pub fn getCallbackContract(self: Self) Hash160 {
        return self.callback_contract;
    }
    
    /// Gets callback method
    pub fn getCallbackMethod(self: Self) []const u8 {
        return self.callback_method;
    }
    
    /// Gets user data
    pub fn getUserData(self: Self) []const u8 {
        return self.user_data;
    }
    
    /// Checks if request has user data
    pub fn hasUserData(self: Self) bool {
        return self.user_data.len > 0;
    }
    
    /// Checks if request has filter
    pub fn hasFilter(self: Self) bool {
        return self.filter.len > 0;
    }
    
    /// Validates oracle request
    pub fn validate(self: Self) !void {
        if (self.url.len == 0) {
            return error.EmptyUrl;
        }
        
        if (self.callback_method.len == 0) {
            return error.EmptyCallbackMethod;
        }
        
        if (self.gas_for_response == 0) {
            return error.ZeroGasForResponse;
        }
        
        try self.callback_contract.validate();
        try self.original_transaction_hash.validate();
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return self.request_id == other.request_id and
               self.original_transaction_hash.eql(other.original_transaction_hash) and
               self.gas_for_response == other.gas_for_response and
               std.mem.eql(u8, self.url, other.url) and
               std.mem.eql(u8, self.filter, other.filter) and
               self.callback_contract.eql(other.callback_contract) and
               std.mem.eql(u8, self.callback_method, other.callback_method) and
               std.mem.eql(u8, self.user_data, other.user_data);
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&self.request_id));
        
        const tx_hash = self.original_transaction_hash.hash();
        hasher.update(std.mem.asBytes(&tx_hash));
        
        hasher.update(std.mem.asBytes(&self.gas_for_response));
        hasher.update(self.url);
        hasher.update(self.filter);
        
        const contract_hash = self.callback_contract.hash();
        hasher.update(std.mem.asBytes(&contract_hash));
        
        hasher.update(self.callback_method);
        hasher.update(self.user_data);
        
        return hasher.final();
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const tx_hash_str = try self.original_transaction_hash.toString(allocator);
        defer allocator.free(tx_hash_str);
        
        const callback_contract_str = try self.callback_contract.toString(allocator);
        defer allocator.free(callback_contract_str);
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"requestid\":{},\"originaltxid\":\"{s}\",\"gasforresponse\":{},\"url\":\"{s}\",\"filter\":\"{s}\",\"callbackcontract\":\"{s}\",\"callbackmethod\":\"{s}\",\"userdata\":\"{s}\"}}",
            .{
                self.request_id,
                tx_hash_str,
                self.gas_for_response,
                self.url,
                self.filter,
                callback_contract_str,
                self.callback_method,
                self.user_data,
            }
        );
    }
    
    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        const request_id = @as(u64, @intCast(json_obj.get("requestid").?.integer));
        
        const original_tx_hash_str = json_obj.get("originaltxid").?.string;
        const original_transaction_hash = try Hash256.initWithString(original_tx_hash_str);
        
        const gas_for_response = @as(u64, @intCast(json_obj.get("gasforresponse").?.integer));
        
        const url = try allocator.dupe(u8, json_obj.get("url").?.string);
        const filter = try allocator.dupe(u8, json_obj.get("filter").?.string);
        
        const callback_contract_str = json_obj.get("callbackcontract").?.string;
        const callback_contract = try Hash160.initWithString(callback_contract_str);
        
        const callback_method = try allocator.dupe(u8, json_obj.get("callbackmethod").?.string);
        const user_data = try allocator.dupe(u8, json_obj.get("userdata").?.string);
        
        return Self.init(
            request_id,
            original_transaction_hash,
            gas_for_response,
            url,
            filter,
            callback_contract,
            callback_method,
            user_data,
        );
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        allocator.free(self.filter);
        allocator.free(self.callback_method);
        allocator.free(self.user_data);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const url_copy = try allocator.dupe(u8, self.url);
        const filter_copy = try allocator.dupe(u8, self.filter);
        const callback_method_copy = try allocator.dupe(u8, self.callback_method);
        const user_data_copy = try allocator.dupe(u8, self.user_data);
        
        return Self.init(
            self.request_id,
            self.original_transaction_hash,
            self.gas_for_response,
            url_copy,
            filter_copy,
            self.callback_contract,
            callback_method_copy,
            user_data_copy,
        );
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "OracleRequest(id: {}, url: {s}, callback: {s}, gas: {})",
            .{ self.request_id, self.url, self.callback_method, self.gas_for_response }
        );
    }
    
    /// Gets estimated response size
    pub fn getEstimatedResponseSize(self: Self) usize {
        // Estimate based on URL and filter complexity
        return self.url.len + self.filter.len + 1024; // Base overhead
    }
    
    /// Checks if request is for HTTPS URL
    pub fn isHttpsUrl(self: Self) bool {
        return std.mem.startsWith(u8, self.url, "https://");
    }
    
    /// Checks if request has complex filter
    pub fn hasComplexFilter(self: Self) bool {
        return std.mem.indexOf(u8, self.filter, "[") != null or
               std.mem.indexOf(u8, self.filter, ".") != null;
    }
};

// Tests (converted from Swift OracleRequest tests)
test "OracleRequest creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test oracle request creation (equivalent to Swift tests)
    const original_tx_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    const callback_contract = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    var request = OracleRequest.init(
        12345,
        original_tx_hash,
        1000000,
        "https://api.example.com/data",
        "$.result",
        callback_contract,
        "callback",
        "test_data",
    );
    
    try testing.expectEqual(@as(u64, 12345), request.getRequestId());
    try testing.expect(request.getOriginalTransactionHash().eql(original_tx_hash));
    try testing.expectEqual(@as(u64, 1000000), request.getGasForResponse());
    try testing.expectEqualStrings("https://api.example.com/data", request.getUrl());
    try testing.expectEqualStrings("$.result", request.getFilter());
    try testing.expect(request.getCallbackContract().eql(callback_contract));
    try testing.expectEqualStrings("callback", request.getCallbackMethod());
    try testing.expectEqualStrings("test_data", request.getUserData());
    
    // Test boolean checks
    try testing.expect(request.hasUserData());
    try testing.expect(request.hasFilter());
    try testing.expect(request.isHttpsUrl());
    try testing.expect(request.hasComplexFilter()); // Has "." in filter
    
    // Test validation
    try request.validate();
}

test "OracleRequest equality and hashing" {
    const testing = std.testing;
    
    // Test equality (equivalent to Swift Hashable tests)
    const tx_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    const request1 = OracleRequest.init(111, tx_hash, 1000, "https://api.test.com", "$.data", contract_hash, "process", "user");
    const request2 = OracleRequest.init(111, tx_hash, 1000, "https://api.test.com", "$.data", contract_hash, "process", "user");
    const request3 = OracleRequest.init(222, tx_hash, 1000, "https://api.test.com", "$.data", contract_hash, "process", "user");
    
    try testing.expect(request1.eql(request2));
    try testing.expect(!request1.eql(request3));
    
    // Test hashing
    const hash1 = request1.hash();
    const hash2 = request2.hash();
    const hash3 = request3.hash();
    
    try testing.expectEqual(hash1, hash2); // Same requests should have same hash
    try testing.expectNotEqual(hash1, hash3); // Different requests should have different hash
}

test "OracleRequest validation" {
    const testing = std.testing;
    
    const tx_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    // Test valid request
    const valid_request = OracleRequest.init(123, tx_hash, 1000, "https://api.com", "$.data", contract_hash, "callback", "data");
    try valid_request.validate();
    
    // Test invalid request (empty URL)
    const invalid_url_request = OracleRequest.init(123, tx_hash, 1000, "", "$.data", contract_hash, "callback", "data");
    try testing.expectError(error.EmptyUrl, invalid_url_request.validate());
    
    // Test invalid request (empty callback method)
    const invalid_method_request = OracleRequest.init(123, tx_hash, 1000, "https://api.com", "$.data", contract_hash, "", "data");
    try testing.expectError(error.EmptyCallbackMethod, invalid_method_request.validate());
    
    // Test invalid request (zero gas)
    const zero_gas_request = OracleRequest.init(123, tx_hash, 0, "https://api.com", "$.data", contract_hash, "callback", "data");
    try testing.expectError(error.ZeroGasForResponse, zero_gas_request.validate());
}

test "OracleRequest JSON serialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON encoding/decoding (equivalent to Swift Codable tests)
    const tx_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    const original_request = OracleRequest.init(
        99999,
        tx_hash,
        2000000,
        "https://api.test.com/endpoint",
        "$.result.value",
        contract_hash,
        "processData",
        "base64_user_data",
    );
    
    const json_str = try original_request.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(json_str.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_str, "99999") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "https://api.test.com/endpoint") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "processData") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "requestid") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "originaltxid") != null);
    
    var decoded_request = try OracleRequest.decodeFromJson(json_str, allocator);
    defer decoded_request.deinit(allocator);
    
    try testing.expect(original_request.eql(decoded_request));
}

test "OracleRequest utility methods" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test formatting
    const tx_hash = try Hash256.initWithString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12");
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    const request = OracleRequest.init(
        777,
        tx_hash,
        500000,
        "https://data.api.com",
        "$.price",
        contract_hash,
        "updatePrice",
        "price_data",
    );
    
    const formatted = try request.format(allocator);
    defer allocator.free(formatted);
    
    try testing.expect(std.mem.indexOf(u8, formatted, "OracleRequest") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "777") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "https://data.api.com") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "updatePrice") != null);
    
    // Test estimated size
    const estimated_size = request.getEstimatedResponseSize();
    try testing.expect(estimated_size > 1000); // Should include base overhead
    
    // Test cloning
    var cloned_request = try request.clone(allocator);
    defer cloned_request.deinit(allocator);
    
    try testing.expect(request.eql(cloned_request));
}