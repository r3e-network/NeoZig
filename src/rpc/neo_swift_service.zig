//! Neo Swift Service implementation
//!
//! Complete conversion from NeoSwift NeoSwiftService.swift protocol
//! Provides service interface for Neo RPC operations.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Request = @import("request.zig").Request;
const json_utils = @import("../utils/json_utils.zig");
const Response = @import("response.zig").Response;

/// Neo Swift service protocol (converted from Swift NeoSwiftService)
pub const NeoSwiftService = struct {
    /// Service implementation
    service_impl: ServiceImplementation,

    const Self = @This();

    fn initFromUrl(url: []const u8) Self {
        const allocator = std.heap.page_allocator;
        const http_service = allocator.create(@import("http_service.zig").HttpService) catch unreachable;
        http_service.* = @import("http_service.zig").HttpService.init(allocator, url, false);
        const impl = ServiceImplementation.init(http_service, allocator, true);
        return Self{ .service_impl = impl };
    }

    /// Creates Neo Swift service.
    /// Accepts either a `ServiceImplementation` or an endpoint URL string.
    /// When passed a URL, the service is created with `std.heap.page_allocator`
    /// as a convenience for tests and quick-start usage.
    pub fn init(arg: anytype) Self {
        const Arg = @TypeOf(arg);
        if (Arg == ServiceImplementation) return Self{ .service_impl = arg };
        if (Arg == *ServiceImplementation) return Self{ .service_impl = arg.* };
        if (Arg == []const u8) return initFromUrl(arg);
        if (Arg == []u8) return initFromUrl(arg);

        switch (@typeInfo(Arg)) {
            .pointer => |ptr_info| switch (ptr_info.size) {
                .one => switch (@typeInfo(ptr_info.child)) {
                    .array => |array_info| {
                        if (array_info.child == u8) return initFromUrl(arg[0..]);
                    },
                    else => {},
                },
                .slice => if (ptr_info.child == u8) return initFromUrl(arg[0..]),
                else => {},
            },
            .array => |array_info| {
                if (array_info.child == u8) return initFromUrl(arg[0..]);
            },
            else => {},
        }

        @compileError("Unsupported NeoSwiftService.init argument");
    }

    /// Releases owned resources
    pub fn deinit(self: *Self) void {
        self.service_impl.deinit();
    }

    /// Sends request (equivalent to Swift send<T: Response<U>, U>(_ request: Request<T, U>))
    pub fn send(
        self: *Self,
        comptime T: type,
        comptime U: type,
        request: *Request(T, U),
    ) !T {
        return try self.service_impl.performRequest(T, U, request);
    }

    /// Sends batch requests (additional utility)
    pub fn sendBatch(
        self: *Self,
        requests: []const std.json.Value,
        allocator: std.mem.Allocator,
    ) ![]std.json.Value {
        return try self.service_impl.performBatchRequest(requests, allocator);
    }

    /// Validates service connectivity
    pub fn validateConnectivity(self: *Self) !bool {
        return try self.service_impl.checkConnectivity();
    }

    /// Gets service configuration
    pub fn getConfiguration(self: Self) ServiceConfiguration {
        return self.service_impl.getConfiguration();
    }

    /// Sets service timeout
    pub fn setTimeout(self: *Self, timeout_ms: u32) void {
        self.service_impl.setTimeout(timeout_ms);
    }

    /// Sets the maximum response body size captured into memory.
    /// Passing 0 resets to the default cap.
    pub fn setMaxResponseBytes(self: *Self, max_response_bytes: usize) void {
        self.service_impl.setMaxResponseBytes(max_response_bytes);
    }

    /// Gets service statistics
    pub fn getStatistics(self: Self) ServiceStatistics {
        return self.service_impl.getStatistics();
    }

    pub fn getAllocator(self: Self) std.mem.Allocator {
        return self.service_impl.http_service.allocator;
    }

    /// Marks this wrapper as no longer owning the underlying transport.
    /// Useful when transferring ownership to another component.
    pub fn relinquish(self: *Self) void {
        self.service_impl.owns_http_service = false;
    }
};

/// Service implementation interface
pub const ServiceImplementation = struct {
    /// HTTP service reference
    http_service: *@import("http_service.zig").HttpService,
    /// Ownership flag for http_service
    owns_http_service: bool,
    /// Allocator used to manage http_service lifetime
    allocator: std.mem.Allocator,
    /// Request counter
    request_counter: u32,
    /// Statistics
    statistics: ServiceStatistics,

    const Self = @This();

    /// Creates service implementation
    pub fn init(http_service: *@import("http_service.zig").HttpService, allocator: std.mem.Allocator, owns_http_service: bool) Self {
        return Self{
            .http_service = http_service,
            .owns_http_service = owns_http_service,
            .allocator = allocator,
            .request_counter = 1,
            .statistics = ServiceStatistics.init(),
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.owns_http_service) {
            self.http_service.deinit();
            self.allocator.destroy(self.http_service);
            self.owns_http_service = false;
            self.http_service = undefined;
        }
    }

    /// Performs JSON-RPC request
    pub fn performRequest(
        self: *Self,
        comptime T: type,
        comptime U: type,
        request: *Request(T, U),
    ) !T {
        // Increment statistics
        self.statistics.total_requests += 1;

        // Serialize request to JSON
        const request_json = try request.toJson();
        defer json_utils.freeValue(request_json, request.allocator);

        const request_bytes = try std.json.stringifyAlloc(self.http_service.allocator, request_json, .{});
        defer self.http_service.allocator.free(request_bytes);

        // Perform HTTP request
        const start_time = std.time.nanoTimestamp();

        const response_body = self.http_service.performIO(request_bytes) catch |err| {
            self.statistics.failed_requests += 1;
            return err;
        };
        defer self.http_service.allocator.free(response_body);

        const end_time = std.time.nanoTimestamp();
        self.statistics.total_response_time_ns += @intCast(end_time - start_time);
        self.statistics.successful_requests += 1;

        // Parse response
        const parsed_response = try @import("response_parser.zig").validateRpcResponse(self.http_service.allocator, response_body);
        defer json_utils.freeValue(parsed_response, self.http_service.allocator);

        const response_obj = parsed_response.object;
        const result_value = response_obj.get("result") orelse return errors.NetworkError.InvalidResponse;
        const response = try @import("response_parser.zig").parseResponseResult(T, result_value, self.http_service.allocator);
        return response;
    }

    /// Performs batch request
    pub fn performBatchRequest(
        self: *Self,
        requests: []const std.json.Value,
        allocator: std.mem.Allocator,
    ) ![]std.json.Value {
        // Build batch request JSON
        const batch_request = try @import("request.zig").RequestUtils.createBatchRequest(requests, allocator);
        defer allocator.free(batch_request);

        // Perform HTTP request
        const response_body = try self.http_service.performIO(batch_request);
        defer self.http_service.allocator.free(response_body);

        // Parse batch response
        return try @import("request.zig").RequestUtils.parseBatchResponse(response_body, allocator);
    }

    /// Checks connectivity
    pub fn checkConnectivity(self: *Self) !bool {
        return try self.http_service.validateConnectivity();
    }

    /// Gets configuration
    pub fn getConfiguration(self: Self) ServiceConfiguration {
        return ServiceConfiguration{
            .endpoint = self.http_service.url,
            .timeout_ms = self.http_service.http_client.timeout_ms,
            .max_retries = self.http_service.http_client.max_retries,
            .include_raw_responses = self.http_service.include_raw_responses,
        };
    }

    /// Sets timeout
    pub fn setTimeout(self: *Self, timeout_ms: u32) void {
        self.http_service.setTimeout(timeout_ms);
    }

    /// Sets the maximum response body size captured into memory.
    /// Passing 0 resets to the default cap.
    pub fn setMaxResponseBytes(self: *Self, max_response_bytes: usize) void {
        self.http_service.setMaxResponseBytes(max_response_bytes);
    }

    /// Gets statistics
    pub fn getStatistics(self: Self) ServiceStatistics {
        return self.statistics;
    }

    /// Resets statistics
    pub fn resetStatistics(self: *Self) void {
        self.statistics = ServiceStatistics.init();
    }
};

/// Service configuration
pub const ServiceConfiguration = struct {
    endpoint: []const u8,
    timeout_ms: u32,
    max_retries: u32,
    include_raw_responses: bool,

    /// Validates configuration
    pub fn validate(self: ServiceConfiguration) !void {
        if (self.endpoint.len == 0) {
            return errors.ValidationError.InvalidParameter;
        }

        if (self.timeout_ms == 0 or self.timeout_ms > 300000) { // Max 5 minutes
            return errors.ValidationError.ParameterOutOfRange;
        }

        if (self.max_retries > 10) {
            return errors.ValidationError.ParameterOutOfRange;
        }
    }

    /// Gets configuration summary
    pub fn getSummary(self: ServiceConfiguration, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "Endpoint: {s}, Timeout: {}ms, Retries: {}, Raw: {}", .{ self.endpoint, self.timeout_ms, self.max_retries, self.include_raw_responses });
    }
};

/// Service statistics
pub const ServiceStatistics = struct {
    total_requests: u32,
    successful_requests: u32,
    failed_requests: u32,
    total_response_time_ns: u64,

    const Self = @This();

    /// Creates empty statistics
    pub fn init() Self {
        return Self{
            .total_requests = 0,
            .successful_requests = 0,
            .failed_requests = 0,
            .total_response_time_ns = 0,
        };
    }

    /// Gets success rate
    pub fn getSuccessRate(self: Self) f64 {
        if (self.total_requests == 0) return 0.0;
        return @as(f64, @floatFromInt(self.successful_requests)) / @as(f64, @floatFromInt(self.total_requests));
    }

    /// Gets average response time
    pub fn getAverageResponseTimeMs(self: Self) f64 {
        if (self.successful_requests == 0) return 0.0;
        const avg_ns = self.total_response_time_ns / self.successful_requests;
        return @as(f64, @floatFromInt(avg_ns)) / @as(f64, std.time.ns_per_ms);
    }

    /// Gets failure rate
    pub fn getFailureRate(self: Self) f64 {
        if (self.total_requests == 0) return 0.0;
        return @as(f64, @floatFromInt(self.failed_requests)) / @as(f64, @floatFromInt(self.total_requests));
    }

    /// Formats statistics
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "Requests: {d}, Success: {d:.1}%, Avg Response: {d:.1}ms", .{ self.total_requests, self.getSuccessRate() * 100.0, self.getAverageResponseTimeMs() });
    }
};

/// Service factory
pub const ServiceFactory = struct {
    /// Creates service for MainNet
    pub fn mainnet(allocator: std.mem.Allocator) !NeoSwiftService {
        const http_service = try allocator.create(@import("http_service.zig").HttpService);
        errdefer allocator.destroy(http_service);
        http_service.* = @import("http_service.zig").HttpServiceFactory.mainnet(allocator);
        const service_impl = ServiceImplementation.init(http_service, allocator, true);
        return NeoSwiftService.init(service_impl);
    }

    /// Creates service for TestNet
    pub fn testnet(allocator: std.mem.Allocator) !NeoSwiftService {
        const http_service = try allocator.create(@import("http_service.zig").HttpService);
        errdefer allocator.destroy(http_service);
        http_service.* = @import("http_service.zig").HttpServiceFactory.testnet(allocator);
        const service_impl = ServiceImplementation.init(http_service, allocator, true);
        return NeoSwiftService.init(service_impl);
    }

    /// Creates service for local node
    pub fn localhost(allocator: std.mem.Allocator, port: ?u16) !NeoSwiftService {
        const http_service = try allocator.create(@import("http_service.zig").HttpService);
        errdefer allocator.destroy(http_service);
        http_service.* = @import("http_service.zig").HttpServiceFactory.localhost(allocator, port);
        const service_impl = ServiceImplementation.init(http_service, allocator, true);
        return NeoSwiftService.init(service_impl);
    }

    /// Creates custom service
    pub fn custom(
        allocator: std.mem.Allocator,
        endpoint: []const u8,
        timeout_ms: u32,
        max_retries: u32,
    ) !NeoSwiftService {
        var http_service = try allocator.create(@import("http_service.zig").HttpService);
        errdefer allocator.destroy(http_service);
        http_service.* = @import("http_service.zig").HttpService.init(allocator, endpoint, false);
        http_service.setTimeout(timeout_ms);
        http_service.setMaxRetries(max_retries);

        const service_impl = ServiceImplementation.init(http_service, allocator, true);
        return NeoSwiftService.init(service_impl);
    }
};

// Tests (converted from Swift NeoSwiftService tests)
test "NeoSwiftService creation and configuration" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test service creation
    var http_service = try allocator.create(@import("http_service.zig").HttpService);
    http_service.* = @import("http_service.zig").HttpService.init(allocator, "http://localhost:20332", false);
    defer {
        http_service.deinit();
        allocator.destroy(http_service);
    }

    const service_impl = ServiceImplementation.init(http_service, allocator, false);
    var neo_service = NeoSwiftService.init(service_impl);
    defer neo_service.deinit();

    // Test configuration
    const config = neo_service.getConfiguration();
    try testing.expectEqualStrings("http://localhost:20332", config.endpoint);

    // Test timeout setting
    neo_service.setTimeout(15000);
    const updated_config = neo_service.getConfiguration();
    try testing.expectEqual(@as(u32, 15000), updated_config.timeout_ms);
}

test "ServiceStatistics operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test statistics tracking
    var stats = ServiceStatistics.init();

    try testing.expectEqual(@as(u32, 0), stats.total_requests);
    try testing.expectEqual(@as(f64, 0.0), stats.getSuccessRate());
    try testing.expectEqual(@as(f64, 0.0), stats.getAverageResponseTimeMs());

    // Simulate some requests
    stats.total_requests = 10;
    stats.successful_requests = 8;
    stats.failed_requests = 2;
    stats.total_response_time_ns = 8 * 100 * std.time.ns_per_ms; // 100ms average

    try testing.expectEqual(@as(f64, 0.8), stats.getSuccessRate());
    try testing.expectEqual(@as(f64, 0.2), stats.getFailureRate());
    try testing.expectEqual(@as(f64, 100.0), stats.getAverageResponseTimeMs());

    // Test formatting
    const formatted = try stats.format(allocator);
    defer allocator.free(formatted);

    try testing.expect(std.mem.indexOf(u8, formatted, "10") != null);
    try testing.expect(std.mem.indexOf(u8, formatted, "80.0%") != null);
}

test "ServiceConfiguration validation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test valid configuration
    const valid_config = ServiceConfiguration{
        .endpoint = "https://testnet1.neo.coz.io:443",
        .timeout_ms = 30000,
        .max_retries = 3,
        .include_raw_responses = false,
    };

    try valid_config.validate();

    const summary = try valid_config.getSummary(allocator);
    defer allocator.free(summary);

    try testing.expect(std.mem.indexOf(u8, summary, "testnet1") != null);
    try testing.expect(std.mem.indexOf(u8, summary, "30000ms") != null);

    // Test invalid configurations
    const empty_endpoint_config = ServiceConfiguration{
        .endpoint = "",
        .timeout_ms = 30000,
        .max_retries = 3,
        .include_raw_responses = false,
    };

    try testing.expectError(errors.ValidationError.InvalidParameter, empty_endpoint_config.validate());

    const invalid_timeout_config = ServiceConfiguration{
        .endpoint = "https://valid.endpoint",
        .timeout_ms = 0,
        .max_retries = 3,
        .include_raw_responses = false,
    };

    try testing.expectError(errors.ValidationError.ParameterOutOfRange, invalid_timeout_config.validate());
}

test "ServiceFactory network presets" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test network factory methods
    var mainnet_service = try ServiceFactory.mainnet(allocator);
    defer mainnet_service.deinit();
    const mainnet_config = mainnet_service.getConfiguration();
    try testing.expect(std.mem.containsAtLeast(u8, mainnet_config.endpoint, 1, "mainnet"));

    var testnet_service = try ServiceFactory.testnet(allocator);
    defer testnet_service.deinit();
    const testnet_config = testnet_service.getConfiguration();
    try testing.expect(std.mem.containsAtLeast(u8, testnet_config.endpoint, 1, "testnet"));

    var localhost_service = try ServiceFactory.localhost(allocator, null);
    defer localhost_service.deinit();
    const localhost_config = localhost_service.getConfiguration();
    try testing.expect(std.mem.containsAtLeast(u8, localhost_config.endpoint, 1, "localhost"));

    // Test custom service
    var custom_service = try ServiceFactory.custom(
        allocator,
        "https://custom.neo.node:8080",
        20000, // 20 second timeout
        5, // 5 retries
    );
    defer custom_service.deinit();
    const custom_config = custom_service.getConfiguration();

    try testing.expectEqualStrings("https://custom.neo.node:8080", custom_config.endpoint);
    try testing.expectEqual(@as(u32, 20000), custom_config.timeout_ms);
    try testing.expectEqual(@as(u32, 5), custom_config.max_retries);
}
