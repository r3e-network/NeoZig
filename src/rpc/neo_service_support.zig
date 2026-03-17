const std = @import("std");
const errors = @import("../core/errors.zig");

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

        if (self.timeout_ms == 0 or self.timeout_ms > 300000) {
            return errors.ValidationError.ParameterOutOfRange;
        }

        if (self.max_retries > 10) {
            return errors.ValidationError.ParameterOutOfRange;
        }
    }

    /// Gets configuration summary
    pub fn getSummary(self: ServiceConfiguration, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "Endpoint: {s}, Timeout: {}ms, Retries: {}, Raw: {}",
            .{ self.endpoint, self.timeout_ms, self.max_retries, self.include_raw_responses },
        );
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
        return @as(f64, @floatFromInt(self.successful_requests)) /
            @as(f64, @floatFromInt(self.total_requests));
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
        return @as(f64, @floatFromInt(self.failed_requests)) /
            @as(f64, @floatFromInt(self.total_requests));
    }

    /// Formats statistics
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "Requests: {d}, Success: {d:.1}%, Avg Response: {d:.1}ms",
            .{
                self.total_requests,
                self.getSuccessRate() * 100.0,
                self.getAverageResponseTimeMs(),
            },
        );
    }
};
