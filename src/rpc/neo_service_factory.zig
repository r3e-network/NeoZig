const std = @import("std");

pub fn Factory(
    comptime NeoServiceType: type,
    comptime ServiceImplementationType: type,
    comptime HttpServiceType: type,
    comptime HttpServiceFactoryType: type,
) type {
    return struct {
        pub fn mainnet(allocator: std.mem.Allocator) !NeoServiceType {
            const http_service = try allocator.create(HttpServiceType);
            errdefer allocator.destroy(http_service);
            http_service.* = HttpServiceFactoryType.mainnet(allocator);
            const service_impl = ServiceImplementationType.init(http_service, allocator, true);
            return NeoServiceType.init(service_impl);
        }

        pub fn testnet(allocator: std.mem.Allocator) !NeoServiceType {
            const http_service = try allocator.create(HttpServiceType);
            errdefer allocator.destroy(http_service);
            http_service.* = HttpServiceFactoryType.testnet(allocator);
            const service_impl = ServiceImplementationType.init(http_service, allocator, true);
            return NeoServiceType.init(service_impl);
        }

        pub fn localhost(allocator: std.mem.Allocator, port: ?u16) !NeoServiceType {
            const http_service = try allocator.create(HttpServiceType);
            errdefer allocator.destroy(http_service);
            http_service.* = HttpServiceFactoryType.localhost(allocator, port);
            const service_impl = ServiceImplementationType.init(http_service, allocator, true);
            return NeoServiceType.init(service_impl);
        }

        pub fn custom(
            allocator: std.mem.Allocator,
            endpoint: []const u8,
            timeout_ms: u32,
            max_retries: u32,
        ) !NeoServiceType {
            var http_service = try allocator.create(HttpServiceType);
            errdefer allocator.destroy(http_service);
            http_service.* = HttpServiceType.init(allocator, endpoint, false);
            http_service.setTimeout(timeout_ms);
            http_service.setMaxRetries(max_retries);

            const service_impl = ServiceImplementationType.init(http_service, allocator, true);
            return NeoServiceType.init(service_impl);
        }
    };
}
