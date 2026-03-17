const std = @import("std");

const constants = @import("../core/constants.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const HttpClient = @import("http_client.zig").HttpClient;
const HttpService = @import("http_service.zig").HttpService;
const NeoConfig = @import("neo_config.zig").NeoConfig;
const NeoService = @import("neo_service.zig").NeoService;
const ServiceImplementation = @import("neo_service.zig").ServiceImplementation;

pub fn mixin(comptime Client: type) type {
    return struct {
        pub const Builder = struct {
            allocator: std.mem.Allocator,
            client_config: NeoConfig,
            endpoint_value: ?[]const u8,
            include_raw_responses: bool,
            timeout_ms: u32,
            max_retries: u32,
            max_response_bytes: usize,

            const BuilderSelf = @This();

            pub fn init(allocator: std.mem.Allocator) BuilderSelf {
                return .{
                    .allocator = allocator,
                    .client_config = NeoConfig.init(),
                    .endpoint_value = null,
                    .include_raw_responses = false,
                    .timeout_ms = 30_000,
                    .max_retries = 3,
                    .max_response_bytes = HttpClient.DEFAULT_MAX_RESPONSE_BYTES,
                };
            }

            pub fn config(self: BuilderSelf, config_value: NeoConfig) BuilderSelf {
                var next = self;
                next.client_config = config_value;
                return next;
            }

            pub fn endpoint(self: BuilderSelf, endpoint_value: []const u8) BuilderSelf {
                var next = self;
                next.endpoint_value = endpoint_value;
                return next;
            }

            pub fn includeRawResponses(self: BuilderSelf, enabled: bool) BuilderSelf {
                var next = self;
                next.include_raw_responses = enabled;
                return next;
            }

            pub fn timeoutMs(self: BuilderSelf, timeout_ms: u32) BuilderSelf {
                var next = self;
                next.timeout_ms = timeout_ms;
                return next;
            }

            pub fn maxRetries(self: BuilderSelf, max_retries: u32) BuilderSelf {
                var next = self;
                next.max_retries = max_retries;
                return next;
            }

            pub fn maxResponseBytes(self: BuilderSelf, max_response_bytes: usize) BuilderSelf {
                var next = self;
                next.max_response_bytes = max_response_bytes;
                return next;
            }

            pub fn build(self: BuilderSelf) !Client {
                try self.client_config.validate();

                const resolved_endpoint = self.endpoint_value orelse HttpService.DEFAULT_URL;
                const http_service = try self.allocator.create(HttpService);
                errdefer self.allocator.destroy(http_service);

                http_service.* = HttpService.init(
                    self.allocator,
                    resolved_endpoint,
                    self.include_raw_responses,
                );
                http_service.setTimeout(self.timeout_ms);
                http_service.setMaxRetries(self.max_retries);
                http_service.setMaxResponseBytes(self.max_response_bytes);

                const service_impl = ServiceImplementation.init(http_service, self.allocator, true);
                return Client.init(
                    self.allocator,
                    self.client_config,
                    NeoService.init(service_impl),
                );
            }
        };

        pub fn init(
            allocator: std.mem.Allocator,
            config: NeoConfig,
            service: NeoService,
        ) Client {
            return Client{
                .allocator = allocator,
                .config = config,
                .service = service,
            };
        }

        pub fn builder(allocator: std.mem.Allocator) Builder {
            return Builder.init(allocator);
        }

        pub fn fromEndpoint(
            allocator: std.mem.Allocator,
            endpoint: []const u8,
            config: ?NeoConfig,
        ) !Client {
            return Builder.init(allocator)
                .endpoint(endpoint)
                .config(config orelse NeoConfig.init())
                .build();
        }

        /// Ownership: this function moves `service` into the returned client. The
        /// passed-in `service` pointer is invalidated (its owned transport is
        /// relinquished and the internal pointer cleared) to prevent double-free.
        pub fn build(
            allocator: std.mem.Allocator,
            service: *NeoService,
            config: ?NeoConfig,
        ) Client {
            const final_config = config orelse NeoConfig.init();
            const owned_service = service.*;
            service.relinquish();
            service.service_impl.http_service = undefined;
            return Client.init(allocator, final_config, owned_service);
        }

        pub fn getNnsResolver(self: Client) Hash160 {
            return self.config.nns_resolver;
        }

        pub fn getBlockInterval(self: Client) u32 {
            return self.config.block_interval;
        }

        pub fn getPollingInterval(self: Client) u32 {
            return self.config.polling_interval;
        }

        pub fn getMaxValidUntilBlockIncrement(self: Client) u32 {
            return self.config.max_valid_until_block_increment;
        }

        pub fn allowTransmissionOnFault(self: *Client) void {
            self.config.allows_transmission_on_fault = true;
        }

        pub fn preventTransmissionOnFault(self: *Client) void {
            self.config.allows_transmission_on_fault = false;
        }

        pub fn getService(self: *Client) *NeoService {
            return &self.service;
        }

        pub fn deinit(self: *Client) void {
            self.service.deinit();
        }

        pub fn setNNSResolver(self: *Client, nns_resolver: Hash160) void {
            self.config.nns_resolver = nns_resolver;
        }

        pub fn getNetworkMagicNumber(self: *Client) !u32 {
            if (self.config.network_magic == null) {
                var request = try self.getVersion();
                var version = try request.send();
                defer version.deinit(self.allocator);

                if (version.protocol) |protocol| {
                    self.config.network_magic = protocol.network;
                    NeoConfig.setAddressVersion(protocol.address_version);
                    if (protocol.ms_per_block) |ms_per_block| {
                        self.config.block_interval = ms_per_block;
                    }
                    if (protocol.max_valid_until_block_increment) |max_valid_until| {
                        self.config.max_valid_until_block_increment = max_valid_until;
                    }
                } else {
                    self.config.network_magic = constants.DEFAULT_NETWORK_MAGIC;
                }
            }
            return self.config.network_magic.?;
        }

        pub fn getNetworkMagicNumberBytes(self: *Client) ![4]u8 {
            const magic_int = try self.getNetworkMagicNumber();
            return std.mem.toBytes(std.mem.nativeToBig(u32, magic_int));
        }
    };
}
