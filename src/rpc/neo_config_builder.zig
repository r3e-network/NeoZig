pub fn Builder(comptime Config: type, comptime Hash160Type: type) type {
    return struct {
        config: Config,

        const BuilderSelf = @This();

        pub fn init() BuilderSelf {
            return .{ .config = Config.init() };
        }

        pub fn networkMagic(self: BuilderSelf, magic: u32) BuilderSelf {
            var next = self;
            _ = next.config.setNetworkMagic(magic);
            return next;
        }

        pub fn blockInterval(self: BuilderSelf, interval: u32) BuilderSelf {
            var next = self;
            _ = next.config.setBlockInterval(interval);
            return next;
        }

        pub fn maxValidUntilBlockIncrement(self: BuilderSelf, increment: u32) BuilderSelf {
            var next = self;
            next.config.max_valid_until_block_increment = increment;
            return next;
        }

        pub fn pollingInterval(self: BuilderSelf, interval: u32) BuilderSelf {
            var next = self;
            _ = next.config.setPollingInterval(interval);
            return next;
        }

        pub fn allowTransmissionOnFault(self: BuilderSelf, enabled: bool) BuilderSelf {
            var next = self;
            if (enabled) {
                _ = next.config.allowTransmissionOnFault();
            } else {
                _ = next.config.preventTransmissionOnFault();
            }
            return next;
        }

        pub fn nnsResolver(self: BuilderSelf, resolver: Hash160Type) BuilderSelf {
            var next = self;
            _ = next.config.setNnsResolver(resolver);
            return next;
        }

        pub fn build(self: BuilderSelf) !Config {
            try self.config.validate();
            return self.config;
        }
    };
}
