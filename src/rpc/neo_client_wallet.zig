const std = @import("std");

const Hash160 = @import("../types/hash160.zig").Hash160;
const Nep17Balances = @import("responses.zig").Nep17Balances;
const Nep17Transfers = @import("responses.zig").Nep17Transfers;
const AddressValidation = @import("extended_responses.zig").NeoValidateAddress;
const RpcParam = @import("rpc_operation.zig").RpcParam;
const RpcRequest = @import("rpc_operation.zig").RpcRequest;

pub fn mixin(comptime Client: type) type {
    return struct {
        pub fn getNep17Balances(self: *Client, script_hash: Hash160) !RpcRequest(Nep17Balances) {
            const address = try script_hash.toAddress(self.allocator);
            defer self.allocator.free(address);

            const params = [_]RpcParam{RpcParam.initString(address)};
            return RpcRequest(Nep17Balances).init(self.allocator, &self.service, "getnep17balances", &params);
        }

        pub fn getNep17Transfers(
            self: *Client,
            script_hash: Hash160,
            from_time: ?u64,
            to_time: ?u64,
        ) !RpcRequest(Nep17Transfers) {
            const address = try script_hash.toAddress(self.allocator);
            defer self.allocator.free(address);

            var params = std.ArrayList(RpcParam).init(self.allocator);
            defer params.deinit();

            try params.append(RpcParam.initString(address));

            if (from_time) |from| {
                try params.append(RpcParam.initInt(from));
                if (to_time) |to| {
                    try params.append(RpcParam.initInt(to));
                }
            }

            return RpcRequest(Nep17Transfers).init(self.allocator, &self.service, "getnep17transfers", params.items);
        }

        pub fn validateAddress(self: *Client, address: []const u8) !RpcRequest(AddressValidation) {
            const params = [_]RpcParam{RpcParam.initString(address)};
            return RpcRequest(AddressValidation).init(self.allocator, &self.service, "validateaddress", &params);
        }
    };
}
