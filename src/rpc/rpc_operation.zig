const std = @import("std");

const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const NeoService = @import("neo_service.zig").NeoService;
const Request = @import("request.zig").Request;
const json_utils = @import("../utils/json_utils.zig");

/// RPC parameter wrapper
pub const RpcParam = union(enum) {
    String: []const u8,
    Integer: i64,
    Boolean: bool,
    ContractParameters: []const ContractParameter,
    Signers: []const Signer,

    pub fn initString(value: []const u8) RpcParam {
        return RpcParam{ .String = value };
    }

    pub fn initInt(value: anytype) RpcParam {
        return RpcParam{ .Integer = @intCast(value) };
    }

    pub fn initBool(value: bool) RpcParam {
        return RpcParam{ .Boolean = value };
    }

    pub fn initArray(value: anytype) RpcParam {
        if (@TypeOf(value) == []const ContractParameter or @TypeOf(value) == []ContractParameter) {
            return RpcParam{ .ContractParameters = value };
        } else if (@TypeOf(value) == []const Signer or @TypeOf(value) == []Signer) {
            return RpcParam{ .Signers = value };
        } else {
            @compileError("Unsupported array type for RPC parameter");
        }
    }

    pub fn clone(self: RpcParam, allocator: std.mem.Allocator) !RpcParam {
        return switch (self) {
            .String => |value| RpcParam.initString(try allocator.dupe(u8, value)),
            .Integer => |value| RpcParam{ .Integer = value },
            .Boolean => |value| RpcParam{ .Boolean = value },
            .ContractParameters => |items| blk: {
                const cloned = try allocator.alloc(ContractParameter, items.len);
                var count: usize = 0;
                errdefer {
                    for (cloned[0..count]) |item| item.deinit(allocator);
                    allocator.free(cloned);
                }
                for (items) |item| {
                    cloned[count] = try item.clone(allocator);
                    count += 1;
                }
                break :blk RpcParam{ .ContractParameters = cloned };
            },
            .Signers => |items| blk: {
                const cloned = try allocator.alloc(Signer, items.len);
                var count: usize = 0;
                errdefer {
                    for (cloned[0..count]) |*item| item.deinit(allocator);
                    allocator.free(cloned);
                }
                for (items) |item| {
                    cloned[count] = try item.cloneOwned(allocator);
                    count += 1;
                }
                break :blk RpcParam{ .Signers = cloned };
            },
        };
    }

    pub fn deinit(self: RpcParam, allocator: std.mem.Allocator) void {
        switch (self) {
            .String => |value| allocator.free(@constCast(value)),
            .ContractParameters => |items| {
                for (items) |item| item.deinit(allocator);
                allocator.free(@constCast(items));
            },
            .Signers => |items| {
                for (items) |item| {
                    var mutable_item = item;
                    mutable_item.deinit(allocator);
                }
                allocator.free(@constCast(items));
            },
            else => {},
        }
    }
};

fn contractParametersToJson(
    items: []const ContractParameter,
    allocator: std.mem.Allocator,
) !std.json.Value {
    var value = std.json.Value{ .array = std.json.Array.init(allocator) };
    errdefer value.array.deinit();
    for (items) |item| {
        try value.array.append(try item.toJsonValue(allocator));
    }
    return value;
}

fn signersToJson(signers: []const Signer, allocator: std.mem.Allocator) !std.json.Value {
    var value = std.json.Value{ .array = std.json.Array.init(allocator) };
    errdefer value.array.deinit();
    for (signers) |signer| {
        try value.array.append(try signer.toJsonValue(allocator));
    }
    return value;
}

fn paramToJson(param: RpcParam, allocator: std.mem.Allocator) !std.json.Value {
    var value: std.json.Value = .{ .null = {} };
    if (param == .String) {
        value = std.json.Value{ .string = try allocator.dupe(u8, param.String) };
    } else if (param == .Integer) {
        value = std.json.Value{ .integer = param.Integer };
    } else if (param == .Boolean) {
        value = std.json.Value{ .bool = param.Boolean };
    } else if (param == .ContractParameters) {
        value = try contractParametersToJson(param.ContractParameters, allocator);
    } else if (param == .Signers) {
        value = try signersToJson(param.Signers, allocator);
    }
    return value;
}

fn cloneRpcParams(allocator: std.mem.Allocator, params: []const RpcParam) ![]RpcParam {
    const cloned = try allocator.alloc(RpcParam, params.len);
    var count: usize = 0;
    errdefer {
        for (cloned[0..count]) |param| {
            param.deinit(allocator);
        }
        allocator.free(cloned);
    }

    for (params) |param| {
        cloned[count] = try param.clone(allocator);
        count += 1;
    }

    return cloned;
}

/// Generic RPC request
pub fn RpcRequest(comptime T: type) type {
    return struct {
        allocator: std.mem.Allocator,
        service: *NeoService,
        method: []const u8,
        params: []RpcParam,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            service: *NeoService,
            method: []const u8,
            params: []const RpcParam,
        ) !Self {
            const cloned_params = try cloneRpcParams(allocator, params);
            return Self{
                .allocator = allocator,
                .service = service,
                .method = method,
                .params = cloned_params,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.params) |param| {
                param.deinit(self.allocator);
            }
            self.allocator.free(self.params);
            self.params = self.params[0..0];
        }

        /// Sends the request
        pub fn send(self: *Self) !T {
            defer self.deinit();

            var params_list = std.ArrayList(std.json.Value).init(self.allocator);
            defer params_list.deinit();

            for (self.params) |param| {
                try params_list.append(try paramToJson(param, self.allocator));
            }

            const params_slice = try params_list.toOwnedSlice();
            defer {
                for (params_slice) |value| {
                    json_utils.freeValue(value, self.allocator);
                }
                self.allocator.free(params_slice);
            }

            var request = try Request(T, T).init(self.allocator, self.method, params_slice);
            return try request.sendUsing(self.service);
        }
    };
}
