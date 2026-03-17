const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");
const common = @import("responses_common.zig");

const jsonValueToOwnedString = common.jsonValueToOwnedString;
const parseIntFromJson = common.parseIntFromJson;

pub const ContractParameterDefinition = struct {
    name: []const u8,
    parameter_type: []const u8,

    pub fn init() ContractParameterDefinition {
        return ContractParameterDefinition{
            .name = "",
            .parameter_type = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractParameterDefinition {
        const obj = json_value.object;
        return ContractParameterDefinition{
            .name = try allocator.dupe(u8, obj.get("name").?.string),
            .parameter_type = try allocator.dupe(u8, obj.get("type").?.string),
        };
    }

    pub fn deinit(self: *const ContractParameterDefinition, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.parameter_type.len > 0) allocator.free(@constCast(self.parameter_type));
    }
};

pub const ContractMethod = struct {
    name: []const u8,
    parameters: []const ContractParameterDefinition,
    return_type: []const u8,
    offset: ?u32,
    safe: bool,

    pub fn init() ContractMethod {
        return ContractMethod{
            .name = "",
            .parameters = &[_]ContractParameterDefinition{},
            .return_type = "",
            .offset = null,
            .safe = false,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractMethod {
        const obj = json_value.object;

        const name = try allocator.dupe(u8, obj.get("name").?.string);
        const return_type = try allocator.dupe(u8, obj.get("returntype").?.string);
        const offset = if (obj.get("offset")) |offset_value| try parseIntFromJson(u32, offset_value) else null;

        const safe = if (obj.get("safe")) |safe_value|
            switch (safe_value) {
                .bool => safe_value.bool,
                .string => std.mem.eql(u8, safe_value.string, "true"),
                else => false,
            }
        else
            false;

        var parameters = ArrayList(ContractParameterDefinition).init(allocator);
        var params_cleanup = true;
        defer if (params_cleanup) {
            for (parameters.items) |*param| param.deinit(allocator);
            parameters.deinit();
        };
        if (obj.get("parameters")) |params_value| {
            if (params_value != .array) return errors.SerializationError.InvalidFormat;
            for (params_value.array.items) |param_value| {
                try parameters.append(try ContractParameterDefinition.fromJson(param_value, allocator));
            }
        }

        const parameters_slice = try parameters.toOwnedSlice();
        params_cleanup = false;

        return ContractMethod{
            .name = name,
            .parameters = parameters_slice,
            .return_type = return_type,
            .offset = offset,
            .safe = safe,
        };
    }

    pub fn deinit(self: *const ContractMethod, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.return_type.len > 0) allocator.free(@constCast(self.return_type));
        if (self.parameters.len > 0) {
            for (self.parameters) |*param| param.deinit(allocator);
            allocator.free(@constCast(self.parameters));
        }
    }
};

pub const ContractEvent = struct {
    name: []const u8,
    parameters: []const ContractParameterDefinition,

    pub fn init() ContractEvent {
        return ContractEvent{
            .name = "",
            .parameters = &[_]ContractParameterDefinition{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractEvent {
        const obj = json_value.object;

        const name = try allocator.dupe(u8, obj.get("name").?.string);

        var parameters = ArrayList(ContractParameterDefinition).init(allocator);
        var params_cleanup = true;
        defer if (params_cleanup) {
            for (parameters.items) |*param| param.deinit(allocator);
            parameters.deinit();
        };
        if (obj.get("parameters")) |params_value| {
            if (params_value != .array) return errors.SerializationError.InvalidFormat;
            for (params_value.array.items) |param_value| {
                try parameters.append(try ContractParameterDefinition.fromJson(param_value, allocator));
            }
        }

        const parameters_slice = try parameters.toOwnedSlice();
        params_cleanup = false;

        return ContractEvent{
            .name = name,
            .parameters = parameters_slice,
        };
    }

    pub fn deinit(self: *const ContractEvent, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.parameters.len > 0) {
            for (self.parameters) |*param| param.deinit(allocator);
            allocator.free(@constCast(self.parameters));
        }
    }
};

pub const ContractABI = struct {
    methods: []const ContractMethod,
    events: []const ContractEvent,

    pub fn init() ContractABI {
        return ContractABI{
            .methods = &[_]ContractMethod{},
            .events = &[_]ContractEvent{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractABI {
        const obj = json_value.object;

        var methods = ArrayList(ContractMethod).init(allocator);
        var methods_cleanup = true;
        defer if (methods_cleanup) {
            for (methods.items) |*method| method.deinit(allocator);
            methods.deinit();
        };
        if (obj.get("methods")) |methods_value| {
            if (methods_value != .array) return errors.SerializationError.InvalidFormat;
            for (methods_value.array.items) |method_value| {
                try methods.append(try ContractMethod.fromJson(method_value, allocator));
            }
        }

        var events = ArrayList(ContractEvent).init(allocator);
        var events_cleanup = true;
        defer if (events_cleanup) {
            for (events.items) |*event| event.deinit(allocator);
            events.deinit();
        };
        if (obj.get("events")) |events_value| {
            if (events_value != .array) return errors.SerializationError.InvalidFormat;
            for (events_value.array.items) |event_value| {
                try events.append(try ContractEvent.fromJson(event_value, allocator));
            }
        }

        const methods_slice = try methods.toOwnedSlice();
        methods_cleanup = false;

        const events_slice = try events.toOwnedSlice();
        events_cleanup = false;

        return ContractABI{
            .methods = methods_slice,
            .events = events_slice,
        };
    }

    pub fn deinit(self: *ContractABI, allocator: std.mem.Allocator) void {
        if (self.methods.len > 0) {
            for (self.methods) |*method| method.deinit(allocator);
            allocator.free(@constCast(self.methods));
        }

        if (self.events.len > 0) {
            for (self.events) |*event| event.deinit(allocator);
            allocator.free(@constCast(self.events));
        }
    }
};

pub const ContractPermission = struct {
    contract: []const u8,
    methods: []const []const u8,

    pub fn init() ContractPermission {
        return ContractPermission{
            .contract = "",
            .methods = &[_][]const u8{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractPermission {
        const obj = json_value.object;

        const contract_value = obj.get("contract") orelse return errors.SerializationError.InvalidFormat;
        const contract = try jsonValueToOwnedString(contract_value, allocator);

        var methods = ArrayList([]const u8).init(allocator);
        var methods_cleanup = true;
        defer if (methods_cleanup) {
            for (methods.items) |method| {
                if (method.len > 0) allocator.free(@constCast(method));
            }
            methods.deinit();
        };
        if (obj.get("methods")) |methods_value| {
            switch (methods_value) {
                .array => |method_array| {
                    for (method_array.items) |entry| {
                        if (entry != .string) return errors.SerializationError.InvalidFormat;
                        const method_copy = try allocator.dupe(u8, entry.string);
                        errdefer allocator.free(method_copy);
                        try methods.append(method_copy);
                    }
                },
                .string => |method_name| {
                    const method_copy = try allocator.dupe(u8, method_name);
                    errdefer allocator.free(method_copy);
                    try methods.append(method_copy);
                },
                else => return errors.SerializationError.InvalidFormat,
            }
        }

        const methods_slice = try methods.toOwnedSlice();
        methods_cleanup = false;

        return ContractPermission{
            .contract = contract,
            .methods = methods_slice,
        };
    }

    pub fn deinit(self: *const ContractPermission, allocator: std.mem.Allocator) void {
        if (self.contract.len > 0) allocator.free(@constCast(self.contract));
        if (self.methods.len > 0) {
            for (self.methods) |method| {
                if (method.len > 0) allocator.free(@constCast(method));
            }
            allocator.free(@constCast(self.methods));
        }
    }
};
