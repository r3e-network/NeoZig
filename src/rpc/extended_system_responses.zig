const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const contract_types = @import("responses_contract.zig");

const ContractManifest = contract_types.ContractManifest;
const ContractNef = contract_types.ContractNef;

/// Neo list plugins response
pub const NeoListPlugins = struct {
    plugins: []const Plugin,

    pub const Plugin = struct {
        name: []const u8,
        version: []const u8,
        interfaces: []const []const u8,

        pub fn init() Plugin {
            return Plugin{
                .name = "",
                .version = "",
                .interfaces = &[_][]const u8{},
            };
        }

        pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Plugin {
            if (json_value != .object) return errors.SerializationError.InvalidFormat;
            const obj = json_value.object;

            const name_value = obj.get("name") orelse return errors.SerializationError.InvalidFormat;
            if (name_value != .string) return errors.SerializationError.InvalidFormat;
            const name = try allocator.dupe(u8, name_value.string);
            errdefer allocator.free(name);

            const version_value = obj.get("version") orelse return errors.SerializationError.InvalidFormat;
            if (version_value != .string) return errors.SerializationError.InvalidFormat;
            const version = try allocator.dupe(u8, version_value.string);
            errdefer allocator.free(version);

            var interfaces = ArrayList([]const u8).init(allocator);
            errdefer {
                for (interfaces.items) |iface| allocator.free(@constCast(iface));
                interfaces.deinit();
            }
            if (obj.get("interfaces")) |interfaces_array| {
                if (interfaces_array != .array) return errors.SerializationError.InvalidFormat;
                for (interfaces_array.array.items) |interface| {
                    if (interface != .string) return errors.SerializationError.InvalidFormat;
                    const iface_copy = try allocator.dupe(u8, interface.string);
                    errdefer allocator.free(iface_copy);
                    try interfaces.append(iface_copy);
                }
            }

            return Plugin{
                .name = name,
                .version = version,
                .interfaces = try interfaces.toOwnedSlice(),
            };
        }

        pub fn deinit(self: *Plugin, allocator: std.mem.Allocator) void {
            if (self.name.len > 0) allocator.free(@constCast(self.name));
            if (self.version.len > 0) allocator.free(@constCast(self.version));
            if (self.interfaces.len > 0) {
                for (self.interfaces) |iface| {
                    if (iface.len > 0) allocator.free(@constCast(iface));
                }
                allocator.free(@constCast(self.interfaces));
                self.interfaces = &[_][]const u8{};
            }
            self.name = "";
            self.version = "";
        }
    };

    pub fn init() NeoListPlugins {
        return NeoListPlugins{
            .plugins = &[_]Plugin{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoListPlugins {
        if (json_value != .array) return errors.SerializationError.InvalidFormat;
        const array = json_value.array;

        var plugins = ArrayList(Plugin).init(allocator);
        errdefer {
            for (plugins.items) |*plugin| plugin.deinit(allocator);
            plugins.deinit();
        }
        for (array.items) |plugin_item| {
            var plugin = try Plugin.fromJson(plugin_item, allocator);
            errdefer plugin.deinit(allocator);
            try plugins.append(plugin);
        }

        return NeoListPlugins{ .plugins = try plugins.toOwnedSlice() };
    }

    pub fn deinit(self: *NeoListPlugins, allocator: std.mem.Allocator) void {
        if (self.plugins.len > 0) {
            for (self.plugins) |*plugin| {
                plugin.deinit(allocator);
            }
            allocator.free(@constCast(self.plugins));
            self.plugins = &[_]Plugin{};
        }
    }
};

/// Native contract state
pub const NativeContractState = struct {
    id: i32,
    hash: Hash160,
    nef: ContractNef,
    manifest: ContractManifest,
    update_history: []const u32,

    pub fn init() NativeContractState {
        return NativeContractState{
            .id = 0,
            .hash = Hash160.ZERO,
            .nef = ContractNef.init(),
            .manifest = ContractManifest.init(),
            .update_history = &[_]u32{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NativeContractState {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var update_history = ArrayList(u32).init(allocator);
        errdefer update_history.deinit();
        if (obj.get("updatehistory")) |history_array| {
            if (history_array != .array) return errors.SerializationError.InvalidFormat;
            for (history_array.array.items) |item| {
                if (item != .integer) return errors.SerializationError.InvalidFormat;
                try update_history.append(@intCast(item.integer));
            }
        }
        const update_history_slice = try update_history.toOwnedSlice();
        errdefer allocator.free(update_history_slice);

        const nef_value = obj.get("nef") orelse return errors.SerializationError.InvalidFormat;
        var nef = try ContractNef.fromJson(nef_value, allocator);
        errdefer nef.deinit(allocator);

        const manifest_value = obj.get("manifest") orelse return errors.SerializationError.InvalidFormat;
        var manifest = try ContractManifest.fromJson(manifest_value, allocator);
        errdefer manifest.deinit(allocator);

        return NativeContractState{
            .id = @intCast(obj.get("id").?.integer),
            .hash = try Hash160.initWithString(obj.get("hash").?.string),
            .nef = nef,
            .manifest = manifest,
            .update_history = update_history_slice,
        };
    }

    pub fn deinit(self: *NativeContractState, allocator: std.mem.Allocator) void {
        self.nef.deinit(allocator);
        self.manifest.deinit(allocator);
        if (self.update_history.len > 0) allocator.free(@constCast(self.update_history));
        self.update_history = &[_]u32{};
    }
};

/// Express contract state
pub const ExpressContractState = struct {
    hash: Hash160,
    manifest: ContractManifest,

    pub fn init() ExpressContractState {
        return ExpressContractState{
            .hash = Hash160.ZERO,
            .manifest = ContractManifest.init(),
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ExpressContractState {
        const obj = json_value.object;

        return ExpressContractState{
            .hash = try Hash160.initWithString(obj.get("hash").?.string),
            .manifest = try ContractManifest.fromJson(obj.get("manifest").?, allocator),
        };
    }

    pub fn deinit(self: *ExpressContractState, allocator: std.mem.Allocator) void {
        self.manifest.deinit(allocator);
    }
};

/// Express shutdown
pub const ExpressShutdown = struct {
    process_id: u32,

    pub fn init() ExpressShutdown {
        return ExpressShutdown{ .process_id = 0 };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ExpressShutdown {
        _ = allocator;
        const obj = json_value.object;

        return ExpressShutdown{
            .process_id = @intCast(obj.get("processId").?.integer),
        };
    }
};

/// Diagnostics
pub const Diagnostics = struct {
    invocation_id: []const u8,
    invocation_counter: u32,

    pub fn init() Diagnostics {
        return Diagnostics{
            .invocation_id = "",
            .invocation_counter = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Diagnostics {
        const obj = json_value.object;

        return Diagnostics{
            .invocation_id = try allocator.dupe(u8, obj.get("invocationId").?.string),
            .invocation_counter = @intCast(obj.get("invocationCounter").?.integer),
        };
    }

    pub fn deinit(self: *Diagnostics, allocator: std.mem.Allocator) void {
        if (self.invocation_id.len > 0) allocator.free(@constCast(self.invocation_id));
        self.invocation_id = "";
    }
};

pub const ContractStorageEntry = @import("protocol_responses.zig").ContractStorageEntry;
