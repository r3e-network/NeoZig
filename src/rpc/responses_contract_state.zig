const std = @import("std");

const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const common = @import("responses_common.zig");
const manifest_mod = @import("responses_contract_manifest.zig");

const stringifyJsonValue = common.stringifyJsonValue;
const parseIntFromJson = common.parseIntFromJson;

/// Contract state response
pub const ContractState = struct {
    id: i32,
    update_counter: u32,
    hash: Hash160,
    nef: ContractNef,
    manifest: manifest_mod.ContractManifest,

    pub fn init() ContractState {
        return ContractState{
            .id = 0,
            .update_counter = 0,
            .hash = Hash160.ZERO,
            .nef = ContractNef.init(),
            .manifest = manifest_mod.ContractManifest.init(),
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractState {
        const obj = json_value.object;

        var nef = try ContractNef.fromJson(obj.get("nef").?, allocator);
        errdefer nef.deinit(allocator);

        var manifest = try manifest_mod.ContractManifest.fromJson(obj.get("manifest").?, allocator);
        errdefer manifest.deinit(allocator);

        return ContractState{
            .id = try parseIntFromJson(i32, obj.get("id").?),
            .update_counter = try parseIntFromJson(u32, obj.get("updatecounter").?),
            .hash = try Hash160.initWithString(obj.get("hash").?.string),
            .nef = nef,
            .manifest = manifest,
        };
    }

    pub fn deinit(self: *ContractState, allocator: std.mem.Allocator) void {
        self.nef.deinit(allocator);
        self.manifest.deinit(allocator);
    }
};

/// Contract NEF
pub const ContractNef = struct {
    magic: u32,
    compiler: []const u8,
    source: ?[]const u8,
    script: []const u8,
    checksum: u32,

    pub fn init() ContractNef {
        return ContractNef{
            .magic = 0,
            .compiler = "",
            .source = null,
            .script = &[_]u8{},
            .checksum = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractNef {
        const obj = json_value.object;

        const magic = try parseIntFromJson(u32, obj.get("magic").?);
        const compiler = try allocator.dupe(u8, obj.get("compiler").?.string);

        const source = if (obj.get("source")) |source_value|
            switch (source_value) {
                .string => |str| try allocator.dupe(u8, str),
                .null => null,
                else => try stringifyJsonValue(source_value, allocator),
            }
        else
            null;

        const script_field = obj.get("script") orelse return errors.SerializationError.InvalidFormat;
        const script = switch (script_field) {
            .string => |str| try allocator.dupe(u8, str),
            else => return errors.SerializationError.InvalidFormat,
        };

        const checksum = try parseIntFromJson(u32, obj.get("checksum").?);

        return ContractNef{
            .magic = magic,
            .compiler = compiler,
            .source = source,
            .script = script,
            .checksum = checksum,
        };
    }

    pub fn deinit(self: *ContractNef, allocator: std.mem.Allocator) void {
        if (self.compiler.len > 0) allocator.free(@constCast(self.compiler));
        if (self.script.len > 0) allocator.free(@constCast(self.script));
        if (self.source) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
        }
    }
};
