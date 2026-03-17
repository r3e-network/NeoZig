const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const StringUtils = @import("../utils/string_extensions.zig").StringUtils;
const common = @import("responses_common.zig");
const abi_mod = @import("responses_contract_abi.zig");

const stringifyJsonValue = common.stringifyJsonValue;

pub const ContractFeatures = struct {
    storage: bool,
    payable: bool,

    pub fn init() ContractFeatures {
        return ContractFeatures{ .storage = false, .payable = false };
    }

    pub fn fromJson(json_value: std.json.Value) !ContractFeatures {
        if (json_value == .null) return ContractFeatures.init();
        if (json_value != .object) return errors.SerializationError.InvalidFormat;

        const obj = json_value.object;
        const storage = if (obj.get("storage")) |value|
            switch (value) {
                .bool => |b| b,
                else => false,
            }
        else
            false;

        const payable = if (obj.get("payable")) |value|
            switch (value) {
                .bool => |b| b,
                else => false,
            }
        else
            false;

        return ContractFeatures{ .storage = storage, .payable = payable };
    }
};

pub const ContractManifest = struct {
    name: ?[]const u8,
    groups: []const ContractGroup,
    features: ?ContractFeatures,
    supported_standards: []const []const u8,
    abi: ?abi_mod.ContractABI,
    permissions: []const abi_mod.ContractPermission,
    trusts: []const []const u8,
    extra: ?[]const u8,

    pub fn init() ContractManifest {
        return ContractManifest{
            .name = null,
            .groups = &[_]ContractGroup{},
            .features = null,
            .supported_standards = &[_][]const u8{},
            .abi = null,
            .permissions = &[_]abi_mod.ContractPermission{},
            .trusts = &[_][]const u8{},
            .extra = null,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractManifest {
        const obj = json_value.object;

        const name = if (obj.get("name")) |name_value|
            switch (name_value) {
                .string => |str| try allocator.dupe(u8, str),
                .null => null,
                else => try stringifyJsonValue(name_value, allocator),
            }
        else
            null;

        var groups = ArrayList(ContractGroup).init(allocator);
        var groups_cleanup = TrueFlag{};
        defer if (groups_cleanup.value) {
            for (groups.items) |*group| group.deinit(allocator);
            groups.deinit();
        };
        if (obj.get("groups")) |groups_value| {
            if (groups_value != .array) return errors.SerializationError.InvalidFormat;
            for (groups_value.array.items) |group_value| {
                try groups.append(try ContractGroup.fromJson(group_value, allocator));
            }
        }

        var features: ?ContractFeatures = null;
        if (obj.get("features")) |features_value| {
            features = try ContractFeatures.fromJson(features_value);
        }

        var standards = ArrayList([]const u8).init(allocator);
        var standards_cleanup = TrueFlag{};
        defer if (standards_cleanup.value) {
            for (standards.items) |standard| {
                if (standard.len > 0) allocator.free(@constCast(standard));
            }
            standards.deinit();
        };
        if (obj.get("supportedstandards")) |standards_value| {
            if (standards_value != .array) return errors.SerializationError.InvalidFormat;
            for (standards_value.array.items) |entry| {
                if (entry != .string) return errors.SerializationError.InvalidFormat;
                const standard_copy = try allocator.dupe(u8, entry.string);
                errdefer allocator.free(standard_copy);
                try standards.append(standard_copy);
            }
        }

        var permissions = ArrayList(abi_mod.ContractPermission).init(allocator);
        var permissions_cleanup = TrueFlag{};
        defer if (permissions_cleanup.value) {
            for (permissions.items) |*permission| permission.deinit(allocator);
            permissions.deinit();
        };
        if (obj.get("permissions")) |permissions_value| {
            if (permissions_value != .array) return errors.SerializationError.InvalidFormat;
            for (permissions_value.array.items) |permission_value| {
                try permissions.append(try abi_mod.ContractPermission.fromJson(permission_value, allocator));
            }
        }

        var trusts = ArrayList([]const u8).init(allocator);
        var trusts_cleanup = TrueFlag{};
        defer if (trusts_cleanup.value) {
            for (trusts.items) |trust| {
                if (trust.len > 0) allocator.free(@constCast(trust));
            }
            trusts.deinit();
        };
        if (obj.get("trusts")) |trusts_value| {
            if (trusts_value != .array) return errors.SerializationError.InvalidFormat;
            for (trusts_value.array.items) |trust_value| {
                const value = switch (trust_value) {
                    .string => |str| try allocator.dupe(u8, str),
                    else => try stringifyJsonValue(trust_value, allocator),
                };
                try trusts.append(value);
            }
        }

        var abi_opt: ?abi_mod.ContractABI = null;
        errdefer if (abi_opt) |*abi_value| abi_value.deinit(allocator);
        if (obj.get("abi")) |abi_value| {
            abi_opt = try abi_mod.ContractABI.fromJson(abi_value, allocator);
        }

        const extra = if (obj.get("extra")) |extra_value|
            switch (extra_value) {
                .null => null,
                else => try stringifyJsonValue(extra_value, allocator),
            }
        else
            null;

        const groups_slice = try groups.toOwnedSlice();
        groups_cleanup.value = false;

        const standards_slice = try standards.toOwnedSlice();
        standards_cleanup.value = false;

        const permissions_slice = try permissions.toOwnedSlice();
        permissions_cleanup.value = false;

        const trusts_slice = try trusts.toOwnedSlice();
        trusts_cleanup.value = false;

        return ContractManifest{
            .name = name,
            .groups = groups_slice,
            .features = features,
            .supported_standards = standards_slice,
            .abi = abi_opt,
            .permissions = permissions_slice,
            .trusts = trusts_slice,
            .extra = extra,
        };
    }

    pub fn deinit(self: *ContractManifest, allocator: std.mem.Allocator) void {
        if (self.name) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
        }

        if (self.groups.len > 0) {
            for (self.groups) |*group| group.deinit(allocator);
            allocator.free(@constCast(self.groups));
        }

        if (self.supported_standards.len > 0) {
            for (self.supported_standards) |standard| {
                if (standard.len > 0) allocator.free(@constCast(standard));
            }
            allocator.free(@constCast(self.supported_standards));
        }

        if (self.abi) |*abi_value| {
            abi_value.deinit(allocator);
        }

        if (self.permissions.len > 0) {
            for (self.permissions) |*permission| permission.deinit(allocator);
            allocator.free(@constCast(self.permissions));
        }

        if (self.trusts.len > 0) {
            for (self.trusts) |trust| {
                if (trust.len > 0) allocator.free(@constCast(trust));
            }
            allocator.free(@constCast(self.trusts));
        }

        if (self.extra) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
        }
    }
};

const TrueFlag = struct {
    value: bool = true,
};

pub const ContractGroup = struct {
    public_key: []const u8,
    signature: []const u8,

    pub fn init() ContractGroup {
        return ContractGroup{
            .public_key = "",
            .signature = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractGroup {
        const obj = json_value.object;

        const pub_key_value = obj.get("pubkey") orelse obj.get("pubKey") orelse return errors.SerializationError.InvalidFormat;
        if (pub_key_value != .string) return errors.SerializationError.InvalidFormat;
        const cleaned_pub_key = StringUtils.cleanedHexPrefix(pub_key_value.string);

        const pub_key_bytes = try StringUtils.bytesFromHex(cleaned_pub_key, allocator);
        defer allocator.free(pub_key_bytes);
        if (pub_key_bytes.len != constants.PUBLIC_KEY_SIZE_COMPRESSED) {
            return errors.ValidationError.InvalidLength;
        }

        const public_key = try allocator.dupe(u8, cleaned_pub_key);

        const signature_value = obj.get("signature") orelse return errors.SerializationError.InvalidFormat;
        if (signature_value != .string) return errors.SerializationError.InvalidFormat;
        const decoded_signature = try StringUtils.base64Decoded(signature_value.string, allocator);
        defer allocator.free(decoded_signature);
        if (decoded_signature.len == 0) {
            return errors.ValidationError.InvalidLength;
        }

        const signature = try allocator.dupe(u8, signature_value.string);

        return ContractGroup{
            .public_key = public_key,
            .signature = signature,
        };
    }

    pub fn deinit(self: *const ContractGroup, allocator: std.mem.Allocator) void {
        if (self.public_key.len > 0) allocator.free(@constCast(self.public_key));
        if (self.signature.len > 0) allocator.free(@constCast(self.signature));
    }
};
