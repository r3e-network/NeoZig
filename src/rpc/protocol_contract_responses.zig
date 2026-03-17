const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const json_utils = @import("../utils/json_utils.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const StringUtils = @import("../utils/string_extensions.zig").StringUtils;
const ScriptBuilder = @import("../script/script_builder.zig").ScriptBuilder;
const ContractNef = @import("responses_contract.zig").ContractNef;

/// Contract manifest
pub const ContractManifest = struct {
    name: ?[]const u8,
    groups: []const ContractGroup,
    features: ?std.json.Value,
    supported_standards: []const []const u8,
    abi: ?ContractABI,
    permissions: []const ContractPermission,
    trusts: []const []const u8,
    extra: ?std.json.Value,

    const Self = @This();

    pub fn init(
        name: ?[]const u8,
        groups: []const ContractGroup,
        features: ?std.json.Value,
        supported_standards: []const []const u8,
        abi: ?ContractABI,
        permissions: []const ContractPermission,
        trusts: []const []const u8,
        extra: ?std.json.Value,
    ) Self {
        return Self{
            .name = name,
            .groups = groups,
            .features = features,
            .supported_standards = supported_standards,
            .abi = abi,
            .permissions = permissions,
            .trusts = trusts,
            .extra = extra,
        };
    }

    pub fn createGroup(
        group_key_pair: anytype,
        deployment_sender: Hash160,
        nef_checksum: i32,
        contract_name: ?[]const u8,
        allocator: std.mem.Allocator,
    ) !ContractGroup {
        const contract_hash_bytes = try buildContractHashScript(
            deployment_sender,
            nef_checksum,
            contract_name orelse "",
            allocator,
        );
        defer allocator.free(contract_hash_bytes);

        const signature_data = try signMessage(contract_hash_bytes, group_key_pair, allocator);
        defer allocator.free(signature_data);

        const pub_key_hex = try group_key_pair.public_key.toHex(allocator);
        defer allocator.free(pub_key_hex);

        const signature_base64 = try StringUtils.base64Encoded(signature_data, allocator);
        defer allocator.free(signature_base64);

        return ContractGroup.init(
            try allocator.dupe(u8, pub_key_hex),
            try allocator.dupe(u8, signature_base64),
        );
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var result = Self.init(
            null,
            &[_]ContractGroup{},
            null,
            &[_][]const u8{},
            null,
            &[_]ContractPermission{},
            &[_][]const u8{},
            null,
        );
        errdefer result.deinit(allocator);

        if (obj.get("name")) |n| {
            if (n != .string) return errors.SerializationError.InvalidFormat;
            result.name = try allocator.dupe(u8, n.string);
        }

        if (obj.get("groups")) |groups_array| {
            if (groups_array != .array) return errors.SerializationError.InvalidFormat;
            var groups = ArrayList(ContractGroup).init(allocator);
            errdefer {
                for (groups.items) |*group| group.deinit(allocator);
                groups.deinit();
            }
            for (groups_array.array.items) |group_item| {
                var group = try ContractGroup.fromJson(group_item, allocator);
                errdefer group.deinit(allocator);
                try groups.append(group);
            }
            result.groups = try groups.toOwnedSlice();
        }

        if (obj.get("features")) |features_value| {
            result.features = try json_utils.cloneValue(features_value, allocator);
        }

        if (obj.get("supportedstandards")) |standards_array| {
            if (standards_array != .array) return errors.SerializationError.InvalidFormat;
            var standards = ArrayList([]const u8).init(allocator);
            errdefer {
                for (standards.items) |standard| allocator.free(@constCast(standard));
                standards.deinit();
            }
            for (standards_array.array.items) |standard| {
                if (standard != .string) return errors.SerializationError.InvalidFormat;
                const standard_copy = try allocator.dupe(u8, standard.string);
                errdefer allocator.free(standard_copy);
                try standards.append(standard_copy);
            }
            result.supported_standards = try standards.toOwnedSlice();
        }

        if (obj.get("abi")) |abi| {
            result.abi = try ContractABI.fromJson(abi, allocator);
        }

        if (obj.get("permissions")) |perms_array| {
            if (perms_array != .array) return errors.SerializationError.InvalidFormat;
            var permissions = ArrayList(ContractPermission).init(allocator);
            errdefer {
                for (permissions.items) |*permission| permission.deinit(allocator);
                permissions.deinit();
            }
            for (perms_array.array.items) |perm_item| {
                var permission = try ContractPermission.fromJson(perm_item, allocator);
                errdefer permission.deinit(allocator);
                try permissions.append(permission);
            }
            result.permissions = try permissions.toOwnedSlice();
        }

        if (obj.get("trusts")) |trusts_array| {
            if (trusts_array != .array) return errors.SerializationError.InvalidFormat;
            var trusts = ArrayList([]const u8).init(allocator);
            errdefer {
                for (trusts.items) |trust| allocator.free(@constCast(trust));
                trusts.deinit();
            }
            for (trusts_array.array.items) |trust| {
                if (trust != .string) return errors.SerializationError.InvalidFormat;
                const trust_copy = try allocator.dupe(u8, trust.string);
                errdefer allocator.free(trust_copy);
                try trusts.append(trust_copy);
            }
            result.trusts = try trusts.toOwnedSlice();
        }

        if (obj.get("extra")) |extra_value| {
            result.extra = try json_utils.cloneValue(extra_value, allocator);
        }

        return result;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.name) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
            self.name = null;
        }

        if (self.groups.len > 0) {
            for (self.groups) |*group| group.deinit(allocator);
            allocator.free(@constCast(self.groups));
            self.groups = &[_]ContractGroup{};
        }

        if (self.supported_standards.len > 0) {
            for (self.supported_standards) |standard| {
                if (standard.len > 0) allocator.free(@constCast(standard));
            }
            allocator.free(@constCast(self.supported_standards));
            self.supported_standards = &[_][]const u8{};
        }

        if (self.abi) |*abi_value| {
            abi_value.deinit(allocator);
            self.abi = null;
        }

        if (self.permissions.len > 0) {
            for (self.permissions) |*permission| permission.deinit(allocator);
            allocator.free(@constCast(self.permissions));
            self.permissions = &[_]ContractPermission{};
        }

        if (self.trusts.len > 0) {
            for (self.trusts) |trust| {
                if (trust.len > 0) allocator.free(@constCast(trust));
            }
            allocator.free(@constCast(self.trusts));
            self.trusts = &[_][]const u8{};
        }

        if (self.features) |value| {
            json_utils.freeValue(value, allocator);
            self.features = null;
        }

        if (self.extra) |value| {
            json_utils.freeValue(value, allocator);
            self.extra = null;
        }
    }
};

/// Contract group
pub const ContractGroup = struct {
    pub_key: []const u8,
    signature: []const u8,

    const Self = @This();

    pub fn init(pub_key: []const u8, signature: []const u8) Self {
        return Self{
            .pub_key = pub_key,
            .signature = signature,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Self {
        const obj = json_value.object;

        const pub_key_str = if (obj.get("pubkey")) |pk|
            pk.string
        else if (obj.get("pubKey")) |pk|
            pk.string
        else
            return errors.throwIllegalArgument("Missing public key in contract group");

        const cleaned_pub_key = StringUtils.cleanedHexPrefix(pub_key_str);

        const pub_key_bytes = try StringUtils.bytesFromHex(cleaned_pub_key, allocator);
        defer allocator.free(pub_key_bytes);

        if (pub_key_bytes.len != constants.PUBLIC_KEY_SIZE_COMPRESSED) {
            return errors.throwIllegalArgument("Invalid public key length");
        }

        const signature_str = obj.get("signature").?.string;
        const signature_bytes = try StringUtils.base64Decoded(signature_str, allocator);
        defer allocator.free(signature_bytes);

        if (signature_bytes.len == 0) {
            return errors.throwIllegalArgument("Invalid signature format");
        }

        return Self.init(
            try allocator.dupe(u8, cleaned_pub_key),
            try allocator.dupe(u8, signature_str),
        );
    }

    pub fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
        if (self.pub_key.len > 0) allocator.free(@constCast(self.pub_key));
        if (self.signature.len > 0) allocator.free(@constCast(self.signature));
    }
};

/// Contract ABI
pub const ContractABI = struct {
    methods: []const ContractMethodInfo,
    events: []const ContractEventInfo,

    pub fn init() ContractABI {
        return ContractABI{
            .methods = &[_]ContractMethodInfo{},
            .events = &[_]ContractEventInfo{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractABI {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var result = ContractABI.init();
        errdefer result.deinit(allocator);

        if (obj.get("methods")) |methods_array| {
            if (methods_array != .array) return errors.SerializationError.InvalidFormat;
            var methods = ArrayList(ContractMethodInfo).init(allocator);
            errdefer {
                for (methods.items) |*method| method.deinit(allocator);
                methods.deinit();
            }
            for (methods_array.array.items) |method| {
                var parsed = try ContractMethodInfo.fromJson(method, allocator);
                errdefer parsed.deinit(allocator);
                try methods.append(parsed);
            }
            result.methods = try methods.toOwnedSlice();
        }

        if (obj.get("events")) |events_array| {
            if (events_array != .array) return errors.SerializationError.InvalidFormat;
            var events = ArrayList(ContractEventInfo).init(allocator);
            errdefer {
                for (events.items) |*event| event.deinit(allocator);
                events.deinit();
            }
            for (events_array.array.items) |event| {
                var parsed = try ContractEventInfo.fromJson(event, allocator);
                errdefer parsed.deinit(allocator);
                try events.append(parsed);
            }
            result.events = try events.toOwnedSlice();
        }

        return result;
    }

    pub fn deinit(self: *ContractABI, allocator: std.mem.Allocator) void {
        if (self.methods.len > 0) {
            for (self.methods) |*method| method.deinit(allocator);
            allocator.free(@constCast(self.methods));
            self.methods = &[_]ContractMethodInfo{};
        }

        if (self.events.len > 0) {
            for (self.events) |*event| event.deinit(allocator);
            allocator.free(@constCast(self.events));
            self.events = &[_]ContractEventInfo{};
        }
    }
};

/// Contract method info
pub const ContractMethodInfo = struct {
    name: []const u8,
    parameters: []const ContractParameterDefinition,
    return_type: []const u8,
    offset: u32,
    safe: bool,

    pub fn init() ContractMethodInfo {
        return ContractMethodInfo{
            .name = "",
            .parameters = &[_]ContractParameterDefinition{},
            .return_type = "Any",
            .offset = 0,
            .safe = false,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractMethodInfo {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var result = ContractMethodInfo.init();
        errdefer result.deinit(allocator);

        const name_value = obj.get("name") orelse return errors.SerializationError.InvalidFormat;
        if (name_value != .string) return errors.SerializationError.InvalidFormat;
        result.name = try allocator.dupe(u8, name_value.string);

        const return_type_value = obj.get("returntype") orelse return errors.SerializationError.InvalidFormat;
        if (return_type_value != .string) return errors.SerializationError.InvalidFormat;
        result.return_type = try allocator.dupe(u8, return_type_value.string);

        const offset_value = obj.get("offset") orelse return errors.SerializationError.InvalidFormat;
        if (offset_value != .integer) return errors.SerializationError.InvalidFormat;
        result.offset = @intCast(offset_value.integer);

        const safe_value = obj.get("safe") orelse return errors.SerializationError.InvalidFormat;
        if (safe_value != .bool) return errors.SerializationError.InvalidFormat;
        result.safe = safe_value.bool;

        if (obj.get("parameters")) |params_array| {
            if (params_array != .array) return errors.SerializationError.InvalidFormat;
            var parameters = ArrayList(ContractParameterDefinition).init(allocator);
            errdefer {
                for (parameters.items) |*param| param.deinit(allocator);
                parameters.deinit();
            }
            for (params_array.array.items) |param| {
                var parsed = try ContractParameterDefinition.fromJson(param, allocator);
                errdefer parsed.deinit(allocator);
                try parameters.append(parsed);
            }
            result.parameters = try parameters.toOwnedSlice();
        }

        return result;
    }

    pub fn deinit(self: *const ContractMethodInfo, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.return_type.len > 0 and (self.return_type.ptr != "Any".ptr or self.return_type.len != "Any".len)) {
            allocator.free(@constCast(self.return_type));
        }
        if (self.parameters.len > 0) {
            for (self.parameters) |*param| {
                param.deinit(allocator);
            }
            allocator.free(@constCast(self.parameters));
        }
    }
};

/// Contract parameter definition
pub const ContractParameterDefinition = struct {
    name: []const u8,
    parameter_type: []const u8,

    pub fn init(name: []const u8, parameter_type: []const u8) ContractParameterDefinition {
        return ContractParameterDefinition{
            .name = name,
            .parameter_type = parameter_type,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractParameterDefinition {
        const obj = json_value.object;

        return ContractParameterDefinition.init(
            try allocator.dupe(u8, obj.get("name").?.string),
            try allocator.dupe(u8, obj.get("type").?.string),
        );
    }

    pub fn deinit(self: *const ContractParameterDefinition, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.parameter_type.len > 0) allocator.free(@constCast(self.parameter_type));
    }
};

/// Contract event info
pub const ContractEventInfo = struct {
    name: []const u8,
    parameters: []const ContractParameterDefinition,

    pub fn init() ContractEventInfo {
        return ContractEventInfo{
            .name = "",
            .parameters = &[_]ContractParameterDefinition{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractEventInfo {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var result = ContractEventInfo.init();
        errdefer result.deinit(allocator);

        const name_value = obj.get("name") orelse return errors.SerializationError.InvalidFormat;
        if (name_value != .string) return errors.SerializationError.InvalidFormat;
        result.name = try allocator.dupe(u8, name_value.string);

        if (obj.get("parameters")) |params_array| {
            if (params_array != .array) return errors.SerializationError.InvalidFormat;
            var parameters = ArrayList(ContractParameterDefinition).init(allocator);
            errdefer {
                for (parameters.items) |*param| param.deinit(allocator);
                parameters.deinit();
            }
            for (params_array.array.items) |param| {
                var parsed = try ContractParameterDefinition.fromJson(param, allocator);
                errdefer parsed.deinit(allocator);
                try parameters.append(parsed);
            }
            result.parameters = try parameters.toOwnedSlice();
        }

        return result;
    }

    pub fn deinit(self: *const ContractEventInfo, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.parameters.len > 0) {
            for (self.parameters) |*param| {
                param.deinit(allocator);
            }
            allocator.free(@constCast(self.parameters));
        }
    }
};

/// Contract permission
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
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var result = ContractPermission.init();
        errdefer result.deinit(allocator);

        const contract_value = obj.get("contract") orelse return errors.SerializationError.InvalidFormat;
        if (contract_value != .string) return errors.SerializationError.InvalidFormat;
        result.contract = try allocator.dupe(u8, contract_value.string);

        if (obj.get("methods")) |methods_array| {
            if (methods_array != .array) return errors.SerializationError.InvalidFormat;
            var methods = ArrayList([]const u8).init(allocator);
            errdefer {
                for (methods.items) |method| allocator.free(@constCast(method));
                methods.deinit();
            }
            for (methods_array.array.items) |method| {
                if (method != .string) return errors.SerializationError.InvalidFormat;
                const method_copy = try allocator.dupe(u8, method.string);
                errdefer allocator.free(method_copy);
                try methods.append(method_copy);
            }
            result.methods = try methods.toOwnedSlice();
        }

        return result;
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

/// Contract storage entry
pub const ContractStorageEntry = struct {
    key: []const u8,
    value: []const u8,

    pub fn init(key: []const u8, value: []const u8) ContractStorageEntry {
        return ContractStorageEntry{ .key = key, .value = value };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractStorageEntry {
        const obj = json_value.object;

        return ContractStorageEntry.init(
            try allocator.dupe(u8, obj.get("key").?.string),
            try allocator.dupe(u8, obj.get("value").?.string),
        );
    }

    pub fn deinit(self: *ContractStorageEntry, allocator: std.mem.Allocator) void {
        if (self.key.len > 0) allocator.free(@constCast(self.key));
        if (self.value.len > 0) allocator.free(@constCast(self.value));
        self.key = "";
        self.value = "";
    }
};

fn buildContractHashScript(
    deployment_sender: Hash160,
    nef_checksum: i32,
    contract_name: []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    return try ScriptBuilder.buildContractHashScript(
        deployment_sender,
        @intCast(nef_checksum),
        contract_name,
        allocator,
    );
}

fn signMessage(message: []const u8, key_pair: anytype, allocator: std.mem.Allocator) ![]u8 {
    const message_hash = Hash256.sha256(message);
    const signature = try key_pair.private_key.sign(message_hash);

    return try allocator.dupe(u8, signature.toSlice());
}
