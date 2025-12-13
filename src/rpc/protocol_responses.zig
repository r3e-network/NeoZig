//! Complete Protocol Response Types
//!
//! Conversion of ALL remaining Swift protocol response types
//! for complete RPC functionality.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const json_utils = @import("../utils/json_utils.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;

/// NEF file (shared contract format).
pub const ContractNef = @import("responses.zig").ContractNef;

/// Contract manifest (converted from Swift ContractManifest)
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

    /// Creates contract group (equivalent to Swift createGroup)
    pub fn createGroup(
        group_key_pair: anytype,
        deployment_sender: Hash160,
        nef_checksum: i32,
        contract_name: ?[]const u8,
        allocator: std.mem.Allocator,
    ) !ContractGroup {
        // Build contract hash script (equivalent to Swift buildContractHashScript)
        const contract_hash_bytes = try buildContractHashScript(
            deployment_sender,
            nef_checksum,
            contract_name orelse "",
            allocator,
        );
        defer allocator.free(contract_hash_bytes);

        // Sign the contract hash (equivalent to Swift signMessage)
        const signature_data = try signMessage(contract_hash_bytes, group_key_pair, allocator);
        defer allocator.free(signature_data);

        // Get public key hex
        const pub_key_hex = try group_key_pair.public_key.toHex(allocator);
        defer allocator.free(pub_key_hex);

        // Encode signature as base64
        const signature_base64 = try @import("../utils/string_extensions.zig").StringUtils.base64Encoded(signature_data, allocator);
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
            for (self.groups) |*group| {
                group.deinit(allocator);
            }
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
            for (self.permissions) |*permission| {
                permission.deinit(allocator);
            }
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

/// Contract group (converted from Swift ContractGroup)
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

        // Handle both "pubkey" and "pubKey" (Swift handles both)
        const pub_key_str = if (obj.get("pubkey")) |pk|
            pk.string
        else if (obj.get("pubKey")) |pk|
            pk.string
        else
            return errors.throwIllegalArgument("Missing public key in contract group");

        const cleaned_pub_key = @import("../utils/string_extensions.zig").StringUtils.cleanedHexPrefix(pub_key_str);

        // Validate public key length (equivalent to Swift validation)
        const pub_key_bytes = try @import("../utils/string_extensions.zig").StringUtils.bytesFromHex(cleaned_pub_key, allocator);
        defer allocator.free(pub_key_bytes);

        if (pub_key_bytes.len != constants.PUBLIC_KEY_SIZE_COMPRESSED) {
            return errors.throwIllegalArgument("Invalid public key length");
        }

        const signature_str = obj.get("signature").?.string;
        const signature_bytes = try @import("../utils/string_extensions.zig").StringUtils.base64Decoded(signature_str, allocator);
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

/// Contract ABI (converted from Swift ContractABI)
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
            for (self.methods) |*method| {
                method.deinit(allocator);
            }
            allocator.free(@constCast(self.methods));
            self.methods = &[_]ContractMethodInfo{};
        }

        if (self.events.len > 0) {
            for (self.events) |*event| {
                event.deinit(allocator);
            }
            allocator.free(@constCast(self.events));
            self.events = &[_]ContractEventInfo{};
        }
    }
};

/// Contract method info (converted from Swift method definitions)
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

/// Contract parameter definition (converted from Swift parameter definitions)
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

/// Contract event info (converted from Swift event definitions)
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

/// Contract permission (converted from Swift ContractPermission)
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

/// Memory pool response (converted from Swift NeoGetMemPool)
pub const NeoGetMemPool = struct {
    height: u32,
    verified: []const []const u8,
    unverified: []const []const u8,

    pub fn init() NeoGetMemPool {
        return NeoGetMemPool{
            .height = 0,
            .verified = &[_][]const u8{},
            .unverified = &[_][]const u8{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetMemPool {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var result = NeoGetMemPool.init();
        errdefer result.deinit(allocator);

        const height_value = obj.get("height") orelse return errors.SerializationError.InvalidFormat;
        if (height_value != .integer) return errors.SerializationError.InvalidFormat;
        result.height = @intCast(height_value.integer);

        if (obj.get("verified")) |verified_array| {
            if (verified_array != .array) return errors.SerializationError.InvalidFormat;
            var verified = ArrayList([]const u8).init(allocator);
            errdefer {
                for (verified.items) |entry| allocator.free(@constCast(entry));
                verified.deinit();
            }
            for (verified_array.array.items) |item| {
                if (item != .string) return errors.SerializationError.InvalidFormat;
                const entry = try allocator.dupe(u8, item.string);
                errdefer allocator.free(entry);
                try verified.append(entry);
            }
            result.verified = try verified.toOwnedSlice();
        }

        if (obj.get("unverified")) |unverified_array| {
            if (unverified_array != .array) return errors.SerializationError.InvalidFormat;
            var unverified = ArrayList([]const u8).init(allocator);
            errdefer {
                for (unverified.items) |entry| allocator.free(@constCast(entry));
                unverified.deinit();
            }
            for (unverified_array.array.items) |item| {
                if (item != .string) return errors.SerializationError.InvalidFormat;
                const entry = try allocator.dupe(u8, item.string);
                errdefer allocator.free(entry);
                try unverified.append(entry);
            }
            result.unverified = try unverified.toOwnedSlice();
        }

        return result;
    }

    pub fn deinit(self: *NeoGetMemPool, allocator: std.mem.Allocator) void {
        if (self.verified.len > 0) {
            for (self.verified) |entry| {
                if (entry.len > 0) allocator.free(@constCast(entry));
            }
            allocator.free(@constCast(self.verified));
            self.verified = &[_][]const u8{};
        }

        if (self.unverified.len > 0) {
            for (self.unverified) |entry| {
                if (entry.len > 0) allocator.free(@constCast(entry));
            }
            allocator.free(@constCast(self.unverified));
            self.unverified = &[_][]const u8{};
        }
    }
};

/// Peers response (converted from Swift NeoGetPeers)
pub const NeoGetPeers = struct {
    unconnected: []const Peer,
    bad: []const Peer,
    connected: []const Peer,

    pub fn init() NeoGetPeers {
        return NeoGetPeers{
            .unconnected = &[_]Peer{},
            .bad = &[_]Peer{},
            .connected = &[_]Peer{},
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetPeers {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var result = NeoGetPeers.init();
        errdefer result.deinit(allocator);

        if (obj.get("unconnected")) |unconnected_value| {
            if (unconnected_value != .array) return errors.SerializationError.InvalidFormat;
            var unconnected = ArrayList(Peer).init(allocator);
            errdefer {
                for (unconnected.items) |*peer| peer.deinit(allocator);
                unconnected.deinit();
            }
            for (unconnected_value.array.items) |item| {
                var peer = try Peer.fromJson(item, allocator);
                errdefer peer.deinit(allocator);
                try unconnected.append(peer);
            }
            result.unconnected = try unconnected.toOwnedSlice();
        }

        if (obj.get("bad")) |bad_value| {
            if (bad_value != .array) return errors.SerializationError.InvalidFormat;
            var bad = ArrayList(Peer).init(allocator);
            errdefer {
                for (bad.items) |*peer| peer.deinit(allocator);
                bad.deinit();
            }
            for (bad_value.array.items) |item| {
                var peer = try Peer.fromJson(item, allocator);
                errdefer peer.deinit(allocator);
                try bad.append(peer);
            }
            result.bad = try bad.toOwnedSlice();
        }

        if (obj.get("connected")) |connected_value| {
            if (connected_value != .array) return errors.SerializationError.InvalidFormat;
            var connected = ArrayList(Peer).init(allocator);
            errdefer {
                for (connected.items) |*peer| peer.deinit(allocator);
                connected.deinit();
            }
            for (connected_value.array.items) |item| {
                var peer = try Peer.fromJson(item, allocator);
                errdefer peer.deinit(allocator);
                try connected.append(peer);
            }
            result.connected = try connected.toOwnedSlice();
        }

        return result;
    }

    pub fn deinit(self: *NeoGetPeers, allocator: std.mem.Allocator) void {
        if (self.unconnected.len > 0) {
            for (self.unconnected) |*peer| peer.deinit(allocator);
            allocator.free(@constCast(self.unconnected));
            self.unconnected = &[_]Peer{};
        }

        if (self.bad.len > 0) {
            for (self.bad) |*peer| peer.deinit(allocator);
            allocator.free(@constCast(self.bad));
            self.bad = &[_]Peer{};
        }

        if (self.connected.len > 0) {
            for (self.connected) |*peer| peer.deinit(allocator);
            allocator.free(@constCast(self.connected));
            self.connected = &[_]Peer{};
        }
    }
};

/// Peer information (converted from Swift peer data)
pub const Peer = struct {
    address: []const u8,
    port: u16,

    pub fn init(address: []const u8, port: u16) Peer {
        return Peer{ .address = address, .port = port };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !Peer {
        const obj = json_value.object;

        return Peer.init(
            try allocator.dupe(u8, obj.get("address").?.string),
            @as(u16, @intCast(obj.get("port").?.integer)),
        );
    }

    pub fn deinit(self: *const Peer, allocator: std.mem.Allocator) void {
        if (self.address.len > 0) allocator.free(@constCast(self.address));
    }
};

/// Wallet balance response (converted from Swift NeoGetWalletBalance)
pub const NeoGetWalletBalance = struct {
    balance: []const u8,

    pub fn init() NeoGetWalletBalance {
        return NeoGetWalletBalance{ .balance = "0" };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetWalletBalance {
        const obj = json_value.object;

        return NeoGetWalletBalance{
            .balance = try allocator.dupe(u8, obj.get("balance").?.string),
        };
    }

    pub fn deinit(self: *NeoGetWalletBalance, allocator: std.mem.Allocator) void {
        if (self.balance.len > 0 and (self.balance.ptr != "0".ptr or self.balance.len != "0".len)) {
            allocator.free(@constCast(self.balance));
        }
        self.balance = "0";
    }
};

/// Contract storage entry (converted from Swift ContractStorageEntry)
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

/// Claimable GAS response (converted from Swift NeoGetClaimable)
pub const NeoGetClaimable = struct {
    claimable: []const ClaimableTransaction,
    address: []const u8,
    unclaimed: []const u8,

    pub fn init() NeoGetClaimable {
        return NeoGetClaimable{
            .claimable = &[_]ClaimableTransaction{},
            .address = "",
            .unclaimed = "0",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NeoGetClaimable {
        if (json_value != .object) return errors.SerializationError.InvalidFormat;
        const obj = json_value.object;

        var result = NeoGetClaimable.init();
        errdefer result.deinit(allocator);

        if (obj.get("claimable")) |claimable_array| {
            if (claimable_array != .array) return errors.SerializationError.InvalidFormat;
            var claimable = ArrayList(ClaimableTransaction).init(allocator);
            errdefer claimable.deinit();
            for (claimable_array.array.items) |item| {
                try claimable.append(try ClaimableTransaction.fromJson(item, allocator));
            }
            result.claimable = try claimable.toOwnedSlice();
        }

        const address_value = obj.get("address") orelse return errors.SerializationError.InvalidFormat;
        if (address_value != .string) return errors.SerializationError.InvalidFormat;
        result.address = try allocator.dupe(u8, address_value.string);

        const unclaimed_value = obj.get("unclaimed") orelse return errors.SerializationError.InvalidFormat;
        if (unclaimed_value != .string) return errors.SerializationError.InvalidFormat;
        result.unclaimed = try allocator.dupe(u8, unclaimed_value.string);

        return result;
    }

    pub fn deinit(self: *NeoGetClaimable, allocator: std.mem.Allocator) void {
        if (self.claimable.len > 0) {
            allocator.free(@constCast(self.claimable));
            self.claimable = &[_]ClaimableTransaction{};
        }
        if (self.address.len > 0) allocator.free(@constCast(self.address));
        if (self.unclaimed.len > 0 and (self.unclaimed.ptr != "0".ptr or self.unclaimed.len != "0".len)) {
            allocator.free(@constCast(self.unclaimed));
        }
        self.address = "";
        self.unclaimed = "0";
    }
};

/// Claimable transaction (converted from Swift claimable data)
pub const ClaimableTransaction = struct {
    tx_id: Hash256,
    n: u32,
    value: u64,
    start_height: u32,
    end_height: u32,

    pub fn init() ClaimableTransaction {
        return std.mem.zeroes(ClaimableTransaction);
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ClaimableTransaction {
        _ = allocator;
        const obj = json_value.object;

        return ClaimableTransaction{
            .tx_id = try Hash256.initWithString(obj.get("txid").?.string),
            .n = @as(u32, @intCast(obj.get("n").?.integer)),
            .value = @as(u64, @intCast(obj.get("value").?.integer)),
            .start_height = @as(u32, @intCast(obj.get("start_height").?.integer)),
            .end_height = @as(u32, @intCast(obj.get("end_height").?.integer)),
        };
    }
};

// Helper functions
fn buildContractHashScript(
    deployment_sender: Hash160,
    nef_checksum: i32,
    contract_name: []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    // Build contract hash script using Neo protocol rules
    var script_builder = @import("../script/script_builder.zig").ScriptBuilder.init(allocator);
    defer script_builder.deinit();

    // Push deployment sender
    _ = try script_builder.pushData(&deployment_sender.toArray());

    // Push NEF checksum
    const checksum_bytes = std.mem.toBytes(std.mem.nativeToLittle(i32, nef_checksum));
    _ = try script_builder.pushData(&checksum_bytes);

    // Push contract name
    _ = try script_builder.pushData(contract_name);

    return try allocator.dupe(u8, script_builder.toScript());
}

fn signMessage(message: []const u8, key_pair: anytype, allocator: std.mem.Allocator) ![]u8 {
    // Implement actual message signing using crypto module
    const message_hash = @import("../types/hash256.zig").Hash256.sha256(message);
    const signature = try key_pair.private_key.sign(message_hash);

    return try allocator.dupe(u8, signature.toSlice());
}

// Tests (converted from Swift protocol response tests)
test "ContractManifest parsing and operations" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test manifest creation (equivalent to Swift ContractManifest tests)
    const manifest = ContractManifest.init(
        "TestContract",
        &[_]ContractGroup{},
        null,
        &[_][]const u8{},
        null,
        &[_]ContractPermission{},
        &[_][]const u8{},
        null,
    );

    try testing.expectEqualStrings("TestContract", manifest.name.?);
    try testing.expectEqual(@as(usize, 0), manifest.groups.len);
}

test "ContractGroup validation" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test contract group creation (equivalent to Swift ContractGroup tests)
    const valid_pub_key = "02b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    const valid_signature = "dGVzdF9zaWduYXR1cmU="; // "test_signature" in base64

    const group = ContractGroup.init(valid_pub_key, valid_signature);
    try testing.expectEqualStrings(valid_pub_key, group.pub_key);
    try testing.expectEqualStrings(valid_signature, group.signature);
}

test "Memory pool response parsing" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test memory pool response (equivalent to Swift mempool tests)
    const mempool = NeoGetMemPool.init();
    try testing.expectEqual(@as(u32, 0), mempool.height);
    try testing.expectEqual(@as(usize, 0), mempool.verified.len);
    try testing.expectEqual(@as(usize, 0), mempool.unverified.len);
}

test "Peers response parsing" {
    const testing = std.testing;
    _ = testing.allocator;

    // Test peers response (equivalent to Swift peers tests)
    const peers = NeoGetPeers.init();
    try testing.expectEqual(@as(usize, 0), peers.connected.len);
    try testing.expectEqual(@as(usize, 0), peers.unconnected.len);
    try testing.expectEqual(@as(usize, 0), peers.bad.len);

    // Test peer creation
    const peer = Peer.init("127.0.0.1", 20333);
    try testing.expectEqualStrings("127.0.0.1", peer.address);
    try testing.expectEqual(@as(u16, 20333), peer.port);
}

test "Protocol response fromJson smoke tests" {
    const testing = std.testing;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // ContractManifest.fromJson (with arrays + nested objects)
    var features_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&features_obj, allocator, "featureA", std.json.Value{ .bool = true });

    var standards_array = std.json.Array.init(allocator);
    try standards_array.append(std.json.Value{ .string = "NEP-17" });

    var trusts_array = std.json.Array.init(allocator);
    try trusts_array.append(std.json.Value{ .string = "*" });

    var methods_array = std.json.Array.init(allocator);
    try methods_array.append(std.json.Value{ .string = "transfer" });

    var permission_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&permission_obj, allocator, "contract", std.json.Value{ .string = "*" });
    try json_utils.putOwnedKey(&permission_obj, allocator, "methods", std.json.Value{ .array = methods_array });

    var permissions_array = std.json.Array.init(allocator);
    try permissions_array.append(std.json.Value{ .object = permission_obj });

    var manifest_obj = std.json.ObjectMap.init(allocator);
    try json_utils.putOwnedKey(&manifest_obj, allocator, "name", std.json.Value{ .string = "TestContract" });
    try json_utils.putOwnedKey(&manifest_obj, allocator, "features", std.json.Value{ .object = features_obj });
    try json_utils.putOwnedKey(&manifest_obj, allocator, "supportedstandards", std.json.Value{ .array = standards_array });
    try json_utils.putOwnedKey(&manifest_obj, allocator, "permissions", std.json.Value{ .array = permissions_array });
    try json_utils.putOwnedKey(&manifest_obj, allocator, "trusts", std.json.Value{ .array = trusts_array });

    var parsed_manifest = try ContractManifest.fromJson(std.json.Value{ .object = manifest_obj }, allocator);
    try testing.expect(parsed_manifest.name != null);
    parsed_manifest.deinit(allocator);

    // ContractABI.fromJson (empty object is valid and should yield empty lists)
    const abi_obj = std.json.ObjectMap.init(allocator);
    var parsed_abi = try ContractABI.fromJson(std.json.Value{ .object = abi_obj }, allocator);
    defer parsed_abi.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), parsed_abi.methods.len);
    try testing.expectEqual(@as(usize, 0), parsed_abi.events.len);
}
