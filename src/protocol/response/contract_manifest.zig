//! Contract Manifest Implementation
//!
//! Neo N3
//! Provides contract manifest structure for smart contract metadata.

const std = @import("std");

const Hash160 = @import("../../types/hash160.zig").Hash160;
const ECKeyPair = @import("../../crypto/ec_key_pair.zig").ECKeyPair;
const Sign = @import("../../crypto/sign.zig").Sign;
const ScriptBuilder = @import("../../script/script_builder.zig").ScriptBuilder;
const json_utils = @import("../../utils/json_utils.zig");

/// Contract group information
pub const ContractGroup = struct {
    /// Public key (hex string)
    pub_key: []const u8,
    /// Signature (base64 encoded)
    signature: []const u8,

    const Self = @This();

    /// Creates new contract group
    pub fn init(pub_key: []const u8, signature: []const u8, allocator: std.mem.Allocator) !Self {
        // Validate public key
        const cleaned_key = if (std.mem.startsWith(u8, pub_key, "0x"))
            pub_key[2..]
        else
            pub_key;

        const key_bytes = try @import("../../utils/string_extensions.zig").StringUtils.bytesFromHex(cleaned_key, allocator);
        defer allocator.free(key_bytes);

        if (key_bytes.len != @import("../../core/constants.zig").PUBLIC_KEY_SIZE_COMPRESSED) {
            return error.InvalidPublicKey;
        }

        // Validate signature is valid base64
        if (!isValidBase64(signature)) {
            return error.InvalidSignature;
        }

        return Self{
            .pub_key = try allocator.dupe(u8, cleaned_key),
            .signature = try allocator.dupe(u8, signature),
        };
    }

    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.pub_key, other.pub_key) and
            std.mem.eql(u8, self.signature, other.signature);
    }

    /// Hash function
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.pub_key);
        hasher.update(self.signature);
        return hasher.final();
    }

    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.pub_key);
        allocator.free(self.signature);
    }

    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        return Self.init(self.pub_key, self.signature, allocator);
    }
};

/// Contract ABI stub (basic)
pub const ContractABI = struct {
    methods: []ContractMethod,
    events: []ContractEvent,

    const Self = @This();

    pub fn init(methods: []ContractMethod, events: []ContractEvent) Self {
        return Self{ .methods = methods, .events = events };
    }

    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        var methods_copy = try allocator.alloc(ContractMethod, self.methods.len);
        var methods_count: usize = 0;
        errdefer {
            for (methods_copy[0..methods_count]) |*method| {
                method.deinit(allocator);
            }
            allocator.free(methods_copy);
        }
        for (self.methods) |method| {
            methods_copy[methods_count] = try method.clone(allocator);
            methods_count += 1;
        }

        var events_copy = try allocator.alloc(ContractEvent, self.events.len);
        var events_count: usize = 0;
        errdefer {
            for (events_copy[0..events_count]) |*event| {
                event.deinit(allocator);
            }
            allocator.free(events_copy);
        }
        for (self.events) |event| {
            events_copy[events_count] = try event.clone(allocator);
            events_count += 1;
        }

        return Self.init(methods_copy, events_copy);
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        for (self.methods) |*method| {
            method.deinit(allocator);
        }
        allocator.free(self.methods);

        for (self.events) |*event| {
            event.deinit(allocator);
        }
        allocator.free(self.events);
    }
};

/// Contract method information
pub const ContractMethod = struct {
    name: []const u8,
    parameters: []ContractParameter,
    return_type: []const u8,

    const Self = @This();
    const ContractParameter = @import("../../types/contract_parameter.zig").ContractParameter;

    pub fn init(name: []const u8, parameters: []ContractParameter, return_type: []const u8) Self {
        return Self{ .name = name, .parameters = parameters, .return_type = return_type };
    }

    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const name_copy = try allocator.dupe(u8, self.name);
        errdefer allocator.free(name_copy);
        const return_copy = try allocator.dupe(u8, self.return_type);
        errdefer allocator.free(return_copy);

        var params_copy = try allocator.alloc(ContractParameter, self.parameters.len);
        var params_count: usize = 0;
        errdefer {
            for (params_copy[0..params_count]) |param| {
                param.deinit(allocator);
            }
            allocator.free(params_copy);
        }
        for (self.parameters) |param| {
            params_copy[params_count] = try param.clone(allocator);
            params_count += 1;
        }

        return Self.init(name_copy, params_copy, return_copy);
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        for (self.parameters) |param| {
            param.deinit(allocator);
        }
        allocator.free(self.parameters);

        allocator.free(self.return_type);
    }
};

/// Contract event information
pub const ContractEvent = struct {
    name: []const u8,
    parameters: []ContractParameter,

    const Self = @This();
    const ContractParameter = @import("../../types/contract_parameter.zig").ContractParameter;

    pub fn init(name: []const u8, parameters: []ContractParameter) Self {
        return Self{ .name = name, .parameters = parameters };
    }

    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const name_copy = try allocator.dupe(u8, self.name);
        errdefer allocator.free(name_copy);

        var params_copy = try allocator.alloc(ContractParameter, self.parameters.len);
        var params_count: usize = 0;
        errdefer {
            for (params_copy[0..params_count]) |param| {
                param.deinit(allocator);
            }
            allocator.free(params_copy);
        }
        for (self.parameters) |param| {
            params_copy[params_count] = try param.clone(allocator);
            params_count += 1;
        }

        return Self.init(name_copy, params_copy);
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        for (self.parameters) |param| {
            param.deinit(allocator);
        }
        allocator.free(self.parameters);
    }
};

/// Contract permission information
pub const ContractPermission = struct {
    contract: []const u8,
    methods: [][]const u8,

    const Self = @This();

    pub fn init(contract: []const u8, methods: [][]const u8) Self {
        return Self{ .contract = contract, .methods = methods };
    }

    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const contract_copy = try allocator.dupe(u8, self.contract);
        errdefer allocator.free(contract_copy);

        var methods_copy = try allocator.alloc([]const u8, self.methods.len);
        var methods_count: usize = 0;
        errdefer {
            for (methods_copy[0..methods_count]) |method| {
                allocator.free(method);
            }
            allocator.free(methods_copy);
        }
        for (self.methods) |method| {
            methods_copy[methods_count] = try allocator.dupe(u8, method);
            methods_count += 1;
        }

        return Self.init(contract_copy, methods_copy);
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.contract);

        for (self.methods) |method| {
            allocator.free(method);
        }
        allocator.free(self.methods);
    }
};

/// Contract manifest
pub const ContractManifest = struct {
    /// Contract name
    name: ?[]const u8,
    /// Contract groups
    groups: []ContractGroup,
    /// Contract features
    features: ?std.json.ObjectMap,
    /// Supported standards
    supported_standards: [][]const u8,
    /// Contract ABI
    abi: ?ContractABI,
    /// Permissions
    permissions: []ContractPermission,
    /// Trusted contracts/groups
    trusts: [][]const u8,
    /// Extra metadata
    extra: ?std.json.ObjectMap,

    const Self = @This();

    /// Creates contract manifest
    pub fn init(
        name: ?[]const u8,
        groups: []const ContractGroup,
        features: ?std.json.ObjectMap,
        supported_standards: []const []const u8,
        abi: ?ContractABI,
        permissions: []const ContractPermission,
        trusts: []const []const u8,
        extra: ?std.json.ObjectMap,
        allocator: std.mem.Allocator,
    ) !Self {
        const name_copy = if (name) |n| try allocator.dupe(u8, n) else null;
        errdefer if (name_copy) |owned| allocator.free(owned);

        var groups_copy = try allocator.alloc(ContractGroup, groups.len);
        var groups_count: usize = 0;
        errdefer {
            for (groups_copy[0..groups_count]) |*group| {
                group.deinit(allocator);
            }
            allocator.free(groups_copy);
        }
        for (groups) |group| {
            groups_copy[groups_count] = try group.clone(allocator);
            groups_count += 1;
        }

        var standards_copy = try allocator.alloc([]const u8, supported_standards.len);
        var standards_count: usize = 0;
        errdefer {
            for (standards_copy[0..standards_count]) |standard| {
                allocator.free(standard);
            }
            allocator.free(standards_copy);
        }
        for (supported_standards) |standard| {
            standards_copy[standards_count] = try allocator.dupe(u8, standard);
            standards_count += 1;
        }

        var permissions_copy = try allocator.alloc(ContractPermission, permissions.len);
        var permissions_count: usize = 0;
        errdefer {
            for (permissions_copy[0..permissions_count]) |*permission| {
                permission.deinit(allocator);
            }
            allocator.free(permissions_copy);
        }
        for (permissions) |permission| {
            permissions_copy[permissions_count] = try permission.clone(allocator);
            permissions_count += 1;
        }

        var trusts_copy = try allocator.alloc([]const u8, trusts.len);
        var trusts_count: usize = 0;
        errdefer {
            for (trusts_copy[0..trusts_count]) |trust| {
                allocator.free(trust);
            }
            allocator.free(trusts_copy);
        }
        for (trusts) |trust| {
            trusts_copy[trusts_count] = try allocator.dupe(u8, trust);
            trusts_count += 1;
        }

        var abi_copy: ?ContractABI = if (abi) |manifest_abi| try manifest_abi.clone(allocator) else null;
        errdefer if (abi_copy) |*manifest_abi| manifest_abi.deinit(allocator);

        const features_copy = try cloneObjectMapOptional(features, allocator);
        errdefer freeObjectMapOptional(features_copy, allocator);

        const extra_copy = try cloneObjectMapOptional(extra, allocator);
        errdefer freeObjectMapOptional(extra_copy, allocator);

        return Self{
            .name = name_copy,
            .groups = groups_copy,
            .features = features_copy,
            .supported_standards = standards_copy,
            .abi = abi_copy,
            .permissions = permissions_copy,
            .trusts = trusts_copy,
            .extra = extra_copy,
        };
    }

    /// Deep clone with owned memory.
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        return try Self.init(
            self.name,
            self.groups,
            self.features,
            self.supported_standards,
            self.abi,
            self.permissions,
            self.trusts,
            self.extra,
            allocator,
        );
    }

    /// Creates group for manifest
    pub fn createGroup(
        group_key_pair: ECKeyPair,
        deployment_sender: Hash160,
        nef_checksum: u32,
        contract_name: ?[]const u8,
        allocator: std.mem.Allocator,
    ) !ContractGroup {
        // Build contract hash script
        const name_str = contract_name orelse "";
        const contract_hash_script = try ScriptBuilder.buildContractHashScript(
            deployment_sender,
            nef_checksum,
            name_str,
            allocator,
        );
        defer allocator.free(contract_hash_script);

        // Sign the contract hash
        const signature_data = try Sign.signMessage(contract_hash_script, group_key_pair, allocator);
        defer signature_data.deinit(allocator);

        // Get public key hex
        const pub_key_hex = try group_key_pair.getPublicKey().toHexString(allocator);
        defer allocator.free(pub_key_hex);

        // Get signature base64
        const signature_bytes = signature_data.toBytes();
        const signature_b64 = try base64Encode(signature_bytes, allocator);
        defer allocator.free(signature_b64);

        return try ContractGroup.init(pub_key_hex, signature_b64, allocator);
    }

    /// Checks if manifest has specific standard
    pub fn hasStandard(self: Self, standard: []const u8) bool {
        for (self.supported_standards) |supported| {
            if (std.mem.eql(u8, supported, standard)) {
                return true;
            }
        }
        return false;
    }

    /// Checks if manifest supports NEP-17
    pub fn isNep17(self: Self) bool {
        return self.hasStandard("NEP-17");
    }

    /// Checks if manifest supports NEP-11
    pub fn isNep11(self: Self) bool {
        return self.hasStandard("NEP-11");
    }

    /// Gets contract name or default
    pub fn getNameOrDefault(self: Self) []const u8 {
        return self.name orelse "Unnamed Contract";
    }

    /// Checks if has groups
    pub fn hasGroups(self: Self) bool {
        return self.groups.len > 0;
    }

    /// Checks if has permissions
    pub fn hasPermissions(self: Self) bool {
        return self.permissions.len > 0;
    }

    /// Checks if has trusts
    pub fn hasTrusts(self: Self) bool {
        return self.trusts.len > 0;
    }

    /// Equality comparison
    pub fn eql(self: Self, other: Self) bool {
        // Compare name
        if (self.name == null and other.name == null) {
            // Both null - OK
        } else if (self.name == null or other.name == null) {
            return false;
        } else {
            if (!std.mem.eql(u8, self.name.?, other.name.?)) {
                return false;
            }
        }

        // Compare arrays
        if (self.groups.len != other.groups.len or
            self.supported_standards.len != other.supported_standards.len or
            self.permissions.len != other.permissions.len or
            self.trusts.len != other.trusts.len)
        {
            return false;
        }

        // Compare groups
        for (self.groups, 0..) |group, i| {
            if (!group.eql(other.groups[i])) {
                return false;
            }
        }

        return true;
    }

    /// Hash function
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);

        if (self.name) |name| {
            hasher.update(name);
        }

        for (self.groups) |group| {
            const group_hash = group.hash();
            hasher.update(std.mem.asBytes(&group_hash));
        }

        for (self.supported_standards) |standard| {
            hasher.update(standard);
        }

        return hasher.final();
    }

    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.name) |name| {
            allocator.free(name);
        }

        for (self.groups) |*group| {
            group.deinit(allocator);
        }
        allocator.free(self.groups);

        freeObjectMapOptional(self.features, allocator);

        for (self.supported_standards) |standard| {
            allocator.free(standard);
        }
        allocator.free(self.supported_standards);

        if (self.abi) |*abi| {
            abi.deinit(allocator);
        }

        for (self.permissions) |*permission| {
            permission.deinit(allocator);
        }
        allocator.free(self.permissions);

        for (self.trusts) |trust| {
            allocator.free(trust);
        }
        allocator.free(self.trusts);

        freeObjectMapOptional(self.extra, allocator);
    }

    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(allocator, "ContractManifest(name: {s}, groups: {}, standards: {}, permissions: {})", .{ self.getNameOrDefault(), self.groups.len, self.supported_standards.len, self.permissions.len });
    }
};

/// Helper functions
fn cloneObjectMapOptional(
    map_opt: ?std.json.ObjectMap,
    allocator: std.mem.Allocator,
) !?std.json.ObjectMap {
    if (map_opt) |map| {
        const cloned_value = try json_utils.cloneValue(std.json.Value{ .object = map }, allocator);
        return cloned_value.object;
    }
    return null;
}

fn freeObjectMapOptional(map_opt: ?std.json.ObjectMap, allocator: std.mem.Allocator) void {
    if (map_opt) |map| {
        json_utils.freeValue(std.json.Value{ .object = map }, allocator);
    }
}

fn isValidBase64(data: []const u8) bool {
    if (data.len == 0) return false;
    if (data.len % 4 != 0) return false;

    var padding_started = false;
    for (data, 0..) |char, idx| {
        if (char == '=') {
            padding_started = true;
            if (idx < data.len - 2) return false;
            continue;
        }

        if (padding_started) return false;

        const is_valid =
            (char >= 'A' and char <= 'Z') or
            (char >= 'a' and char <= 'z') or
            (char >= '0' and char <= '9') or
            char == '+' or
            char == '/';
        if (!is_valid) return false;
    }

    return true;
}

fn base64Encode(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    return encoder.encode(encoded, data);
}

// Tests
test "ContractGroup creation and validation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test contract group creation
    const valid_pub_key = "0302000000000000000000000000000000000000000000000000000000000000ab"; // 33 bytes
    const valid_signature = "dGVzdF9zaWduYXR1cmU="; // "test_signature" in base64

    var group = try ContractGroup.init(valid_pub_key, valid_signature, allocator);
    defer group.deinit(allocator);

    try testing.expect(std.mem.indexOf(u8, group.pub_key, "0302") != null);
    try testing.expectEqualStrings(valid_signature, group.signature);

    // Test invalid public key (wrong length)
    const invalid_pub_key = "030200"; // Too short
    try testing.expectError(error.InvalidPublicKey, ContractGroup.init(invalid_pub_key, valid_signature, allocator));

    // Test invalid signature (not base64)
    const invalid_signature = "not_base64!";
    try testing.expectError(error.InvalidSignature, ContractGroup.init(valid_pub_key, invalid_signature, allocator));
}

test "ContractManifest creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test manifest creation
    const name = "TestContract";
    const standards = [_][]const u8{ "NEP-17", "NEP-11" };

    var manifest = try ContractManifest.init(
        name,
        &[_]ContractGroup{},
        null,
        standards[0..],
        null,
        &[_]ContractPermission{},
        &[_][]const u8{},
        null,
        allocator,
    );
    defer manifest.deinit(allocator);

    try testing.expectEqualStrings("TestContract", manifest.getNameOrDefault());
    try testing.expect(manifest.isNep17());
    try testing.expect(manifest.isNep11());
    try testing.expect(!manifest.hasGroups());
    try testing.expect(!manifest.hasPermissions());
    try testing.expect(!manifest.hasTrusts());
}

test "ContractManifest standard detection" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test standard detection
    const nep17_standards = [_][]const u8{"NEP-17"};

    var nep17_manifest = try ContractManifest.init(
        "NEP17Token",
        &[_]ContractGroup{},
        null,
        nep17_standards[0..],
        null,
        &[_]ContractPermission{},
        &[_][]const u8{},
        null,
        allocator,
    );
    defer nep17_manifest.deinit(allocator);

    try testing.expect(nep17_manifest.hasStandard("NEP-17"));
    try testing.expect(!nep17_manifest.hasStandard("NEP-11"));
    try testing.expect(nep17_manifest.isNep17());
    try testing.expect(!nep17_manifest.isNep11());
}

test "ContractGroup equality and hashing" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test group equality
    const pub_key = "0302000000000000000000000000000000000000000000000000000000000000ab";
    const signature = "dGVzdF9zaWduYXR1cmU=";

    var group1 = try ContractGroup.init(pub_key, signature, allocator);
    defer group1.deinit(allocator);

    var group2 = try ContractGroup.init(pub_key, signature, allocator);
    defer group2.deinit(allocator);

    var group3 = try ContractGroup.init(pub_key, "b3RoZXJfc2lnbmF0dXJl", allocator); // Different signature
    defer group3.deinit(allocator);

    try testing.expect(group1.eql(group2));
    try testing.expect(!group1.eql(group3));

    // Test hashing
    const hash1 = group1.hash();
    const hash2 = group2.hash();
    const hash3 = group3.hash();

    try testing.expectEqual(hash1, hash2); // Same groups should have same hash
    try testing.expect(hash1 != hash3); // Different groups should have different hash
}
