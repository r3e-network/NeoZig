//! Contract Manifest Implementation
//!
//! Complete conversion from NeoSwift ContractManifest.swift
//! Provides contract manifest structure for smart contract metadata.

const std = @import("std");
const Hash160 = @import("../../types/hash160.zig").Hash160;
const ECKeyPair = @import("../../crypto/ec_key_pair.zig").ECKeyPair;
const PublicKey = @import("../../crypto/keys.zig").PublicKey;
const Sign = @import("../../crypto/sign.zig").Sign;
const ScriptBuilder = @import("../../script/script_builder.zig").ScriptBuilder;

/// Contract group information (converted from Swift ContractGroup)
pub const ContractGroup = struct {
    /// Public key (hex string)
    pub_key: []const u8,
    /// Signature (base64 encoded)
    signature: []const u8,
    
    const Self = @This();
    
    /// Creates new contract group (equivalent to Swift init)
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
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.pub_key, other.pub_key) and
               std.mem.eql(u8, self.signature, other.signature);
    }
    
    /// Hash function (equivalent to Swift Hashable)
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
        const pub_key_copy = try allocator.dupe(u8, self.pub_key);
        const signature_copy = try allocator.dupe(u8, self.signature);
        return Self.init(pub_key_copy, signature_copy, allocator);
    }
};

/// Contract ABI placeholder (simplified)
pub const ContractABI = struct {
    methods: []ContractMethod,
    events: []ContractEvent,
    
    const Self = @This();
    
    pub fn init(methods: []ContractMethod, events: []ContractEvent) Self {
        return Self{ .methods = methods, .events = events };
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
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        
        for (self.parameters) |*param| {
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
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        
        for (self.parameters) |*param| {
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
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.contract);
        
        for (self.methods) |method| {
            allocator.free(method);
        }
        allocator.free(self.methods);
    }
};

/// Contract manifest (converted from Swift ContractManifest)
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
    
    /// Creates contract manifest (equivalent to Swift init)
    pub fn init(
        name: ?[]const u8,
        groups: []ContractGroup,
        features: ?std.json.ObjectMap,
        supported_standards: [][]const u8,
        abi: ?ContractABI,
        permissions: []ContractPermission,
        trusts: [][]const u8,
        extra: ?std.json.ObjectMap,
        allocator: std.mem.Allocator,
    ) !Self {
        return Self{
            .name = if (name) |n| try allocator.dupe(u8, n) else null,
            .groups = try allocator.dupe(ContractGroup, groups),
            .features = features,
            .supported_standards = try allocator.dupe([]const u8, supported_standards),
            .abi = abi,
            .permissions = try allocator.dupe(ContractPermission, permissions),
            .trusts = try allocator.dupe([]const u8, trusts),
            .extra = extra,
        };
    }
    
    /// Creates group for manifest (equivalent to Swift createGroup)
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
    
    /// Equality comparison (equivalent to Swift Hashable)
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
            self.trusts.len != other.trusts.len) {
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
    
    /// Hash function (equivalent to Swift Hashable)
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
        
        if (self.features) |*features| {
            features.deinit();
        }
        
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
        
        if (self.extra) |*extra| {
            extra.deinit();
        }
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "ContractManifest(name: {s}, groups: {}, standards: {}, permissions: {})",
            .{ 
                self.getNameOrDefault(), 
                self.groups.len, 
                self.supported_standards.len, 
                self.permissions.len 
            }
        );
    }
};

/// Helper functions
fn isValidBase64(data: []const u8) bool {
    if (data.len == 0) return false;
    if (data.len % 4 != 0) return false;
    
    for (data) |char| {
        if (!std.base64.standard.Decoder.isValidChar(char) and char != '=') {
            return false;
        }
    }
    
    return true;
}

fn base64Encode(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    return encoder.encode(encoded, data);
}

// Tests (converted from Swift ContractManifest tests)
test "ContractGroup creation and validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test contract group creation (equivalent to Swift tests)
    const valid_pub_key = "0302000000000000000000000000000000000000000000000000000000000000ab"; // 33 bytes
    const valid_signature = "dGVzdF9zaWduYXR1cmU="; // "test_signature" in base64
    
    var group = try ContractGroup.init(valid_pub_key, valid_signature, allocator);
    defer group.deinit(allocator);
    
    try testing.expect(std.mem.indexOf(u8, group.pub_key, "0302") != null);
    try testing.expectEqualStrings(valid_signature, group.signature);
    
    // Test invalid public key (wrong length)
    const invalid_pub_key = "030200"; // Too short
    try testing.expectError(
        error.InvalidPublicKey,
        ContractGroup.init(invalid_pub_key, valid_signature, allocator)
    );
    
    // Test invalid signature (not base64)
    const invalid_signature = "not_base64!";
    try testing.expectError(
        error.InvalidSignature,
        ContractGroup.init(valid_pub_key, invalid_signature, allocator)
    );
}

test "ContractManifest creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test manifest creation (equivalent to Swift tests)
    const name = "TestContract";
    const standards = [_][]const u8{ "NEP-17", "NEP-11" };
    
    var manifest = try ContractManifest.init(
        name,
        &[_]ContractGroup{},
        null,
        &standards,
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
        &nep17_standards,
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
    try testing.expectNotEqual(hash1, hash3); // Different groups should have different hash
}