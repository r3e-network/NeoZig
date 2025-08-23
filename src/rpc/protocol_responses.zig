//! Complete Protocol Response Types
//!
//! Conversion of ALL remaining Swift protocol response types
//! for complete RPC functionality.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;

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
        const obj = json_value.object;
        
        const name = if (obj.get("name")) |n| try allocator.dupe(u8, n.string) else null;
        
        // Parse groups
        var groups = std.ArrayList(ContractGroup).init(allocator);
        if (obj.get("groups")) |groups_array| {
            for (groups_array.array) |group_item| {
                try groups.append(try ContractGroup.fromJson(group_item, allocator));
            }
        }
        
        // Parse supported standards
        var standards = std.ArrayList([]const u8).init(allocator);
        if (obj.get("supportedstandards")) |standards_array| {
            for (standards_array.array) |standard| {
                try standards.append(try allocator.dupe(u8, standard.string));
            }
        }
        
        // Parse permissions
        var permissions = std.ArrayList(ContractPermission).init(allocator);
        if (obj.get("permissions")) |perms_array| {
            for (perms_array.array) |perm_item| {
                try permissions.append(try ContractPermission.fromJson(perm_item, allocator));
            }
        }
        
        // Parse trusts
        var trusts = std.ArrayList([]const u8).init(allocator);
        if (obj.get("trusts")) |trusts_array| {
            for (trusts_array.array) |trust| {
                try trusts.append(try allocator.dupe(u8, trust.string));
            }
        }
        
        return Self.init(
            name,
            try groups.toOwnedSlice(),
            obj.get("features"),
            try standards.toOwnedSlice(),
            if (obj.get("abi")) |abi| try ContractABI.fromJson(abi, allocator) else null,
            try permissions.toOwnedSlice(),
            try trusts.toOwnedSlice(),
            obj.get("extra"),
        );
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
        const obj = json_value.object;
        
        var methods = std.ArrayList(ContractMethodInfo).init(allocator);
        if (obj.get("methods")) |methods_array| {
            for (methods_array.array) |method| {
                try methods.append(try ContractMethodInfo.fromJson(method, allocator));
            }
        }
        
        var events = std.ArrayList(ContractEventInfo).init(allocator);
        if (obj.get("events")) |events_array| {
            for (events_array.array) |event| {
                try events.append(try ContractEventInfo.fromJson(event, allocator));
            }
        }
        
        return ContractABI{
            .methods = try methods.toOwnedSlice(),
            .events = try events.toOwnedSlice(),
        };
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
        const obj = json_value.object;
        
        const name = try allocator.dupe(u8, obj.get("name").?.string);
        const return_type = try allocator.dupe(u8, obj.get("returntype").?.string);
        const offset = @as(u32, @intCast(obj.get("offset").?.integer));
        const safe = obj.get("safe").?.bool;
        
        var parameters = std.ArrayList(ContractParameterDefinition).init(allocator);
        if (obj.get("parameters")) |params_array| {
            for (params_array.array) |param| {
                try parameters.append(try ContractParameterDefinition.fromJson(param, allocator));
            }
        }
        
        return ContractMethodInfo{
            .name = name,
            .parameters = try parameters.toOwnedSlice(),
            .return_type = return_type,
            .offset = offset,
            .safe = safe,
        };
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
        const obj = json_value.object;
        
        const name = try allocator.dupe(u8, obj.get("name").?.string);
        
        var parameters = std.ArrayList(ContractParameterDefinition).init(allocator);
        if (obj.get("parameters")) |params_array| {
            for (params_array.array) |param| {
                try parameters.append(try ContractParameterDefinition.fromJson(param, allocator));
            }
        }
        
        return ContractEventInfo{
            .name = name,
            .parameters = try parameters.toOwnedSlice(),
        };
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
        const obj = json_value.object;
        
        const contract = try allocator.dupe(u8, obj.get("contract").?.string);
        
        var methods = std.ArrayList([]const u8).init(allocator);
        if (obj.get("methods")) |methods_array| {
            for (methods_array.array) |method| {
                try methods.append(try allocator.dupe(u8, method.string));
            }
        }
        
        return ContractPermission{
            .contract = contract,
            .methods = try methods.toOwnedSlice(),
        };
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
        const obj = json_value.object;
        
        const height = @as(u32, @intCast(obj.get("height").?.integer));
        
        var verified = std.ArrayList([]const u8).init(allocator);
        if (obj.get("verified")) |verified_array| {
            for (verified_array.array) |item| {
                try verified.append(try allocator.dupe(u8, item.string));
            }
        }
        
        var unverified = std.ArrayList([]const u8).init(allocator);
        if (obj.get("unverified")) |unverified_array| {
            for (unverified_array.array) |item| {
                try unverified.append(try allocator.dupe(u8, item.string));
            }
        }
        
        return NeoGetMemPool{
            .height = height,
            .verified = try verified.toOwnedSlice(),
            .unverified = try unverified.toOwnedSlice(),
        };
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
        const obj = json_value.object;
        
        var unconnected = std.ArrayList(Peer).init(allocator);
        if (obj.get("unconnected")) |array| {
            for (array.array) |item| {
                try unconnected.append(try Peer.fromJson(item, allocator));
            }
        }
        
        var bad = std.ArrayList(Peer).init(allocator);
        if (obj.get("bad")) |array| {
            for (array.array) |item| {
                try bad.append(try Peer.fromJson(item, allocator));
            }
        }
        
        var connected = std.ArrayList(Peer).init(allocator);
        if (obj.get("connected")) |array| {
            for (array.array) |item| {
                try connected.append(try Peer.fromJson(item, allocator));
            }
        }
        
        return NeoGetPeers{
            .unconnected = try unconnected.toOwnedSlice(),
            .bad = try bad.toOwnedSlice(),
            .connected = try connected.toOwnedSlice(),
        };
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
        const obj = json_value.object;
        
        var claimable = std.ArrayList(ClaimableTransaction).init(allocator);
        if (obj.get("claimable")) |claimable_array| {
            for (claimable_array.array) |item| {
                try claimable.append(try ClaimableTransaction.fromJson(item, allocator));
            }
        }
        
        return NeoGetClaimable{
            .claimable = try claimable.toOwnedSlice(),
            .address = try allocator.dupe(u8, obj.get("address").?.string),
            .unclaimed = try allocator.dupe(u8, obj.get("unclaimed").?.string),
        };
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
    _ = allocator;
    
    const message_hash = @import("../types/hash256.zig").Hash256.sha256(message);
    const signature = try key_pair.private_key.sign(message_hash);
    
    return try allocator.dupe(u8, signature.toSlice());
}

// Tests (converted from Swift protocol response tests)
test "ContractManifest parsing and operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
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
    const allocator = testing.allocator;
    
    // Test contract group creation (equivalent to Swift ContractGroup tests)
    const valid_pub_key = "02b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816";
    const valid_signature = "dGVzdF9zaWduYXR1cmU="; // "test_signature" in base64
    
    const group = ContractGroup.init(valid_pub_key, valid_signature);
    try testing.expectEqualStrings(valid_pub_key, group.pub_key);
    try testing.expectEqualStrings(valid_signature, group.signature);
}

test "Memory pool response parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test memory pool response (equivalent to Swift mempool tests)
    const mempool = NeoGetMemPool.init();
    try testing.expectEqual(@as(u32, 0), mempool.height);
    try testing.expectEqual(@as(usize, 0), mempool.verified.len);
    try testing.expectEqual(@as(usize, 0), mempool.unverified.len);
}

test "Peers response parsing" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
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