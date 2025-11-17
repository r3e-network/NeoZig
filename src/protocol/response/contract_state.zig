//! Contract State Implementation
//!
//! Complete conversion from NeoSwift ContractState.swift
//! Provides smart contract state information.

const std = @import("std");


const Hash160 = @import("../../types/hash160.zig").Hash160;
const ContractNef = @import("contract_nef.zig").ContractNef;
const ContractManifest = @import("contract_manifest.zig").ContractManifest;

/// Contract state structure (converted from Swift ContractState)
pub const ContractState = struct {
    /// Contract ID
    id: i32,
    /// Contract update counter
    update_counter: u32,
    /// Contract hash
    hash: Hash160,
    /// Contract NEF file
    nef: ContractNef,
    /// Contract manifest
    manifest: ContractManifest,
    
    const Self = @This();
    
    /// Creates new ContractState (equivalent to Swift init)
    pub fn init(
        id: i32,
        update_counter: u32,
        hash: Hash160,
        nef: ContractNef,
        manifest: ContractManifest,
    ) Self {
        return Self{
            .id = id,
            .update_counter = update_counter,
            .hash = hash,
            .nef = nef,
            .manifest = manifest,
        };
    }
    
    /// Gets contract ID
    pub fn getId(self: Self) i32 {
        return self.id;
    }
    
    /// Gets contract hash
    pub fn getHash(self: Self) Hash160 {
        return self.hash;
    }
    
    /// Gets update counter
    pub fn getUpdateCounter(self: Self) u32 {
        return self.update_counter;
    }
    
    /// Gets contract NEF
    pub fn getNef(self: Self) ContractNef {
        return self.nef;
    }
    
    /// Gets contract manifest
    pub fn getManifest(self: Self) ContractManifest {
        return self.manifest;
    }
    
    /// Checks if contract has been updated
    pub fn hasBeenUpdated(self: Self) bool {
        return self.update_counter > 0;
    }
    
    /// Gets contract name from manifest
    pub fn getContractName(self: Self) []const u8 {
        return self.manifest.getNameOrDefault();
    }
    
    /// Checks if contract supports specific standard
    pub fn supportsStandard(self: Self, standard: []const u8) bool {
        return self.manifest.hasStandard(standard);
    }
    
    /// Checks if contract is NEP-17
    pub fn isNep17(self: Self) bool {
        return self.manifest.isNep17();
    }
    
    /// Checks if contract is NEP-11
    pub fn isNep11(self: Self) bool {
        return self.manifest.isNep11();
    }
    
    /// Equality comparison (equivalent to Swift ==)
    pub fn eql(self: Self, other: Self) bool {
        return self.id == other.id and
               self.update_counter == other.update_counter and
               self.hash.eql(other.hash) and
               self.nef.eql(other.nef) and
               self.manifest.eql(other.manifest);
    }
    
    /// Hash function (equivalent to Swift hash(into:))
    pub fn hashValue(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&self.id));
        hasher.update(std.mem.asBytes(&self.update_counter));
        
        const hash_value = self.hash.hash();
        hasher.update(std.mem.asBytes(&hash_value));
        
        const nef_hash = self.nef.hash();
        hasher.update(std.mem.asBytes(&nef_hash));
        
        const manifest_hash = self.manifest.hash();
        hasher.update(std.mem.asBytes(&manifest_hash));
        
        return hasher.final();
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const hash_str = try self.hash.toString(allocator);
        defer allocator.free(hash_str);
        
        const nef_json = try self.nef.encodeToJson(allocator);
        defer allocator.free(nef_json);
        
        const manifest_json = try self.manifest.encodeToJson(allocator);
        defer allocator.free(manifest_json);
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"id\":{},\"updatecounter\":{},\"hash\":\"{s}\",\"nef\":{s},\"manifest\":{s}}}",
            .{ self.id, self.update_counter, hash_str, nef_json, manifest_json }
        );
    }
    
    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        const id = @as(i32, @intCast(json_obj.get("id").?.integer));
        const update_counter = @as(u32, @intCast(json_obj.get("updatecounter").?.integer));
        const hash = try Hash160.initWithString(json_obj.get("hash").?.string);
        
        const nef_json = try std.json.stringifyAlloc(allocator, json_obj.get("nef").?, .{});
        defer allocator.free(nef_json);
        var nef = try ContractNef.decodeFromJson(nef_json, allocator);
        
        const manifest_json = try std.json.stringifyAlloc(allocator, json_obj.get("manifest").?, .{});
        defer allocator.free(manifest_json);
        var manifest = try ContractManifest.decodeFromJson(manifest_json, allocator);
        
        return Self.init(id, update_counter, hash, nef, manifest);
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.nef.deinit(allocator);
        self.manifest.deinit(allocator);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const cloned_nef = try self.nef.clone(allocator);
        const cloned_manifest = try self.manifest.clone(allocator);
        
        return Self.init(
            self.id,
            self.update_counter,
            self.hash,
            cloned_nef,
            cloned_manifest,
        );
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const hash_str = try self.hash.toString(allocator);
        defer allocator.free(hash_str);
        
        return try std.fmt.allocPrint(
            allocator,
            "ContractState(id: {}, hash: {s}, name: {s}, updates: {})",
            .{ self.id, hash_str, self.getContractName(), self.update_counter }
        );
    }
};

// Tests (converted from Swift ContractState tests)
test "ContractState creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test contract state creation
    const contract_hash = try Hash160.initWithString("0x1234567890abcdef1234567890abcdef12345678");
    
    const compiler = try allocator.dupe(u8, "neon");
    const script = try allocator.dupe(u8, "VgEMDEhlbGxvIFdvcmxkIQ==");
    var nef = ContractNef.init(
        ContractNef.NEF_MAGIC,
        compiler,
        null,
        &[_]@import("contract_nef.zig").ContractMethodToken{},
        script,
        0x12345678
    );
    defer nef.deinit(allocator);
    
    var manifest = ContractManifest.init(
        "TestContract",
        &[_]@import("contract_manifest.zig").ContractGroup{},
        null,
        &[_][]const u8{"NEP-17"},
        null,
        &[_]@import("contract_manifest.zig").ContractPermission{},
        &[_][]const u8{},
        null,
        allocator,
    ) catch unreachable;
    defer manifest.deinit(allocator);
    
    var contract_state = ContractState.init(1, 0, contract_hash, nef, manifest);
    defer contract_state.deinit(allocator);
    
    try testing.expectEqual(@as(i32, 1), contract_state.getId());
    try testing.expect(contract_state.getHash().eql(contract_hash));
    try testing.expectEqual(@as(u32, 0), contract_state.getUpdateCounter());
    try testing.expect(!contract_state.hasBeenUpdated());
    try testing.expectEqualStrings("TestContract", contract_state.getContractName());
    try testing.expect(contract_state.supportsStandard("NEP-17"));
    try testing.expect(contract_state.isNep17());
}