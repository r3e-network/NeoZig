//! NEP-6 Contract Implementation
//!
//! Complete conversion from NeoSwift NEP6Contract.swift
//! Provides NEP-6 wallet contract structure.

const std = @import("std");
const ContractParameterType = @import("../types/contract_parameter.zig").ContractParameterType;

/// NEP-6 parameter structure (converted from Swift NEP6Parameter)
pub const NEP6Parameter = struct {
    /// Parameter name
    param_name: []const u8,
    /// Parameter type
    param_type: ContractParameterType,
    
    const Self = @This();
    
    /// Creates new NEP-6 parameter (equivalent to Swift init)
    pub fn init(param_name: []const u8, param_type: ContractParameterType) Self {
        return Self{
            .param_name = param_name,
            .param_type = param_type,
        };
    }
    
    /// Gets parameter name
    pub fn getParamName(self: Self) []const u8 {
        return self.param_name;
    }
    
    /// Gets parameter type
    pub fn getParamType(self: Self) ContractParameterType {
        return self.param_type;
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        return std.mem.eql(u8, self.param_name, other.param_name) and
               self.param_type == other.param_type;
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(self.param_name);
        hasher.update(&[_]u8{@intFromEnum(self.param_type)});
        return hasher.final();
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try std.fmt.allocPrint(
            allocator,
            "{{\"name\":\"{s}\",\"type\":\"{s}\"}}",
            .{ self.param_name, self.param_type.toString() }
        );
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.param_name);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const param_name_copy = try allocator.dupe(u8, self.param_name);
        return Self.init(param_name_copy, self.param_type);
    }
};

/// NEP-6 contract structure (converted from Swift NEP6Contract)
pub const NEP6Contract = struct {
    /// Contract script (optional)
    script: ?[]const u8,
    /// NEP-6 parameters
    nep6_parameters: []NEP6Parameter,
    /// Whether contract is deployed
    is_deployed: bool,
    
    const Self = @This();
    
    /// Creates new NEP-6 contract (equivalent to Swift init)
    pub fn init(script: ?[]const u8, nep6_parameters: []NEP6Parameter, is_deployed: bool) Self {
        return Self{
            .script = script,
            .nep6_parameters = nep6_parameters,
            .is_deployed = is_deployed,
        };
    }
    
    /// Gets contract script
    pub fn getScript(self: Self) ?[]const u8 {
        return self.script;
    }
    
    /// Gets NEP-6 parameters
    pub fn getNep6Parameters(self: Self) []const NEP6Parameter {
        return self.nep6_parameters;
    }
    
    /// Checks if contract is deployed
    pub fn isDeployed(self: Self) bool {
        return self.is_deployed;
    }
    
    /// Checks if contract has script
    pub fn hasScript(self: Self) bool {
        return self.script != null;
    }
    
    /// Gets parameter count
    pub fn getParameterCount(self: Self) usize {
        return self.nep6_parameters.len;
    }
    
    /// Gets parameter by index
    pub fn getParameter(self: Self, index: usize) ?NEP6Parameter {
        if (index >= self.nep6_parameters.len) return null;
        return self.nep6_parameters[index];
    }
    
    /// Finds parameter by name
    pub fn findParameterByName(self: Self, name: []const u8) ?NEP6Parameter {
        for (self.nep6_parameters) |param| {
            if (std.mem.eql(u8, param.param_name, name)) {
                return param;
            }
        }
        return null;
    }
    
    /// Equality comparison (equivalent to Swift Hashable)
    pub fn eql(self: Self, other: Self) bool {
        // Compare script
        if (self.script == null and other.script == null) {
            // Both null - OK
        } else if (self.script == null or other.script == null) {
            return false; // One null, one not
        } else {
            if (!std.mem.eql(u8, self.script.?, other.script.?)) {
                return false;
            }
        }
        
        // Compare deployment status
        if (self.is_deployed != other.is_deployed) {
            return false;
        }
        
        // Compare parameters
        if (self.nep6_parameters.len != other.nep6_parameters.len) {
            return false;
        }
        
        for (self.nep6_parameters, 0..) |param, i| {
            if (!param.eql(other.nep6_parameters[i])) {
                return false;
            }
        }
        
        return true;
    }
    
    /// Hash function (equivalent to Swift Hashable)
    pub fn hash(self: Self) u64 {
        var hasher = std.hash.Wyhash.init(0);
        
        if (self.script) |script| {
            hasher.update(script);
        }
        
        hasher.update(&[_]u8{if (self.is_deployed) 1 else 0});
        
        for (self.nep6_parameters) |param| {
            const param_hash = param.hash();
            hasher.update(std.mem.asBytes(&param_hash));
        }
        
        return hasher.final();
    }
    
    /// JSON encoding (equivalent to Swift Codable)
    pub fn encodeToJson(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const script_str = if (self.script) |script|
            try std.fmt.allocPrint(allocator, "\"{s}\"", .{script})
        else
            try allocator.dupe(u8, "null");
        defer allocator.free(script_str);
        
        // Encode parameters array
        var params_json = std.ArrayList(u8).init(allocator);
        defer params_json.deinit();
        
        try params_json.appendSlice("[");
        for (self.nep6_parameters, 0..) |param, i| {
            if (i > 0) try params_json.appendSlice(",");
            const param_json = try param.encodeToJson(allocator);
            defer allocator.free(param_json);
            try params_json.appendSlice(param_json);
        }
        try params_json.appendSlice("]");
        
        return try std.fmt.allocPrint(
            allocator,
            "{{\"script\":{s},\"parameters\":{s},\"deployed\":{}}}",
            .{ script_str, params_json.items, self.is_deployed }
        );
    }
    
    /// JSON decoding (equivalent to Swift Codable)
    pub fn decodeFromJson(json_str: []const u8, allocator: std.mem.Allocator) !Self {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();
        
        const json_obj = parsed.value.object;
        
        const script = if (json_obj.get("script")) |script_value|
            switch (script_value) {
                .string => |s| try allocator.dupe(u8, s),
                .null => null,
                else => null,
            }
        else
            null;
        
        const is_deployed = json_obj.get("deployed").?.bool;
        
        // Parse parameters array
        const params_array = json_obj.get("parameters").?.array;
        var parameters = try std.ArrayList(NEP6Parameter).initCapacity(allocator, params_array.items.len);
        defer parameters.deinit();
        
        for (params_array.items) |param_value| {
            const param_obj = param_value.object;
            const param_name = try allocator.dupe(u8, param_obj.get("name").?.string);
            const type_str = param_obj.get("type").?.string;
            const param_type = ContractParameterType.fromString(type_str) orelse .Any;
            
            try parameters.append(NEP6Parameter.init(param_name, param_type));
        }
        
        return Self.init(script, try parameters.toOwnedSlice(), is_deployed);
    }
    
    /// Cleanup allocated resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (self.script) |script| {
            allocator.free(script);
        }
        
        for (self.nep6_parameters) |*param| {
            param.deinit(allocator);
        }
        allocator.free(self.nep6_parameters);
    }
    
    /// Clone with owned memory
    pub fn clone(self: Self, allocator: std.mem.Allocator) !Self {
        const script_copy = if (self.script) |script|
            try allocator.dupe(u8, script)
        else
            null;
        
        var params_copy = try std.ArrayList(NEP6Parameter).initCapacity(allocator, self.nep6_parameters.len);
        defer params_copy.deinit();
        
        for (self.nep6_parameters) |param| {
            try params_copy.append(try param.clone(allocator));
        }
        
        return Self.init(script_copy, try params_copy.toOwnedSlice(), self.is_deployed);
    }
    
    /// Format for display
    pub fn format(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const script_info = if (self.hasScript()) "with script" else "no script";
        const deploy_status = if (self.isDeployed()) "deployed" else "not deployed";
        
        return try std.fmt.allocPrint(
            allocator,
            "NEP6Contract({s}, {} params, {s})",
            .{ script_info, self.getParameterCount(), deploy_status }
        );
    }
};

// Tests (converted from Swift NEP6Contract tests)
test "NEP6Parameter creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test parameter creation
    const param_name = try allocator.dupe(u8, "testParam");
    var parameter = NEP6Parameter.init(param_name, ContractParameterType.String);
    defer parameter.deinit(allocator);
    
    try testing.expectEqualStrings("testParam", parameter.getParamName());
    try testing.expectEqual(ContractParameterType.String, parameter.getParamType());
    
    // Test JSON encoding
    const json_str = try parameter.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(std.mem.indexOf(u8, json_str, "testParam") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "String") != null);
}

test "NEP6Contract creation and properties" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test contract creation
    const script = try allocator.dupe(u8, "0c14aa7b0d2f2c22b42f");
    const param_name = try allocator.dupe(u8, "owner");
    const parameter = NEP6Parameter.init(param_name, ContractParameterType.Hash160);
    const parameters = [_]NEP6Parameter{parameter};
    
    var contract = NEP6Contract.init(script, &parameters, true);
    defer contract.deinit(allocator);
    
    try testing.expect(contract.hasScript());
    try testing.expect(contract.isDeployed());
    try testing.expectEqualStrings("0c14aa7b0d2f2c22b42f", contract.getScript().?);
    try testing.expectEqual(@as(usize, 1), contract.getParameterCount());
    
    // Test parameter lookup
    const found_param = contract.findParameterByName("owner");
    try testing.expect(found_param != null);
    try testing.expectEqual(ContractParameterType.Hash160, found_param.?.getParamType());
    
    const not_found = contract.findParameterByName("nonexistent");
    try testing.expect(not_found == null);
}

test "NEP6Contract JSON operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test JSON encoding/decoding
    const parameters = [_]NEP6Parameter{};
    var original_contract = NEP6Contract.init(null, &parameters, false);
    defer original_contract.deinit(allocator);
    
    const json_str = try original_contract.encodeToJson(allocator);
    defer allocator.free(json_str);
    
    try testing.expect(std.mem.indexOf(u8, json_str, "\"script\":null") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"deployed\":false") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"parameters\":[]") != null);
    
    // Note: Full JSON decoding test would require proper JSON parsing setup
}