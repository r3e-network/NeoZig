//! Neo ListPlugins Implementation
//!
//! Complete conversion from NeoSwift NeoListPlugins.swift

const std = @import("std");

pub const Plugin = struct {
    name: []const u8,
    version: []const u8,
    interfaces: [][]const u8,
    
    pub fn init(name: []const u8, version: []const u8, interfaces: [][]const u8) @This() {
        return .{ .name = name, .version = version, .interfaces = interfaces };
    }
    
    pub fn getName(self: @This()) []const u8 {
        return self.name;
    }
    
    pub fn getVersion(self: @This()) []const u8 {
        return self.version;
    }
    
    pub fn getInterfaceCount(self: @This()) usize {
        return self.interfaces.len;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version);
        
        for (self.interfaces) |interface| {
            allocator.free(interface);
        }
        allocator.free(self.interfaces);
    }
};

pub const NeoListPlugins = struct {
    result: ?[]Plugin,
    
    pub fn init(result: ?[]Plugin) @This() {
        return .{ .result = result };
    }
    
    pub fn getPlugins(self: @This()) ?[]Plugin {
        return self.result;
    }
    
    pub fn getPluginCount(self: @This()) usize {
        if (self.result) |plugins| {
            return plugins.len;
        }
        return 0;
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        if (self.result) |plugins| {
            for (plugins) |*plugin| {
                plugin.deinit(allocator);
            }
            allocator.free(plugins);
        }
    }
};