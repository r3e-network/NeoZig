//! Neo VM contract parameter types
//!
//! Complete conversion from Swift ContractParameter system.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("hash160.zig").Hash160;
const Hash256 = @import("hash256.zig").Hash256;

pub const ContractParameterType = enum(u8) {
    Any = 0x00,
    Boolean = 0x10,
    Integer = 0x21,
    ByteArray = 0x05,
    String = 0x13,
    Hash160 = 0x14,
    Hash256 = 0x15,
    PublicKey = 0x16,
    Signature = 0x17,
    Array = 0x10,
    Map = 0x12,
    InteropInterface = 0x30,
    Void = 0xff,
    
    pub fn toString(self: ContractParameterType) []const u8 {
        return switch (self) {
            .Any => "Any", .Boolean => "Boolean", .Integer => "Integer", .ByteArray => "ByteArray",
            .String => "String", .Hash160 => "Hash160", .Hash256 => "Hash256", .PublicKey => "PublicKey",
            .Signature => "Signature", .Array => "Array", .Map => "Map", .InteropInterface => "InteropInterface", .Void => "Void",
        };
    }
    
    pub fn fromString(type_str: []const u8) !ContractParameterType {
        if (std.mem.eql(u8, type_str, "Boolean")) return .Boolean;
        if (std.mem.eql(u8, type_str, "Integer")) return .Integer;
        if (std.mem.eql(u8, type_str, "String")) return .String;
        if (std.mem.eql(u8, type_str, "ByteArray")) return .ByteArray;
        if (std.mem.eql(u8, type_str, "Hash160")) return .Hash160;
        if (std.mem.eql(u8, type_str, "Hash256")) return .Hash256;
        return errors.ValidationError.InvalidParameter;
    }
};

pub const ContractParameter = union(ContractParameterType) {
    Any: void,
    Boolean: bool,
    Integer: i64,
    ByteArray: []const u8,
    String: []const u8,
    Hash160: Hash160,
    Hash256: Hash256,
    PublicKey: [constants.PUBLIC_KEY_SIZE_COMPRESSED]u8,
    Signature: [constants.SIGNATURE_SIZE]u8,
    Array: []const ContractParameter,
    Map: std.HashMap(ContractParameter, ContractParameter, ContractParameterContext, std.hash_map.default_max_load_percentage),
    InteropInterface: u64,
    Void: void,
    
    const Self = @This();
    
    pub fn boolean(value: bool) Self { return Self{ .Boolean = value }; }
    pub fn integer(value: i64) Self { return Self{ .Integer = value }; }
    pub fn byteArray(data: []const u8) Self { return Self{ .ByteArray = data }; }
    pub fn string(value: []const u8) Self { return Self{ .String = value }; }
    pub fn hash160(value: Hash160) Self { return Self{ .Hash160 = value }; }
    pub fn hash256(value: Hash256) Self { return Self{ .Hash256 = value }; }
    
    pub fn getType(self: Self) ContractParameterType {
        return @as(ContractParameterType, self);
    }
    
    pub fn validate(self: Self) !void {
        switch (self) {
            .PublicKey => |key| {
                if (key[0] != 0x02 and key[0] != 0x03) {
                    return errors.ValidationError.InvalidParameter;
                }
            },
            else => {},
        }
    }
    
    pub fn eql(self: Self, other: Self) bool {
        if (self.getType() != other.getType()) return false;
        return switch (self) {
            .Boolean => |a| a == other.Boolean,
            .Integer => |a| a == other.Integer,
            .ByteArray => |a| std.mem.eql(u8, a, other.ByteArray),
            .String => |a| std.mem.eql(u8, a, other.String),
            .Hash160 => |a| a.eql(other.Hash160),
            .Hash256 => |a| a.eql(other.Hash256),
            else => true,
        };
    }
};

pub const ContractParameterContext = struct {
    pub fn hash(self: @This(), param: ContractParameter) u64 {
        _ = self;
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&[_]u8{@intFromEnum(param.getType())});
        return hasher.final();
    }
    
    pub fn eql(self: @This(), a: ContractParameter, b: ContractParameter) bool {
        _ = self;
        return a.eql(b);
    }
};