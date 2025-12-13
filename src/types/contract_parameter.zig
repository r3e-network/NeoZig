//! Neo VM contract parameter types
//!
//! Complete conversion from Swift ContractParameter system.

const std = @import("std");
const ArrayList = std.ArrayList;
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("hash160.zig").Hash160;
const Hash256 = @import("hash256.zig").Hash256;
const JsonValue = std.json.Value;
const base64 = std.base64;
const json_utils = @import("../utils/json_utils.zig");

pub const ContractParameterType = enum(u8) {
    Any = 0x00,
    Boolean = 0x10,
    Integer = 0x11,
    ByteArray = 0x12,
    String = 0x13,
    Hash160 = 0x14,
    Hash256 = 0x15,
    PublicKey = 0x16,
    Signature = 0x17,
    Array = 0x20,
    Map = 0x22,
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
    pub fn publicKey(bytes: []const u8) Self {
        std.debug.assert(bytes.len == constants.PUBLIC_KEY_SIZE_COMPRESSED);
        var key: [constants.PUBLIC_KEY_SIZE_COMPRESSED]u8 = undefined;
        @memcpy(&key, bytes[0..constants.PUBLIC_KEY_SIZE_COMPRESSED]);
        return Self{ .PublicKey = key };
    }
    pub fn signature(bytes: []const u8) Self {
        std.debug.assert(bytes.len == constants.SIGNATURE_SIZE);
        var sig: [constants.SIGNATURE_SIZE]u8 = undefined;
        @memcpy(&sig, bytes[0..constants.SIGNATURE_SIZE]);
        return Self{ .Signature = sig };
    }
    pub fn array(items: []const ContractParameter) Self {
        return Self{ .Array = items };
    }
    pub fn void_param() Self {
        return Self{ .Void = {} };
    }

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
            .Any => true,
            .Void => true,
            .Boolean => |a| a == other.Boolean,
            .Integer => |a| a == other.Integer,
            .ByteArray => |a| std.mem.eql(u8, a, other.ByteArray),
            .String => |a| std.mem.eql(u8, a, other.String),
            .Hash160 => |a| a.eql(other.Hash160),
            .Hash256 => |a| a.eql(other.Hash256),
            .PublicKey => |a| std.mem.eql(u8, &a, &other.PublicKey),
            .Signature => |a| std.mem.eql(u8, &a, &other.Signature),
            .Array => |a| {
                const b = other.Array;
                if (a.len != b.len) return false;
                for (a, b) |item_a, item_b| {
                    if (!item_a.eql(item_b)) return false;
                }
                return true;
            },
            .Map => |a| {
                const b = other.Map;
                if (a.count() != b.count()) return false;

                var it = a.iterator();
                while (it.next()) |entry| {
                    const b_value = b.get(entry.key_ptr.*) orelse return false;
                    if (!entry.value_ptr.*.eql(b_value)) return false;
                }
                return true;
            },
            .InteropInterface => |a| a == other.InteropInterface,
        };
    }

    pub fn toJsonValue(self: Self, allocator: std.mem.Allocator) std.mem.Allocator.Error!JsonValue {
        var obj = std.json.ObjectMap.init(allocator);
        errdefer obj.deinit();

        const type_str = try allocator.dupe(u8, self.getType().toString());
        try json_utils.putOwnedKey(&obj, allocator, "type", JsonValue{ .string = type_str });

        const value = try self.asJsonValue(allocator);
        try json_utils.putOwnedKey(&obj, allocator, "value", value);

        return JsonValue{ .object = obj };
    }

    fn asJsonValue(self: Self, allocator: std.mem.Allocator) std.mem.Allocator.Error!JsonValue {
        return switch (self) {
            .Any => JsonValue.null,
            .Boolean => |value| JsonValue{ .bool = value },
            .Integer => |value| JsonValue{ .string = try std.fmt.allocPrint(allocator, "{d}", .{value}) },
            .ByteArray => |bytes| {
                const size = base64.standard.Encoder.calcSize(bytes.len);
                const buffer = try allocator.alloc(u8, size);
                const encoded = base64.standard.Encoder.encode(buffer, bytes);
                return JsonValue{ .string = encoded };
            },
            .String => |str| JsonValue{ .string = try allocator.dupe(u8, str) },
            .Hash160 => |hash| {
                const hex = try hash.string(allocator);
                return JsonValue{ .string = hex };
            },
            .Hash256 => |hash| {
                const hex = try hash.string(allocator);
                return JsonValue{ .string = hex };
            },
            .PublicKey => |key| {
                const hex = std.fmt.bytesToHex(key, .lower);
                return JsonValue{ .string = try allocator.dupe(u8, &hex) };
            },
            .Signature => |sig| {
                const hex = std.fmt.bytesToHex(sig, .lower);
                return JsonValue{ .string = try allocator.dupe(u8, &hex) };
            },
            .Array => |items| {
                var list = ArrayList(JsonValue).init(allocator);
                for (items) |item| {
                    const json_value = try item.toJsonValue(allocator);
                    try list.append(json_value);
                }
                return JsonValue{ .array = list };
            },
            .Map => |map| {
                var obj = std.json.ObjectMap.init(allocator);
                var it = map.iterator();
                while (it.next()) |entry| {
                    const key_json = try entry.key_ptr.*.toJsonValue(allocator);
                    const value_json = try entry.value_ptr.*.toJsonValue(allocator);
                    try obj.put(try stringifyKey(key_json, allocator), value_json);
                }
                return JsonValue{ .object = obj };
            },
            .InteropInterface => |iface| JsonValue{ .string = try std.fmt.allocPrint(allocator, "{d}", .{iface}) },
            .Void => JsonValue.null,
        };
    }
};

    pub const ContractParameterContext = struct {
        pub fn hash(self: @This(), param: ContractParameter) u64 {
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(&[_]u8{@intFromEnum(param.getType())});
            switch (param) {
                .Any => {},
                .Boolean => |value| {
                    const byte: u8 = if (value) 1 else 0;
                    hasher.update(&[_]u8{byte});
                },
                .Integer => |value| {
                    const bytes = std.mem.toBytes(std.mem.nativeToLittle(i64, value));
                    hasher.update(&bytes);
                },
                .ByteArray => |bytes| hasher.update(bytes),
                .String => |str| hasher.update(str),
                .Hash160 => |hash160_value| hasher.update(&hash160_value.toArray()),
                .Hash256 => |hash256_value| hasher.update(&hash256_value.toArray()),
                .PublicKey => |key| hasher.update(&key),
                .Signature => |sig| hasher.update(&sig),
                .Array => |items| {
                    for (items) |item| {
                        const child_hash = self.hash(item);
                        const bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, child_hash));
                        hasher.update(&bytes);
                    }
                },
                .Map => |map| {
                    var iterator = map.iterator();
                    var aggregate: u64 = 0;
                    while (iterator.next()) |entry| {
                        const key_hash = self.hash(entry.key_ptr.*);
                        const value_hash = self.hash(entry.value_ptr.*);
                        aggregate ^= key_hash ^ std.math.rotl(u64, value_hash, 1);
                    }
                    const bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, aggregate));
                    hasher.update(&bytes);
                },
                .InteropInterface => |iface| {
                    const bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, iface));
                    hasher.update(&bytes);
                },
                .Void => {},
            }
            return hasher.final();
        }
        
        pub fn eql(self: @This(), a: ContractParameter, b: ContractParameter) bool {
            _ = self;
            return a.eql(b);
        }
};

fn stringifyKey(value: JsonValue, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
    return switch (value) {
        .string => |str| allocator.dupe(u8, str),
        .bool => |b| try std.fmt.allocPrint(allocator, "{s}", .{if (b) "true" else "false"}),
        .integer => |i| try std.fmt.allocPrint(allocator, "{d}", .{i}),
        .float => |f| try std.fmt.allocPrint(allocator, "{d}", .{f}),
        else => allocator.dupe(u8, "unsupported"),
    };
}
