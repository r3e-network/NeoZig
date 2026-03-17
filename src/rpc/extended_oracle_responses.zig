const std = @import("std");

const Hash160 = @import("../types/hash160.zig").Hash160;

/// Oracle request
pub const OracleRequest = struct {
    url: []const u8,
    filter: ?[]const u8,
    callback_contract: Hash160,
    callback_method: []const u8,
    user_data: []const u8,
    gas_for_response: u64,

    pub fn init() OracleRequest {
        return OracleRequest{
            .url = "",
            .filter = null,
            .callback_contract = Hash160.ZERO,
            .callback_method = "",
            .user_data = "",
            .gas_for_response = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !OracleRequest {
        const obj = json_value.object;

        return OracleRequest{
            .url = try allocator.dupe(u8, obj.get("url").?.string),
            .filter = if (obj.get("filter")) |f| try allocator.dupe(u8, f.string) else null,
            .callback_contract = try Hash160.initWithString(obj.get("callbackContract").?.string),
            .callback_method = try allocator.dupe(u8, obj.get("callbackMethod").?.string),
            .user_data = try allocator.dupe(u8, obj.get("userData").?.string),
            .gas_for_response = @intCast(obj.get("gasForResponse").?.integer),
        };
    }

    pub fn deinit(self: *OracleRequest, allocator: std.mem.Allocator) void {
        if (self.url.len > 0) allocator.free(@constCast(self.url));
        if (self.filter) |value| {
            if (value.len > 0) allocator.free(@constCast(value));
            self.filter = null;
        }
        if (self.callback_method.len > 0) allocator.free(@constCast(self.callback_method));
        if (self.user_data.len > 0) allocator.free(@constCast(self.user_data));
        self.url = "";
        self.callback_method = "";
        self.user_data = "";
    }
};

/// Contract method token
pub const ContractMethodToken = struct {
    hash: Hash160,
    method: []const u8,
    parameters_count: u16,
    has_return_value: bool,
    call_flags: u8,

    pub fn init() ContractMethodToken {
        return ContractMethodToken{
            .hash = Hash160.ZERO,
            .method = "",
            .parameters_count = 0,
            .has_return_value = false,
            .call_flags = 0,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !ContractMethodToken {
        const obj = json_value.object;

        return ContractMethodToken{
            .hash = try Hash160.initWithString(obj.get("hash").?.string),
            .method = try allocator.dupe(u8, obj.get("method").?.string),
            .parameters_count = @intCast(obj.get("parameterscount").?.integer),
            .has_return_value = obj.get("hasreturnvalue").?.bool,
            .call_flags = @intCast(obj.get("callflags").?.integer),
        };
    }

    pub fn deinit(self: *ContractMethodToken, allocator: std.mem.Allocator) void {
        if (self.method.len > 0) allocator.free(@constCast(self.method));
        self.method = "";
    }
};

/// Name state
pub const NameState = struct {
    name: []const u8,
    expiration: u32,
    admin: ?Hash160,

    pub fn init() NameState {
        return NameState{
            .name = "",
            .expiration = 0,
            .admin = null,
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !NameState {
        const obj = json_value.object;

        return NameState{
            .name = try allocator.dupe(u8, obj.get("name").?.string),
            .expiration = @intCast(obj.get("expiration").?.integer),
            .admin = if (obj.get("admin")) |a| try Hash160.initWithString(a.string) else null,
        };
    }
};

/// Record state
pub const RecordState = struct {
    name: []const u8,
    record_type: []const u8,
    data: []const u8,

    pub fn init() RecordState {
        return RecordState{
            .name = "",
            .record_type = "",
            .data = "",
        };
    }

    pub fn fromJson(json_value: std.json.Value, allocator: std.mem.Allocator) !RecordState {
        const obj = json_value.object;

        return RecordState{
            .name = try allocator.dupe(u8, obj.get("name").?.string),
            .record_type = try allocator.dupe(u8, obj.get("type").?.string),
            .data = try allocator.dupe(u8, obj.get("data").?.string),
        };
    }

    pub fn deinit(self: *RecordState, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(@constCast(self.name));
        if (self.record_type.len > 0) allocator.free(@constCast(self.record_type));
        if (self.data.len > 0) allocator.free(@constCast(self.data));
        self.name = "";
        self.record_type = "";
        self.data = "";
    }
};

/// Oracle response code
pub const OracleResponseCode = enum(u8) {
    Success = 0x00,
    ProtocolNotSupported = 0x10,
    ConsensusUnreachable = 0x12,
    NotFound = 0x14,
    Timeout = 0x16,
    Forbidden = 0x18,
    ResponseTooLarge = 0x1a,
    InsufficientFunds = 0x1c,
    ContentTypeNotSupported = 0x1f,
    Error = 0xff,

    const Self = @This();

    pub fn getByte(self: Self) u8 {
        return @intFromEnum(self);
    }

    pub fn getJsonValue(self: Self) []const u8 {
        return switch (self) {
            .Success => "Success",
            .ProtocolNotSupported => "ProtocolNotSupported",
            .ConsensusUnreachable => "ConsensusUnreachable",
            .NotFound => "NotFound",
            .Timeout => "Timeout",
            .Forbidden => "Forbidden",
            .ResponseTooLarge => "ResponseTooLarge",
            .InsufficientFunds => "InsufficientFunds",
            .ContentTypeNotSupported => "ContentTypeNotSupported",
            .Error => "Error",
        };
    }

    pub fn fromByte(byte_value: u8) ?Self {
        return switch (byte_value) {
            0x00 => .Success,
            0x10 => .ProtocolNotSupported,
            0x12 => .ConsensusUnreachable,
            0x14 => .NotFound,
            0x16 => .Timeout,
            0x18 => .Forbidden,
            0x1a => .ResponseTooLarge,
            0x1c => .InsufficientFunds,
            0x1f => .ContentTypeNotSupported,
            0xff => .Error,
            else => null,
        };
    }

    pub fn fromJsonValue(json_value: []const u8) ?Self {
        if (std.mem.eql(u8, json_value, "Success")) return .Success;
        if (std.mem.eql(u8, json_value, "NotFound")) return .NotFound;
        if (std.mem.eql(u8, json_value, "Timeout")) return .Timeout;
        if (std.mem.eql(u8, json_value, "Forbidden")) return .Forbidden;
        if (std.mem.eql(u8, json_value, "Error")) return .Error;
        return null;
    }
};
