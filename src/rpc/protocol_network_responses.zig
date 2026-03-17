const std = @import("std");
const ArrayList = std.ArrayList;

const errors = @import("../core/errors.zig");

/// Memory pool response
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

/// Peers response
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

/// Peer information
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
