//! Neo GetPeers Implementation
//!
//! Complete conversion from NeoSwift NeoGetPeers.swift

const std = @import("std");

pub const Peer = struct {
    address: []const u8,
    port: u16,
    
    pub fn init(address: []const u8, port: u16) @This() {
        return .{ .address = address, .port = port };
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.address);
    }
};

pub const Peers = struct {
    unconnected: []Peer,
    bad: []Peer,
    connected: []Peer,
    
    pub fn init(unconnected: []Peer, bad: []Peer, connected: []Peer) @This() {
        return .{ .unconnected = unconnected, .bad = bad, .connected = connected };
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        for (self.unconnected) |*peer| peer.deinit(allocator);
        for (self.bad) |*peer| peer.deinit(allocator);
        for (self.connected) |*peer| peer.deinit(allocator);
        allocator.free(self.unconnected);
        allocator.free(self.bad);
        allocator.free(self.connected);
    }
};

pub const NeoGetPeers = struct {
    result: ?Peers,
    
    pub fn init(result: ?Peers) @This() {
        return .{ .result = result };
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        if (self.result) |*peers| {
            peers.deinit(allocator);
        }
    }
};