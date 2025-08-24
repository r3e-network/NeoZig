//! RecordState Implementation
//!
//! Complete conversion from NeoSwift RecordState.swift

const std = @import("std");
const RecordType = @import("../../types/record_type.zig").RecordType;

pub const RecordState = struct {
    name: []const u8,
    record_type: RecordType,
    data: []const u8,
    
    pub fn init(name: []const u8, record_type: RecordType, data: []const u8) @This() {
        return .{ .name = name, .record_type = record_type, .data = data };
    }
    
    pub fn getName(self: @This()) []const u8 {
        return self.name;
    }
    
    pub fn getRecordType(self: @This()) RecordType {
        return self.record_type;
    }
    
    pub fn getData(self: @This()) []const u8 {
        return self.data;
    }
    
    pub fn isAddressRecord(self: @This()) bool {
        return self.record_type.isAddressType();
    }
    
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.data);
    }
};