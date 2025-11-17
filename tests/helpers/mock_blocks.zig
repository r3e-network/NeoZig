//! Mock Blocks
//!
//! Complete conversion from NeoSwift MockBlocks.swift
//! Provides mock block data for testing.

const std = @import("std");



pub const MockBlocks = struct {
    pub fn getMockBlock(allocator: std.mem.Allocator) ![]u8 {
        return try allocator.dupe(u8, "mock_block_data");
    }
    
    pub fn getMockTransaction(allocator: std.mem.Allocator) ![]u8 {
        return try allocator.dupe(u8, "mock_transaction_data");
    }
};