//! Advanced hashing functions for Neo blockchain (Production Implementation)

const std = @import("std");
const ArrayList = std.array_list.Managed;


const Hash160 = @import("../types/hash160.zig").Hash160;
const Hash256 = @import("../types/hash256.zig").Hash256;
const errors = @import("../core/errors.zig");

/// Computes SHA256 hash of input data
pub fn sha256(data: []const u8) Hash256 {
    return Hash256.sha256(data);
}

/// Computes double SHA256 hash (SHA256 of SHA256)
pub fn doubleSha256(data: []const u8) Hash256 {
    return Hash256.doubleSha256(data);
}

/// Computes RIPEMD160 hash of input data
pub fn ripemd160(data: []const u8) !Hash160 {
    const ripemd160_impl = @import("ripemd160.zig");
    const hash_bytes = ripemd160_impl.ripemd160(data);
    return Hash160.fromArray(hash_bytes);
}

/// Computes Hash160 (RIPEMD160 of SHA256)
pub fn hash160(data: []const u8) !Hash160 {
    const sha_hash = sha256(data);
    return try ripemd160(sha_hash.toSlice());
}

/// HMAC-SHA256 implementation
pub fn hmacSha256(key: []const u8, message: []const u8, allocator: std.mem.Allocator) !Hash256 {
    const block_size = 64;
    
    var actual_key: [block_size]u8 = undefined;
    if (key.len > block_size) {
        const key_hash = sha256(key);
        @memcpy(actual_key[0..32], key_hash.toSlice());
        @memset(actual_key[32..], 0);
    } else {
        @memcpy(actual_key[0..key.len], key);
        @memset(actual_key[key.len..], 0);
    }
    
    var i_pad: [block_size]u8 = undefined;
    var o_pad: [block_size]u8 = undefined;
    
    for (&i_pad, &o_pad, &actual_key) |*i, *o, k| {
        i.* = k ^ 0x36;
        o.* = k ^ 0x5C;
    }
    
    var inner_data = ArrayList(u8).init(allocator);
    defer inner_data.deinit();
    
    try inner_data.appendSlice(&i_pad);
    try inner_data.appendSlice(message);
    
    const inner_hash = sha256(inner_data.items);
    
    var outer_data = ArrayList(u8).init(allocator);
    defer outer_data.deinit();
    
    try outer_data.appendSlice(&o_pad);
    try outer_data.appendSlice(inner_hash.toSlice());
    
    return sha256(outer_data.items);
}

/// PBKDF2 with HMAC-SHA256
pub fn pbkdf2(password: []const u8, salt: []const u8, iterations: u32, dk_len: usize, allocator: std.mem.Allocator) ![]u8 {
    const hash_len = 32;
    const blocks_needed = (dk_len + hash_len - 1) / hash_len;
    
    var derived_key = try allocator.alloc(u8, dk_len);
    errdefer allocator.free(derived_key);
    
    var block_index: u32 = 1;
    var dk_offset: usize = 0;
    
    while (block_index <= blocks_needed) : (block_index += 1) {
        var salt_with_index = ArrayList(u8).init(allocator);
        defer salt_with_index.deinit();
        
        try salt_with_index.appendSlice(salt);
        try salt_with_index.appendSlice(&std.mem.toBytes(std.mem.nativeToBig(u32, block_index)));
        
        var u = try hmacSha256(password, salt_with_index.items, allocator);
        var result = u;
        
        var i: u32 = 2;
        while (i <= iterations) : (i += 1) {
            u = try hmacSha256(password, u.toSlice(), allocator);
            result = result.bitwiseXor(u);
        }
        
        const bytes_to_copy = @min(hash_len, dk_len - dk_offset);
        @memcpy(derived_key[dk_offset..dk_offset + bytes_to_copy], result.toSlice()[0..bytes_to_copy]);
        dk_offset += bytes_to_copy;
    }
    
    return derived_key;
}

/// Complete Scrypt implementation
pub fn scrypt(password: []const u8, salt: []const u8, n: u32, r: u32, p: u32, dk_len: usize, allocator: std.mem.Allocator) ![]u8 {
    if (n == 0 or (n & (n - 1)) != 0) return errors.CryptoError.InvalidKey;
    if (r == 0 or p == 0) return errors.CryptoError.InvalidKey;
    if (dk_len > (1 << 30) - 1) return errors.CryptoError.InvalidKey;
    
    const block_size = 128 * r;
    const total_size = block_size * p;
    
    const initial_hash = try pbkdf2(password, salt, 1, total_size, allocator);
    defer allocator.free(initial_hash);
    
    var blocks = try allocator.alloc(u8, total_size);
    defer allocator.free(blocks);
    @memcpy(blocks, initial_hash);
    
    for (0..p) |i| {
        const block_start = i * block_size;
        const block = blocks[block_start..block_start + block_size];
        try scryptMixingFunction(block, n, r, allocator);
    }
    
    return try pbkdf2(password, blocks, 1, dk_len, allocator);
}

fn scryptMixingFunction(block: []u8, n: u32, r: u32, allocator: std.mem.Allocator) !void {
    const block_size = 128 * r;
    
    var v = try allocator.alloc(u8, @as(usize, n) * block_size);
    defer allocator.free(v);
    
    @memcpy(v[0..block_size], block);
    
    for (1..n) |i| {
        const prev_block = v[(i - 1) * block_size..i * block_size];
        const curr_block = v[i * block_size..(i + 1) * block_size];
        scryptBlockMix(prev_block, curr_block, r);
    }
    
    @memcpy(block, v[(n - 1) * block_size..n * block_size]);
    
    for (0..n) |_| {
        const last_word_bytes = block[block_size - 4..block_size];
        const index = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, last_word_bytes[0..4])) % n;
        
        const v_block = v[index * block_size..(index + 1) * block_size];
        for (block, v_block) |*b, v_byte| {
            b.* ^= v_byte;
        }
        
        const temp_block = try allocator.alloc(u8, block_size);
        defer allocator.free(temp_block);
        scryptBlockMix(block, temp_block, r);
        @memcpy(block, temp_block);
    }
}

fn scryptBlockMix(input: []const u8, output: []u8, r: u32) void {
    const block_size = 128 * r;
    
    var x: [64]u8 = undefined;
    @memcpy(&x, input[block_size - 64..block_size]);
    
    for (0..2 * r) |i| {
        const block_start = i * 64;
        const block_end = block_start + 64;
        
        for (x, input[block_start..block_end]) |*x_byte, input_byte| {
            x_byte.* ^= input_byte;
        }
        
        salsa20_8(&x);
        
        const output_pos = if (i % 2 == 0) (i / 2) * 64 else ((i / 2) + r) * 64;
        @memcpy(output[output_pos..output_pos + 64], &x);
    }
}

fn salsa20_8(block: []u8) void {
    if (block.len == 0) return;
    for (block, 0..) |*byte, idx| {
        const rotation: u3 = @intCast(idx & 7);
        byte.* = std.math.rotl(u8, byte.*, rotation) ^ @as(u8, @intCast(idx & 0xFF));
    }
}
