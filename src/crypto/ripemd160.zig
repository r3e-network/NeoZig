//! RIPEMD-160 hash function implementation
//!
//! Production-ready implementation of RIPEMD-160 as specified in ISO/IEC 10118-3:2004
//! Used by Neo blockchain for creating script hashes and addresses.

const std = @import("std");

/// RIPEMD-160 hasher state
pub const Ripemd160 = struct {
    state: [5]u32,
    buffer: [64]u8,
    buffer_len: u8,
    total_len: u64,
    
    const Self = @This();
    
    const INITIAL_STATE = [5]u32{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    
    pub fn init() Self {
        return Self{
            .state = INITIAL_STATE,
            .buffer = undefined,
            .buffer_len = 0,
            .total_len = 0,
        };
    }
    
    pub fn update(self: *Self, data: []const u8) void {
        self.total_len += data.len;
        var remaining = data;
        
        if (self.buffer_len > 0) {
            const space = 64 - self.buffer_len;
            const to_copy = @min(space, remaining.len);
            @memcpy(self.buffer[self.buffer_len..self.buffer_len + to_copy], remaining[0..to_copy]);
            self.buffer_len += @intCast(to_copy);
            remaining = remaining[to_copy..];
            
            if (self.buffer_len == 64) {
                self.processBlock(&self.buffer);
                self.buffer_len = 0;
            }
        }
        
        while (remaining.len >= 64) {
            const block = remaining[0..64];
            self.processBlock(block);
            remaining = remaining[64..];
        }
        
        if (remaining.len > 0) {
            @memcpy(self.buffer[0..remaining.len], remaining);
            self.buffer_len = @intCast(remaining.len);
        }
    }
    
    pub fn final(self: *Self, out: []u8) void {
        std.debug.assert(out.len >= 20);
        
        const bit_len = self.total_len * 8;
        self.update(&[_]u8{0x80});
        
        while (self.buffer_len != 56) {
            if (self.buffer_len < 56) {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            } else {
                while (self.buffer_len < 64) {
                    self.buffer[self.buffer_len] = 0;
                    self.buffer_len += 1;
                }
                self.processBlock(&self.buffer);
                self.buffer_len = 0;
                @memset(&self.buffer, 0);
            }
        }
        
        const length_bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, bit_len));
        @memcpy(self.buffer[56..64], &length_bytes);
        self.processBlock(&self.buffer);
        
        for (self.state, 0..) |word, i| {
            const word_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, word));
            @memcpy(out[i * 4..(i + 1) * 4], &word_bytes);
        }
    }
    
    fn processBlock(self: *Self, block: []const u8) void {
        var x: [16]u32 = undefined;
        for (x, 0..) |*word, i| {
            const bytes = block[i * 4..(i + 1) * 4];
            word.* = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, bytes[0..4]));
        }
        
        var al = self.state[0]; var bl = self.state[1]; var cl = self.state[2]; var dl = self.state[3]; var el = self.state[4];
        var ar = al; var br = bl; var cr = cl; var dr = dl; var er = el;
        
        // RIPEMD-160 rounds implementation
        inline for (0..80) |i| {
            const t = al +% f(i, bl, cl, dl) +% x[r[i]] +% k(i);
            const rotated = std.math.rotl(u32, t, s[i]);
            al = el; el = dl; dl = std.math.rotl(u32, cl, 10); cl = bl; bl = rotated +% el;
        }
        
        inline for (0..80) |i| {
            const t = ar +% f(79 - i, br, cr, dr) +% x[rh[i]] +% kh(i);
            const rotated = std.math.rotl(u32, t, sh[i]);
            ar = er; er = dr; dr = std.math.rotl(u32, cr, 10); cr = br; br = rotated +% er;
        }
        
        const t = self.state[1] +% cl +% dr;
        self.state[1] = self.state[2] +% dl +% er;
        self.state[2] = self.state[3] +% el +% ar;
        self.state[3] = self.state[4] +% al +% br;
        self.state[4] = self.state[0] +% bl +% cr;
        self.state[0] = t;
    }
    
    fn f(round: usize, x: u32, y: u32, z: u32) u32 {
        return switch (round / 16) {
            0 => x ^ y ^ z,
            1 => (x & y) | (~x & z),
            2 => (x | ~y) ^ z,
            3 => (x & z) | (y & ~z),
            4 => x ^ (y | ~z),
            else => unreachable,
        };
    }
    
    fn k(round: usize) u32 {
        return switch (round / 16) {
            0 => 0x00000000, 1 => 0x5A827999, 2 => 0x6ED9EBA1, 3 => 0x8F1BBCDC, 4 => 0xA953FD4E,
            else => unreachable,
        };
    }
    
    fn kh(round: usize) u32 {
        return switch (round / 16) {
            0 => 0x50A28BE6, 1 => 0x5C4DD124, 2 => 0x6D703EF3, 3 => 0x7A6D76E9, 4 => 0x00000000,
            else => unreachable,
        };
    }
    
    const r = [80]u8{ 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8, 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2, 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13 };
    const rh = [80]u8{ 5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2, 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14, 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11 };
    const s = [80]u5{ 11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12, 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12, 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6 };
    const sh = [80]u5{ 8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11, 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8, 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11 };
};

/// Compute RIPEMD-160 hash of data
pub fn ripemd160(data: []const u8) [20]u8 {
    var hasher = Ripemd160.init();
    hasher.update(data);
    var result: [20]u8 = undefined;
    hasher.final(&result);
    return result;
}