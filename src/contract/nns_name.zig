//! NNS Name implementation
//!
//! Complete conversion from NeoSwift NNSName.swift
//! Handles Neo Name Service domain name validation and operations.

const std = @import("std");
const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");

/// Neo Name Service domain name (converted from Swift NNSName)
pub const NNSName = struct {
    /// Domain name
    name: []const u8,
    
    const Self = @This();
    
    /// Creates NNS name with validation (equivalent to Swift init)
    pub fn init(name: []const u8, allocator: std.mem.Allocator) !Self {
        if (!isValidNNSName(name, true)) {
            return errors.throwIllegalArgument("Invalid NNS domain name");
        }
        
        return Self{
            .name = try allocator.dupe(u8, name),
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
    
    /// Gets name (equivalent to Swift .name property)
    pub fn getName(self: Self) []const u8 {
        return self.name;
    }
    
    /// Gets UTF-8 bytes (equivalent to Swift .bytes property)
    pub fn getBytes(self: Self) []const u8 {
        return self.name; // Already UTF-8 in Zig
    }
    
    /// Checks if second-level domain (equivalent to Swift .isSecondLevelDomain property)
    pub fn isSecondLevelDomain(self: Self) bool {
        return isValidNNSName(self.name, false);
    }
    
    /// Validates NNS name (equivalent to Swift isValidNNSName)
    pub fn isValidNNSName(name: []const u8, allow_multiple_fragments: bool) bool {
        // Check length constraints (3-255 characters)
        if (name.len < 3 or name.len > 255) return false;
        
        // Split into fragments by '.'
        var fragment_count: usize = 1;
        for (name) |char| {
            if (char == '.') fragment_count += 1;
        }
        
        // Check fragment count (2-8 fragments)
        if (fragment_count < 2 or fragment_count > 8) return false;
        
        // If more than 2 fragments, check if allowed
        if (fragment_count > 2 and !allow_multiple_fragments) return false;
        
        // Validate each fragment
        var fragment_iterator = std.mem.split(u8, name, ".");
        var fragment_index: usize = 0;
        var fragments_array = [_][]const u8{""} ** 8;
        
        while (fragment_iterator.next()) |fragment| {
            if (fragment_index >= 8) return false;
            fragments_array[fragment_index] = fragment;
            fragment_index += 1;
        }
        
        // Check each fragment
        for (fragments_array[0..fragment_count], 0..) |fragment, i| {
            const is_root = (i == fragment_count - 1);
            if (!checkFragment(fragment, is_root)) return false;
        }
        
        return true;
    }
    
    /// Validates individual fragment (equivalent to Swift checkFragment)
    fn checkFragment(fragment: []const u8, is_root: bool) bool {
        const max_length: usize = if (is_root) 16 else 63;
        
        // Check length
        if (fragment.len == 0 or fragment.len > max_length) return false;
        
        // Check first character
        const first_char = fragment[0];
        if (is_root and !std.ascii.isAlphabetic(first_char)) return false;
        
        // Check all characters
        for (fragment) |char| {
            if (!isValidNNSChar(char, is_root)) return false;
        }
        
        // Check that fragment doesn't start or end with hyphen
        if (fragment[0] == '-' or fragment[fragment.len - 1] == '-') return false;
        
        return true;
    }
    
    /// Checks if character is valid for NNS (equivalent to Swift character validation)
    fn isValidNNSChar(char: u8, is_root: bool) bool {
        // Letters are always valid
        if (std.ascii.isAlphabetic(char)) return true;
        
        // Numbers are valid for non-root fragments
        if (std.ascii.isDigit(char) and !is_root) return true;
        
        // Hyphen is valid (but not at start/end, checked elsewhere)
        if (char == '-') return true;
        
        return false;
    }
    
    /// Gets root domain (equivalent to Swift root domain extraction)
    pub fn getRootDomain(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const last_dot = std.mem.lastIndexOf(u8, self.name, ".") orelse {
            return errors.throwIllegalArgument("Invalid domain format");
        };
        
        return try allocator.dupe(u8, self.name[last_dot + 1..]);
    }
    
    /// Gets subdomain parts (equivalent to Swift subdomain extraction)
    pub fn getSubdomains(self: Self, allocator: std.mem.Allocator) ![][]u8 {
        var subdomains = std.ArrayList([]u8).init(allocator);
        defer subdomains.deinit();
        
        var fragment_iterator = std.mem.split(u8, self.name, ".");
        while (fragment_iterator.next()) |fragment| {
            try subdomains.append(try allocator.dupe(u8, fragment));
        }
        
        // Remove last fragment (root domain)
        if (subdomains.items.len > 0) {
            const last_index = subdomains.items.len - 1;
            allocator.free(subdomains.items[last_index]);
            _ = subdomains.pop();
        }
        
        return try subdomains.toOwnedSlice();
    }
    
    /// Gets full qualified domain name (utility method)
    pub fn getFQDN(self: Self, allocator: std.mem.Allocator) ![]u8 {
        return try allocator.dupe(u8, self.name);
    }
    
    /// Checks if domain is under specific root
    pub fn isUnderRoot(self: Self, root_domain: []const u8) bool {
        return std.mem.endsWith(u8, self.name, root_domain);
    }
    
    /// Gets domain level (number of fragments)
    pub fn getDomainLevel(self: Self) u32 {
        var level: u32 = 1;
        for (self.name) |char| {
            if (char == '.') level += 1;
        }
        return level;
    }
};

/// NNS utilities
pub const NNSUtils = struct {
    /// Common NNS root domains
    pub const COMMON_ROOTS = [_][]const u8{
        "neo",
        "test",
        "local",
    };
    
    /// Suggests valid NNS name (utility function)
    pub fn suggestValidName(invalid_name: []const u8, allocator: std.mem.Allocator) ![]u8 {
        // Basic suggestion: lowercase, remove invalid chars, add .neo if needed
        var suggested = std.ArrayList(u8).init(allocator);
        defer suggested.deinit();
        
        for (invalid_name) |char| {
            if (std.ascii.isAlphaNumeric(char) or char == '.' or char == '-') {
                try suggested.append(std.ascii.toLower(char));
            }
        }
        
        // Add .neo if no root domain
        if (std.mem.indexOf(u8, suggested.items, ".") == null) {
            try suggested.appendSlice(".neo");
        }
        
        return try suggested.toOwnedSlice();
    }
    
    /// Checks if name exists in common roots
    pub fn isCommonRoot(root: []const u8) bool {
        for (COMMON_ROOTS) |common_root| {
            if (std.mem.eql(u8, root, common_root)) {
                return true;
            }
        }
        return false;
    }
    
    /// Normalizes domain name (utility function)
    pub fn normalizeDomainName(name: []const u8, allocator: std.mem.Allocator) ![]u8 {
        // Convert to lowercase and trim
        var normalized = try allocator.alloc(u8, name.len);
        
        for (name, 0..) |char, i| {
            normalized[i] = std.ascii.toLower(char);
        }
        
        return normalized;
    }
};

// Tests (converted from Swift NNSName tests)
test "NNSName creation and validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test valid NNS name creation (equivalent to Swift NNSName tests)
    var valid_name = try NNSName.init("example.neo", allocator);
    defer valid_name.deinit(allocator);
    
    try testing.expectEqualStrings("example.neo", valid_name.getName());
    try testing.expect(valid_name.isSecondLevelDomain());
    
    // Test domain level
    try testing.expectEqual(@as(u32, 2), valid_name.getDomainLevel());
    
    // Test root domain extraction
    const root_domain = try valid_name.getRootDomain(allocator);
    defer allocator.free(root_domain);
    
    try testing.expectEqualStrings("neo", root_domain);
    
    // Test subdomain extraction
    const subdomains = try valid_name.getSubdomains(allocator);
    defer {
        for (subdomains) |subdomain| {
            allocator.free(subdomain);
        }
        allocator.free(subdomains);
    }
    
    try testing.expectEqual(@as(usize, 1), subdomains.len);
    try testing.expectEqualStrings("example", subdomains[0]);
}

test "NNSName validation rules" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test valid names (equivalent to Swift validation tests)
    try testing.expect(NNSName.isValidNNSName("test.neo", true));
    try testing.expect(NNSName.isValidNNSName("sub.domain.neo", true));
    try testing.expect(NNSName.isValidNNSName("valid-name.neo", true));
    
    // Test invalid names
    try testing.expect(!NNSName.isValidNNSName("", true)); // Empty
    try testing.expect(!NNSName.isValidNNSName("x", true)); // Too short
    try testing.expect(!NNSName.isValidNNSName("a" ** 256, true)); // Too long
    try testing.expect(!NNSName.isValidNNSName("onlyone", true)); // No domain
    try testing.expect(!NNSName.isValidNNSName("too.many.sub.domain.levels.here.more.neo", true)); // Too many levels
    
    // Test second-level domain restrictions
    try testing.expect(NNSName.isValidNNSName("test.neo", false)); // Second-level OK
    try testing.expect(!NNSName.isValidNNSName("sub.test.neo", false)); // Third-level not allowed
    
    // Test fragment validation
    try testing.expect(!NNSName.isValidNNSName("-invalid.neo", true)); // Starts with hyphen
    try testing.expect(!NNSName.isValidNNSName("invalid-.neo", true)); // Ends with hyphen
    try testing.expect(!NNSName.isValidNNSName("inv@lid.neo", true)); // Invalid character
}

test "NNSName fragment validation" {
    const testing = std.testing;
    
    // Test individual fragment validation (equivalent to Swift checkFragment tests)
    try testing.expect(NNSName.checkFragment("valid", false));
    try testing.expect(NNSName.checkFragment("test123", false));
    try testing.expect(NNSName.checkFragment("with-hyphen", false));
    try testing.expect(NNSName.checkFragment("neo", true)); // Root fragment
    
    // Test invalid fragments
    try testing.expect(!NNSName.checkFragment("", false)); // Empty
    try testing.expect(!NNSName.checkFragment("-invalid", false)); // Starts with hyphen
    try testing.expect(!NNSName.checkFragment("invalid-", false)); // Ends with hyphen
    try testing.expect(!NNSName.checkFragment("inv@lid", false)); // Invalid character
    try testing.expect(!NNSName.checkFragment("123", true)); // Root can't start with number
    
    // Test length constraints
    const long_fragment = "a" ** 64;
    try testing.expect(!NNSName.checkFragment(long_fragment, false)); // Too long for subdomain
    
    const long_root = "a" ** 17;
    try testing.expect(!NNSName.checkFragment(long_root, true)); // Too long for root
}

test "NNSName error handling" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test invalid name creation (equivalent to Swift error tests)
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        NNSName.init("", allocator)
    );
    
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        NNSName.init("invalid", allocator)
    );
    
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        NNSName.init("too.many.sub.domain.levels.here.more.levels.neo", allocator)
    );
    
    try testing.expectError(
        errors.NeoError.IllegalArgument,
        NNSName.init("-invalid.neo", allocator)
    );
}

test "NNSName utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var nns_name = try NNSName.init("subdomain.example.neo", allocator);
    defer nns_name.deinit(allocator);
    
    // Test domain operations
    try testing.expectEqual(@as(u32, 3), nns_name.getDomainLevel());
    try testing.expect(nns_name.isUnderRoot("neo"));
    try testing.expect(nns_name.isUnderRoot("example.neo"));
    try testing.expect(!nns_name.isUnderRoot("other"));
    
    // Test FQDN
    const fqdn = try nns_name.getFQDN(allocator);
    defer allocator.free(fqdn);
    
    try testing.expectEqualStrings("subdomain.example.neo", fqdn);
}

test "NNSUtils helper functions" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Test name suggestion (utility function tests)
    const invalid_name = "INVALID@NAME#WITH$SYMBOLS";
    const suggested = try NNSUtils.suggestValidName(invalid_name, allocator);
    defer allocator.free(suggested);
    
    try testing.expect(suggested.len > 0);
    try testing.expect(std.mem.endsWith(u8, suggested, ".neo"));
    
    // Test common root checking
    try testing.expect(NNSUtils.isCommonRoot("neo"));
    try testing.expect(NNSUtils.isCommonRoot("test"));
    try testing.expect(NNSUtils.isCommonRoot("local"));
    try testing.expect(!NNSUtils.isCommonRoot("unknown"));
    
    // Test name normalization
    const mixed_case = "ExAmPlE.NeO";
    const normalized = try NNSUtils.normalizeDomainName(mixed_case, allocator);
    defer allocator.free(normalized);
    
    try testing.expectEqualStrings("example.neo", normalized);
}

test "NNSName domain operations" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var complex_name = try NNSName.init("api.service.example.neo", allocator);
    defer complex_name.deinit(allocator);
    
    // Test complex domain operations
    try testing.expectEqual(@as(u32, 4), complex_name.getDomainLevel());
    try testing.expect(!complex_name.isSecondLevelDomain());
    
    // Test root domain extraction
    const root = try complex_name.getRootDomain(allocator);
    defer allocator.free(root);
    try testing.expectEqualStrings("neo", root);
    
    // Test subdomain extraction
    const subdomains = try complex_name.getSubdomains(allocator);
    defer {
        for (subdomains) |subdomain| {
            allocator.free(subdomain);
        }
        allocator.free(subdomains);
    }
    
    try testing.expectEqual(@as(usize, 3), subdomains.len);
    try testing.expectEqualStrings("api", subdomains[0]);
    try testing.expectEqualStrings("service", subdomains[1]);
    try testing.expectEqualStrings("example", subdomains[2]);
    
    // Test under root checking
    try testing.expect(complex_name.isUnderRoot("neo"));
    try testing.expect(complex_name.isUnderRoot("example.neo"));
    try testing.expect(complex_name.isUnderRoot("service.example.neo"));
    try testing.expect(!complex_name.isUnderRoot("other.neo"));
}