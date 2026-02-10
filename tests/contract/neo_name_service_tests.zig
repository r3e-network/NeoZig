//! Neo Name Service Tests
//!
//!
//! Tests NNS domain name resolution and management.

const std = @import("std");

const testing = std.testing;
const NeoNameService = @import("../../src/contract/neo_name_service.zig").NeoNameService;
const NNSName = @import("../../src/contract/nns_name.zig").NNSName;
const Hash160 = @import("../../src/types/hash160.zig").Hash160;
const RecordType = @import("../../src/types/record_type.zig").RecordType;
const TestUtils = @import("../helpers/test_utilities.zig");

test "NNS name validation" {
    const allocator = testing.allocator;

    // Test valid NNS names
    const valid_names = [_][]const u8{
        "test.neo",
        "example.neo",
        "sub.domain.neo",
        "a.neo",
    };

    for (valid_names) |name| {
        var nns_name = try NNSName.init(name, allocator);
        defer nns_name.deinit(allocator);

        try testing.expectEqualStrings(name, nns_name.getName());
        try testing.expect(!nns_name.isEmpty());
    }
}

test "NNS record type operations" {
    const testing = std.testing;

    // Test A record
    try testing.expect(RecordType.A.isAddressType());
    try testing.expect(!RecordType.A.supportsText());

    // Test CNAME record
    try testing.expect(!RecordType.CNAME.isAddressType());
    try testing.expect(RecordType.CNAME.supportsText());

    // Test TXT record
    try testing.expect(RecordType.TXT.supportsText());
    try testing.expect(!RecordType.TXT.isAddressType());
}

test "NNS service functionality" {
    const allocator = testing.allocator;

    var client = try TestUtils.makeClientStub(allocator);
    defer TestUtils.destroyClientStub(&client);

    const nns_hash = try Hash160.initWithString("0x50ac1c37690cc2cfc594472833cf57505d5f46de");
    const nns = NeoNameService.init(allocator, nns_hash, &client);

    try testing.expect(nns.getScriptHash().eql(nns_hash));
    try nns.validate();
}
