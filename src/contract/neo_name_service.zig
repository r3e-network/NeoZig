//! Neo Name Service implementation
//!
//! Complete conversion from NeoSwift NeoNameService.swift
//! Provides complete NeoNameService contract interaction and domain management.

const std = @import("std");
const ArrayList = std.ArrayList;

const constants = @import("../core/constants.zig");
const errors = @import("../core/errors.zig");
const Hash160 = @import("../types/hash160.zig").Hash160;
const ContractParameter = @import("../types/contract_parameter.zig").ContractParameter;
const NonFungibleToken = @import("non_fungible_token.zig").NonFungibleToken;
const TransactionBuilder = @import("../transaction/transaction_builder.zig").TransactionBuilder;
const StackItem = @import("../rpc/responses.zig").StackItem;
const RecordType = @import("../types/record_type.zig").RecordType;
const Iterator = @import("iterator.zig").Iterator;
const NeoSwift = @import("../rpc/neo_client.zig").NeoSwift;
const Signer = @import("../transaction/transaction_builder.zig").Signer;
const StringUtils = @import("../utils/string_extensions.zig").StringUtils;

/// Neo Name Service contract (converted from Swift NeoNameService)
pub const NeoNameService = struct {
    /// Method names (match Swift constants)
    pub const ADD_ROOT = "addRoot";
    pub const ROOTS = "roots";
    pub const SET_PRICE = "setPrice";
    pub const GET_PRICE = "getPrice";
    pub const IS_AVAILABLE = "isAvailable";
    pub const REGISTER = "register";
    pub const RENEW = "renew";
    pub const SET_ADMIN = "setAdmin";
    pub const SET_RECORD = "setRecord";
    pub const GET_RECORD = "getRecord";
    pub const GET_ALL_RECORDS = "getAllRecords";
    pub const DELETE_RECORD = "deleteRecord";
    pub const RESOLVE = "resolve";
    pub const PROPERTIES = "properties";

    /// Property names (match Swift property constants)
    pub const NAME_PROPERTY = "name";
    pub const EXPIRATION_PROPERTY = "expiration";
    pub const ADMIN_PROPERTY = "admin";

    /// Base non-fungible token
    non_fungible_token: NonFungibleToken,

    const Self = @This();

    /// Creates NeoNameService instance (equivalent to Swift init)
    pub fn init(allocator: std.mem.Allocator, nns_resolver: Hash160, neo_swift: ?*anyopaque) Self {
        return Self{
            .non_fungible_token = NonFungibleToken.init(allocator, nns_resolver, neo_swift),
        };
    }

    /// Gets contract script hash (forwarded from underlying token).
    pub fn getScriptHash(self: Self) Hash160 {
        return self.non_fungible_token.getScriptHash();
    }

    /// Validates that the contract has a usable script hash.
    pub fn validate(self: Self) !void {
        return self.non_fungible_token.validate();
    }

    /// Returns true if this contract is native.
    pub fn isNativeContract(self: Self) bool {
        return self.non_fungible_token.isNativeContract();
    }

    /// Gets contract name (equivalent to Swift getName() override)
    pub fn getName(self: Self) ![]const u8 {
        _ = self;
        return "NameService";
    }

    /// Gets contract symbol (equivalent to Swift getSymbol() override)
    pub fn getSymbol(self: Self) ![]const u8 {
        _ = self;
        return "NNS";
    }

    /// Gets contract decimals (equivalent to Swift getDecimals() override)
    pub fn getDecimals(self: Self) !u8 {
        _ = self;
        return 0; // NFTs are not divisible
    }

    // ============================================================================
    // ROOT MANAGEMENT (converted from Swift root management methods)
    // ============================================================================

    /// Adds root domain (equivalent to Swift addRoot)
    pub fn addRoot(self: Self, root: []const u8) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.string(root)};
        return try self.non_fungible_token.token.smart_contract.invokeFunction(ADD_ROOT, &params);
    }

    /// Gets all root domains (equivalent to Swift roots)
    pub fn getRoots(self: Self) !Iterator([]const u8) {
        return try self.callFunctionReturningIterator([]const u8, ROOTS, &[_]ContractParameter{}, stringMapper);
    }

    // ============================================================================
    // PRICING METHODS (converted from Swift pricing methods)
    // ============================================================================

    /// Sets domain price (equivalent to Swift setPrice)
    pub fn setPrice(self: Self, price: i64) !TransactionBuilder {
        const params = [_]ContractParameter{ContractParameter.integer(price)};
        return try self.non_fungible_token.token.smart_contract.invokeFunction(SET_PRICE, &params);
    }

    /// Gets domain price (equivalent to Swift getPrice)
    pub fn getPrice(self: Self) !i64 {
        return try self.non_fungible_token.token.smart_contract.callFunctionReturningInt(GET_PRICE, &[_]ContractParameter{});
    }

    // ============================================================================
    // DOMAIN AVAILABILITY AND REGISTRATION (converted from Swift domain methods)
    // ============================================================================

    /// Checks if domain is available (equivalent to Swift isAvailable)
    pub fn isAvailable(self: Self, domain_name: []const u8) !bool {
        const params = [_]ContractParameter{ContractParameter.string(domain_name)};
        return try self.non_fungible_token.token.smart_contract.callFunctionReturningBool(IS_AVAILABLE, &params);
    }

    /// Registers domain (equivalent to Swift register)
    pub fn register(
        self: Self,
        domain_name: []const u8,
        owner: Hash160,
        admin: ?Hash160,
    ) !TransactionBuilder {
        var params = ArrayList(ContractParameter).init(self.non_fungible_token.token.smart_contract.allocator);
        defer params.deinit();

        try params.append(ContractParameter.string(domain_name));
        try params.append(ContractParameter.hash160(owner));

        if (admin) |admin_hash| {
            try params.append(ContractParameter.hash160(admin_hash));
        }

        return try self.non_fungible_token.token.smart_contract.invokeFunction(REGISTER, params.items);
    }

    /// Renews domain registration (equivalent to Swift renew)
    pub fn renew(self: Self, domain_name: []const u8, years: u32) !TransactionBuilder {
        const params = [_]ContractParameter{
            ContractParameter.string(domain_name),
            ContractParameter.integer(@intCast(years)),
        };
        return try self.non_fungible_token.token.smart_contract.invokeFunction(RENEW, &params);
    }

    // ============================================================================
    // DOMAIN ADMINISTRATION (converted from Swift admin methods)
    // ============================================================================

    /// Sets domain admin (equivalent to Swift setAdmin)
    pub fn setAdmin(self: Self, domain_name: []const u8, admin: Hash160) !TransactionBuilder {
        const params = [_]ContractParameter{
            ContractParameter.string(domain_name),
            ContractParameter.hash160(admin),
        };
        return try self.non_fungible_token.token.smart_contract.invokeFunction(SET_ADMIN, &params);
    }

    // ============================================================================
    // RECORD MANAGEMENT (converted from Swift record methods)
    // ============================================================================

    /// Sets domain record (equivalent to Swift setRecord)
    pub fn setRecord(
        self: Self,
        domain_name: []const u8,
        record_type: RecordType,
        data: []const u8,
    ) !TransactionBuilder {
        const params = [_]ContractParameter{
            ContractParameter.string(domain_name),
            ContractParameter.integer(record_type.getByte()),
            ContractParameter.string(data),
        };
        return try self.non_fungible_token.token.smart_contract.invokeFunction(SET_RECORD, &params);
    }

    /// Gets domain record (equivalent to Swift getRecord)
    pub fn getRecord(
        self: Self,
        domain_name: []const u8,
        record_type: RecordType,
    ) ![]u8 {
        const params = [_]ContractParameter{
            ContractParameter.string(domain_name),
            ContractParameter.integer(record_type.getByte()),
        };
        return try self.non_fungible_token.token.smart_contract.callFunctionReturningString(GET_RECORD, &params);
    }

    /// Gets all domain records (equivalent to Swift getAllRecords)
    pub fn getAllRecords(self: Self, domain_name: []const u8) !Iterator(DomainRecord) {
        const params = [_]ContractParameter{ContractParameter.string(domain_name)};
        return try self.callFunctionReturningIterator(DomainRecord, GET_ALL_RECORDS, &params, recordMapper);
    }

    /// Deletes domain record (equivalent to Swift deleteRecord)
    pub fn deleteRecord(
        self: Self,
        domain_name: []const u8,
        record_type: RecordType,
    ) !TransactionBuilder {
        const params = [_]ContractParameter{
            ContractParameter.string(domain_name),
            ContractParameter.integer(record_type.getByte()),
        };
        return try self.non_fungible_token.token.smart_contract.invokeFunction(DELETE_RECORD, &params);
    }

    /// Resolves domain (equivalent to Swift resolve)
    pub fn resolve(
        self: Self,
        domain_name: []const u8,
        record_type: RecordType,
    ) ![]u8 {
        const params = [_]ContractParameter{
            ContractParameter.string(domain_name),
            ContractParameter.integer(record_type.getByte()),
        };
        return try self.non_fungible_token.token.smart_contract.callFunctionReturningString(RESOLVE, &params);
    }

    // ============================================================================
    // DOMAIN PROPERTIES (converted from Swift property methods)
    // ============================================================================

    /// Gets domain properties (equivalent to Swift properties)
    pub fn getDomainProperties(self: Self, domain_name: []const u8) !DomainProperties {
        const params = [_]ContractParameter{ContractParameter.string(domain_name)};

        const smart_contract = self.non_fungible_token.token.smart_contract;
        if (smart_contract.neo_swift == null) return errors.NeoError.InvalidConfiguration;

        const neo_swift: *NeoSwift = @ptrCast(@alignCast(smart_contract.neo_swift.?));
        var request = try neo_swift.invokeFunction(smart_contract.script_hash, PROPERTIES, &params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const stack_item = try invocation.getFirstStackItem();
        const map = switch (stack_item) {
            .Map => |m| m,
            else => return errors.SerializationError.InvalidFormat,
        };

        var name: ?[]const u8 = null;
        var expiration: ?u64 = null;
        var admin: ?Hash160 = null;

        errdefer if (name) |n| smart_contract.allocator.free(n);

        var it = map.iterator();
        while (it.next()) |entry| {
            const key = try entry.key_ptr.getString(smart_contract.allocator);
            defer smart_contract.allocator.free(key);

            if (std.mem.eql(u8, key, NAME_PROPERTY)) {
                const value = try entry.value_ptr.getString(smart_contract.allocator);
                if (name) |existing| smart_contract.allocator.free(existing);
                name = value;
                continue;
            }

            if (std.mem.eql(u8, key, EXPIRATION_PROPERTY)) {
                const exp_value = try entry.value_ptr.getInteger();
                if (exp_value < 0) return errors.SerializationError.InvalidFormat;
                expiration = @intCast(exp_value);
                continue;
            }

            if (std.mem.eql(u8, key, ADMIN_PROPERTY)) {
                if (entry.value_ptr.* == .Any) {
                    if (entry.value_ptr.Any == null) {
                        admin = null;
                        continue;
                    }
                    const any_value = entry.value_ptr.Any.?;
                    if (any_value.len == 0) {
                        admin = null;
                        continue;
                    }
                    if (!StringUtils.isValidHex(any_value)) {
                        return errors.SerializationError.InvalidFormat;
                    }
                    admin = try Hash160.initWithString(any_value);
                    continue;
                }

                const bytes = try entry.value_ptr.getByteArray(smart_contract.allocator);
                defer smart_contract.allocator.free(bytes);

                if (bytes.len == 0) {
                    admin = null;
                    continue;
                }

                if (bytes.len == constants.HASH160_SIZE) {
                    var buf: [constants.HASH160_SIZE]u8 = undefined;
                    @memcpy(&buf, bytes);
                    std.mem.reverse(u8, &buf);
                    admin = Hash160.fromArray(buf);
                    continue;
                }

                if (!StringUtils.isValidHex(bytes)) {
                    return errors.SerializationError.InvalidFormat;
                }
                admin = try Hash160.initWithString(bytes);
            }
        }

        if (name == null or expiration == null) {
            return errors.SerializationError.InvalidFormat;
        }

        return DomainProperties{
            .name = name.?,
            .expiration = expiration.?,
            .admin = admin,
        };
    }

    /// Checks domain ownership (utility method)
    pub fn isDomainOwner(self: Self, domain_name: []const u8, owner: Hash160) !bool {
        const domain_owner = try self.non_fungible_token.ownerOf(domain_name);
        return domain_owner.eql(owner);
    }

    /// Gets domain expiration (utility method)
    pub fn getDomainExpiration(self: Self, domain_name: []const u8) !u64 {
        const properties = try self.getDomainProperties(domain_name);
        return properties.expiration;
    }

    /// Checks if domain is expired (utility method)
    pub fn isDomainExpired(self: Self, domain_name: []const u8) !bool {
        const expiration = try self.getDomainExpiration(domain_name);
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        return current_time > expiration;
    }

    fn callFunctionReturningIterator(
        self: Self,
        comptime T: type,
        function_name: []const u8,
        params: []const ContractParameter,
        mapper: fn (StackItem, std.mem.Allocator) !T,
    ) !Iterator(T) {
        const smart_contract = self.non_fungible_token.token.smart_contract;
        if (smart_contract.neo_swift == null) return errors.NeoError.InvalidConfiguration;

        const neo_swift: *NeoSwift = @ptrCast(@alignCast(smart_contract.neo_swift.?));
        var request = try neo_swift.invokeFunction(smart_contract.script_hash, function_name, params, &[_]Signer{});
        var invocation = try request.send();
        const service_allocator = neo_swift.getService().getAllocator();
        defer invocation.deinit(service_allocator);

        if (invocation.hasFaulted()) {
            return errors.ContractError.ContractExecutionFailed;
        }

        const session_id = invocation.session orelse return errors.NetworkError.InvalidResponse;
        const first_item = try invocation.getFirstStackItem();
        const interop = switch (first_item) {
            .InteropInterface => |iface| iface,
            else => return errors.SerializationError.InvalidFormat,
        };

        return try Iterator(T).init(
            smart_contract.allocator,
            smart_contract.neo_swift.?,
            session_id,
            interop.iterator_id,
            mapper,
        );
    }
};

/// Domain record structure
pub const DomainRecord = struct {
    record_type: RecordType,
    data: []const u8,

    pub fn init(record_type: RecordType, data: []const u8) DomainRecord {
        return DomainRecord{
            .record_type = record_type,
            .data = data,
        };
    }

    pub fn deinit(self: *DomainRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

/// Domain properties structure
pub const DomainProperties = struct {
    name: []const u8,
    expiration: u64,
    admin: ?Hash160,

    pub fn deinit(self: *DomainProperties, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }

    pub fn isExpired(self: DomainProperties) bool {
        const current_time = @as(u64, @intCast(std.time.timestamp()));
        return current_time > self.expiration;
    }

    pub fn hasAdmin(self: DomainProperties) bool {
        return self.admin != null;
    }
};

/// Stack item mappers for iterators
fn stringMapper(stack_item: StackItem, allocator: std.mem.Allocator) ![]const u8 {
    return try stack_item.getString(allocator);
}

fn recordMapper(stack_item: StackItem, allocator: std.mem.Allocator) !DomainRecord {
    const values = switch (stack_item) {
        .Array => |items| items,
        .Struct => |items| items,
        else => return errors.SerializationError.InvalidFormat,
    };

    if (values.len < 2) return errors.SerializationError.InvalidFormat;

    const record_type_value = try values[0].getInteger();
    if (record_type_value < 0 or record_type_value > 0xFF) {
        return errors.SerializationError.InvalidFormat;
    }

    const record_type = RecordType.fromByte(@intCast(record_type_value)) orelse {
        return errors.SerializationError.InvalidFormat;
    };

    const data = try values[1].getString(allocator);
    return DomainRecord.init(record_type, data);
}

/// NNS utilities
pub const NNSUtils = struct {
    /// Default NNS resolver script hash (MainNet)
    pub const DEFAULT_NNS_RESOLVER: Hash160 = Hash160{ .bytes = [_]u8{ 0x50, 0xac, 0x1c, 0x37, 0x69, 0x0c, 0xc2, 0xcf, 0xc5, 0x94, 0x47, 0x28, 0x33, 0xcf, 0x57, 0x50, 0x5d, 0x5f, 0x46, 0xde } };

    /// Validates domain name format
    pub fn validateDomainName(domain_name: []const u8) !void {
        if (!@import("nns_name.zig").NNSName.isValidNNSName(domain_name, true)) {
            return errors.ContractError.InvalidContract;
        }
    }

    /// Gets domain cost estimate
    pub fn estimateDomainCost(domain_name: []const u8, years: u32, price_per_year: i64) !i64 {
        _ = domain_name; // Length-based pricing could be implemented
        return price_per_year * @as(i64, @intCast(years));
    }

    /// Parses domain from token ID
    pub fn parseDomainFromTokenId(token_id: []const u8, allocator: std.mem.Allocator) ![]u8 {
        // Token ID is typically the domain name in NNS
        return try allocator.dupe(u8, token_id);
    }

    /// Creates token ID from domain
    pub fn createTokenIdFromDomain(domain_name: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return try allocator.dupe(u8, domain_name);
    }

    /// Validates record data for type
    pub fn validateRecordData(record_type: RecordType, data: []const u8) !void {
        try record_type.validateRecordData(data);
    }

    /// Gets supported record types
    pub fn getSupportedRecordTypes() []const RecordType {
        return &[_]RecordType{ .A, .AAAA, .CNAME, .TXT };
    }

    /// Checks if record type is supported
    pub fn isRecordTypeSupported(record_type: RecordType) bool {
        const supported = getSupportedRecordTypes();
        for (supported) |supported_type| {
            if (supported_type == record_type) return true;
        }
        return false;
    }
};

/// NNS domain manager (additional utility)
pub const NNSDomainManager = struct {
    nns: NeoNameService,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, nns: NeoNameService) Self {
        return Self{
            .nns = nns,
            .allocator = allocator,
        };
    }

    /// Registers domain with records
    pub fn registerDomainWithRecords(
        self: Self,
        domain_name: []const u8,
        owner: Hash160,
        admin: ?Hash160,
        records: []const DomainRecord,
    ) ![]TransactionBuilder {
        var transactions = ArrayList(TransactionBuilder).init(self.allocator);
        defer transactions.deinit();

        // First, register the domain
        const register_tx = try self.nns.register(domain_name, owner, admin);
        try transactions.append(register_tx);

        // Then, set all records
        for (records) |record| {
            const record_tx = try self.nns.setRecord(domain_name, record.record_type, record.data);
            try transactions.append(record_tx);
        }

        return try transactions.toOwnedSlice();
    }

    /// Gets complete domain info
    pub fn getCompleteDomainInfo(self: Self, domain_name: []const u8) !CompleteDomainInfo {
        const properties = try self.nns.getDomainProperties(domain_name);
        const all_records = try self.nns.getAllRecords(domain_name);

        return CompleteDomainInfo{
            .properties = properties,
            .records_iterator = all_records,
            .is_available = try self.nns.isAvailable(domain_name),
        };
    }

    /// Transfers domain with records (utility method)
    pub fn transferDomainWithRecords(
        self: Self,
        domain_name: []const u8,
        from: Hash160,
        to: Hash160,
        transfer_admin: bool,
    ) ![]TransactionBuilder {
        var transactions = ArrayList(TransactionBuilder).init(self.allocator);
        defer transactions.deinit();

        // Transfer the NFT
        const transfer_tx = try self.nns.non_fungible_token.transfer(from, to, domain_name, null);
        try transactions.append(transfer_tx);

        // Transfer admin if requested
        if (transfer_admin) {
            const admin_tx = try self.nns.setAdmin(domain_name, to);
            try transactions.append(admin_tx);
        }

        return try transactions.toOwnedSlice();
    }
};

/// Complete domain information
pub const CompleteDomainInfo = struct {
    properties: DomainProperties,
    records_iterator: Iterator(DomainRecord),
    is_available: bool,

    pub fn deinit(self: *CompleteDomainInfo, allocator: std.mem.Allocator) void {
        self.properties.deinit(allocator);
        self.records_iterator.deinit();
    }

    pub fn isExpired(self: CompleteDomainInfo) bool {
        return self.properties.isExpired();
    }

    pub fn hasAdmin(self: CompleteDomainInfo) bool {
        return self.properties.hasAdmin();
    }
};

// Tests (converted from Swift NeoNameService tests)
test "NeoNameService creation and basic properties" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const nns = NeoNameService.init(allocator, NNSUtils.DEFAULT_NNS_RESOLVER, null);

    // Test basic properties (equivalent to Swift NeoNameService tests)
    try testing.expectEqualStrings("NameService", try nns.getName());
    try testing.expectEqualStrings("NNS", try nns.getSymbol());
    try testing.expectEqual(@as(u8, 0), try nns.getDecimals());
}

test "NeoNameService domain operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const nns = NeoNameService.init(allocator, NNSUtils.DEFAULT_NNS_RESOLVER, null);

    // Test domain availability check (equivalent to Swift domain tests)
    try testing.expectError(errors.NeoError.InvalidConfiguration, nns.isAvailable("test.neo"));

    // Test domain registration
    var register_tx = try nns.register("newdomain.neo", Hash160.ZERO, null);
    defer register_tx.deinit();

    try testing.expect(register_tx.getScript() != null);

    // Test domain renewal
    var renew_tx = try nns.renew("existing.neo", 2);
    defer renew_tx.deinit();

    try testing.expect(renew_tx.getScript() != null);
}

test "NeoNameService record management" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const nns = NeoNameService.init(allocator, NNSUtils.DEFAULT_NNS_RESOLVER, null);

    // Test record operations (equivalent to Swift record tests)
    var set_record_tx = try nns.setRecord("example.neo", RecordType.A, "192.168.1.1");
    defer set_record_tx.deinit();

    try testing.expect(set_record_tx.getScript() != null);

    var delete_record_tx = try nns.deleteRecord("example.neo", RecordType.A);
    defer delete_record_tx.deinit();

    try testing.expect(delete_record_tx.getScript() != null);

    var set_admin_tx = try nns.setAdmin("example.neo", Hash160.ZERO);
    defer set_admin_tx.deinit();

    try testing.expect(set_admin_tx.getScript() != null);
}

test "NNSUtils validation and utilities" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test domain validation (equivalent to Swift validation tests)
    try NNSUtils.validateDomainName("valid.neo");

    try testing.expectError(errors.ContractError.InvalidContract, NNSUtils.validateDomainName("invalid"));

    // Test cost estimation
    const cost = try NNSUtils.estimateDomainCost("test.neo", 2, 1000000);
    try testing.expectEqual(@as(i64, 2000000), cost); // 2 years * 1M per year

    // Test token ID operations
    const token_id = try NNSUtils.createTokenIdFromDomain("example.neo", allocator);
    defer allocator.free(token_id);

    const parsed_domain = try NNSUtils.parseDomainFromTokenId(token_id, allocator);
    defer allocator.free(parsed_domain);

    try testing.expectEqualStrings("example.neo", parsed_domain);

    // Test record type support
    try testing.expect(NNSUtils.isRecordTypeSupported(RecordType.A));
    try testing.expect(NNSUtils.isRecordTypeSupported(RecordType.TXT));

    const supported_types = NNSUtils.getSupportedRecordTypes();
    try testing.expectEqual(@as(usize, 4), supported_types.len);
}

test "NNSDomainManager advanced operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const nns = NeoNameService.init(allocator, NNSUtils.DEFAULT_NNS_RESOLVER, null);
    const domain_manager = NNSDomainManager.init(allocator, nns);

    // Test domain registration with records
    const records = [_]DomainRecord{
        DomainRecord.init(RecordType.A, try allocator.dupe(u8, "192.168.1.1")),
        DomainRecord.init(RecordType.TXT, try allocator.dupe(u8, "Test domain")),
    };
    defer {
        for (records) |*record| {
            var mutable_record = record.*;
            mutable_record.deinit(allocator);
        }
    }

    const registration_txs = try domain_manager.registerDomainWithRecords(
        "complete.neo",
        Hash160.ZERO,
        null,
        &records,
    );
    defer {
        for (registration_txs) |*tx| {
            tx.deinit();
        }
        allocator.free(registration_txs);
    }

    try testing.expect(registration_txs.len >= 1); // At least registration transaction

    // Test domain transfer
    const transfer_txs = try domain_manager.transferDomainWithRecords(
        "transfer.neo",
        Hash160.ZERO,
        Hash160.ZERO,
        true,
    );
    defer {
        for (transfer_txs) |*tx| {
            tx.deinit();
        }
        allocator.free(transfer_txs);
    }

    try testing.expect(transfer_txs.len >= 1);
}
