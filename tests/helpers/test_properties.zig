//! Test Properties
//!
//! Complete conversion from NeoSwift TestProperties.swift
//! Provides shared test constants and utilities.

const std = @import("std");



pub const TestProperties = struct {
    pub const defaultAccountPrivateKey = "e6e919577dd7b8e97805151c05ae07ff4f752654d6d8797597aca989c02c4cb3";
    pub const defaultAccountPublicKey = "02163946a133e3d2e0d987fb90cb01b060ed1780f1718e2da28edf13b965fd2b600b";
    pub const defaultAccountAddress = "NZNos2WqTbu5oCgyfss9kUJgBXJqhuYAaj";
    pub const defaultAccountWIF = "L25kgAQJXNHnhc7Sx9bomxxwVSMsZdkaNQ3m2VfHrnLzKWMLP13A";
    pub const defaultAccountPassword = "Pwd12345678";
    pub const defaultAccountEncryptedPrivateKey = "6PYVPVe1fQznphjbUxXP9KZJqPMVnVwCx5s5pr5axRJ8uHkMtZg97eT2kA";
    
    pub const neoTokenHash = "ef4073a0f2b305a38ec4050e4d3d28bc40ea63f5";
    pub const gasTokenHash = "d2a4cff31913016155e38e474a2c06d08be276cf";
    
    pub const committeeAccountAddress = "NX8GreRFGFK5wpGMWetpX93HmtrezGogzk";
    pub const committeeAccountVerificationScript = "0c2102163946a133e3d2e0d987fb90cb01b060ed1780f1718e2da28edf13b965fd2b600b4156e7b327";
};