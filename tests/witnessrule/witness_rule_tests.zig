//! Witness Rule Tests
//!
//! Complete conversion from NeoSwift WitnessRuleTests.swift
//! Tests witness rule functionality and validation.

const std = @import("std");


const testing = std.testing;
const WitnessRule = @import("../../src/transaction/witness_rule.zig").WitnessRule;
const WitnessAction = @import("../../src/transaction/witness_action.zig").WitnessAction;
const WitnessCondition = @import("../../src/transaction/witness_condition.zig").WitnessCondition;

test "Witness rule creation" {
    const allocator = testing.allocator;
    
    const action = WitnessAction.Allow;
    const condition = WitnessCondition.Factory.createBoolean(true);
    
    var witness_rule = try WitnessRule.init(action, condition, allocator);
    defer witness_rule.deinit(allocator);
    
    try testing.expectEqual(action, witness_rule.getAction());
    try witness_rule.validate();
}

test "Witness rule evaluation" {
    const allocator = testing.allocator;
    
    const allow_action = WitnessAction.Allow;
    const true_condition = WitnessCondition.Factory.createBoolean(true);
    
    var allow_rule = try WitnessRule.init(allow_action, true_condition, allocator);
    defer allow_rule.deinit(allocator);
    
    const context = @import("../../src/transaction/witness_condition.zig").EvaluationContext.init();
    const result = allow_rule.evaluate(context);
    
    try testing.expect(result); // Allow + true condition = true
}