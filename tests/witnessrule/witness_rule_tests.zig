//! Witness Rule Tests
//!
//! Complete conversion from NeoSwift WitnessRuleTests.swift
//! Tests witness rule functionality and validation.

const std = @import("std");

const testing = std.testing;
const neo = @import("neo-zig");
const WitnessRule = neo.transaction.WitnessRule;
const WitnessAction = neo.transaction.WitnessAction;
const WitnessCondition = neo.transaction.WitnessCondition;
const WitnessContext = neo.transaction.WitnessContext;

test "Witness rule creation" {
    const action = WitnessAction.Allow;
    const condition = WitnessCondition.boolean(true);

    const witness_rule = WitnessRule.init(action, condition);

    try testing.expectEqual(action, witness_rule.action);
    try witness_rule.validate();
}

test "Witness rule evaluation" {
    const allow_action = WitnessAction.Allow;
    const true_condition = WitnessCondition.boolean(true);

    const allow_rule = WitnessRule.init(allow_action, true_condition);

    const context = WitnessContext.init();
    const result = allow_rule.evaluate(context);
    
    try testing.expect(result); // Allow + true condition = true
}
