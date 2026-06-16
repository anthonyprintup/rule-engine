use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::abi::{
    ReDiagnosticView, ReNode, ReNodeView, ReParseResult, ReParseStatus, ReParsedRuleSet,
    RePatternView, ReRuleView, ReStringView,
};
use crate::ast_bridge::{build_ruleset, error_ruleset, parse_result};
use crate::model::{
    diagnostic_view, empty_diagnostic_view, empty_node_view, empty_pattern_view, empty_rule_view,
    empty_string_view, node_ptr, node_ref, node_view, pattern, pattern_view, rule, rule_view,
    ruleset, string_view, BridgeParsedRuleSet,
};

/// Parses a YARA source buffer into a Rust-owned rule-set arena.
///
/// # Safety
///
/// `source` must be null, or point to `len` readable bytes that remain valid for
/// the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_parse(source: *const u8, len: usize) -> ReParseResult {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if source.is_null() {
            return parse_result(error_ruleset("null source"), ReParseStatus::NullSource);
        }
        let bytes = unsafe { std::slice::from_raw_parts(source, len) };
        parse_result(build_ruleset(bytes), ReParseStatus::Ok)
    }));

    result.unwrap_or_else(|_| {
        parse_result(
            error_ruleset("panic while parsing YARA source"),
            ReParseStatus::Panic,
        )
    })
}

/// Releases a rule-set arena returned by [`re_yara_bridge_parse`].
///
/// # Safety
///
/// `rules` must be null, or a live pointer returned by `re_yara_bridge_parse`
/// that has not already been passed to this function.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_free(rules: *mut ReParsedRuleSet) {
    if rules.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(rules as *mut BridgeParsedRuleSet);
    }
}

/// Returns the bridge ABI version stored in a parsed rule set.
///
/// # Safety
///
/// `rules` must be null, or a live pointer returned by `re_yara_bridge_parse`.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_version(rules: *const ReParsedRuleSet) -> u32 {
    ruleset(rules).map(|rules| rules.version).unwrap_or(0)
}

/// Returns the number of imports in a parsed rule set.
///
/// # Safety
///
/// `rules` must be null, or a live pointer returned by `re_yara_bridge_parse`.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_import_count(rules: *const ReParsedRuleSet) -> usize {
    ruleset(rules).map(|rules| rules.imports.len()).unwrap_or(0)
}

/// Returns an import string view by index.
///
/// # Safety
///
/// `rules` must be null, or a live pointer returned by `re_yara_bridge_parse`.
/// Any returned view is borrowed from `rules` and expires when `rules` is freed.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_import_at(
    rules: *const ReParsedRuleSet,
    index: usize,
) -> ReStringView {
    ruleset(rules)
        .and_then(|rules| rules.imports.get(index))
        .map(|value| string_view(value))
        .unwrap_or_else(empty_string_view)
}

/// Returns the number of includes in a parsed rule set.
///
/// # Safety
///
/// `rules` must be null, or a live pointer returned by `re_yara_bridge_parse`.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_include_count(rules: *const ReParsedRuleSet) -> usize {
    ruleset(rules)
        .map(|rules| rules.includes.len())
        .unwrap_or(0)
}

/// Returns an include string view by index.
///
/// # Safety
///
/// `rules` must be null, or a live pointer returned by `re_yara_bridge_parse`.
/// Any returned view is borrowed from `rules` and expires when `rules` is freed.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_include_at(
    rules: *const ReParsedRuleSet,
    index: usize,
) -> ReStringView {
    ruleset(rules)
        .and_then(|rules| rules.includes.get(index))
        .map(|value| string_view(value))
        .unwrap_or_else(empty_string_view)
}

/// Returns the number of parse diagnostics in a parsed rule set.
///
/// # Safety
///
/// `rules` must be null, or a live pointer returned by `re_yara_bridge_parse`.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_diagnostic_count(rules: *const ReParsedRuleSet) -> usize {
    ruleset(rules)
        .map(|rules| rules.diagnostics.len())
        .unwrap_or(0)
}

/// Returns a parse diagnostic view by index.
///
/// # Safety
///
/// `rules` must be null, or a live pointer returned by `re_yara_bridge_parse`.
/// Any returned view is borrowed from `rules` and expires when `rules` is freed.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_diagnostic_at(
    rules: *const ReParsedRuleSet,
    index: usize,
) -> ReDiagnosticView {
    ruleset(rules)
        .and_then(|rules| rules.diagnostics.get(index))
        .map(diagnostic_view)
        .unwrap_or_else(empty_diagnostic_view)
}

/// Returns the number of rules in a parsed rule set.
///
/// # Safety
///
/// `rules` must be null, or a live pointer returned by `re_yara_bridge_parse`.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_rule_count(rules: *const ReParsedRuleSet) -> usize {
    ruleset(rules).map(|rules| rules.rules.len()).unwrap_or(0)
}

/// Returns a rule view by index.
///
/// # Safety
///
/// `rules` must be null, or a live pointer returned by `re_yara_bridge_parse`.
/// Any returned view is borrowed from `rules` and expires when `rules` is freed.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_rule_at(
    rules: *const ReParsedRuleSet,
    index: usize,
) -> ReRuleView {
    ruleset(rules)
        .and_then(|rules| rules.rules.get(index))
        .map(rule_view)
        .unwrap_or_else(empty_rule_view)
}

/// Returns a rule tag string view by index.
///
/// # Safety
///
/// `rule_view` must come from a live rule-set arena that has not been freed.
/// Any returned view is borrowed from that arena.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_rule_tag_at(
    _rules: *const ReParsedRuleSet,
    rule_view: ReRuleView,
    index: usize,
) -> ReStringView {
    rule(rule_view.rule)
        .and_then(|rule| rule.tags.get(index))
        .map(|value| string_view(value))
        .unwrap_or_else(empty_string_view)
}

/// Returns a rule pattern view by index.
///
/// # Safety
///
/// `rule_view` must come from a live rule-set arena that has not been freed.
/// Any returned view is borrowed from that arena.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_rule_pattern_at(
    _rules: *const ReParsedRuleSet,
    rule_view: ReRuleView,
    index: usize,
) -> RePatternView {
    rule(rule_view.rule)
        .and_then(|rule| rule.patterns.get(index))
        .map(pattern_view)
        .unwrap_or_else(empty_pattern_view)
}

/// Returns the root condition node for a rule.
///
/// # Safety
///
/// `rule_view` must come from a live rule-set arena that has not been freed.
/// Any returned node pointer is borrowed from that arena.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_rule_condition(
    _rules: *const ReParsedRuleSet,
    rule_view: ReRuleView,
) -> *const ReNode {
    rule(rule_view.rule)
        .map(|rule| node_ptr(&rule.condition))
        .unwrap_or(std::ptr::null())
}

/// Returns a pattern modifier string view by index.
///
/// # Safety
///
/// `pattern_view` must come from a live rule-set arena that has not been freed.
/// Any returned view is borrowed from that arena.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_pattern_modifier_at(
    _rules: *const ReParsedRuleSet,
    pattern_view: RePatternView,
    index: usize,
) -> ReStringView {
    pattern(pattern_view.pattern)
        .and_then(|pattern| pattern.modifiers.get(index))
        .map(|value| string_view(value))
        .unwrap_or_else(empty_string_view)
}

/// Returns a node view from a condition tree node pointer.
///
/// # Safety
///
/// `node` must be null, or a node pointer borrowed from a live rule-set arena.
/// Any returned view is borrowed from that arena.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_node_view(
    _rules: *const ReParsedRuleSet,
    node: *const ReNode,
) -> ReNodeView {
    node_ref(node)
        .map(node_view)
        .unwrap_or_else(empty_node_view)
}

/// Returns a node name string view by index.
///
/// # Safety
///
/// `node` must be null, or a node pointer borrowed from a live rule-set arena.
/// Any returned view is borrowed from that arena.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_node_name_at(
    _rules: *const ReParsedRuleSet,
    node: *const ReNode,
    index: usize,
) -> ReStringView {
    node_ref(node)
        .and_then(|node| node.names.get(index))
        .map(|value| string_view(value))
        .unwrap_or_else(empty_string_view)
}

/// Returns a child node pointer by index.
///
/// # Safety
///
/// `node` must be null, or a node pointer borrowed from a live rule-set arena.
/// Any returned child pointer is borrowed from that arena.
#[no_mangle]
pub unsafe extern "C" fn re_yara_bridge_node_child_at(
    _rules: *const ReParsedRuleSet,
    node: *const ReNode,
    index: usize,
) -> *const ReNode {
    node_ref(node)
        .and_then(|node| node.children.get(index))
        .map(node_ptr)
        .unwrap_or(std::ptr::null())
}
