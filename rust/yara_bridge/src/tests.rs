use crate::abi::*;

fn re_yara_bridge_parse(source: *const u8, len: usize) -> ReParseResult {
    unsafe { crate::ffi::re_yara_bridge_parse(source, len) }
}

fn re_yara_bridge_free(rules: *mut ReParsedRuleSet) {
    unsafe { crate::ffi::re_yara_bridge_free(rules) }
}

fn re_yara_bridge_version(rules: *const ReParsedRuleSet) -> u32 {
    unsafe { crate::ffi::re_yara_bridge_version(rules) }
}

fn re_yara_bridge_import_count(rules: *const ReParsedRuleSet) -> usize {
    unsafe { crate::ffi::re_yara_bridge_import_count(rules) }
}

fn re_yara_bridge_import_at(rules: *const ReParsedRuleSet, index: usize) -> ReStringView {
    unsafe { crate::ffi::re_yara_bridge_import_at(rules, index) }
}

fn re_yara_bridge_diagnostic_count(rules: *const ReParsedRuleSet) -> usize {
    unsafe { crate::ffi::re_yara_bridge_diagnostic_count(rules) }
}

fn re_yara_bridge_diagnostic_at(rules: *const ReParsedRuleSet, index: usize) -> ReDiagnosticView {
    unsafe { crate::ffi::re_yara_bridge_diagnostic_at(rules, index) }
}

fn re_yara_bridge_rule_count(rules: *const ReParsedRuleSet) -> usize {
    unsafe { crate::ffi::re_yara_bridge_rule_count(rules) }
}

fn re_yara_bridge_rule_at(rules: *const ReParsedRuleSet, index: usize) -> ReRuleView {
    unsafe { crate::ffi::re_yara_bridge_rule_at(rules, index) }
}

fn re_yara_bridge_rule_pattern_at(
    rules: *const ReParsedRuleSet,
    rule_view: ReRuleView,
    index: usize,
) -> RePatternView {
    unsafe { crate::ffi::re_yara_bridge_rule_pattern_at(rules, rule_view, index) }
}

fn re_yara_bridge_rule_condition(
    rules: *const ReParsedRuleSet,
    rule_view: ReRuleView,
) -> *const ReNode {
    unsafe { crate::ffi::re_yara_bridge_rule_condition(rules, rule_view) }
}

fn re_yara_bridge_node_view(rules: *const ReParsedRuleSet, node: *const ReNode) -> ReNodeView {
    unsafe { crate::ffi::re_yara_bridge_node_view(rules, node) }
}

fn re_yara_bridge_node_name_at(
    rules: *const ReParsedRuleSet,
    node: *const ReNode,
    index: usize,
) -> ReStringView {
    unsafe { crate::ffi::re_yara_bridge_node_name_at(rules, node, index) }
}

fn re_yara_bridge_node_child_at(
    rules: *const ReParsedRuleSet,
    node: *const ReNode,
    index: usize,
) -> *const ReNode {
    unsafe { crate::ffi::re_yara_bridge_node_child_at(rules, node, index) }
}

fn view_to_str(value: ReStringView) -> String {
    if value.data.is_null() || value.len == 0 {
        return String::new();
    }
    unsafe { std::slice::from_raw_parts(value.data, value.len) }
        .iter()
        .map(|byte| *byte as char)
        .collect()
}

struct OwnedParse {
    result: ReParseResult,
}

impl OwnedParse {
    fn parse(source: &[u8]) -> Self {
        Self {
            result: re_yara_bridge_parse(source.as_ptr(), source.len()),
        }
    }
}

impl Drop for OwnedParse {
    fn drop(&mut self) {
        re_yara_bridge_free(self.result.rules);
    }
}

#[test]
fn parses_valid_yara_rule_into_versioned_abi_views() {
    let source = br#"
import "process"

rule encoded_powershell {
    strings:
        $enc = "-enc" ascii
    condition:
        process.name == "powershell.exe" and $enc
}
"#;

    let parsed = OwnedParse::parse(source);

    assert_eq!(parsed.result.status, ReParseStatus::Ok);
    assert!(!parsed.result.rules.is_null());
    assert_eq!(
        re_yara_bridge_version(parsed.result.rules),
        crate::abi::BRIDGE_VERSION
    );
    assert_eq!(re_yara_bridge_import_count(parsed.result.rules), 1);
    assert_eq!(
        view_to_str(re_yara_bridge_import_at(parsed.result.rules, 0)),
        "process"
    );
    assert_eq!(re_yara_bridge_rule_count(parsed.result.rules), 1);
    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    assert_eq!(view_to_str(rule.identifier), "encoded_powershell");
    assert_eq!(rule.patterns_len, 1);
    let pattern = re_yara_bridge_rule_pattern_at(parsed.result.rules, rule, 0);
    assert_eq!(view_to_str(pattern.identifier), "$enc");
    assert_eq!(pattern.kind, RePatternKind::Text);
}

#[test]
fn parses_numeric_operators_into_expression_nodes() {
    let parsed = OwnedParse::parse(
        br#"
import "process"

rule numeric_filter {
    condition:
        process.pid + 4 * 2 == 50 and (process.pid & 15) == 10
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let root = re_yara_bridge_node_view(parsed.result.rules, condition);
    assert_eq!(root.kind, ReNodeKind::And);
    let lhs = re_yara_bridge_node_child_at(parsed.result.rules, condition, 0);
    let lhs = re_yara_bridge_node_view(parsed.result.rules, lhs);
    assert_eq!(lhs.kind, ReNodeKind::Equal);
}

#[test]
fn parses_pattern_metadata_operators_into_expression_nodes() {
    let parsed = OwnedParse::parse(
        br#"
rule pattern_metadata {
    strings:
        $enc = "-enc" ascii
    condition:
        #enc == 2 and @enc[1] == 16 and !enc[1] == 4
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let root = re_yara_bridge_node_view(parsed.result.rules, condition);
    assert_eq!(root.kind, ReNodeKind::And);
    assert_eq!(root.children_len, 3);
}

#[test]
fn parses_pattern_set_of_into_expression_nodes() {
    let parsed = OwnedParse::parse(
        br#"
rule pattern_sets {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        all of them and 1 of ($a, $b)
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let first = re_yara_bridge_node_child_at(parsed.result.rules, condition, 0);
    let first = re_yara_bridge_node_view(parsed.result.rules, first);
    assert_eq!(first.kind, ReNodeKind::Of);
    assert_eq!(view_to_str(first.text), "all");
}

#[test]
fn parses_extended_string_operators_into_expression_nodes() {
    let parsed = OwnedParse::parse(
        br#"
import "process"

rule string_ops {
    condition:
        process.command_line icontains "-ENC" and
        process.path startswith "fixtures/windows" and
        process.path endswith ".exe" and
        process.name iequals "POWERSHELL.EXE"
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let first = re_yara_bridge_node_child_at(parsed.result.rules, condition, 0);
    let first = re_yara_bridge_node_view(parsed.result.rules, first);
    assert_eq!(first.kind, ReNodeKind::IContains);
}

#[test]
fn parses_with_expression_into_local_binding_nodes() {
    let parsed = OwnedParse::parse(
        br#"
import "process"

rule with_alias {
    condition:
        with cmd = process.command_line : (cmd icontains "-ENC")
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let value = re_yara_bridge_node_view(parsed.result.rules, condition);
    assert_eq!(value.kind, ReNodeKind::With);
    assert_eq!(
        view_to_str(re_yara_bridge_node_name_at(
            parsed.result.rules,
            condition,
            0
        )),
        "cmd"
    );
}

#[test]
fn parses_for_in_range_and_tuple_into_expression_nodes() {
    let parsed = OwnedParse::parse(
        br#"
rule loop_filters {
    condition:
        for all i in (1..3) : (i > 0) and
        for any e in (1, 2, 3) : (e == 3)
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let first = re_yara_bridge_node_child_at(parsed.result.rules, condition, 0);
    let first = re_yara_bridge_node_view(parsed.result.rules, first);
    assert_eq!(first.kind, ReNodeKind::ForIn);
    assert_eq!(view_to_str(first.text), "all");
}

#[test]
fn parses_for_of_pattern_body_into_expression_nodes() {
    let parsed = OwnedParse::parse(
        br#"
rule for_of_patterns {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        for any of them : ( $ ) and
        for all of ($a, $b) : ( # >= 1 )
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let first = re_yara_bridge_node_child_at(parsed.result.rules, condition, 0);
    let first = re_yara_bridge_node_view(parsed.result.rules, first);
    assert_eq!(first.kind, ReNodeKind::ForOf);
    assert_eq!(view_to_str(first.text), "any");
}

#[test]
fn parses_bool_tuple_of_into_expression_nodes() {
    let parsed = OwnedParse::parse(
        br#"
rule bool_tuple_of {
    condition:
        any of (true, false, 1 == 1) and
        2 of (true, false, true)
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let first = re_yara_bridge_node_child_at(parsed.result.rules, condition, 0);
    let first = re_yara_bridge_node_view(parsed.result.rules, first);
    assert_eq!(first.kind, ReNodeKind::Of);
    assert_eq!(view_to_str(first.text), "bool_any");
    assert_eq!(first.children_len, 3);

    let second = re_yara_bridge_node_child_at(parsed.result.rules, condition, 1);
    let second = re_yara_bridge_node_view(parsed.result.rules, second);
    assert_eq!(second.kind, ReNodeKind::Of);
    assert_eq!(view_to_str(second.text), "bool_expr");
    assert_eq!(second.children_len, 4);
}

#[test]
fn parses_anchored_pattern_set_of_into_expression_nodes() {
    let parsed = OwnedParse::parse(
        br#"
rule anchored_of {
    strings:
        $a = "alpha" ascii
        $b = "beta" ascii
    condition:
        any of ($a, $b) at 8 and
        all of them in (4..16)
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let first = re_yara_bridge_node_child_at(parsed.result.rules, condition, 0);
    let first = re_yara_bridge_node_view(parsed.result.rules, first);
    assert_eq!(first.kind, ReNodeKind::Of);
    assert_eq!(view_to_str(first.text), "at_any");
    assert_eq!(first.names_len, 2);
    assert_eq!(first.children_len, 1);

    let second = re_yara_bridge_node_child_at(parsed.result.rules, condition, 1);
    let second = re_yara_bridge_node_view(parsed.result.rules, second);
    assert_eq!(second.kind, ReNodeKind::Of);
    assert_eq!(view_to_str(second.text), "in_all");
    assert_eq!(second.names_len, 1);
    assert_eq!(second.children_len, 2);
}

#[test]
fn parses_lookup_expression_nodes() {
    let parsed = OwnedParse::parse(
        br#"
rule lookup_values {
    condition:
        numbers[1] == 42 and proc["name"] == "powershell.exe"
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let first_equal = re_yara_bridge_node_child_at(parsed.result.rules, condition, 0);
    let first_equal_child = re_yara_bridge_node_child_at(parsed.result.rules, first_equal, 0);
    let lookup = re_yara_bridge_node_view(parsed.result.rules, first_equal_child);
    assert_eq!(lookup.kind, ReNodeKind::Lookup);
}

#[test]
fn parses_function_calls_into_expression_nodes() {
    let parsed = OwnedParse::parse(
        br#"
import "demo"

rule function_call {
    condition:
        demo.score(42, "alpha")
}
"#,
    );

    let rule = re_yara_bridge_rule_at(parsed.result.rules, 0);
    let condition = re_yara_bridge_rule_condition(parsed.result.rules, rule);
    let value = re_yara_bridge_node_view(parsed.result.rules, condition);
    assert_eq!(value.kind, ReNodeKind::FunctionCall);
    assert_eq!(view_to_str(value.text), "score");
    assert_eq!(value.names_len, 2);
    assert_eq!(
        view_to_str(re_yara_bridge_node_name_at(
            parsed.result.rules,
            condition,
            0
        )),
        "demo"
    );
    assert_eq!(
        view_to_str(re_yara_bridge_node_name_at(
            parsed.result.rules,
            condition,
            1
        )),
        "score"
    );
    assert_eq!(value.children_len, 2);
}

#[test]
fn reports_invalid_yara_rule_as_error_payload() {
    let parsed = OwnedParse::parse(b"rule bad { condition: and }");

    assert_eq!(parsed.result.status, ReParseStatus::Ok);
    assert_eq!(re_yara_bridge_diagnostic_count(parsed.result.rules), 1);
    let diagnostic = re_yara_bridge_diagnostic_at(parsed.result.rules, 0);
    assert!(!view_to_str(diagnostic.message).is_empty());
}

#[test]
fn c_abi_handles_null_source_without_panicking() {
    let parsed = ReParseResult {
        rules: std::ptr::null_mut(),
        status: ReParseStatus::Panic,
    };
    let mut owned = OwnedParse { result: parsed };
    owned.result = re_yara_bridge_parse(std::ptr::null(), 0);

    assert_eq!(owned.result.status, ReParseStatus::NullSource);
    assert_eq!(re_yara_bridge_diagnostic_count(owned.result.rules), 1);
    let diagnostic = re_yara_bridge_diagnostic_at(owned.result.rules, 0);
    assert_eq!(view_to_str(diagnostic.message), "null source");
}
