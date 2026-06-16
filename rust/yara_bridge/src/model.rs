use crate::abi::{
    ReDiagnosticView, ReNode, ReNodeKind, ReNodeView, ReParsedRuleSet, RePattern, RePatternKind,
    RePatternView, ReRule, ReRuleView, ReSpan, ReStringView,
};

pub(crate) struct BridgeParsedRuleSet {
    pub(crate) version: u32,
    pub(crate) imports: Vec<String>,
    pub(crate) includes: Vec<String>,
    pub(crate) rules: Vec<BridgeRule>,
    pub(crate) diagnostics: Vec<BridgeDiagnostic>,
}

pub(crate) struct BridgeDiagnostic {
    pub(crate) source: String,
    pub(crate) span: ReSpan,
    pub(crate) message: String,
}

pub(crate) struct BridgeRule {
    pub(crate) identifier: String,
    pub(crate) is_private: bool,
    pub(crate) is_global: bool,
    pub(crate) tags: Vec<String>,
    pub(crate) patterns: Vec<BridgePattern>,
    pub(crate) condition: BridgeNode,
    pub(crate) span: ReSpan,
}

pub(crate) struct BridgePattern {
    pub(crate) identifier: String,
    pub(crate) kind: RePatternKind,
    pub(crate) literal: String,
    pub(crate) modifiers: Vec<String>,
}

pub(crate) struct BridgeNode {
    pub(crate) kind: ReNodeKind,
    pub(crate) text: String,
    pub(crate) int_value: i64,
    pub(crate) float_value: f64,
    pub(crate) names: Vec<String>,
    pub(crate) children: Vec<BridgeNode>,
    pub(crate) span: ReSpan,
}

pub(crate) fn string_view(value: &str) -> ReStringView {
    ReStringView {
        data: value.as_ptr(),
        len: value.len(),
    }
}

pub(crate) fn empty_string_view() -> ReStringView {
    ReStringView {
        data: std::ptr::null(),
        len: 0,
    }
}

pub(crate) fn ruleset<'a>(rules: *const ReParsedRuleSet) -> Option<&'a BridgeParsedRuleSet> {
    unsafe { (rules as *const BridgeParsedRuleSet).as_ref() }
}

pub(crate) fn rule<'a>(rule: *const ReRule) -> Option<&'a BridgeRule> {
    unsafe { (rule as *const BridgeRule).as_ref() }
}

pub(crate) fn pattern<'a>(pattern: *const RePattern) -> Option<&'a BridgePattern> {
    unsafe { (pattern as *const BridgePattern).as_ref() }
}

pub(crate) fn node_ref<'a>(node: *const ReNode) -> Option<&'a BridgeNode> {
    unsafe { (node as *const BridgeNode).as_ref() }
}

pub(crate) fn rule_ptr(rule: &BridgeRule) -> *const ReRule {
    rule as *const BridgeRule as *const ReRule
}

pub(crate) fn pattern_ptr(pattern: &BridgePattern) -> *const RePattern {
    pattern as *const BridgePattern as *const RePattern
}

pub(crate) fn node_ptr(node: &BridgeNode) -> *const ReNode {
    node as *const BridgeNode as *const ReNode
}

pub(crate) fn diagnostic_view(value: &BridgeDiagnostic) -> ReDiagnosticView {
    ReDiagnosticView {
        source: string_view(&value.source),
        span: value.span,
        message: string_view(&value.message),
    }
}

pub(crate) fn rule_view(value: &BridgeRule) -> ReRuleView {
    ReRuleView {
        rule: rule_ptr(value),
        identifier: string_view(&value.identifier),
        is_private: value.is_private,
        is_global: value.is_global,
        tags_len: value.tags.len(),
        patterns_len: value.patterns.len(),
        span: value.span,
    }
}

pub(crate) fn pattern_view(value: &BridgePattern) -> RePatternView {
    RePatternView {
        pattern: pattern_ptr(value),
        identifier: string_view(&value.identifier),
        kind: value.kind,
        literal: string_view(&value.literal),
        modifiers_len: value.modifiers.len(),
    }
}

pub(crate) fn node_view(value: &BridgeNode) -> ReNodeView {
    ReNodeView {
        node: node_ptr(value),
        kind: value.kind,
        text: string_view(&value.text),
        int_value: value.int_value,
        float_value: value.float_value,
        names_len: value.names.len(),
        children_len: value.children.len(),
        span: value.span,
    }
}

pub(crate) fn empty_diagnostic_view() -> ReDiagnosticView {
    ReDiagnosticView {
        source: empty_string_view(),
        span: ReSpan::default(),
        message: empty_string_view(),
    }
}

pub(crate) fn empty_rule_view() -> ReRuleView {
    ReRuleView {
        rule: std::ptr::null(),
        identifier: empty_string_view(),
        is_private: false,
        is_global: false,
        tags_len: 0,
        patterns_len: 0,
        span: ReSpan::default(),
    }
}

pub(crate) fn empty_pattern_view() -> RePatternView {
    RePatternView {
        pattern: std::ptr::null(),
        identifier: empty_string_view(),
        kind: RePatternKind::Unknown,
        literal: empty_string_view(),
        modifiers_len: 0,
    }
}

pub(crate) fn empty_node_view() -> ReNodeView {
    ReNodeView {
        node: std::ptr::null(),
        kind: ReNodeKind::Unsupported,
        text: empty_string_view(),
        int_value: 0,
        float_value: 0.0,
        names_len: 0,
        children_len: 0,
        span: ReSpan::default(),
    }
}
