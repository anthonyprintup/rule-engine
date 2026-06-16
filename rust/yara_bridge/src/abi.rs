pub(crate) const BRIDGE_VERSION: u32 = 1;

pub struct ReParsedRuleSet {
    _private: [u8; 0],
}

pub struct ReRule {
    _private: [u8; 0],
}

pub struct RePattern {
    _private: [u8; 0],
}

pub struct ReNode {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReParseStatus {
    Ok = 0,
    NullSource = 1,
    Panic = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReNodeKind {
    Unsupported = 0,
    True = 1,
    False = 2,
    And = 3,
    Or = 4,
    Of = 5,
    With = 6,
    ForOf = 7,
    ForIn = 8,
    Range = 9,
    Tuple = 10,
    IterableExpr = 11,
    Lookup = 12,
    Not = 13,
    Negate = 14,
    Add = 15,
    Subtract = 16,
    Multiply = 17,
    Divide = 18,
    Modulo = 19,
    BitwiseNot = 20,
    ShiftLeft = 21,
    ShiftRight = 22,
    BitwiseAnd = 23,
    BitwiseOr = 24,
    BitwiseXor = 25,
    Equal = 26,
    NotEqual = 27,
    Greater = 28,
    GreaterEqual = 29,
    Less = 30,
    LessEqual = 31,
    Contains = 32,
    IContains = 33,
    StartsWith = 34,
    IStartsWith = 35,
    EndsWith = 36,
    IEndsWith = 37,
    IEquals = 38,
    Field = 39,
    PatternMatch = 40,
    PatternCount = 41,
    PatternOffset = 42,
    PatternLength = 43,
    LiteralString = 44,
    LiteralInteger = 45,
    LiteralFloat = 46,
    Identifier = 47,
    Defined = 48,
    FunctionCall = 49,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RePatternKind {
    Text = 0,
    Hex = 1,
    Regexp = 2,
    Unknown = 3,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReStringView {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReSpan {
    pub start: u64,
    pub end: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReParseResult {
    pub rules: *mut ReParsedRuleSet,
    pub status: ReParseStatus,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReDiagnosticView {
    pub source: ReStringView,
    pub span: ReSpan,
    pub message: ReStringView,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReRuleView {
    pub rule: *const ReRule,
    pub identifier: ReStringView,
    pub is_private: bool,
    pub is_global: bool,
    pub tags_len: usize,
    pub patterns_len: usize,
    pub span: ReSpan,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RePatternView {
    pub pattern: *const RePattern,
    pub identifier: ReStringView,
    pub kind: RePatternKind,
    pub literal: ReStringView,
    pub modifiers_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReNodeView {
    pub node: *const ReNode,
    pub kind: ReNodeKind,
    pub text: ReStringView,
    pub int_value: i64,
    pub float_value: f64,
    pub names_len: usize,
    pub children_len: usize,
    pub span: ReSpan,
}
