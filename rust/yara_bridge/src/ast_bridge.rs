use crate::abi::{
    ReNodeKind, ReParseResult, ReParseStatus, ReParsedRuleSet, RePatternKind, ReSpan,
    BRIDGE_VERSION,
};
use crate::model::{BridgeDiagnostic, BridgeNode, BridgeParsedRuleSet, BridgePattern, BridgeRule};
use yara_x_parser::ast::{self, Expr, Item, Pattern, RuleFlags, WithSpan, AST};
use yara_x_parser::Span;

fn span_view(span: &Span) -> ReSpan {
    ReSpan {
        start: span.start() as u64,
        end: span.end() as u64,
    }
}

fn node(
    kind: ReNodeKind,
    text: impl Into<String>,
    int_value: i64,
    float_value: f64,
    names: Vec<String>,
    children: Vec<BridgeNode>,
    span: Span,
) -> BridgeNode {
    BridgeNode {
        kind,
        text: text.into(),
        int_value,
        float_value,
        names,
        children,
        span: span_view(&span),
    }
}

fn unary(kind: ReNodeKind, expr: &Expr<'_>, span: Span) -> BridgeNode {
    node(kind, "", 0, 0.0, Vec::new(), vec![expr_to_node(expr)], span)
}

fn binary(kind: ReNodeKind, expr: &ast::BinaryExpr<'_>) -> BridgeNode {
    node(
        kind,
        "",
        0,
        0.0,
        Vec::new(),
        vec![expr_to_node(&expr.lhs), expr_to_node(&expr.rhs)],
        expr.span(),
    )
}

fn nary(kind: ReNodeKind, expr: &ast::NAryExpr<'_>) -> BridgeNode {
    node(
        kind,
        "",
        0,
        0.0,
        Vec::new(),
        expr.operands().map(expr_to_node).collect(),
        expr.span(),
    )
}

fn expression_names(expr: &Expr<'_>) -> Vec<String> {
    let converted = expr_to_node(expr);
    if !converted.names.is_empty() {
        return converted.names;
    }
    if !converted.text.is_empty() {
        return vec![converted.text];
    }
    Vec::new()
}

fn expr_to_node(expr: &Expr<'_>) -> BridgeNode {
    match expr {
        Expr::True { span, .. } => node(
            ReNodeKind::True,
            "",
            0,
            0.0,
            Vec::new(),
            Vec::new(),
            span.clone(),
        ),
        Expr::False { span, .. } => node(
            ReNodeKind::False,
            "",
            0,
            0.0,
            Vec::new(),
            Vec::new(),
            span.clone(),
        ),
        Expr::LiteralString(value) => {
            let text = value.as_str().unwrap_or(value.literal);
            node(
                ReNodeKind::LiteralString,
                text,
                0,
                0.0,
                Vec::new(),
                Vec::new(),
                value.span(),
            )
        }
        Expr::LiteralInteger(value) => node(
            ReNodeKind::LiteralInteger,
            value.value.to_string(),
            value.value,
            0.0,
            Vec::new(),
            Vec::new(),
            value.span(),
        ),
        Expr::LiteralFloat(value) => node(
            ReNodeKind::LiteralFloat,
            value.value.to_string(),
            0,
            value.value,
            Vec::new(),
            Vec::new(),
            value.span(),
        ),
        Expr::Ident(value) => node(
            ReNodeKind::Identifier,
            value.name,
            0,
            0.0,
            vec![value.name.to_string()],
            Vec::new(),
            value.span(),
        ),
        Expr::PatternMatch(value) => node(
            ReNodeKind::PatternMatch,
            value.identifier.name,
            0,
            0.0,
            vec![value.identifier.name.to_string()],
            Vec::new(),
            value.span(),
        ),
        Expr::PatternCount(value) => {
            let children = if let Some(range) = &value.range {
                vec![
                    expr_to_node(&range.lower_bound),
                    expr_to_node(&range.upper_bound),
                ]
            } else {
                Vec::new()
            };
            node(
                ReNodeKind::PatternCount,
                value.identifier.name,
                0,
                0.0,
                vec![pattern_identifier_name(value.identifier.name)],
                children,
                value.span(),
            )
        }
        Expr::PatternOffset(value) => node(
            ReNodeKind::PatternOffset,
            value.identifier.name,
            0,
            0.0,
            vec![pattern_identifier_name(value.identifier.name)],
            value.index.iter().map(expr_to_node).collect(),
            value.span(),
        ),
        Expr::PatternLength(value) => node(
            ReNodeKind::PatternLength,
            value.identifier.name,
            0,
            0.0,
            vec![pattern_identifier_name(value.identifier.name)],
            value.index.iter().map(expr_to_node).collect(),
            value.span(),
        ),
        Expr::FieldAccess(value) => {
            let mut names = Vec::new();
            for operand in value.operands() {
                if let Expr::Ident(ident) = operand {
                    names.push(ident.name.to_string());
                } else {
                    names.push("unsupported".to_string());
                }
            }
            if names.len() == 1 && names[0] != "unsupported" {
                let text = names[0].clone();
                return node(
                    ReNodeKind::Identifier,
                    text,
                    0,
                    0.0,
                    names,
                    Vec::new(),
                    value.span(),
                );
            }
            node(
                ReNodeKind::Field,
                "",
                0,
                0.0,
                names,
                Vec::new(),
                value.span(),
            )
        }
        Expr::Lookup(value) => node(
            ReNodeKind::Lookup,
            "",
            0,
            0.0,
            Vec::new(),
            vec![expr_to_node(&value.primary), expr_to_node(&value.index)],
            expr.span(),
        ),
        Expr::FuncCall(value) => {
            let mut names = Vec::new();
            if let Some(object) = &value.object {
                names.extend(expression_names(object));
            }
            names.push(value.identifier.name.to_string());
            let mut children = Vec::new();
            for arg in &value.args {
                children.push(expr_to_node(arg));
            }
            node(
                ReNodeKind::FunctionCall,
                value.identifier.name,
                0,
                0.0,
                names,
                children,
                value.span(),
            )
        }
        Expr::Defined(value) => unary(ReNodeKind::Defined, &value.operand, value.span()),
        Expr::Not(value) => unary(ReNodeKind::Not, &value.operand, value.span()),
        Expr::And(value) => nary(ReNodeKind::And, value),
        Expr::Or(value) => nary(ReNodeKind::Or, value),
        Expr::Of(value) => of_node(value),
        Expr::ForOf(value) => for_of_node(value),
        Expr::ForIn(value) => for_in_node(value),
        Expr::With(value) => with_node(value),
        Expr::Minus(value) => unary(ReNodeKind::Negate, &value.operand, value.span()),
        Expr::Add(value) => nary(ReNodeKind::Add, value),
        Expr::Sub(value) => nary(ReNodeKind::Subtract, value),
        Expr::Mul(value) => nary(ReNodeKind::Multiply, value),
        Expr::Div(value) => nary(ReNodeKind::Divide, value),
        Expr::Mod(value) => nary(ReNodeKind::Modulo, value),
        Expr::BitwiseNot(value) => unary(ReNodeKind::BitwiseNot, &value.operand, value.span()),
        Expr::Shl(value) => binary(ReNodeKind::ShiftLeft, value),
        Expr::Shr(value) => binary(ReNodeKind::ShiftRight, value),
        Expr::BitwiseAnd(value) => binary(ReNodeKind::BitwiseAnd, value),
        Expr::BitwiseOr(value) => binary(ReNodeKind::BitwiseOr, value),
        Expr::BitwiseXor(value) => binary(ReNodeKind::BitwiseXor, value),
        Expr::Eq(value) => binary(ReNodeKind::Equal, value),
        Expr::Ne(value) => binary(ReNodeKind::NotEqual, value),
        Expr::Gt(value) => binary(ReNodeKind::Greater, value),
        Expr::Ge(value) => binary(ReNodeKind::GreaterEqual, value),
        Expr::Lt(value) => binary(ReNodeKind::Less, value),
        Expr::Le(value) => binary(ReNodeKind::LessEqual, value),
        Expr::Contains(value) => binary(ReNodeKind::Contains, value),
        Expr::IContains(value) => binary(ReNodeKind::IContains, value),
        Expr::StartsWith(value) => binary(ReNodeKind::StartsWith, value),
        Expr::IStartsWith(value) => binary(ReNodeKind::IStartsWith, value),
        Expr::EndsWith(value) => binary(ReNodeKind::EndsWith, value),
        Expr::IEndsWith(value) => binary(ReNodeKind::IEndsWith, value),
        Expr::IEquals(value) => binary(ReNodeKind::IEquals, value),
        _ => node(
            ReNodeKind::Unsupported,
            "",
            0,
            0.0,
            Vec::new(),
            Vec::new(),
            expr.span(),
        ),
    }
}

fn for_of_node(value: &ast::ForOf<'_>) -> BridgeNode {
    let (quantifier, mut children) = quantifier_node(&value.quantifier);
    children.push(expr_to_node(&value.body));
    node(
        ReNodeKind::ForOf,
        quantifier,
        0,
        0.0,
        pattern_set_names(&value.pattern_set),
        children,
        value.span(),
    )
}

fn for_in_node(value: &ast::ForIn<'_>) -> BridgeNode {
    let (quantifier, mut children) = quantifier_node(&value.quantifier);
    children.push(iterable_node(&value.iterable));
    children.push(expr_to_node(&value.body));
    let names = value
        .variables
        .iter()
        .map(|variable| variable.name.to_string())
        .collect();
    node(
        ReNodeKind::ForIn,
        quantifier,
        0,
        0.0,
        names,
        children,
        value.span(),
    )
}

fn iterable_node(value: &ast::Iterable<'_>) -> BridgeNode {
    match value {
        ast::Iterable::Range(range) => node(
            ReNodeKind::Range,
            "",
            0,
            0.0,
            Vec::new(),
            vec![
                expr_to_node(&range.lower_bound),
                expr_to_node(&range.upper_bound),
            ],
            value.span(),
        ),
        ast::Iterable::ExprTuple(items) => node(
            ReNodeKind::Tuple,
            "",
            0,
            0.0,
            Vec::new(),
            items.iter().map(expr_to_node).collect(),
            value.span(),
        ),
        ast::Iterable::Expr(expr) => node(
            ReNodeKind::IterableExpr,
            "",
            0,
            0.0,
            Vec::new(),
            vec![expr_to_node(expr)],
            value.span(),
        ),
    }
}

fn with_node(value: &ast::With<'_>) -> BridgeNode {
    let names = value
        .declarations
        .iter()
        .map(|declaration| declaration.identifier.name.to_string())
        .collect();
    let mut children: Vec<BridgeNode> = value
        .declarations
        .iter()
        .map(|declaration| expr_to_node(&declaration.expression))
        .collect();
    children.push(expr_to_node(&value.body));
    node(ReNodeKind::With, "", 0, 0.0, names, children, value.span())
}

fn of_node(value: &ast::Of<'_>) -> BridgeNode {
    let (quantifier, mut children) = quantifier_node(&value.quantifier);
    match &value.items {
        ast::OfItems::PatternSet(pattern_set) => {
            let text = match &value.anchor {
                Some(ast::MatchAnchor::At(anchor)) => {
                    children.push(expr_to_node(&anchor.expr));
                    format!("at_{quantifier}")
                }
                Some(ast::MatchAnchor::In(anchor)) => {
                    children.push(expr_to_node(&anchor.range.lower_bound));
                    children.push(expr_to_node(&anchor.range.upper_bound));
                    format!("in_{quantifier}")
                }
                None => quantifier.to_string(),
            };
            node(
                ReNodeKind::Of,
                text,
                0,
                0.0,
                pattern_set_names(pattern_set),
                children,
                value.span(),
            )
        }
        ast::OfItems::BoolExprTuple(tuple) => {
            if value.anchor.is_some() {
                return node(
                    ReNodeKind::Unsupported,
                    "of_bool_tuple_anchor",
                    0,
                    0.0,
                    Vec::new(),
                    Vec::new(),
                    value.span(),
                );
            }
            children.extend(tuple.iter().map(expr_to_node));
            node(
                ReNodeKind::Of,
                format!("bool_{quantifier}"),
                0,
                0.0,
                Vec::new(),
                children,
                value.span(),
            )
        }
    }
}

fn quantifier_node(value: &ast::Quantifier<'_>) -> (&'static str, Vec<BridgeNode>) {
    match value {
        ast::Quantifier::All { .. } => ("all", Vec::new()),
        ast::Quantifier::Any { .. } => ("any", Vec::new()),
        ast::Quantifier::None { .. } => ("none", Vec::new()),
        ast::Quantifier::Expr(expr) => ("expr", vec![expr_to_node(expr)]),
        ast::Quantifier::Percentage(expr) => ("percentage", vec![expr_to_node(expr)]),
    }
}

fn pattern_set_names(value: &ast::PatternSet<'_>) -> Vec<String> {
    match value {
        ast::PatternSet::Them { .. } => vec!["them".to_string()],
        ast::PatternSet::Set(items) => items
            .iter()
            .map(|item| {
                let mut name = pattern_identifier_name(item.identifier);
                if item.wildcard {
                    name.push('*');
                }
                name
            })
            .collect(),
    }
}

fn pattern_identifier_name(name: &str) -> String {
    if name.starts_with('$') {
        return name.to_string();
    }
    if name.len() <= 1 {
        return "$".to_string();
    }
    format!("${}", &name[1..])
}

fn pattern_kind(pattern: &Pattern<'_>) -> RePatternKind {
    match pattern {
        Pattern::Text(_) => RePatternKind::Text,
        Pattern::Hex(_) => RePatternKind::Hex,
        Pattern::Regexp(_) => RePatternKind::Regexp,
    }
}

fn pattern_literal(pattern: &Pattern<'_>) -> String {
    match pattern {
        Pattern::Text(value) => value
            .text
            .as_str()
            .unwrap_or(value.text.literal)
            .to_string(),
        Pattern::Hex(value) => format!("{:?}", value.sub_patterns),
        Pattern::Regexp(value) => value.regexp.literal.to_string(),
    }
}

fn bridge_pattern(pattern: &Pattern<'_>) -> BridgePattern {
    BridgePattern {
        identifier: pattern.identifier().name.to_string(),
        kind: pattern_kind(pattern),
        literal: pattern_literal(pattern),
        modifiers: pattern
            .modifiers()
            .iter()
            .map(|modifier| modifier.to_string())
            .collect(),
    }
}

fn bridge_rule(rule: &ast::Rule<'_>) -> BridgeRule {
    BridgeRule {
        identifier: rule.identifier.name.to_string(),
        is_private: rule.flags.contains(RuleFlags::Private),
        is_global: rule.flags.contains(RuleFlags::Global),
        tags: rule
            .tags
            .iter()
            .flat_map(|tags| tags.iter().map(|tag| tag.name.to_string()))
            .collect(),
        patterns: rule
            .patterns
            .iter()
            .flat_map(|patterns| patterns.iter().map(bridge_pattern))
            .collect(),
        condition: expr_to_node(&rule.condition),
        span: span_view(&rule.identifier.span()),
    }
}

fn bridge_diagnostic(message: String, span: Span) -> BridgeDiagnostic {
    BridgeDiagnostic {
        source: String::new(),
        span: span_view(&span),
        message,
    }
}

fn error_span(error: &ast::Error) -> Span {
    match error {
        ast::Error::SyntaxError { span, .. }
        | ast::Error::InvalidInteger { span, .. }
        | ast::Error::InvalidFloat { span, .. }
        | ast::Error::InvalidRegexpModifier { span, .. }
        | ast::Error::InvalidEscapeSequence { span, .. } => span.clone(),
        ast::Error::InvalidUTF8(span) | ast::Error::UnexpectedEscapeSequence(span) => span.clone(),
    }
}

pub(crate) fn build_ruleset(source: &[u8]) -> BridgeParsedRuleSet {
    let ast = AST::from(source);
    let mut out = BridgeParsedRuleSet {
        version: BRIDGE_VERSION,
        imports: Vec::new(),
        includes: Vec::new(),
        rules: Vec::new(),
        diagnostics: Vec::new(),
    };

    for error in ast.errors() {
        out.diagnostics
            .push(bridge_diagnostic(format!("{error:?}"), error_span(error)));
    }

    for item in ast.items() {
        match item {
            Item::Import(import) => out.imports.push(import.module_name.to_string()),
            Item::Include(include) => out.includes.push(include.file_name.to_string()),
            Item::Rule(rule) => out.rules.push(bridge_rule(rule)),
        }
    }

    out
}

pub(crate) fn error_ruleset(message: &str) -> BridgeParsedRuleSet {
    BridgeParsedRuleSet {
        version: BRIDGE_VERSION,
        imports: Vec::new(),
        includes: Vec::new(),
        rules: Vec::new(),
        diagnostics: vec![bridge_diagnostic(message.to_string(), Span(0..0))],
    }
}

pub(crate) fn parse_result(ruleset: BridgeParsedRuleSet, status: ReParseStatus) -> ReParseResult {
    ReParseResult {
        rules: Box::into_raw(Box::new(ruleset)) as *mut ReParsedRuleSet,
        status,
    }
}
