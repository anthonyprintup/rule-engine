#include "rule_engine/python/compiler/frontend.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <locale>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

namespace rule_engine::python::compiler {
    namespace {

        Diagnostic make_diagnostic(std::string code, std::string message,
                                   std::optional<SourceSpan> span = std::nullopt) {
            return Diagnostic {
                .code = std::move(code),
                .severity = DiagnosticSeverity::error,
                .message = std::move(message),
                .span = span,
                .related = {},
            };
        }

        void sort_diagnostics(DiagnosticSet &diagnostics) {
            std::ranges::sort(diagnostics, [](const Diagnostic &left, const Diagnostic &right) {
                const auto left_source = left.span ? left.span->source.value : std::string {};
                const auto right_source = right.span ? right.span->source.value : std::string {};
                if (left_source != right_source) {
                    return left_source < right_source;
                }
                const auto left_begin = left.span ? left.span->begin_byte : 0U;
                const auto right_begin = right.span ? right.span->begin_byte : 0U;
                if (left_begin != right_begin) {
                    return left_begin < right_begin;
                }
                if (left.code != right.code) {
                    return left.code < right.code;
                }
                return left.message < right.message;
            });
        }

        struct AstIndex {
            const AstEnvelope &envelope;
            std::map<AstNodeId, const AstNode *> nodes;

            explicit AstIndex(const AstEnvelope &value): envelope {value} {
                for (const auto &node : envelope.nodes) { nodes.emplace(node.id, &node); }
            }

            [[nodiscard]] const AstNode *node(const AstNodeId id) const {
                const auto found = nodes.find(id);
                return found == nodes.end() ? nullptr : found->second;
            }

            [[nodiscard]] static const AstField *field(const AstNode &node_value, const std::string_view name) {
                const auto found = std::ranges::find(node_value.fields, name, &AstField::name);
                return found == node_value.fields.end() ? nullptr : &*found;
            }

            [[nodiscard]] const AstNode *reference(const AstNode &node_value, const std::string_view name) const {
                const auto *field_value = field(node_value, name);
                if (!field_value) {
                    return nullptr;
                }
                const auto *reference_value = std::get_if<AstNodeReference>(&field_value->value.data);
                return reference_value ? node(reference_value->id) : nullptr;
            }

            [[nodiscard]] std::vector<const AstNode *> sequence(const AstNode &node_value,
                                                                const std::string_view name) const {
                std::vector<const AstNode *> result;
                const auto *field_value = field(node_value, name);
                if (!field_value) {
                    return result;
                }
                const auto *sequence_value = std::get_if<AstValue::Sequence>(&field_value->value.data);
                if (!sequence_value || !*sequence_value) {
                    return result;
                }
                result.reserve((*sequence_value)->values.size());
                for (const auto &value : (*sequence_value)->values) {
                    const auto *reference_value = std::get_if<AstNodeReference>(&value.data);
                    if (reference_value && node(reference_value->id)) {
                        result.push_back(node(reference_value->id));
                    }
                }
                return result;
            }

            [[nodiscard]] std::vector<std::string> string_sequence(const AstNode &node_value,
                                                                   const std::string_view name) const {
                std::vector<std::string> result;
                const auto *field_value = field(node_value, name);
                if (!field_value) {
                    return result;
                }
                const auto *sequence_value = std::get_if<AstValue::Sequence>(&field_value->value.data);
                if (!sequence_value || !*sequence_value) {
                    return result;
                }
                for (const auto &value : (*sequence_value)->values) {
                    if (const auto *text = std::get_if<UnicodeValue>(&value.data)) {
                        result.push_back(text->utf8);
                        continue;
                    }
                    if (const auto *reference_value = std::get_if<AstNodeReference>(&value.data)) {
                        if (const auto *operator_node = node(reference_value->id)) {
                            result.push_back(operator_node->kind);
                        }
                    }
                }
                return result;
            }

            [[nodiscard]] std::optional<std::string> string(const AstNode &node_value,
                                                            const std::string_view name) const {
                const auto *field_value = field(node_value, name);
                if (!field_value) {
                    return std::nullopt;
                }
                const auto *text = std::get_if<UnicodeValue>(&field_value->value.data);
                return text ? std::optional<std::string> {text->utf8} : std::nullopt;
            }
        };

        const std::set<std::string, std::less<>> allowed_import_roots {
            "base64",  "binascii",    "collections", "dataclasses", "datetime", "enum",   "functools",
            "hashlib", "hmac",        "ipaddress",   "itertools",   "json",     "math",   "operator",
            "pathlib", "rule_engine", "statistics",  "struct",      "typing",   "urllib",
        };

        const std::set<std::string, std::less<>> forbidden_calls {
            "__import__", "compile", "delattr", "dir",    "eval", "exec",    "getattr", "globals",
            "help",       "id",      "input",   "locals", "open", "setattr", "vars",
        };

        const std::set<std::string, std::less<>> forbidden_dunders {
            "__bases__", "__class_getitem__", "__del__",          "__delattr__",       "__delete__",
            "__get__",   "__getattr__",       "__getattribute__", "__init_subclass__", "__mro_entries__",
            "__new__",   "__prepare__",       "__set__",          "__setattr__",
        };

        std::string root_name(const AstIndex &index, const AstNode &node) {
            if (node.kind == "Name") {
                return index.string(node, "id").value_or(std::string {});
            }
            if (node.kind != "Attribute") {
                return {};
            }
            const auto *value = index.reference(node, "value");
            return value ? root_name(index, *value) : std::string {};
        }

        std::optional<std::string> attribute_path(const AstIndex &index, const AstNode &node) {
            if (node.kind == "Name") {
                return index.string(node, "id");
            }
            if (node.kind != "Attribute") {
                return std::nullopt;
            }
            const auto *value = index.reference(node, "value");
            const auto attribute = index.string(node, "attr");
            if (!value || !attribute) {
                return std::nullopt;
            }
            const auto prefix = attribute_path(index, *value);
            if (!prefix) {
                return std::nullopt;
            }
            return *prefix + "." + *attribute;
        }

        StaticType annotation_type(const AstIndex &index, const AstNode *annotation) {
            if (!annotation) {
                return {};
            }
            if (annotation->kind == "Name") {
                const auto name = index.string(*annotation, "id").value_or(std::string {});
                if (name == "bool") {
                    return {.kind = StaticTypeKind::boolean, .qualified_name = "bool"};
                }
                if (name == "int") {
                    return {.kind = StaticTypeKind::integer, .qualified_name = "int"};
                }
                if (name == "float") {
                    return {.kind = StaticTypeKind::floating, .qualified_name = "float"};
                }
                if (name == "str") {
                    return {.kind = StaticTypeKind::string, .qualified_name = "str"};
                }
                if (name == "bytes") {
                    return {.kind = StaticTypeKind::bytes, .qualified_name = "bytes"};
                }
                if (name == "None") {
                    return {.kind = StaticTypeKind::none, .qualified_name = "None"};
                }
                return {.kind = StaticTypeKind::model, .qualified_name = name};
            }
            return {.kind = StaticTypeKind::unknown, .qualified_name = annotation->kind};
        }

        bool valid_stable_id(const std::string_view id) {
            if (id.empty() || id.size() > 128) {
                return false;
            }
            const auto valid_edge = [](const unsigned char value) {
                return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9');
            };
            if (!valid_edge(static_cast<unsigned char>(id.front())) ||
                !valid_edge(static_cast<unsigned char>(id.back()))) {
                return false;
            }
            return std::ranges::all_of(id, [](const unsigned char value) {
                return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '.' ||
                       value == '_' || value == '-';
            });
        }

        struct DecoratorInfo {
            SymbolKind kind {SymbolKind::function};
            std::string stable_id;
            bool reportable {};
        };

        DecoratorInfo decorator_info(const AstIndex &index, const AstNode &function, DiagnosticSet &diagnostics) {
            DecoratorInfo result;
            const auto decorators = index.sequence(function, "decorator_list");
            for (const auto *decorator : decorators) {
                if (decorator->kind == "Name") {
                    const auto name = index.string(*decorator, "id").value_or(std::string {});
                    if (name == "overload" || name == "final") {
                        continue;
                    }
                    diagnostics.push_back(make_diagnostic(
                        "PY-DECORATOR", "user-defined decorator '" + name + "' is not supported", decorator->span));
                    continue;
                }
                if (decorator->kind != "Call") {
                    diagnostics.push_back(make_diagnostic(
                        "PY-DECORATOR", "decorator must be a statically recognized call", decorator->span));
                    continue;
                }
                const auto *target = index.reference(*decorator, "func");
                const auto name = target ? root_name(index, *target) : std::string {};
                const auto reportable = name == "rule" || name == "rule_template" || name == "correlation" ||
                                        name == "correlation_template";
                if (!reportable) {
                    diagnostics.push_back(make_diagnostic(
                        "PY-DECORATOR", "decorator '" + name + "' is not in the compiler allowlist", decorator->span));
                    continue;
                }
                const auto arguments = index.sequence(*decorator, "args");
                if (arguments.size() != 1 || arguments.front()->kind != "Constant") {
                    diagnostics.push_back(make_diagnostic(
                        "PY-ID", "reportable decorator requires one literal stable ID", decorator->span));
                    continue;
                }
                const auto id = index.string(*arguments.front(), "value").value_or(std::string {});
                if (!valid_stable_id(id)) {
                    diagnostics.push_back(
                        make_diagnostic("PY-ID", "reportable decorator has an invalid stable ID", decorator->span));
                    continue;
                }
                if (result.reportable) {
                    diagnostics.push_back(make_diagnostic(
                        "PY-DECORATOR", "function has more than one reportable decorator", decorator->span));
                    continue;
                }
                result.reportable = true;
                result.stable_id = id;
                if (name == "rule") {
                    result.kind = SymbolKind::rule;
                } else if (name == "rule_template") {
                    result.kind = SymbolKind::rule_template;
                } else {
                    result.kind = SymbolKind::correlation;
                }
            }
            return result;
        }

        bool contains_kind(const AstIndex &index, const AstNode &node, const std::string_view searched,
                           const bool descend_functions = false) {
            if (node.kind == searched) {
                return true;
            }
            if (!descend_functions &&
                (node.kind == "FunctionDef" || node.kind == "AsyncFunctionDef" || node.kind == "Lambda")) {
                return false;
            }
            for (const auto &field : node.fields) {
                if (const auto *reference = std::get_if<AstNodeReference>(&field.value.data)) {
                    const auto *child = index.node(reference->id);
                    if (child && contains_kind(index, *child, searched, descend_functions)) {
                        return true;
                    }
                }
                const auto *sequence = std::get_if<AstValue::Sequence>(&field.value.data);
                if (!sequence || !*sequence) {
                    continue;
                }
                for (const auto &item : (*sequence)->values) {
                    const auto *reference = std::get_if<AstNodeReference>(&item.data);
                    const auto *child = reference ? index.node(reference->id) : nullptr;
                    if (child && contains_kind(index, *child, searched, descend_functions)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void inspect_forbidden(const AstIndex &index, const AstNode &node, DiagnosticSet &diagnostics) {
            if (node.kind == "Global") {
                diagnostics.push_back(make_diagnostic(
                    "PY-DYNAMIC-GLOBAL", "global declarations and mutable module state are rejected", node.span));
            }
            if (node.kind == "Call") {
                const auto *target = index.reference(node, "func");
                const auto name = target ? root_name(index, *target) : std::string {};
                if (forbidden_calls.contains(name)) {
                    diagnostics.push_back(make_diagnostic(
                        "PY-DYNAMIC", "ambient or reflective call '" + name + "' is rejected", node.span));
                }
            }
            if (node.kind == "ClassDef") {
                for (const auto *keyword : index.sequence(node, "keywords")) {
                    if (index.string(*keyword, "arg").value_or(std::string {}) == "metaclass") {
                        diagnostics.push_back(
                            make_diagnostic("PY-DYNAMIC-METACLASS", "metaclasses are rejected", keyword->span));
                    }
                }
                for (const auto *base : index.sequence(node, "bases")) {
                    if (base->kind != "Name" && base->kind != "Attribute") {
                        diagnostics.push_back(
                            make_diagnostic("PY-DYNAMIC-BASE", "class bases must be statically named", base->span));
                    }
                }
            }
            if (node.kind == "FunctionDef" || node.kind == "AsyncFunctionDef") {
                const auto name = index.string(node, "name").value_or(std::string {});
                if (forbidden_dunders.contains(name)) {
                    diagnostics.push_back(
                        make_diagnostic("PY-DYNAMIC-DUNDER", "dynamic dunder '" + name + "' is rejected", node.span));
                }
            }

            for (const auto &field : node.fields) {
                if (const auto *reference = std::get_if<AstNodeReference>(&field.value.data)) {
                    if (const auto *child = index.node(reference->id)) {
                        inspect_forbidden(index, *child, diagnostics);
                    }
                }
                const auto *sequence = std::get_if<AstValue::Sequence>(&field.value.data);
                if (!sequence || !*sequence) {
                    continue;
                }
                for (const auto &item : (*sequence)->values) {
                    const auto *reference = std::get_if<AstNodeReference>(&item.data);
                    if (reference && index.node(reference->id)) {
                        inspect_forbidden(index, *index.node(reference->id), diagnostics);
                    }
                }
            }
        }

        struct FunctionModel {
            std::string module;
            std::string name;
            std::string qualified_name;
            ExecutableId executable;
            SymbolKind symbol_kind {SymbolKind::function};
            SourceSpan span;
            const AstNode *node {};
            std::vector<std::pair<std::string, StaticType>> parameters;
            StaticType return_type;
            bool public_api {};
            bool async {};
            bool generator {};
        };

        void bind_import(const AstIndex &index, const AstNode &node, const std::set<std::string, std::less<>> &modules,
                         const std::string &current_module, std::vector<BoundSymbol> &symbols,
                         DiagnosticSet &diagnostics) {
            const auto aliases = index.sequence(node, "names");
            for (const auto *alias : aliases) {
                const auto name = index.string(*alias, "name").value_or(std::string {});
                if (name == "*") {
                    diagnostics.push_back(
                        make_diagnostic("PY-IMPORT-WILDCARD", "wildcard imports are rejected", alias->span));
                    continue;
                }
                const auto root_end = name.find('.');
                const auto root = name.substr(0, root_end);
                const auto local_dependency = modules.contains(name) || name.starts_with("rulepack_deps.");
                if (!local_dependency && !allowed_import_roots.contains(root)) {
                    diagnostics.push_back(make_diagnostic(
                        "PY-IMPORT-AMBIENT", "ambient module '" + name + "' is not in stdlib.v1", alias->span));
                    continue;
                }
                const auto as_name = index.string(*alias, "asname").value_or(std::string {});
                const auto bound_name = as_name.empty() ? root : as_name;
                symbols.push_back(BoundSymbol {
                    .module = current_module,
                    .name = bound_name,
                    .qualified_name = name,
                    .kind = SymbolKind::imported,
                    .type = {.kind = StaticTypeKind::unknown, .qualified_name = "module"},
                    .span = alias->span,
                    .public_api = false,
                    .async = false,
                    .generator = false,
                });
            }
        }

        void bind_import_from(const AstIndex &index, const AstNode &node,
                              const std::set<std::string, std::less<>> &modules, const std::string &current_module,
                              std::vector<BoundSymbol> &symbols, DiagnosticSet &diagnostics) {
            const auto module = index.string(node, "module").value_or(std::string {});
            const auto root_end = module.find('.');
            const auto root = module.substr(0, root_end);
            const auto local_dependency = modules.contains(module) || module.starts_with("rulepack_deps.");
            if (!local_dependency && !allowed_import_roots.contains(root)) {
                diagnostics.push_back(make_diagnostic(
                    "PY-IMPORT-AMBIENT", "ambient module '" + module + "' is not in stdlib.v1", node.span));
                return;
            }
            for (const auto *alias : index.sequence(node, "names")) {
                const auto name = index.string(*alias, "name").value_or(std::string {});
                if (name == "*") {
                    diagnostics.push_back(
                        make_diagnostic("PY-IMPORT-WILDCARD", "wildcard imports are rejected", alias->span));
                    continue;
                }
                const auto as_name = index.string(*alias, "asname").value_or(std::string {});
                auto qualified_name = module;
                qualified_name += '.';
                qualified_name += name;
                symbols.push_back(BoundSymbol {
                    .module = current_module,
                    .name = as_name.empty() ? name : as_name,
                    .qualified_name = std::move(qualified_name),
                    .kind = SymbolKind::imported,
                    .type = {.kind = StaticTypeKind::unknown, .qualified_name = "imported"},
                    .span = alias->span,
                    .public_api = false,
                    .async = false,
                    .generator = false,
                });
            }
        }

        std::vector<std::pair<std::string, StaticType>> bind_parameters(const AstIndex &index, const AstNode &function,
                                                                        const bool public_api,
                                                                        DiagnosticSet &diagnostics) {
            std::vector<std::pair<std::string, StaticType>> parameters;
            const auto *arguments = index.reference(function, "args");
            if (!arguments || arguments->kind != "arguments") {
                diagnostics.push_back(
                    make_diagnostic("PY-AST-FIELD", "function has no valid arguments node", function.span));
                return parameters;
            }
            for (const auto field : {"posonlyargs", "args", "kwonlyargs"}) {
                for (const auto *argument : index.sequence(*arguments, field)) {
                    const auto name = index.string(*argument, "arg").value_or(std::string {});
                    const auto type = annotation_type(index, index.reference(*argument, "annotation"));
                    if (public_api && type.kind == StaticTypeKind::unknown) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-ANNOTATION", "public parameter '" + name + "' requires an annotation", argument->span));
                    }
                    parameters.emplace_back(name, type);
                }
            }
            for (const auto field : {"vararg", "kwarg"}) {
                if (const auto *argument = index.reference(*arguments, field)) {
                    const auto name = index.string(*argument, "arg").value_or(std::string {});
                    const auto type = annotation_type(index, index.reference(*argument, "annotation"));
                    if (public_api && type.kind == StaticTypeKind::unknown) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-ANNOTATION", "public variadic parameter '" + name + "' requires an annotation",
                            argument->span));
                    }
                    parameters.emplace_back(name, type);
                }
            }
            return parameters;
        }

        struct ImportEdge {
            std::string target;
            SourceSpan span;
        };

        void diagnose_import_cycles(const AstEnvelope &envelope, const AstIndex &index,
                                    const std::set<std::string, std::less<>> &modules, DiagnosticSet &diagnostics) {
            std::map<std::string, std::vector<ImportEdge>, std::less<>> graph;
            for (const auto &module : envelope.modules) {
                auto &edges = graph[module.name];
                const auto *root = index.node(module.root);
                if (!root) {
                    continue;
                }
                for (const auto *statement : index.sequence(*root, "body")) {
                    if (statement->kind == "Import") {
                        for (const auto *alias : index.sequence(*statement, "names")) {
                            const auto target = index.string(*alias, "name").value_or(std::string {});
                            if (modules.contains(target)) {
                                edges.push_back(ImportEdge {.target = target, .span = alias->span});
                            }
                        }
                    } else if (statement->kind == "ImportFrom") {
                        const auto target = index.string(*statement, "module").value_or(std::string {});
                        if (modules.contains(target)) {
                            edges.push_back(ImportEdge {.target = target, .span = statement->span});
                        }
                    }
                }
                std::ranges::sort(edges, [](const ImportEdge &left, const ImportEdge &right) {
                    return std::tie(left.target, left.span.begin_byte) < std::tie(right.target, right.span.begin_byte);
                });
            }

            struct Frame {
                std::string module;
                std::size_t next_edge {};
            };
            std::map<std::string, std::uint8_t, std::less<>> colors;
            for (const auto &module : modules) {
                if (colors[module] != 0) {
                    continue;
                }
                colors[module] = 1;
                std::vector<Frame> stack {Frame {.module = module}};
                while (!stack.empty()) {
                    auto &frame = stack.back();
                    const auto &edges = graph[frame.module];
                    if (frame.next_edge == edges.size()) {
                        colors[frame.module] = 2;
                        stack.pop_back();
                        continue;
                    }
                    const auto &edge = edges[frame.next_edge++];
                    if (colors[edge.target] == 1) {
                        diagnostics.push_back(make_diagnostic("PY-IMPORT-CYCLE",
                                                              "pack-local import cycle includes '" + frame.module +
                                                                  "' and '" + edge.target + "'",
                                                              edge.span));
                        continue;
                    }
                    if (colors[edge.target] == 0) {
                        colors[edge.target] = 1;
                        stack.push_back(Frame {.module = edge.target});
                    }
                }
            }
        }

        std::vector<FunctionModel> bind_modules(const AstEnvelope &envelope, const AstIndex &index,
                                                std::vector<BoundSymbol> &symbols, DiagnosticSet &diagnostics) {
            std::vector<FunctionModel> functions;
            std::set<std::string, std::less<>> modules;
            std::set<std::string, std::less<>> declared_functions;
            std::set<std::string, std::less<>> reportable_ids;
            for (const auto &module : envelope.modules) { modules.insert(module.name); }
            diagnose_import_cycles(envelope, index, modules, diagnostics);
            for (const auto &module : envelope.modules) {
                const auto *root = index.node(module.root);
                if (!root) {
                    continue;
                }
                inspect_forbidden(index, *root, diagnostics);
                for (const auto *statement : index.sequence(*root, "body")) {
                    if (statement->kind == "Import") {
                        bind_import(index, *statement, modules, module.name, symbols, diagnostics);
                        continue;
                    }
                    if (statement->kind == "ImportFrom") {
                        bind_import_from(index, *statement, modules, module.name, symbols, diagnostics);
                        continue;
                    }
                    if (statement->kind == "Expr") {
                        const auto *value = index.reference(*statement, "value");
                        if (!value || value->kind != "Constant" || !index.string(*value, "value")) {
                            diagnostics.push_back(make_diagnostic(
                                "PY-TOPLEVEL", "module-level execution is rejected; use declarations only",
                                statement->span));
                        }
                        continue;
                    }
                    if (statement->kind != "FunctionDef" && statement->kind != "AsyncFunctionDef") {
                        diagnostics.push_back(make_diagnostic("PY-TOPLEVEL",
                                                              "top-level " + statement->kind +
                                                                  " is not implemented in this compiler slice",
                                                              statement->span));
                        continue;
                    }

                    const auto name = index.string(*statement, "name").value_or(std::string {});
                    const auto decorator = decorator_info(index, *statement, diagnostics);
                    const auto public_api = decorator.reportable;
                    const auto return_type = annotation_type(index, index.reference(*statement, "returns"));
                    if (public_api && return_type.kind == StaticTypeKind::unknown) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-ANNOTATION", "reportable function requires an explicit bool return annotation",
                            statement->span));
                    } else if (public_api && return_type.kind != StaticTypeKind::boolean) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-TYPE-RETURN", "reportable function return annotation must be bool", statement->span));
                    }
                    auto parameters = bind_parameters(index, *statement, public_api, diagnostics);
                    const auto is_async = statement->kind == "AsyncFunctionDef";
                    const auto has_yield =
                        std::ranges::any_of(index.sequence(*statement, "body"), [&](const AstNode *body) {
                            return contains_kind(index, *body, "Yield") || contains_kind(index, *body, "YieldFrom");
                        });
                    if (public_api && has_yield) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-TYPE-RETURN", "reportable bool entrypoint cannot be a generator", statement->span));
                    }

                    const auto qualified_name = module.name + "." + name;
                    const auto executable = ExecutableId {decorator.reportable ? decorator.stable_id : qualified_name};
                    if (name.empty() || !declared_functions.insert(qualified_name).second) {
                        diagnostics.push_back(make_diagnostic("PY-SYMBOL-DUPLICATE",
                                                              name.empty() ? "function name cannot be empty" :
                                                                             "function '" + qualified_name +
                                                                                 "' is declared more than once",
                                                              statement->span));
                    }
                    if (decorator.reportable && !reportable_ids.insert(executable.value).second) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-ID-DUPLICATE", "reportable stable ID '" + executable.value + "' is not unique",
                            statement->span));
                    }
                    functions.push_back(FunctionModel {
                        .module = module.name,
                        .name = name,
                        .qualified_name = qualified_name,
                        .executable = executable,
                        .symbol_kind = decorator.kind,
                        .span = statement->span,
                        .node = statement,
                        .parameters = std::move(parameters),
                        .return_type = return_type,
                        .public_api = public_api,
                        .async = is_async,
                        .generator = has_yield,
                    });
                    symbols.push_back(BoundSymbol {
                        .module = module.name,
                        .name = name,
                        .qualified_name = qualified_name,
                        .kind = decorator.kind,
                        .type = {.kind = StaticTypeKind::callable, .qualified_name = qualified_name},
                        .span = statement->span,
                        .public_api = public_api,
                        .async = is_async,
                        .generator = has_yield,
                    });
                }
            }
            std::ranges::sort(functions, {}, &FunctionModel::qualified_name);
            std::ranges::sort(symbols, [](const BoundSymbol &left, const BoundSymbol &right) {
                return std::tie(left.module, left.span.begin_byte, left.name) <
                       std::tie(right.module, right.span.begin_byte, right.name);
            });
            return functions;
        }

        std::string hexadecimal(const std::uint64_t value) {
            constexpr std::string_view digits = "0123456789abcdef";
            std::array<char, 16> result {};
            auto remaining = value;
            for (auto index = result.size(); index > 0; --index) {
                result[index - 1] = digits[remaining & 0xfU];
                remaining >>= 4U;
            }
            return std::string {result.data(), result.size()};
        }

        std::string stable_digest(const std::string_view canonical) {
            std::uint64_t value = 1469598103934665603ULL;
            for (const auto character : canonical) {
                value ^= static_cast<unsigned char>(character);
                value *= 1099511628211ULL;
            }
            return "fnv1a64:" + hexadecimal(value);
        }

        void canonical_token(std::ostringstream &output, const std::string_view value) {
            output << value.size() << ':' << value << ';';
        }

        void canonical_fact(std::ostringstream &output, const FactValue &fact) {
            if (!fact.valid()) {
                output << "invalid;";
                return;
            }
            std::visit(
                [&output](const auto &value) {
                    using Value = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::is_same_v<Value, std::monostate>) {
                        output << "none;";
                    } else if constexpr (std::is_same_v<Value, bool>) {
                        output << "bool:" << value << ';';
                    } else if constexpr (std::is_same_v<Value, IntegerValue>) {
                        output << "int:";
                        canonical_token(output, value.decimal);
                    } else if constexpr (std::is_same_v<Value, double>) {
                        output << "float:" << hexadecimal(std::bit_cast<std::uint64_t>(value)) << ';';
                    } else if constexpr (std::is_same_v<Value, UnicodeValue>) {
                        output << "unicode:";
                        canonical_token(output, value.utf8);
                    } else if constexpr (std::is_same_v<Value, BytesValue>) {
                        output << "bytes:" << value.bytes.size() << ':';
                        for (const auto byte : value.bytes) {
                            output << hexadecimal(std::to_integer<std::uint8_t>(byte)).substr(14);
                        }
                        output << ';';
                    } else if constexpr (std::is_same_v<Value, EnumValue>) {
                        output << "enum:";
                        canonical_token(output, value.schema.value);
                        canonical_token(output, value.member);
                    } else if constexpr (std::is_same_v<Value, FactList>) {
                        output << "list:" << value.items.size() << '{';
                        for (const auto &item : value.items) { canonical_fact(output, item); }
                        output << "};";
                    } else if constexpr (std::is_same_v<Value, FactMap>) {
                        output << "map:" << value.entries.size() << '{';
                        for (const auto &entry : value.entries) {
                            canonical_fact(output, entry.key);
                            canonical_fact(output, entry.value);
                        }
                        output << "};";
                    } else if constexpr (std::is_same_v<Value, FactRecord>) {
                        output << "record:";
                        canonical_token(output, value.schema.value);
                        output << value.fields.size() << '{';
                        for (const auto &field : value.fields) {
                            output << field.field_id << ':';
                            canonical_fact(output, field.value);
                        }
                        output << "};";
                    }
                },
                fact.node->data);
        }

        SchemaCatalog normalize_schemas(SchemaCatalog schemas) {
            for (auto &descriptor : schemas.descriptors) {
                for (auto &field : descriptor.fields) {
                    std::ranges::sort(field.label.categories);
                    field.label.categories.erase(std::ranges::unique(field.label.categories).begin(),
                                                 field.label.categories.end());
                }
                std::ranges::sort(descriptor.fields, [](const SchemaField &left, const SchemaField &right) {
                    return std::tie(left.field_id, left.name) < std::tie(right.field_id, right.name);
                });
            }
            std::ranges::sort(schemas.descriptors, [](const SchemaDescriptor &left, const SchemaDescriptor &right) {
                return std::tie(left.id.value, left.qualified_name) < std::tie(right.id.value, right.qualified_name);
            });
            return schemas;
        }

        OperatorBindings normalize_bindings(OperatorBindings bindings) {
            for (auto &binding : bindings) {
                std::ranges::sort(binding.capabilities, {}, &CapabilityId::value);
                binding.capabilities.erase(std::ranges::unique(binding.capabilities).begin(),
                                           binding.capabilities.end());
            }
            std::ranges::sort(bindings, [](const OperatorBinding &left, const OperatorBinding &right) {
                return std::tie(left.id.value, left.executable.value) <
                       std::tie(right.id.value, right.executable.value);
            });
            return bindings;
        }

        enum struct UnaryCode : std::uint32_t { logical_not, positive, negative, invert };
        enum struct BinaryCode : std::uint32_t {
            add,
            subtract,
            multiply,
            true_divide,
            floor_divide,
            modulo,
            power,
            left_shift,
            right_shift,
            bit_or,
            bit_xor,
            bit_and,
        };
        enum struct CompareCode : std::uint32_t {
            equal,
            not_equal,
            less,
            less_equal,
            greater,
            greater_equal,
            is_value,
            is_not,
            contains,
            not_contains,
        };

        struct ExpressionResult {
            std::uint32_t reg {};
            StaticType type;
        };

        struct Lowerer {
            const AstIndex &index;
            const FunctionModel &function;
            CompiledPack &pack;
            std::vector<FactRequirement> &requirements;
            DiagnosticSet &diagnostics;
            BytecodeFunction bytecode;
            std::map<std::string, ExpressionResult, std::less<>> locals;
            std::uint32_t conditional_depth {};
            bool may_fault {};

            Lowerer(const AstIndex &index_value, const FunctionModel &function_value, CompiledPack &pack_value,
                    std::vector<FactRequirement> &requirements_value, DiagnosticSet &diagnostics_value):
                index {index_value},
                function {function_value},
                pack {pack_value},
                requirements {requirements_value},
                diagnostics {diagnostics_value},
                bytecode {.id = function.executable,
                          .qualified_name = function.qualified_name,
                          .register_count = static_cast<std::uint32_t>(function.parameters.size()),
                          .parameter_count = static_cast<std::uint32_t>(function.parameters.size()),
                          .generator = function.generator,
                          .async = function.async,
                          .instructions = {},
                          .exception_regions = {}} {
                for (std::size_t position = 0; position < function.parameters.size(); ++position) {
                    locals.emplace(function.parameters[position].first,
                                   ExpressionResult {.reg = static_cast<std::uint32_t>(position),
                                                     .type = function.parameters[position].second});
                }
            }

            std::uint32_t allocate() { return bytecode.register_count++; }

            void emit(const Opcode opcode, const std::uint32_t destination, const std::uint32_t operand_a,
                      const std::uint32_t operand_b, const std::uint32_t immediate, const SourceSpan &span) {
                bytecode.instructions.push_back(Instruction {
                    .opcode = opcode,
                    .destination = destination,
                    .operand_a = operand_a,
                    .operand_b = operand_b,
                    .immediate = immediate,
                    .span = span,
                });
            }

            std::optional<ExpressionResult> constant(const AstNode &node) {
                const auto *field = index.field(node, "value");
                if (!field) {
                    diagnostics.push_back(make_diagnostic("PY-AST-FIELD", "Constant is missing value", node.span));
                    return std::nullopt;
                }
                FactData data;
                StaticType type;
                if (std::holds_alternative<std::monostate>(field->value.data)) {
                    data = std::monostate {};
                    type = {.kind = StaticTypeKind::none, .qualified_name = "None"};
                } else if (const auto *bool_value = std::get_if<bool>(&field->value.data)) {
                    data = *bool_value;
                    type = {.kind = StaticTypeKind::boolean, .qualified_name = "bool"};
                } else if (const auto *integer_value = std::get_if<IntegerValue>(&field->value.data)) {
                    data = *integer_value;
                    type = {.kind = StaticTypeKind::integer, .qualified_name = "int"};
                } else if (const auto *float_value = std::get_if<AstFloatBits>(&field->value.data)) {
                    data = std::bit_cast<double>(float_value->bits);
                    type = {.kind = StaticTypeKind::floating, .qualified_name = "float"};
                } else if (const auto *unicode_value = std::get_if<UnicodeValue>(&field->value.data)) {
                    data = *unicode_value;
                    type = {.kind = StaticTypeKind::string, .qualified_name = "str"};
                } else if (const auto *bytes_value = std::get_if<BytesValue>(&field->value.data)) {
                    data = *bytes_value;
                    type = {.kind = StaticTypeKind::bytes, .qualified_name = "bytes"};
                } else {
                    diagnostics.push_back(
                        make_diagnostic("PY-TYPE-CONSTANT", "unsupported Constant payload", node.span));
                    return std::nullopt;
                }
                const auto constant_index = static_cast<std::uint32_t>(pack.constants.size());
                pack.constants.push_back(make_fact(std::move(data)));
                const auto destination = allocate();
                emit(Opcode::load_const, destination, 0, 0, constant_index, node.span);
                return ExpressionResult {.reg = destination, .type = std::move(type)};
            }

            std::optional<ExpressionResult> expression(const AstNode &node) {
                if (node.kind == "Constant") {
                    return constant(node);
                }
                if (node.kind == "Name") {
                    const auto name = index.string(node, "id").value_or(std::string {});
                    const auto found = locals.find(name);
                    if (found == locals.end()) {
                        diagnostics.push_back(
                            make_diagnostic("PY-NAME", "name '" + name + "' is not bound", node.span));
                        return std::nullopt;
                    }
                    return found->second;
                }
                if (node.kind == "Attribute") {
                    const auto path = attribute_path(index, node);
                    if (!path) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-ATTRIBUTE", "attribute target must be statically resolvable", node.span));
                        return std::nullopt;
                    }
                    const auto separator = path->find('.');
                    const auto parameter = path->substr(0, separator);
                    if (!locals.contains(parameter)) {
                        diagnostics.push_back(
                            make_diagnostic("PY-ATTRIBUTE", "attribute root is not a bound parameter", node.span));
                        return std::nullopt;
                    }
                    const auto destination = allocate();
                    const auto fact_index = static_cast<std::uint32_t>(requirements.size());
                    requirements.push_back(FactRequirement {
                        .executable = function.executable,
                        .parameter = parameter,
                        .attribute_path = *path,
                        .route = *path,
                        .span = node.span,
                        .conditional = conditional_depth != 0,
                    });
                    emit(Opcode::await_fact, destination, locals.at(parameter).reg, 0, fact_index, node.span);
                    may_fault = true;
                    const auto last = path->substr(path->find_last_of('.') + 1);
                    const auto type = last.starts_with("is_") || last.starts_with("has_") ?
                                          StaticType {.kind = StaticTypeKind::boolean, .qualified_name = "bool"} :
                                          StaticType {.kind = StaticTypeKind::unknown, .qualified_name = "Any"};
                    return ExpressionResult {.reg = destination, .type = type};
                }
                if (node.kind == "UnaryOp") {
                    const auto *operand_node = index.reference(node, "operand");
                    const auto operation =
                        index.string(node, "op")
                            .value_or(index.reference(node, "op") ? index.reference(node, "op")->kind : std::string {});
                    if (!operand_node) {
                        diagnostics.push_back(make_diagnostic("PY-AST-FIELD", "UnaryOp has no operand", node.span));
                        return std::nullopt;
                    }
                    const auto operand = expression(*operand_node);
                    if (!operand) {
                        return std::nullopt;
                    }
                    UnaryCode code {};
                    StaticType result_type = operand->type;
                    if (operation == "Not") {
                        code = UnaryCode::logical_not;
                        result_type = {.kind = StaticTypeKind::boolean, .qualified_name = "bool"};
                    } else if (operation == "UAdd") {
                        code = UnaryCode::positive;
                    } else if (operation == "USub") {
                        code = UnaryCode::negative;
                    } else if (operation == "Invert") {
                        code = UnaryCode::invert;
                    } else {
                        diagnostics.push_back(make_diagnostic(
                            "PY-UNSUPPORTED", "unary operator '" + operation + "' is not supported", node.span));
                        return std::nullopt;
                    }
                    const auto destination = allocate();
                    emit(Opcode::unary_op, destination, operand->reg, 0, static_cast<std::uint32_t>(code), node.span);
                    may_fault = true;
                    return ExpressionResult {.reg = destination, .type = std::move(result_type)};
                }
                if (node.kind == "BinOp") {
                    const auto *left_node = index.reference(node, "left");
                    const auto *right_node = index.reference(node, "right");
                    const auto operation =
                        index.string(node, "op")
                            .value_or(index.reference(node, "op") ? index.reference(node, "op")->kind : std::string {});
                    if (!left_node || !right_node) {
                        diagnostics.push_back(
                            make_diagnostic("PY-AST-FIELD", "BinOp is missing an operand", node.span));
                        return std::nullopt;
                    }
                    const auto left = expression(*left_node);
                    const auto right = expression(*right_node);
                    if (!left || !right) {
                        return std::nullopt;
                    }
                    static const std::map<std::string, BinaryCode, std::less<>> codes {
                        {"Add", BinaryCode::add},
                        {"BitAnd", BinaryCode::bit_and},
                        {"BitOr", BinaryCode::bit_or},
                        {"BitXor", BinaryCode::bit_xor},
                        {"Div", BinaryCode::true_divide},
                        {"FloorDiv", BinaryCode::floor_divide},
                        {"LShift", BinaryCode::left_shift},
                        {"Mod", BinaryCode::modulo},
                        {"Mult", BinaryCode::multiply},
                        {"Pow", BinaryCode::power},
                        {"RShift", BinaryCode::right_shift},
                        {"Sub", BinaryCode::subtract},
                    };
                    const auto code = codes.find(operation);
                    if (code == codes.end()) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-UNSUPPORTED", "binary operator '" + operation + "' is not supported", node.span));
                        return std::nullopt;
                    }
                    StaticType result_type = left->type;
                    if (operation == "Div" || left->type.kind == StaticTypeKind::floating ||
                        right->type.kind == StaticTypeKind::floating) {
                        result_type = {.kind = StaticTypeKind::floating, .qualified_name = "float"};
                    } else if (left->type.kind != right->type.kind) {
                        diagnostics.push_back(
                            make_diagnostic("PY-TYPE", "binary operands have incompatible static types", node.span));
                        return std::nullopt;
                    }
                    const auto destination = allocate();
                    emit(Opcode::binary_op, destination, left->reg, right->reg,
                         static_cast<std::uint32_t>(code->second), node.span);
                    may_fault = true;
                    return ExpressionResult {.reg = destination, .type = std::move(result_type)};
                }
                if (node.kind == "Compare") {
                    const auto *left_node = index.reference(node, "left");
                    const auto comparators = index.sequence(node, "comparators");
                    const auto operations = index.string_sequence(node, "ops");
                    if (!left_node || comparators.size() != 1 || operations.size() != 1) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-NYI-COMPARE", "chained comparisons are represented but not lowered yet", node.span));
                        return std::nullopt;
                    }
                    const auto left = expression(*left_node);
                    const auto right = expression(*comparators.front());
                    if (!left || !right) {
                        return std::nullopt;
                    }
                    static const std::map<std::string, CompareCode, std::less<>> codes {
                        {"Eq", CompareCode::equal},          {"Gt", CompareCode::greater},
                        {"GtE", CompareCode::greater_equal}, {"In", CompareCode::contains},
                        {"Is", CompareCode::is_value},       {"IsNot", CompareCode::is_not},
                        {"Lt", CompareCode::less},           {"LtE", CompareCode::less_equal},
                        {"NotEq", CompareCode::not_equal},   {"NotIn", CompareCode::not_contains},
                    };
                    const auto code = codes.find(operations.front());
                    if (code == codes.end()) {
                        diagnostics.push_back(
                            make_diagnostic("PY-UNSUPPORTED", "comparison operator is unsupported", node.span));
                        return std::nullopt;
                    }
                    const auto destination = allocate();
                    emit(Opcode::compare, destination, left->reg, right->reg, static_cast<std::uint32_t>(code->second),
                         node.span);
                    may_fault = true;
                    return ExpressionResult {
                        .reg = destination,
                        .type = {.kind = StaticTypeKind::boolean, .qualified_name = "bool"},
                    };
                }
                if (node.kind == "BoolOp") {
                    const auto values = index.sequence(node, "values");
                    const auto operation =
                        index.string(node, "op")
                            .value_or(index.reference(node, "op") ? index.reference(node, "op")->kind : std::string {});
                    if (values.size() < 2 || (operation != "And" && operation != "Or")) {
                        diagnostics.push_back(
                            make_diagnostic("PY-AST-FIELD", "BoolOp must contain And/Or values", node.span));
                        return std::nullopt;
                    }
                    const auto first = expression(*values.front());
                    if (!first) {
                        return std::nullopt;
                    }
                    const auto result = allocate();
                    emit(Opcode::move, result, first->reg, 0, 0, values.front()->span);
                    std::vector<std::size_t> exits;
                    for (std::size_t position = 1; position < values.size(); ++position) {
                        auto condition = result;
                        if (operation == "Or") {
                            condition = allocate();
                            emit(Opcode::unary_op, condition, result, 0,
                                 static_cast<std::uint32_t>(UnaryCode::logical_not), values[position - 1]->span);
                        }
                        exits.push_back(bytecode.instructions.size());
                        emit(Opcode::jump_if_false, condition, condition, 0, 0, values[position - 1]->span);
                        ++conditional_depth;
                        const auto next = expression(*values[position]);
                        --conditional_depth;
                        if (!next) {
                            return std::nullopt;
                        }
                        emit(Opcode::move, result, next->reg, 0, 0, values[position]->span);
                    }
                    const auto exit = static_cast<std::uint32_t>(bytecode.instructions.size());
                    for (const auto instruction : exits) { bytecode.instructions[instruction].immediate = exit; }
                    return ExpressionResult {
                        .reg = result,
                        .type = {.kind = StaticTypeKind::boolean, .qualified_name = "bool"},
                    };
                }
                if (node.kind == "Await") {
                    diagnostics.push_back(make_diagnostic(
                        "PY-NYI-ASYNC-LOWERING",
                        "async declaration is supported, but this await expression is not lowered yet", node.span));
                    return std::nullopt;
                }
                if (node.kind == "Yield" || node.kind == "YieldFrom") {
                    diagnostics.push_back(make_diagnostic(
                        "PY-NYI-GENERATOR-LOWERING",
                        "generator declaration is supported, but this yield form is not lowered yet", node.span));
                    return std::nullopt;
                }
                if (node.kind == "Call") {
                    const auto *target = index.reference(node, "func");
                    const auto name = target ? root_name(index, *target) : std::string {};
                    if (forbidden_calls.contains(name)) {
                        return std::nullopt;
                    }
                    diagnostics.push_back(make_diagnostic(
                        "PY-NYI-CALL-LOWERING", "statically bound call '" + name + "' is not lowered yet", node.span));
                    return std::nullopt;
                }
                diagnostics.push_back(make_diagnostic(
                    "PY-NYI-LOWERING", "AST expression '" + node.kind + "' is represented but not lowered yet",
                    node.span));
                return std::nullopt;
            }

            bool statements(const std::vector<const AstNode *> &body) {
                bool terminated {};
                for (const auto *statement : body) {
                    if (terminated) {
                        continue;
                    }
                    if (statement->kind == "Pass") {
                        continue;
                    }
                    if (statement->kind == "Expr") {
                        const auto *value = index.reference(*statement, "value");
                        if (value && value->kind == "Constant" && index.string(*value, "value")) {
                            continue;
                        }
                        if (value) {
                            static_cast<void>(expression(*value));
                        }
                        continue;
                    }
                    if (statement->kind == "Assign") {
                        const auto targets = index.sequence(*statement, "targets");
                        const auto *value = index.reference(*statement, "value");
                        if (targets.size() != 1 || targets.front()->kind != "Name" || !value) {
                            diagnostics.push_back(make_diagnostic(
                                "PY-NYI-ASSIGNMENT", "only one local-name assignment is lowered yet", statement->span));
                            continue;
                        }
                        const auto result = expression(*value);
                        if (result) {
                            locals[index.string(*targets.front(), "id").value_or(std::string {})] = *result;
                        }
                        continue;
                    }
                    if (statement->kind == "Return") {
                        const auto *value = index.reference(*statement, "value");
                        std::optional<ExpressionResult> result;
                        if (value) {
                            result = expression(*value);
                        } else {
                            AstNode synthetic {
                                .id = 0,
                                .kind = "Constant",
                                .span = statement->span,
                                .fields = {AstField {.name = "value", .value = ast_none()}},
                            };
                            result = constant(synthetic);
                        }
                        if (!result) {
                            continue;
                        }
                        if (function.public_api && result->type.kind != StaticTypeKind::boolean) {
                            diagnostics.push_back(make_diagnostic("PY-TYPE-RETURN",
                                                                  "reportable function must return bool on every path",
                                                                  statement->span));
                        }
                        emit(Opcode::return_value, result->reg, result->reg, 0, 0, statement->span);
                        terminated = true;
                        continue;
                    }
                    if (statement->kind == "If") {
                        const auto *test = index.reference(*statement, "test");
                        if (!test) {
                            diagnostics.push_back(
                                make_diagnostic("PY-AST-FIELD", "If is missing test", statement->span));
                            continue;
                        }
                        const auto condition = expression(*test);
                        if (!condition) {
                            continue;
                        }
                        const auto false_jump = bytecode.instructions.size();
                        emit(Opcode::jump_if_false, condition->reg, condition->reg, 0, 0, test->span);
                        ++conditional_depth;
                        const auto body_terminated = statements(index.sequence(*statement, "body"));
                        --conditional_depth;
                        std::optional<std::size_t> end_jump;
                        if (!body_terminated) {
                            end_jump = bytecode.instructions.size();
                            emit(Opcode::jump, 0, 0, 0, 0, statement->span);
                        }
                        bytecode.instructions[false_jump].immediate =
                            static_cast<std::uint32_t>(bytecode.instructions.size());
                        ++conditional_depth;
                        const auto else_terminated = statements(index.sequence(*statement, "orelse"));
                        --conditional_depth;
                        if (end_jump) {
                            bytecode.instructions[*end_jump].immediate =
                                static_cast<std::uint32_t>(bytecode.instructions.size());
                        }
                        terminated = body_terminated && else_terminated;
                        continue;
                    }
                    diagnostics.push_back(make_diagnostic(
                        statement->kind == "AsyncFor" || statement->kind == "AsyncWith" ? "PY-NYI-ASYNC-LOWERING" :
                                                                                          "PY-NYI-STATEMENT-LOWERING",
                        "statement '" + statement->kind + "' is represented but not lowered yet", statement->span));
                }
                return terminated;
            }

            BytecodeFunction lower() {
                const auto terminated = statements(index.sequence(*function.node, "body"));
                if (!terminated) {
                    if (function.public_api) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-TYPE-RETURN", "reportable function does not return bool on every path", function.span));
                    } else {
                        AstNode synthetic {
                            .id = 0,
                            .kind = "Constant",
                            .span = function.span,
                            .fields = {AstField {.name = "value", .value = ast_none()}},
                        };
                        if (const auto result = constant(synthetic)) {
                            emit(Opcode::return_value, result->reg, result->reg, 0, 0, function.span);
                        }
                    }
                }
                return std::move(bytecode);
            }
        };

        std::string canonicalize(const CompiledPack &pack, const std::vector<BoundSymbol> &symbols,
                                 const std::vector<FactRequirement> &requirements) {
            std::ostringstream output;
            output.imbue(std::locale::classic());
            output << "python-static-compiler-v1\n";
            canonical_token(output, pack.pack.value);
            canonical_token(output, pack.version.value);
            canonical_token(output, pack.source_digest.value);
            canonical_token(output, pack.compiler_abi);
            canonical_token(output, pack.schemas.canonical_hash);
            output << '\n';
            for (const auto &descriptor : pack.schemas.descriptors) {
                output << "schema|";
                canonical_token(output, descriptor.id.value);
                output << static_cast<unsigned int>(descriptor.kind) << '|';
                canonical_token(output, descriptor.qualified_name);
                canonical_token(output, descriptor.canonical_hash);
                for (const auto &field : descriptor.fields) {
                    output << field.field_id << '|';
                    canonical_token(output, field.name);
                    canonical_token(output, field.type.value);
                    output << field.optional << '|' << static_cast<unsigned int>(field.label.classification) << '|';
                    for (const auto &category : field.label.categories) { canonical_token(output, category); }
                    output << '\n';
                }
            }
            for (const auto &constant : pack.constants) {
                output << "constant|";
                canonical_fact(output, constant);
                output << '\n';
            }
            for (const auto &symbol : symbols) {
                output << "symbol|" << symbol.qualified_name << '|' << static_cast<unsigned int>(symbol.kind) << '|'
                       << symbol.span.source.value << ':' << symbol.span.begin_byte << ':' << symbol.span.end_byte
                       << '\n';
            }
            for (const auto &function : pack.functions) {
                output << "function|" << function.id.value << '|' << function.qualified_name << '|'
                       << function.register_count << '|' << function.parameter_count << '|' << function.generator << '|'
                       << function.async << '\n';
                for (const auto &instruction : function.instructions) {
                    output << static_cast<unsigned int>(instruction.opcode) << ':' << instruction.destination << ':'
                           << instruction.operand_a << ':' << instruction.operand_b << ':' << instruction.immediate
                           << ':' << instruction.span.source.value << ':' << instruction.span.begin_byte << ':'
                           << instruction.span.end_byte << '\n';
                }
            }
            for (const auto &requirement : requirements) {
                output << "fact|" << requirement.executable.value << '|' << requirement.attribute_path << '|'
                       << requirement.route << '|' << requirement.conditional << '\n';
            }
            for (const auto &binding : pack.bindings) {
                output << "binding|";
                canonical_token(output, binding.id.value);
                canonical_token(output, binding.executable.value);
                canonical_token(output, binding.budget.name);
                for (const auto &capability : binding.capabilities) { canonical_token(output, capability.value); }
                output << '\n';
            }
            return std::move(output).str();
        }

    } // namespace

    std::expected<CompilationArtifact, DiagnosticSet>
    StaticCompiler::compile(const VerifiedRulePack &pack, const std::span<const std::byte> ast_payload,
                            const SchemaCatalog &schemas, const OperatorBindings &bindings) const {
        auto decoded = decode_ast_envelope(ast_payload, pack);
        if (!decoded) {
            return std::unexpected(std::move(decoded.error()));
        }

        const AstIndex index {*decoded};
        DiagnosticSet diagnostics;
        std::vector<BoundSymbol> symbols;
        const auto functions = bind_modules(*decoded, index, symbols, diagnostics);
        if (!diagnostics.empty()) {
            sort_diagnostics(diagnostics);
            return std::unexpected(std::move(diagnostics));
        }

        CompiledPack compiled {
            .pack = pack.manifest.pack,
            .version = pack.manifest.version,
            .source_digest = pack.closure_digest,
            .compiler_abi = "python-3.14.6/static-compiler-v1",
            .semantic_hash = {},
            .schemas = normalize_schemas(schemas),
            .constants = {},
            .functions = {},
            .bindings = normalize_bindings(bindings),
            .optimization_certificates = {},
        };
        std::vector<FactRequirement> requirements;
        for (const auto &function : functions) {
            Lowerer lowerer {index, function, compiled, requirements, diagnostics};
            auto bytecode = lowerer.lower();
            std::vector<std::string> logical_facts;
            for (const auto &requirement : requirements) {
                if (requirement.executable == function.executable) {
                    logical_facts.push_back(requirement.route);
                }
            }
            std::ranges::sort(logical_facts);
            logical_facts.erase(std::ranges::unique(logical_facts).begin(), logical_facts.end());
            const auto trivially_pure =
                !lowerer.may_fault && logical_facts.empty() &&
                std::ranges::all_of(bytecode.instructions, [](const Instruction &instruction) {
                    return instruction.opcode == Opcode::load_const || instruction.opcode == Opcode::return_value;
                });
            compiled.functions.push_back(std::move(bytecode));
            compiled.optimization_certificates.push_back(OptimizationCertificate {
                .executable = function.executable,
                .transitively_pure = trivially_pure,
                .recorder_observable = !trivially_pure,
                .may_fault = lowerer.may_fault,
                .reads_state = false,
                .reads_history = false,
                .calls_services = false,
                .emits_effects = false,
                .logical_facts = std::move(logical_facts),
                .pure_false_prefix_exits = {},
                .semantic_hash = {},
            });
        }
        if (!diagnostics.empty()) {
            sort_diagnostics(diagnostics);
            return std::unexpected(std::move(diagnostics));
        }

        auto artifact = CompilationArtifact {
            .pack = std::move(compiled),
            .symbols = std::move(symbols),
            .fact_requirements = std::move(requirements),
            .canonical_form = {},
        };
        std::ranges::sort(artifact.fact_requirements, [](const FactRequirement &left, const FactRequirement &right) {
            return std::tie(left.executable.value, left.span.source.value, left.span.begin_byte, left.attribute_path) <
                   std::tie(right.executable.value, right.span.source.value, right.span.begin_byte,
                            right.attribute_path);
        });
        artifact.canonical_form = canonicalize(artifact.pack, artifact.symbols, artifact.fact_requirements);
        artifact.pack.semantic_hash = stable_digest(artifact.canonical_form);
        for (auto &certificate : artifact.pack.optimization_certificates) {
            certificate.semantic_hash = stable_digest(artifact.pack.semantic_hash + "|" + certificate.executable.value);
            if (certificate.transitively_pure && artifact.pack.functions.size() == 1 &&
                artifact.pack.constants.size() == 1 &&
                std::holds_alternative<bool>(artifact.pack.constants.front().node->data) &&
                !std::get<bool>(artifact.pack.constants.front().node->data)) {
                certificate.pure_false_prefix_exits.push_back(1);
            }
        }

        auto verified = verify_compiler_output(artifact);
        if (!verified) {
            return std::unexpected(std::move(verified.error()));
        }
        return artifact;
    }

    std::expected<CompiledPack, DiagnosticSet> StaticPackCompiler::compile(const VerifiedRulePack &pack,
                                                                           const SchemaCatalog &schemas,
                                                                           const OperatorBindings &bindings) {
        auto payload = provider_.load(pack);
        if (!payload) {
            return std::unexpected(std::move(payload.error()));
        }
        auto artifact = compiler_.compile(pack, *payload, schemas, bindings);
        if (!artifact) {
            return std::unexpected(std::move(artifact.error()));
        }
        return std::move(artifact->pack);
    }

    std::expected<void, DiagnosticSet> verify_compiler_output(const CompilationArtifact &artifact) {
        auto verified = verify_bytecode(artifact.pack);
        if (!verified) {
            return std::unexpected(std::move(verified.error()));
        }

        DiagnosticSet diagnostics;
        std::set<std::string, std::less<>> certificates;
        for (const auto &certificate : artifact.pack.optimization_certificates) {
            if (!certificates.insert(certificate.executable.value).second) {
                diagnostics.push_back(
                    make_diagnostic("PYC-CERTIFICATE", "executable has duplicate optimizer certificates"));
            }
        }
        for (const auto &function : artifact.pack.functions) {
            if (!certificates.contains(function.id.value)) {
                diagnostics.push_back(make_diagnostic(
                    "PYC-CERTIFICATE", "executable has no optimizer certificate",
                    function.instructions.empty() ? std::nullopt : std::optional {function.instructions.front().span}));
            }
            for (const auto &instruction : function.instructions) {
                const auto in_register_range = [&](const std::uint32_t value) {
                    return value < function.register_count;
                };
                if (instruction.opcode == Opcode::load_const &&
                    instruction.immediate >= artifact.pack.constants.size()) {
                    diagnostics.push_back(
                        make_diagnostic("PYC-CONSTANT", "load_const index is out of range", instruction.span));
                }
                if ((instruction.opcode == Opcode::move || instruction.opcode == Opcode::unary_op ||
                     instruction.opcode == Opcode::jump_if_false || instruction.opcode == Opcode::return_value) &&
                    !in_register_range(instruction.operand_a)) {
                    diagnostics.push_back(make_diagnostic("PYC-OPERAND", "bytecode operand_a register is out of range",
                                                          instruction.span));
                }
                if ((instruction.opcode == Opcode::binary_op || instruction.opcode == Opcode::compare) &&
                    (!in_register_range(instruction.operand_a) || !in_register_range(instruction.operand_b))) {
                    diagnostics.push_back(
                        make_diagnostic("PYC-OPERAND", "bytecode operand register is out of range", instruction.span));
                }
            }
        }
        for (const auto &requirement : artifact.fact_requirements) {
            const auto certificate = std::ranges::find(artifact.pack.optimization_certificates, requirement.executable,
                                                       &OptimizationCertificate::executable);
            if (certificate == artifact.pack.optimization_certificates.end() ||
                std::ranges::find(certificate->logical_facts, requirement.route) == certificate->logical_facts.end()) {
                diagnostics.push_back(make_diagnostic("PYC-FACT-CERTIFICATE",
                                                      "fact requirement is absent from its optimizer certificate",
                                                      requirement.span));
            }
        }
        if (!diagnostics.empty()) {
            sort_diagnostics(diagnostics);
            return std::unexpected(std::move(diagnostics));
        }
        return {};
    }

} // namespace rule_engine::python::compiler
