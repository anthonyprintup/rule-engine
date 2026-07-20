#include "rule_engine/python/compiler/frontend.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <deque>
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
            if (annotation->kind == "Constant") {
                const auto *value = index.field(*annotation, "value");
                if (value != nullptr && std::holds_alternative<std::monostate>(value->value.data)) {
                    return {.kind = StaticTypeKind::none, .qualified_name = "None"};
                }
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
            if (annotation->kind == "Attribute") {
                const auto name = attribute_path(index, *annotation).value_or(std::string {});
                return name.empty() ? StaticType {} :
                                      StaticType {.kind = StaticTypeKind::model, .qualified_name = name};
            }
            if (annotation->kind == "Subscript") {
                const auto *base = index.reference(*annotation, "value");
                const auto *argument = index.reference(*annotation, "slice");
                const auto name = base == nullptr ? std::string {} : root_name(index, *base);
                const auto nested = annotation_type(index, argument);
                if (name == "Identity" || name == "Public" || name == "Internal" || name == "Sensitive" ||
                    name == "Secret" || name == "Final" || name == "ClassVar") {
                    return nested;
                }
                if (name == "list") {
                    return {.kind = StaticTypeKind::list, .qualified_name = "list[" + nested.qualified_name + "]"};
                }
                if (name == "dict") {
                    return {.kind = StaticTypeKind::dictionary, .qualified_name = "dict"};
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

        std::string stable_digest(std::string_view canonical);
        SchemaId schema_for_type(const StaticType &type);

        [[nodiscard]] Classification annotation_classification(const AstIndex &index, const AstNode *annotation) {
            if (annotation == nullptr || annotation->kind != "Subscript") {
                return Classification::internal;
            }
            const auto *base = index.reference(*annotation, "value");
            const auto name = base == nullptr ? std::string {} : root_name(index, *base);
            if (name == "Public") {
                return Classification::public_data;
            }
            if (name == "Sensitive") {
                return Classification::sensitive;
            }
            if (name == "Secret") {
                return Classification::secret;
            }
            return Classification::internal;
        }

        [[nodiscard]] bool valid_provider_route(const std::string_view route) {
            if (route.empty() || route.front() == '.' || route.back() == '.') {
                return false;
            }
            bool segment_start {true};
            for (const auto character : route) {
                if (character == '.') {
                    if (segment_start) {
                        return false;
                    }
                    segment_start = true;
                    continue;
                }
                const auto alpha = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z');
                const auto digit = character >= '0' && character <= '9';
                if ((!alpha && character != '_' && (!digit || segment_start))) {
                    return false;
                }
                segment_start = false;
            }
            return !segment_start;
        }

        void bind_model(const AstIndex &index, const AstNode &node, const std::string &module,
                        std::vector<BoundSymbol> &symbols, SchemaCatalog &generated_schemas,
                        DiagnosticSet &diagnostics) {
            const auto name = index.string(node, "name").value_or(std::string {});
            const auto qualified_name = module + "." + name;
            const auto bases = index.sequence(node, "bases");
            if (bases.size() > 1U) {
                diagnostics.push_back(make_diagnostic(
                    "PY-NYI-C3-MRO", "multiple inheritance is represented but C3 layout is not implemented yet",
                    node.span));
                return;
            }
            if (bases.empty() || root_name(index, *bases.front()) != "Model") {
                const auto base = bases.empty() ? std::string {"object"} : root_name(index, *bases.front());
                diagnostics.push_back(make_diagnostic(
                    "PY-NYI-CLASS", "class base '" + base + "' is not implemented; explicit Model is supported",
                    bases.empty() ? node.span : bases.front()->span));
                return;
            }
            if (!index.sequence(node, "decorator_list").empty()) {
                diagnostics.push_back(make_diagnostic(
                    "PY-NYI-CLASS-DECORATOR", "model class decorators are represented but not lowered yet", node.span));
                return;
            }

            SchemaDescriptor descriptor {
                .id = SchemaId {qualified_name},
                .kind = SchemaKind::model,
                .qualified_name = qualified_name,
                .canonical_hash = {},
                .fields = {},
            };
            std::set<std::string, std::less<>> field_names;
            std::vector<std::string> field_storage;
            for (const auto *statement : index.sequence(node, "body")) {
                if (statement->kind == "Expr") {
                    const auto *value = index.reference(*statement, "value");
                    if (value == nullptr || value->kind != "Constant" || !index.string(*value, "value")) {
                        diagnostics.push_back(
                            make_diagnostic("PY-MODEL", "model class expressions must be docstrings", statement->span));
                    }
                    continue;
                }
                if (statement->kind == "Pass") {
                    continue;
                }
                if (statement->kind == "FunctionDef" || statement->kind == "AsyncFunctionDef") {
                    diagnostics.push_back(make_diagnostic("PY-NYI-MODEL-METHOD",
                                                          "model methods require object/method bytecode absent from F0",
                                                          statement->span));
                    continue;
                }
                if (statement->kind != "AnnAssign") {
                    diagnostics.push_back(make_diagnostic(
                        "PY-MODEL", "model body contains unsupported statement '" + statement->kind + "'",
                        statement->span));
                    continue;
                }
                const auto *target = index.reference(*statement, "target");
                const auto *annotation = index.reference(*statement, "annotation");
                if (target == nullptr || target->kind != "Name" || annotation == nullptr) {
                    diagnostics.push_back(
                        make_diagnostic("PY-MODEL", "model field requires a simple annotated name", statement->span));
                    continue;
                }
                const auto field_name = index.string(*target, "id").value_or(std::string {});
                const auto type = annotation_type(index, annotation);
                if (field_name.empty() || !field_names.insert(field_name).second) {
                    diagnostics.push_back(
                        make_diagnostic("PY-MODEL", "model field names must be nonempty and unique", statement->span));
                    continue;
                }
                if (type.kind == StaticTypeKind::unknown || type.kind == StaticTypeKind::callable) {
                    diagnostics.push_back(make_diagnostic(
                        "PY-TYPE", "model field '" + field_name + "' has an unsupported annotation", annotation->span));
                    continue;
                }
                auto storage = std::string {"eager"};
                if (const auto *value = index.reference(*statement, "value")) {
                    if (value->kind != "Call") {
                        diagnostics.push_back(make_diagnostic(
                            "PY-NYI-MODEL-DEFAULT",
                            "model defaults require canonical default descriptors absent from F0", value->span));
                        continue;
                    }
                    const auto *provider_target = index.reference(*value, "func");
                    if (provider_target == nullptr || root_name(index, *provider_target) != "provider_fact" ||
                        !index.sequence(*value, "args").empty()) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-NYI-MODEL-DEFAULT", "model field call must be provider_fact(route=\"literal.route\")",
                            value->span));
                        continue;
                    }
                    const auto keywords = index.sequence(*value, "keywords");
                    if (keywords.size() != 1U || index.string(*keywords.front(), "arg") != "route") {
                        diagnostics.push_back(make_diagnostic(
                            "PY-FACT-ROUTE", "provider_fact requires exactly one route keyword", value->span));
                        continue;
                    }
                    const auto *route_value = index.reference(*keywords.front(), "value");
                    const auto route = route_value == nullptr ? std::nullopt : index.string(*route_value, "value");
                    if (!route || !valid_provider_route(*route)) {
                        diagnostics.push_back(
                            make_diagnostic("PY-FACT-ROUTE", "provider_fact route must be a literal dotted identifier",
                                            route_value == nullptr ? value->span : route_value->span));
                        continue;
                    }
                    storage = "lazy:" + *route;
                }
                descriptor.fields.push_back(SchemaField {
                    .field_id = static_cast<std::uint32_t>(descriptor.fields.size() + 1U),
                    .name = field_name,
                    .type = schema_for_type(type),
                    .optional = false,
                    .label = {.classification = annotation_classification(index, annotation), .categories = {}},
                });
                field_storage.push_back(std::move(storage));
            }
            std::ostringstream canonical;
            canonical.imbue(std::locale::classic());
            canonical << qualified_name << '|';
            for (std::size_t position = 0; position < descriptor.fields.size(); ++position) {
                const auto &field = descriptor.fields[position];
                canonical << field.field_id << ':' << field.name << ':' << field.type.value << ':'
                          << static_cast<unsigned int>(field.label.classification) << ':' << field_storage[position]
                          << '|';
            }
            descriptor.canonical_hash = stable_digest(std::move(canonical).str());
            generated_schemas.descriptors.push_back(std::move(descriptor));
            symbols.push_back(BoundSymbol {.module = module,
                                           .name = name,
                                           .qualified_name = qualified_name,
                                           .kind = SymbolKind::model,
                                           .type = {.kind = StaticTypeKind::model, .qualified_name = qualified_name},
                                           .span = node.span,
                                           .public_api = true,
                                           .async = false,
                                           .generator = false});
        }

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
                                                std::vector<BoundSymbol> &symbols, SchemaCatalog &generated_schemas,
                                                DiagnosticSet &diagnostics) {
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
                    if (statement->kind == "ClassDef") {
                        bind_model(index, *statement, module.name, symbols, generated_schemas, diagnostics);
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

        [[nodiscard]] SchemaId schema_for_type(const StaticType &type) {
            switch (type.kind) {
                case StaticTypeKind::none: return SchemaId {"none"};
                case StaticTypeKind::boolean: return SchemaId {"bool"};
                case StaticTypeKind::integer: return SchemaId {"int"};
                case StaticTypeKind::floating: return SchemaId {"float"};
                case StaticTypeKind::string: return SchemaId {"text"};
                case StaticTypeKind::bytes: return SchemaId {"bytes"};
                case StaticTypeKind::list: return SchemaId {type.qualified_name.empty() ? "list" : type.qualified_name};
                case StaticTypeKind::dictionary:
                    return SchemaId {type.qualified_name.empty() ? "dict" : type.qualified_name};
                case StaticTypeKind::model: return SchemaId {type.qualified_name};
                case StaticTypeKind::callable:
                case StaticTypeKind::unknown: return SchemaId {"any"};
            }
            return SchemaId {"any"};
        }

        [[nodiscard]] std::string route_name(const FactRoute &route) { return route.provider + "." + route.fact; }

        struct Lowerer {
            const AstIndex &index;
            const FunctionModel &function;
            const std::vector<FunctionModel> &functions;
            CompiledPack &pack;
            std::vector<FactRequirement> &requirements;
            DiagnosticSet &diagnostics;
            BytecodeFunction bytecode;
            std::map<std::string, ExpressionResult, std::less<>> locals;
            struct LoopFrame {
                std::uint32_t continue_target {};
                std::vector<std::size_t> break_jumps;
            };
            std::vector<LoopFrame> loops;
            std::uint32_t conditional_depth {};
            std::uint32_t direct_await_depth {};
            bool may_fault {};

            Lowerer(const AstIndex &index_value, const FunctionModel &function_value,
                    const std::vector<FunctionModel> &functions_value, CompiledPack &pack_value,
                    std::vector<FactRequirement> &requirements_value, DiagnosticSet &diagnostics_value):
                index {index_value},
                function {function_value},
                functions {functions_value},
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

            [[nodiscard]] std::optional<std::size_t> function_index(const AstNode &target) const {
                const auto name = attribute_path(index, target).value_or(std::string {});
                if (name.empty()) {
                    return std::nullopt;
                }
                const auto local_name = function.module + "." + name;
                auto found = std::ranges::find(functions, local_name, &FunctionModel::qualified_name);
                if (found == functions.end()) {
                    found = std::ranges::find(functions, name, &FunctionModel::qualified_name);
                }
                return found == functions.end() ?
                           std::nullopt :
                           std::optional<std::size_t> {static_cast<std::size_t>(found - functions.begin())};
            }

            [[nodiscard]] static bool assignable(const StaticType &actual, const StaticType &expected) {
                return expected.kind == StaticTypeKind::unknown || actual.kind == StaticTypeKind::unknown ||
                       actual.kind == expected.kind ||
                       (actual.kind == StaticTypeKind::boolean && expected.kind == StaticTypeKind::integer);
            }

            [[nodiscard]] static bool numeric(const StaticTypeKind kind) noexcept {
                return kind == StaticTypeKind::boolean || kind == StaticTypeKind::integer ||
                       kind == StaticTypeKind::floating;
            }

            [[nodiscard]] static bool integral(const StaticTypeKind kind) noexcept {
                return kind == StaticTypeKind::boolean || kind == StaticTypeKind::integer;
            }

            [[nodiscard]] static StaticType unify(StaticType left, const StaticType &right) {
                if (left.kind == right.kind && left.qualified_name == right.qualified_name) {
                    return left;
                }
                if (numeric(left.kind) && numeric(right.kind)) {
                    if (left.kind == StaticTypeKind::floating || right.kind == StaticTypeKind::floating) {
                        return {.kind = StaticTypeKind::floating, .qualified_name = "float"};
                    }
                    return {.kind = StaticTypeKind::integer, .qualified_name = "int"};
                }
                return {.kind = StaticTypeKind::unknown, .qualified_name = "Any"};
            }

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

            std::optional<FactValue> literal_fact(const AstNode &node) {
                if (node.kind == "Constant") {
                    const auto *value = index.field(node, "value");
                    if (value == nullptr) {
                        return std::nullopt;
                    }
                    if (std::holds_alternative<std::monostate>(value->value.data)) {
                        return make_fact(std::monostate {});
                    }
                    if (const auto *boolean = std::get_if<bool>(&value->value.data)) {
                        return make_fact(*boolean);
                    }
                    if (const auto *integer = std::get_if<IntegerValue>(&value->value.data)) {
                        return make_fact(*integer);
                    }
                    if (const auto *floating = std::get_if<AstFloatBits>(&value->value.data)) {
                        return make_fact(std::bit_cast<double>(floating->bits));
                    }
                    if (const auto *unicode = std::get_if<UnicodeValue>(&value->value.data)) {
                        return make_fact(*unicode);
                    }
                    if (const auto *bytes = std::get_if<BytesValue>(&value->value.data)) {
                        return make_fact(*bytes);
                    }
                    return std::nullopt;
                }
                if (node.kind == "List") {
                    FactList list;
                    for (const auto *element : index.sequence(node, "elts")) {
                        const auto value = literal_fact(*element);
                        if (!value) {
                            return std::nullopt;
                        }
                        list.items.push_back(*value);
                    }
                    return make_fact(std::move(list));
                }
                if (node.kind == "Dict") {
                    const auto keys = index.sequence(node, "keys");
                    const auto values = index.sequence(node, "values");
                    if (keys.size() != values.size()) {
                        return std::nullopt;
                    }
                    FactMap map;
                    for (std::size_t position = 0; position < keys.size(); ++position) {
                        const auto key = literal_fact(*keys[position]);
                        const auto value = literal_fact(*values[position]);
                        if (!key || !value) {
                            return std::nullopt;
                        }
                        map.entries.push_back(FactMapEntry {.key = *key, .value = *value});
                    }
                    return make_fact(std::move(map));
                }
                return std::nullopt;
            }

            std::optional<ExpressionResult> literal_collection(const AstNode &node) {
                const auto value = literal_fact(node);
                if (!value) {
                    diagnostics.push_back(make_diagnostic(
                        "PY-NYI-COLLECTION-LOWERING",
                        "only recursively constant list and dictionary displays are lowered by the F0 bytecode",
                        node.span));
                    return std::nullopt;
                }
                const auto constant_index = static_cast<std::uint32_t>(pack.constants.size());
                pack.constants.push_back(*value);
                const auto destination = allocate();
                emit(Opcode::load_const, destination, 0U, 0U, constant_index, node.span);
                return ExpressionResult {
                    .reg = destination,
                    .type = {.kind = node.kind == "List" ? StaticTypeKind::list : StaticTypeKind::dictionary,
                             .qualified_name = node.kind == "List" ? "list[Any]" : "dict[Any,Any]"},
                };
            }

            std::optional<ExpressionResult> expression(const AstNode &node) {
                if (node.kind == "Constant") {
                    return constant(node);
                }
                if (node.kind == "List" || node.kind == "Dict") {
                    return literal_collection(node);
                }
                if (node.kind == "Tuple" || node.kind == "Set") {
                    diagnostics.push_back(make_diagnostic(
                        "PY-NYI-COLLECTION-LOWERING",
                        node.kind + " requires a distinct runtime value kind absent from the F0 FactValue constants",
                        node.span));
                    return std::nullopt;
                }
                if (node.kind == "Subscript") {
                    diagnostics.push_back(make_diagnostic(
                        "PY-NYI-SUBSCRIPT-LOWERING",
                        "subscription requires a container access opcode absent from the F0 bytecode contract",
                        node.span));
                    return std::nullopt;
                }
                if (node.kind == "ListComp" || node.kind == "SetComp" || node.kind == "DictComp" ||
                    node.kind == "GeneratorExp") {
                    diagnostics.push_back(make_diagnostic(
                        "PY-NYI-COMPREHENSION-LOWERING",
                        "comprehensions require iterator/container opcodes absent from the F0 bytecode contract",
                        node.span));
                    return std::nullopt;
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
                    const auto last = path->substr(path->find_last_of('.') + 1);
                    const auto type = last.starts_with("is_") || last.starts_with("has_") ?
                                          StaticType {.kind = StaticTypeKind::boolean, .qualified_name = "bool"} :
                                          StaticType {.kind = StaticTypeKind::unknown, .qualified_name = "Any"};
                    const auto route = FactRoute {.provider = parameter, .fact = path->substr(separator + 1U)};
                    const auto expected_schema = schema_for_type(type);
                    const auto operand_constant = static_cast<std::uint32_t>(pack.constants.size());
                    pack.constants.push_back(make_vm_fact_operand(route, expected_schema));
                    requirements.push_back(FactRequirement {
                        .executable = function.executable,
                        .parameter = parameter,
                        .attribute_path = *path,
                        .route = route,
                        .expected_schema = expected_schema,
                        .operand_constant = operand_constant,
                        .span = node.span,
                        .conditional = conditional_depth != 0,
                    });
                    emit(Opcode::await_fact, destination, locals.at(parameter).reg, 0, operand_constant, node.span);
                    may_fault = true;
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
                        if (!numeric(operand->type.kind) && operand->type.kind != StaticTypeKind::unknown) {
                            diagnostics.push_back(
                                make_diagnostic("PY-TYPE", "unary '+' requires a numeric operand", node.span));
                            return std::nullopt;
                        }
                        code = UnaryCode::positive;
                        if (operand->type.kind == StaticTypeKind::boolean) {
                            result_type = {.kind = StaticTypeKind::integer, .qualified_name = "int"};
                        }
                    } else if (operation == "USub") {
                        if (!numeric(operand->type.kind) && operand->type.kind != StaticTypeKind::unknown) {
                            diagnostics.push_back(
                                make_diagnostic("PY-TYPE", "unary '-' requires a numeric operand", node.span));
                            return std::nullopt;
                        }
                        code = UnaryCode::negative;
                        if (operand->type.kind == StaticTypeKind::boolean) {
                            result_type = {.kind = StaticTypeKind::integer, .qualified_name = "int"};
                        }
                    } else if (operation == "Invert") {
                        if (!integral(operand->type.kind) && operand->type.kind != StaticTypeKind::unknown) {
                            diagnostics.push_back(
                                make_diagnostic("PY-TYPE", "unary '~' requires an integer operand", node.span));
                            return std::nullopt;
                        }
                        code = UnaryCode::invert;
                        result_type = {.kind = StaticTypeKind::integer, .qualified_name = "int"};
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
                    StaticType result_type;
                    const auto arithmetic = operation == "Add" || operation == "Sub" || operation == "Mult" ||
                                            operation == "Div" || operation == "FloorDiv" || operation == "Mod" ||
                                            operation == "Pow";
                    const auto bitwise = operation == "LShift" || operation == "RShift" || operation == "BitOr" ||
                                         operation == "BitXor" || operation == "BitAnd";
                    if (arithmetic && numeric(left->type.kind) && numeric(right->type.kind)) {
                        result_type = operation == "Div" || left->type.kind == StaticTypeKind::floating ||
                                              right->type.kind == StaticTypeKind::floating ?
                                          StaticType {.kind = StaticTypeKind::floating, .qualified_name = "float"} :
                                          StaticType {.kind = StaticTypeKind::integer, .qualified_name = "int"};
                    } else if (bitwise && integral(left->type.kind) && integral(right->type.kind)) {
                        result_type = {.kind = StaticTypeKind::integer, .qualified_name = "int"};
                    } else if (operation == "Add" && left->type.kind == right->type.kind &&
                               (left->type.kind == StaticTypeKind::string || left->type.kind == StaticTypeKind::bytes ||
                                left->type.kind == StaticTypeKind::list)) {
                        result_type = left->type;
                    } else if (left->type.kind == StaticTypeKind::unknown ||
                               right->type.kind == StaticTypeKind::unknown) {
                        result_type = {.kind = StaticTypeKind::unknown, .qualified_name = "Any"};
                    } else {
                        diagnostics.push_back(make_diagnostic(
                            "PY-TYPE", "binary operator '" + operation + "' is invalid for the operand types",
                            node.span));
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
                    if (!left_node || comparators.empty() || comparators.size() != operations.size()) {
                        diagnostics.push_back(
                            make_diagnostic("PY-AST-FIELD", "Compare operands and operators do not match", node.span));
                        return std::nullopt;
                    }
                    auto left = expression(*left_node);
                    if (!left) {
                        return std::nullopt;
                    }
                    static const std::map<std::string, CompareCode, std::less<>> codes {
                        {"Eq", CompareCode::equal},          {"Gt", CompareCode::greater},
                        {"GtE", CompareCode::greater_equal}, {"In", CompareCode::contains},
                        {"Is", CompareCode::is_value},       {"IsNot", CompareCode::is_not},
                        {"Lt", CompareCode::less},           {"LtE", CompareCode::less_equal},
                        {"NotEq", CompareCode::not_equal},   {"NotIn", CompareCode::not_contains},
                    };
                    const auto destination = allocate();
                    std::vector<std::size_t> exits;
                    for (std::size_t position = 0; position < comparators.size(); ++position) {
                        if (position != 0U) {
                            exits.push_back(bytecode.instructions.size());
                            emit(Opcode::jump_if_false, destination, destination, 0U, 0U,
                                 comparators[position - 1U]->span);
                            ++conditional_depth;
                        }
                        const auto right = expression(*comparators[position]);
                        if (position != 0U) {
                            --conditional_depth;
                        }
                        if (!right) {
                            return std::nullopt;
                        }
                        const auto code = codes.find(operations[position]);
                        if (code == codes.end()) {
                            diagnostics.push_back(make_diagnostic(
                                "PY-UNSUPPORTED", "comparison operator '" + operations[position] + "' is unsupported",
                                node.span));
                            return std::nullopt;
                        }
                        emit(Opcode::compare, destination, left->reg, right->reg,
                             static_cast<std::uint32_t>(code->second), node.span);
                        left = right;
                    }
                    const auto exit = static_cast<std::uint32_t>(bytecode.instructions.size());
                    for (const auto instruction : exits) { bytecode.instructions[instruction].immediate = exit; }
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
                    auto result_type = first->type;
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
                        result_type = unify(std::move(result_type), next->type);
                        emit(Opcode::move, result, next->reg, 0, 0, values[position]->span);
                    }
                    const auto exit = static_cast<std::uint32_t>(bytecode.instructions.size());
                    for (const auto instruction : exits) { bytecode.instructions[instruction].immediate = exit; }
                    return ExpressionResult {
                        .reg = result,
                        .type = std::move(result_type),
                    };
                }
                if (node.kind == "IfExp") {
                    const auto *test = index.reference(node, "test");
                    const auto *body = index.reference(node, "body");
                    const auto *otherwise = index.reference(node, "orelse");
                    if (test == nullptr || body == nullptr || otherwise == nullptr) {
                        diagnostics.push_back(
                            make_diagnostic("PY-AST-FIELD", "conditional expression is incomplete", node.span));
                        return std::nullopt;
                    }
                    const auto condition = expression(*test);
                    if (!condition) {
                        return std::nullopt;
                    }
                    const auto result = allocate();
                    const auto false_jump = bytecode.instructions.size();
                    emit(Opcode::jump_if_false, condition->reg, condition->reg, 0U, 0U, test->span);
                    ++conditional_depth;
                    const auto when_true = expression(*body);
                    --conditional_depth;
                    if (!when_true) {
                        return std::nullopt;
                    }
                    emit(Opcode::move, result, when_true->reg, 0U, 0U, body->span);
                    const auto end_jump = bytecode.instructions.size();
                    emit(Opcode::jump, 0U, 0U, 0U, 0U, node.span);
                    bytecode.instructions[false_jump].immediate =
                        static_cast<std::uint32_t>(bytecode.instructions.size());
                    ++conditional_depth;
                    const auto when_false = expression(*otherwise);
                    --conditional_depth;
                    if (!when_false) {
                        return std::nullopt;
                    }
                    emit(Opcode::move, result, when_false->reg, 0U, 0U, otherwise->span);
                    bytecode.instructions[end_jump].immediate =
                        static_cast<std::uint32_t>(bytecode.instructions.size());
                    return ExpressionResult {.reg = result, .type = unify(when_true->type, when_false->type)};
                }
                if (node.kind == "NamedExpr") {
                    const auto *target = index.reference(node, "target");
                    const auto *value = index.reference(node, "value");
                    if (target == nullptr || target->kind != "Name" || value == nullptr) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-AST-FIELD", "named expression requires a local-name target", node.span));
                        return std::nullopt;
                    }
                    const auto result = expression(*value);
                    if (!result) {
                        return std::nullopt;
                    }
                    const auto name = index.string(*target, "id").value_or(std::string {});
                    const auto existing = locals.find(name);
                    if (existing == locals.end()) {
                        locals[name] = *result;
                        return result;
                    }
                    emit(Opcode::move, existing->second.reg, result->reg, 0U, 0U, node.span);
                    existing->second.type = unify(existing->second.type, result->type);
                    return existing->second;
                }
                if (node.kind == "Await") {
                    const auto *value = index.reference(node, "value");
                    if (!function.async || value == nullptr) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-TYPE-AWAIT", "await requires an expression inside an async function", node.span));
                        return std::nullopt;
                    }
                    if (value->kind == "Attribute") {
                        return expression(*value);
                    }
                    if (value->kind == "Call") {
                        const auto *target = index.reference(*value, "func");
                        const auto target_index = target == nullptr ? std::nullopt : function_index(*target);
                        if (target_index && functions[*target_index].async) {
                            ++direct_await_depth;
                            auto result = expression(*value);
                            --direct_await_depth;
                            return result;
                        }
                    }
                    diagnostics.push_back(make_diagnostic(
                        "PY-NYI-ASYNC-LOWERING",
                        "await target is represented but has no F0 capability/coroutine operand encoding", node.span));
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
                    const auto target_index = target == nullptr ? std::nullopt : function_index(*target);
                    if (!target_index) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-UNSUPPORTED-CALL", "call target '" + name + "' is not a statically bound pack function",
                            node.span));
                        return std::nullopt;
                    }
                    if (!index.sequence(node, "keywords").empty()) {
                        diagnostics.push_back(make_diagnostic("PY-NYI-CALL-KEYWORDS",
                                                              "keyword arguments are represented but not lowered yet",
                                                              node.span));
                        return std::nullopt;
                    }
                    const auto arguments = index.sequence(node, "args");
                    const auto &callee = functions[*target_index];
                    if (callee.async && direct_await_depth == 0U) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-TYPE-COROUTINE",
                            "async function calls must be directly awaited until cold coroutine values are encoded",
                            node.span));
                        return std::nullopt;
                    }
                    if (arguments.size() != callee.parameters.size()) {
                        diagnostics.push_back(make_diagnostic(
                            "PY-TYPE-CALL", "call to '" + callee.qualified_name + "' has the wrong argument count",
                            node.span));
                        return std::nullopt;
                    }
                    std::vector<ExpressionResult> values;
                    values.reserve(arguments.size());
                    for (std::size_t position = 0; position < arguments.size(); ++position) {
                        const auto value = expression(*arguments[position]);
                        if (!value) {
                            return std::nullopt;
                        }
                        if (!assignable(value->type, callee.parameters[position].second)) {
                            diagnostics.push_back(make_diagnostic("PY-TYPE-CALL",
                                                                  "argument " + std::to_string(position + 1U) +
                                                                      " to '" + callee.qualified_name +
                                                                      "' has incompatible type",
                                                                  arguments[position]->span));
                            return std::nullopt;
                        }
                        values.push_back(*value);
                    }
                    const auto first_argument = bytecode.register_count;
                    for (const auto &value : values) {
                        const auto argument = allocate();
                        emit(Opcode::move, argument, value.reg, 0U, 0U, node.span);
                    }
                    const auto destination = allocate();
                    emit(Opcode::call, destination, first_argument, static_cast<std::uint32_t>(values.size()),
                         static_cast<std::uint32_t>(*target_index), node.span);
                    may_fault = true;
                    return ExpressionResult {.reg = destination, .type = callee.return_type};
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
                        if (value && value->kind == "Yield") {
                            const auto *yielded = index.reference(*value, "value");
                            std::optional<ExpressionResult> result;
                            if (yielded != nullptr) {
                                result = expression(*yielded);
                            } else {
                                AstNode synthetic {.id = 0U,
                                                   .kind = "Constant",
                                                   .span = value->span,
                                                   .fields = {AstField {.name = "value", .value = ast_none()}}};
                                result = constant(synthetic);
                            }
                            if (result) {
                                emit(Opcode::yield_value, result->reg, result->reg, 0U, 0U, value->span);
                            }
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
                            const auto name = index.string(*targets.front(), "id").value_or(std::string {});
                            const auto existing = locals.find(name);
                            if (existing == locals.end()) {
                                locals[name] = *result;
                            } else {
                                emit(Opcode::move, existing->second.reg, result->reg, 0U, 0U, statement->span);
                                existing->second.type = unify(existing->second.type, result->type);
                            }
                        }
                        continue;
                    }
                    if (statement->kind == "AnnAssign") {
                        const auto *target = index.reference(*statement, "target");
                        const auto *annotation = index.reference(*statement, "annotation");
                        const auto *value = index.reference(*statement, "value");
                        if (target == nullptr || target->kind != "Name" || annotation == nullptr) {
                            diagnostics.push_back(make_diagnostic("PY-NYI-ASSIGNMENT",
                                                                  "annotated assignment requires a local-name target",
                                                                  statement->span));
                            continue;
                        }
                        if (value == nullptr) {
                            continue;
                        }
                        const auto declared = annotation_type(index, annotation);
                        const auto result = expression(*value);
                        if (!result) {
                            continue;
                        }
                        if (!assignable(result->type, declared)) {
                            diagnostics.push_back(make_diagnostic("PY-TYPE-ASSIGN",
                                                                  "assigned value is incompatible with its annotation",
                                                                  statement->span));
                            continue;
                        }
                        const auto name = index.string(*target, "id").value_or(std::string {});
                        const auto existing = locals.find(name);
                        if (existing == locals.end()) {
                            locals[name] = ExpressionResult {.reg = result->reg, .type = declared};
                        } else {
                            emit(Opcode::move, existing->second.reg, result->reg, 0U, 0U, statement->span);
                            existing->second.type = declared;
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
                        if (function.return_type.kind != StaticTypeKind::unknown &&
                            !assignable(result->type, function.return_type)) {
                            diagnostics.push_back(make_diagnostic(
                                "PY-TYPE-RETURN",
                                function.public_api ? "reportable function must return bool on every path" :
                                                      "return value is incompatible with the function annotation",
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
                    if (statement->kind == "Match") {
                        const auto *subject = index.reference(*statement, "subject");
                        if (subject == nullptr) {
                            diagnostics.push_back(
                                make_diagnostic("PY-AST-FIELD", "match statement has no subject", statement->span));
                            continue;
                        }
                        const auto subject_value = expression(*subject);
                        if (!subject_value) {
                            continue;
                        }
                        std::vector<std::size_t> end_jumps;
                        bool exhaustive {};
                        bool all_cases_terminate {true};
                        for (const auto *match_case : index.sequence(*statement, "cases")) {
                            const auto *pattern = index.reference(*match_case, "pattern");
                            if (pattern == nullptr) {
                                diagnostics.push_back(
                                    make_diagnostic("PY-AST-FIELD", "match case has no pattern", match_case->span));
                                continue;
                            }
                            std::vector<std::size_t> next_case_jumps;
                            if (pattern->kind == "MatchValue" || pattern->kind == "MatchSingleton") {
                                const AstNode *literal_node = index.reference(*pattern, "value");
                                AstNode singleton;
                                if (pattern->kind == "MatchSingleton") {
                                    const auto *literal = AstIndex::field(*pattern, "value");
                                    if (literal != nullptr) {
                                        singleton = AstNode {
                                            .id = 0U,
                                            .kind = "Constant",
                                            .span = pattern->span,
                                            .fields = {AstField {.name = "value", .value = literal->value}},
                                        };
                                        literal_node = &singleton;
                                    }
                                }
                                const auto literal = literal_node == nullptr ? std::nullopt : expression(*literal_node);
                                if (!literal) {
                                    diagnostics.push_back(make_diagnostic(
                                        "PY-NYI-MATCH-PATTERN",
                                        "match value pattern must be a statically supported literal", pattern->span));
                                    continue;
                                }
                                const auto matched = allocate();
                                emit(Opcode::compare, matched, subject_value->reg, literal->reg,
                                     static_cast<std::uint32_t>(CompareCode::equal), pattern->span);
                                next_case_jumps.push_back(bytecode.instructions.size());
                                emit(Opcode::jump_if_false, matched, matched, 0U, 0U, pattern->span);
                            } else if (pattern->kind == "MatchAs" && index.reference(*pattern, "pattern") == nullptr &&
                                       !index.string(*pattern, "name").has_value()) {
                                exhaustive = true;
                            } else {
                                diagnostics.push_back(make_diagnostic(
                                    "PY-NYI-MATCH-PATTERN",
                                    "pattern '" + pattern->kind +
                                        "' requires binding/rollback or container opcodes absent from F0",
                                    pattern->span));
                                continue;
                            }
                            if (const auto *guard = index.reference(*match_case, "guard")) {
                                ++conditional_depth;
                                const auto guard_value = expression(*guard);
                                --conditional_depth;
                                if (!guard_value) {
                                    continue;
                                }
                                next_case_jumps.push_back(bytecode.instructions.size());
                                emit(Opcode::jump_if_false, guard_value->reg, guard_value->reg, 0U, 0U, guard->span);
                            }
                            ++conditional_depth;
                            const auto case_terminated = statements(index.sequence(*match_case, "body"));
                            --conditional_depth;
                            all_cases_terminate = all_cases_terminate && case_terminated;
                            if (!case_terminated) {
                                end_jumps.push_back(bytecode.instructions.size());
                                emit(Opcode::jump, 0U, 0U, 0U, 0U, match_case->span);
                            }
                            const auto next_case = static_cast<std::uint32_t>(bytecode.instructions.size());
                            for (const auto jump : next_case_jumps) {
                                bytecode.instructions[jump].immediate = next_case;
                            }
                        }
                        const auto end = static_cast<std::uint32_t>(bytecode.instructions.size());
                        for (const auto jump : end_jumps) { bytecode.instructions[jump].immediate = end; }
                        terminated = exhaustive && all_cases_terminate;
                        continue;
                    }
                    if (statement->kind == "While") {
                        const auto loop_start = static_cast<std::uint32_t>(bytecode.instructions.size());
                        const auto *test = index.reference(*statement, "test");
                        if (test == nullptr) {
                            diagnostics.push_back(
                                make_diagnostic("PY-AST-FIELD", "While is missing test", statement->span));
                            continue;
                        }
                        const auto condition = expression(*test);
                        if (!condition) {
                            continue;
                        }
                        const auto false_jump = bytecode.instructions.size();
                        emit(Opcode::jump_if_false, condition->reg, condition->reg, 0U, 0U, test->span);
                        loops.push_back(LoopFrame {.continue_target = loop_start, .break_jumps = {}});
                        ++conditional_depth;
                        const auto body_terminated = statements(index.sequence(*statement, "body"));
                        --conditional_depth;
                        if (!body_terminated) {
                            emit(Opcode::jump, 0U, 0U, 0U, loop_start, statement->span);
                        }
                        auto loop = std::move(loops.back());
                        loops.pop_back();
                        bytecode.instructions[false_jump].immediate =
                            static_cast<std::uint32_t>(bytecode.instructions.size());
                        ++conditional_depth;
                        static_cast<void>(statements(index.sequence(*statement, "orelse")));
                        --conditional_depth;
                        const auto loop_exit = static_cast<std::uint32_t>(bytecode.instructions.size());
                        for (const auto jump : loop.break_jumps) { bytecode.instructions[jump].immediate = loop_exit; }
                        terminated = false;
                        continue;
                    }
                    if (statement->kind == "Break" || statement->kind == "Continue") {
                        if (loops.empty()) {
                            diagnostics.push_back(make_diagnostic(
                                "PY-SCOPE", statement->kind + " appears outside a loop", statement->span));
                            continue;
                        }
                        if (statement->kind == "Break") {
                            loops.back().break_jumps.push_back(bytecode.instructions.size());
                            emit(Opcode::jump, 0U, 0U, 0U, 0U, statement->span);
                        } else {
                            emit(Opcode::jump, 0U, 0U, 0U, loops.back().continue_target, statement->span);
                        }
                        terminated = true;
                        continue;
                    }
                    if (statement->kind == "Raise") {
                        const auto *value = index.reference(*statement, "exc");
                        if (value == nullptr) {
                            diagnostics.push_back(make_diagnostic(
                                "PY-NYI-BARE-RAISE", "bare raise requires active-exception metadata absent from F0",
                                statement->span));
                            continue;
                        }
                        const auto result = expression(*value);
                        if (result) {
                            emit(Opcode::raise_fault, result->reg, result->reg, 0U, 0U, statement->span);
                            terminated = true;
                        }
                        continue;
                    }
                    if (statement->kind == "For") {
                        diagnostics.push_back(make_diagnostic(
                            "PY-NYI-ITERATION-LOWERING",
                            "for loops require iterator opcodes that are absent from the F0 bytecode contract",
                            statement->span));
                        continue;
                    }
                    if (statement->kind == "TryStar") {
                        diagnostics.push_back(make_diagnostic(
                            "PY-NYI-EXCEPTION-GROUP-LOWERING",
                            "except* requires exception-group splitting absent from the F0 bytecode contract",
                            statement->span));
                        continue;
                    }
                    if (statement->kind == "Try") {
                        if (!index.sequence(*statement, "finalbody").empty()) {
                            diagnostics.push_back(make_diagnostic(
                                "PY-NYI-FINALLY-LOWERING",
                                "finally requires unwind-reason metadata absent from the F0 bytecode contract",
                                statement->span));
                            continue;
                        }
                        const auto handlers = index.sequence(*statement, "handlers");
                        if (handlers.size() != 1U || index.reference(*handlers.front(), "type") != nullptr ||
                            index.string(*handlers.front(), "name").has_value()) {
                            diagnostics.push_back(make_diagnostic(
                                "PY-NYI-EXCEPTION-FILTER", "F0 lowers exactly one unbound catch-all except handler",
                                statement->span));
                            continue;
                        }
                        const auto region_begin = static_cast<std::uint32_t>(bytecode.instructions.size());
                        emit(Opcode::enter_try, 0U, 0U, 0U, 0U, statement->span);
                        ++conditional_depth;
                        const auto body_terminated = statements(index.sequence(*statement, "body"));
                        --conditional_depth;
                        const auto region_end = static_cast<std::uint32_t>(bytecode.instructions.size());
                        auto normal_terminated = body_terminated;
                        if (!body_terminated) {
                            emit(Opcode::leave_try, 0U, 0U, 0U, 0U, statement->span);
                            ++conditional_depth;
                            normal_terminated = statements(index.sequence(*statement, "orelse"));
                            --conditional_depth;
                        }
                        std::optional<std::size_t> end_jump;
                        if (!normal_terminated) {
                            end_jump = bytecode.instructions.size();
                            emit(Opcode::jump, 0U, 0U, 0U, 0U, statement->span);
                        }
                        const auto handler_begin = static_cast<std::uint32_t>(bytecode.instructions.size());
                        ++conditional_depth;
                        const auto handler_terminated = statements(index.sequence(*handlers.front(), "body"));
                        --conditional_depth;
                        const auto end = static_cast<std::uint32_t>(bytecode.instructions.size());
                        if (end_jump) {
                            bytecode.instructions[*end_jump].immediate = end;
                        }
                        bytecode.exception_regions.push_back(ExceptionRegion {
                            .begin_instruction = region_begin,
                            .end_instruction = region_end,
                            .handler_instruction = handler_begin,
                            .cleanup_instruction = handler_begin,
                        });
                        terminated = normal_terminated && handler_terminated;
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
                for (const auto &region : function.exception_regions) {
                    output << "exception:" << region.begin_instruction << ':' << region.end_instruction << ':'
                           << region.handler_instruction << ':' << region.cleanup_instruction << '\n';
                }
            }
            for (const auto &requirement : requirements) {
                output << "fact|" << requirement.executable.value << '|' << requirement.attribute_path << '|'
                       << route_name(requirement.route) << '|' << requirement.expected_schema.value << '|'
                       << requirement.operand_constant << '|' << requirement.conditional << '\n';
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
        DiagnosticSet diagnostics;
        if (pack.manifest.compiler_abi != "python-3.14.6/static-compiler-v1") {
            diagnostics.push_back(make_diagnostic(
                "PY-COMPILER-ABI", "verified pack compiler ABI does not select the exact static compiler"));
        }
        if (pack.manifest.budget_profile != balanced_v1.name) {
            diagnostics.push_back(make_diagnostic(
                "PY-BUDGET-PROFILE", "verified pack must select the immutable balanced.v1 budget profile"));
        }
        if (!diagnostics.empty()) {
            sort_diagnostics(diagnostics);
            return std::unexpected(std::move(diagnostics));
        }
        auto decoded = decode_ast_envelope(ast_payload, pack);
        if (!decoded) {
            return std::unexpected(std::move(decoded.error()));
        }

        const AstIndex index {*decoded};
        std::vector<BoundSymbol> symbols;
        SchemaCatalog generated_schemas;
        const auto functions = bind_modules(*decoded, index, symbols, generated_schemas, diagnostics);
        std::set<std::string, std::less<>> reportable_executables;
        for (const auto &function : functions) {
            if (function.public_api) {
                reportable_executables.insert(function.executable.value);
            }
        }
        std::set<std::string, std::less<>> binding_ids;
        for (const auto &binding : bindings) {
            if (binding.id.empty() || !binding_ids.insert(binding.id.value).second) {
                diagnostics.push_back(
                    make_diagnostic("PY-BINDING", "operator binding IDs must be nonempty and unique"));
            }
            if (!reportable_executables.contains(binding.executable.value)) {
                diagnostics.push_back(
                    make_diagnostic("PY-BINDING", "operator binding references an unknown reportable executable '" +
                                                      binding.executable.value + "'"));
            }
            if (binding.budget.name != balanced_v1.name) {
                diagnostics.push_back(make_diagnostic(
                    "PY-BINDING-BUDGET", "operator binding must use the immutable balanced.v1 budget profile"));
            }
        }
        if (!diagnostics.empty()) {
            sort_diagnostics(diagnostics);
            return std::unexpected(std::move(diagnostics));
        }

        auto merged_schemas = schemas;
        for (auto &descriptor : generated_schemas.descriptors) {
            if (std::ranges::find(merged_schemas.descriptors, descriptor.id, &SchemaDescriptor::id) !=
                merged_schemas.descriptors.end()) {
                diagnostics.push_back(make_diagnostic(
                    "PY-SCHEMA-DUPLICATE", "generated model schema '" + descriptor.id.value + "' already exists"));
                continue;
            }
            merged_schemas.descriptors.push_back(std::move(descriptor));
        }
        if (!diagnostics.empty()) {
            sort_diagnostics(diagnostics);
            return std::unexpected(std::move(diagnostics));
        }
        merged_schemas = normalize_schemas(std::move(merged_schemas));
        std::string schema_identity = merged_schemas.canonical_hash;
        for (const auto &descriptor : merged_schemas.descriptors) {
            schema_identity += '|';
            schema_identity += descriptor.id.value;
            schema_identity += '|';
            schema_identity += descriptor.canonical_hash;
        }
        merged_schemas.canonical_hash = stable_digest(schema_identity);

        CompiledPack compiled {
            .pack = pack.manifest.pack,
            .version = pack.manifest.version,
            .source_digest = pack.closure_digest,
            .compiler_abi = "python-3.14.6/static-compiler-v1",
            .semantic_hash = {},
            .schemas = std::move(merged_schemas),
            .constants = {},
            .functions = {},
            .bindings = normalize_bindings(bindings),
            .optimization_certificates = {},
        };
        std::vector<FactRequirement> requirements;
        for (const auto &function : functions) {
            Lowerer lowerer {index, function, functions, compiled, requirements, diagnostics};
            auto bytecode = lowerer.lower();
            std::vector<std::string> logical_facts;
            for (const auto &requirement : requirements) {
                if (requirement.executable == function.executable) {
                    logical_facts.push_back(route_name(requirement.route));
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
        for (std::size_t iteration = 0; iteration < compiled.functions.size(); ++iteration) {
            bool changed {};
            for (std::size_t caller_index = 0; caller_index < compiled.functions.size(); ++caller_index) {
                auto &caller = compiled.optimization_certificates[caller_index];
                for (const auto &instruction : compiled.functions[caller_index].instructions) {
                    if (instruction.opcode != Opcode::call || instruction.immediate >= compiled.functions.size()) {
                        continue;
                    }
                    const auto callee = compiled.optimization_certificates[instruction.immediate];
                    const auto before = std::make_tuple(
                        caller.transitively_pure, caller.recorder_observable, caller.may_fault, caller.reads_state,
                        caller.reads_history, caller.calls_services, caller.emits_effects, caller.logical_facts);
                    caller.transitively_pure = caller.transitively_pure && callee.transitively_pure;
                    caller.recorder_observable = caller.recorder_observable || callee.recorder_observable;
                    caller.may_fault = caller.may_fault || callee.may_fault;
                    caller.reads_state = caller.reads_state || callee.reads_state;
                    caller.reads_history = caller.reads_history || callee.reads_history;
                    caller.calls_services = caller.calls_services || callee.calls_services;
                    caller.emits_effects = caller.emits_effects || callee.emits_effects;
                    caller.logical_facts.insert(caller.logical_facts.end(), callee.logical_facts.begin(),
                                                callee.logical_facts.end());
                    std::ranges::sort(caller.logical_facts);
                    caller.logical_facts.erase(std::ranges::unique(caller.logical_facts).begin(),
                                               caller.logical_facts.end());
                    const auto after = std::make_tuple(
                        caller.transitively_pure, caller.recorder_observable, caller.may_fault, caller.reads_state,
                        caller.reads_history, caller.calls_services, caller.emits_effects, caller.logical_facts);
                    changed = changed || before != after;
                }
            }
            if (!changed) {
                break;
            }
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
                     instruction.opcode == Opcode::jump_if_false || instruction.opcode == Opcode::return_value ||
                     instruction.opcode == Opcode::raise_fault || instruction.opcode == Opcode::yield_value ||
                     instruction.opcode == Opcode::await_fact) &&
                    !in_register_range(instruction.operand_a)) {
                    diagnostics.push_back(make_diagnostic("PYC-OPERAND", "bytecode operand_a register is out of range",
                                                          instruction.span));
                }
                if ((instruction.opcode == Opcode::binary_op || instruction.opcode == Opcode::compare) &&
                    (!in_register_range(instruction.operand_a) || !in_register_range(instruction.operand_b))) {
                    diagnostics.push_back(
                        make_diagnostic("PYC-OPERAND", "bytecode operand register is out of range", instruction.span));
                }
                if (instruction.opcode == Opcode::unary_op &&
                    instruction.immediate > static_cast<std::uint32_t>(UnaryCode::invert)) {
                    diagnostics.push_back(
                        make_diagnostic("PYC-OPERATOR", "unary operation selector is out of range", instruction.span));
                }
                if (instruction.opcode == Opcode::binary_op &&
                    instruction.immediate > static_cast<std::uint32_t>(BinaryCode::bit_and)) {
                    diagnostics.push_back(
                        make_diagnostic("PYC-OPERATOR", "binary operation selector is out of range", instruction.span));
                }
                if (instruction.opcode == Opcode::compare &&
                    instruction.immediate > static_cast<std::uint32_t>(CompareCode::not_contains)) {
                    diagnostics.push_back(make_diagnostic(
                        "PYC-OPERATOR", "comparison operation selector is out of range", instruction.span));
                }
                if (instruction.opcode == Opcode::call) {
                    if (instruction.immediate >= artifact.pack.functions.size() ||
                        instruction.operand_a > function.register_count ||
                        instruction.operand_b > function.register_count - instruction.operand_a) {
                        diagnostics.push_back(
                            make_diagnostic("PYC-CALL", "static call operand is out of range", instruction.span));
                    } else if (instruction.operand_b !=
                               artifact.pack.functions[instruction.immediate].parameter_count) {
                        diagnostics.push_back(
                            make_diagnostic("PYC-CALL", "static call argument count is invalid", instruction.span));
                    }
                }
                if (instruction.opcode == Opcode::yield_value && !function.generator && !function.async) {
                    diagnostics.push_back(make_diagnostic(
                        "PYC-YIELD", "yield opcode is outside a generator or async function", instruction.span));
                }
                if (instruction.opcode == Opcode::await_fact) {
                    if (instruction.immediate >= artifact.pack.constants.size()) {
                        diagnostics.push_back(make_diagnostic(
                            "PYC-FACT-OPERAND", "await_fact constant index is out of range", instruction.span));
                        continue;
                    }
                    const auto operand = decode_vm_fact_operand(artifact.pack.constants[instruction.immediate]);
                    if (!operand) {
                        diagnostics.push_back(make_diagnostic(
                            "PYC-FACT-OPERAND", "await_fact does not reference a canonical fact operand record",
                            instruction.span));
                        continue;
                    }
                    const auto requirement =
                        std::ranges::find_if(artifact.fact_requirements, [&](const FactRequirement &candidate) {
                            return candidate.executable == function.id &&
                                   candidate.operand_constant == instruction.immediate;
                        });
                    if (requirement == artifact.fact_requirements.end() ||
                        requirement->route.provider != operand->route.provider ||
                        requirement->route.fact != operand->route.fact ||
                        requirement->expected_schema != operand->expected_schema) {
                        diagnostics.push_back(make_diagnostic(
                            "PYC-FACT-OPERAND", "await_fact operand does not match its compiler requirement",
                            instruction.span));
                    }
                }
            }

            using RegisterState = std::vector<bool>;
            std::vector<std::optional<RegisterState>> states(function.instructions.size());
            std::deque<std::size_t> worklist;
            if (!function.instructions.empty()) {
                RegisterState entry(function.register_count, false);
                for (std::uint32_t parameter = 0U; parameter < function.parameter_count; ++parameter) {
                    entry[parameter] = true;
                }
                states.front() = std::move(entry);
                worklist.push_back(0U);
            }
            const auto merge_state = [&](const std::size_t successor, const RegisterState &candidate) {
                if (successor >= states.size()) {
                    return;
                }
                if (!states[successor]) {
                    states[successor] = candidate;
                    worklist.push_back(successor);
                    return;
                }
                auto merged = *states[successor];
                for (std::size_t reg = 0; reg < merged.size(); ++reg) { merged[reg] = merged[reg] && candidate[reg]; }
                if (merged != *states[successor]) {
                    states[successor] = std::move(merged);
                    worklist.push_back(successor);
                }
            };
            while (!worklist.empty()) {
                const auto pc = worklist.front();
                worklist.pop_front();
                const auto &instruction = function.instructions[pc];
                auto normal = *states[pc];
                switch (instruction.opcode) {
                    case Opcode::load_const:
                    case Opcode::move:
                    case Opcode::unary_op:
                    case Opcode::binary_op:
                    case Opcode::compare:
                    case Opcode::call:
                    case Opcode::await_fact:
                    case Opcode::await_capability:
                    case Opcode::read_state:
                        if (instruction.destination < normal.size()) {
                            normal[instruction.destination] = true;
                        }
                        break;
                    default: break;
                }
                if (instruction.opcode == Opcode::jump) {
                    merge_state(instruction.immediate, normal);
                } else if (instruction.opcode == Opcode::jump_if_false) {
                    merge_state(instruction.immediate, normal);
                    merge_state(pc + 1U, normal);
                } else if (instruction.opcode != Opcode::return_value && instruction.opcode != Opcode::raise_fault) {
                    merge_state(pc + 1U, normal);
                }
                for (const auto &region : function.exception_regions) {
                    if (pc < region.begin_instruction || pc >= region.end_instruction) {
                        continue;
                    }
                    auto exceptional = *states[pc];
                    if (instruction.destination < exceptional.size()) {
                        exceptional[instruction.destination] = true;
                    }
                    merge_state(region.handler_instruction, exceptional);
                }
            }
            for (std::size_t pc = 0; pc < states.size(); ++pc) {
                if (!states[pc]) {
                    continue;
                }
                const auto &instruction = function.instructions[pc];
                const auto require_initialized = [&](const std::uint32_t reg) {
                    if (reg < states[pc]->size() && !(*states[pc])[reg]) {
                        diagnostics.push_back(make_diagnostic("PYC-UNINITIALIZED",
                                                              "bytecode reads register " + std::to_string(reg) +
                                                                  " before initialization on every path",
                                                              instruction.span));
                    }
                };
                switch (instruction.opcode) {
                    case Opcode::move:
                    case Opcode::unary_op:
                    case Opcode::jump_if_false:
                    case Opcode::return_value:
                    case Opcode::raise_fault:
                    case Opcode::yield_value:
                    case Opcode::await_fact:
                    case Opcode::await_capability:
                    case Opcode::append_effect: require_initialized(instruction.operand_a); break;
                    case Opcode::binary_op:
                    case Opcode::compare:
                        require_initialized(instruction.operand_a);
                        require_initialized(instruction.operand_b);
                        break;
                    case Opcode::call:
                        for (std::uint32_t argument = 0U; argument < instruction.operand_b; ++argument) {
                            require_initialized(instruction.operand_a + argument);
                        }
                        break;
                    default: break;
                }
            }
        }
        for (const auto &requirement : artifact.fact_requirements) {
            const auto certificate = std::ranges::find(artifact.pack.optimization_certificates, requirement.executable,
                                                       &OptimizationCertificate::executable);
            if (certificate == artifact.pack.optimization_certificates.end() ||
                std::ranges::find(certificate->logical_facts, route_name(requirement.route)) ==
                    certificate->logical_facts.end()) {
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
