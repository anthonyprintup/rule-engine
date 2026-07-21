#include "rule_engine/python/compiler/ast.hpp"

#include "ast_internal.hpp"
#include "rule_engine/python/packaging/source_pack.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::compiler {
    namespace {

        constexpr std::size_t maximum_ast_string_bytes = 16U * mebibyte;
        constexpr std::size_t maximum_ast_integer_magnitude_bytes = 4U * kibibyte;
        constexpr std::size_t maximum_ast_name_bytes = 128U;
        constexpr std::uint64_t maximum_ast_values = balanced_v1.compile.ast_nodes * 16U;
        constexpr std::string_view expected_worker_build = "rule-engine-python-worker/1";
        constexpr std::string_view expected_worker_cache_tag = "cpython-314";
        constexpr std::string_view expected_worker_runtime = "3.14.6";
        constexpr std::string_view expected_worker_unicode = "16.0.0";

        Diagnostic json_diagnostic(std::string code, std::string message) {
            return Diagnostic {
                .code = std::move(code),
                .severity = DiagnosticSeverity::error,
                .message = std::move(message),
                .span = std::nullopt,
                .related = {},
            };
        }

        struct AstShape {
            std::string_view kind;
            std::string_view fields;
        };

        constexpr auto ast_shapes = std::to_array<AstShape>({
            {"Add", ""},
            {"And", ""},
            {"AnnAssign", "target|annotation|value|simple"},
            {"Assert", "test|msg"},
            {"Assign", "targets|value|type_comment"},
            {"AsyncFor", "target|iter|body|orelse|type_comment"},
            {"AsyncFunctionDef", "name|args|body|decorator_list|returns|type_comment|type_params"},
            {"AsyncWith", "items|body|type_comment"},
            {"Attribute", "value|attr|ctx"},
            {"AugAssign", "target|op|value"},
            {"AugLoad", ""},
            {"AugStore", ""},
            {"Await", "value"},
            {"BinOp", "left|op|right"},
            {"BitAnd", ""},
            {"BitOr", ""},
            {"BitXor", ""},
            {"BoolOp", "op|values"},
            {"Break", ""},
            {"Call", "func|args|keywords"},
            {"ClassDef", "name|bases|keywords|body|decorator_list|type_params"},
            {"Compare", "left|ops|comparators"},
            {"Constant", "value|kind"},
            {"Continue", ""},
            {"Del", ""},
            {"Delete", "targets"},
            {"Dict", "keys|values"},
            {"DictComp", "key|value|generators"},
            {"Div", ""},
            {"Eq", ""},
            {"ExceptHandler", "type|name|body"},
            {"Expr", "value"},
            {"Expression", "body"},
            {"ExtSlice", ""},
            {"FloorDiv", ""},
            {"For", "target|iter|body|orelse|type_comment"},
            {"FormattedValue", "value|conversion|format_spec"},
            {"FunctionDef", "name|args|body|decorator_list|returns|type_comment|type_params"},
            {"FunctionType", "argtypes|returns"},
            {"GeneratorExp", "elt|generators"},
            {"Global", "names"},
            {"Gt", ""},
            {"GtE", ""},
            {"If", "test|body|orelse"},
            {"IfExp", "test|body|orelse"},
            {"Import", "names"},
            {"ImportFrom", "module|names|level"},
            {"In", ""},
            {"Index", ""},
            {"Interactive", "body"},
            {"Interpolation", "value|str|conversion|format_spec"},
            {"Invert", ""},
            {"Is", ""},
            {"IsNot", ""},
            {"JoinedStr", "values"},
            {"LShift", ""},
            {"Lambda", "args|body"},
            {"List", "elts|ctx"},
            {"ListComp", "elt|generators"},
            {"Load", ""},
            {"Lt", ""},
            {"LtE", ""},
            {"MatMult", ""},
            {"Match", "subject|cases"},
            {"MatchAs", "pattern|name"},
            {"MatchClass", "cls|patterns|kwd_attrs|kwd_patterns"},
            {"MatchMapping", "keys|patterns|rest"},
            {"MatchOr", "patterns"},
            {"MatchSequence", "patterns"},
            {"MatchSingleton", "value"},
            {"MatchStar", "name"},
            {"MatchValue", "value"},
            {"Mod", ""},
            {"Module", "body|type_ignores"},
            {"Mult", ""},
            {"Name", "id|ctx"},
            {"NamedExpr", "target|value"},
            {"Nonlocal", "names"},
            {"Not", ""},
            {"NotEq", ""},
            {"NotIn", ""},
            {"Or", ""},
            {"Param", ""},
            {"ParamSpec", "name|default_value"},
            {"Pass", ""},
            {"Pow", ""},
            {"RShift", ""},
            {"Raise", "exc|cause"},
            {"Return", "value"},
            {"Set", "elts"},
            {"SetComp", "elt|generators"},
            {"Slice", "lower|upper|step"},
            {"Starred", "value|ctx"},
            {"Store", ""},
            {"Sub", ""},
            {"Subscript", "value|slice|ctx"},
            {"Suite", ""},
            {"TemplateStr", "values"},
            {"Try", "body|handlers|orelse|finalbody"},
            {"TryStar", "body|handlers|orelse|finalbody"},
            {"Tuple", "elts|ctx"},
            {"TypeAlias", "name|type_params|value"},
            {"TypeIgnore", "lineno|tag"},
            {"TypeVar", "name|bound|default_value"},
            {"TypeVarTuple", "name|default_value"},
            {"UAdd", ""},
            {"USub", ""},
            {"UnaryOp", "op|operand"},
            {"While", "test|body|orelse"},
            {"With", "items|body|type_comment"},
            {"Yield", "value"},
            {"YieldFrom", "value"},
            {"alias", "name|asname"},
            {"arg", "arg|annotation|type_comment"},
            {"arguments", "posonlyargs|args|vararg|kwonlyargs|kw_defaults|kwarg|defaults"},
            {"comprehension", "target|iter|ifs|is_async"},
            {"keyword", "arg|value"},
            {"match_case", "pattern|guard|body"},
            {"withitem", "context_expr|optional_vars"},
        });

        bool field_shape_matches(const std::string_view encoded, const std::vector<AstField> &fields) {
            if (encoded.empty()) {
                return fields.empty();
            }
            std::size_t begin {};
            std::size_t index {};
            while (begin <= encoded.size()) {
                const auto separator = encoded.find('|', begin);
                const auto end = separator == std::string_view::npos ? encoded.size() : separator;
                if (index >= fields.size() || fields[index].name != encoded.substr(begin, end - begin)) {
                    return false;
                }
                ++index;
                if (separator == std::string_view::npos) {
                    break;
                }
                begin = separator + 1U;
            }
            return index == fields.size();
        }

        struct JsonReader {
            std::string_view input;
            std::size_t offset {};
            std::optional<Diagnostic> failure;

            void fail(std::string code, std::string message) {
                if (!failure) {
                    failure = json_diagnostic(std::move(code), std::move(message));
                }
            }

            [[nodiscard]] char peek() const noexcept { return offset < input.size() ? input[offset] : '\0'; }

            bool consume(const char expected) noexcept {
                if (peek() != expected) {
                    return false;
                }
                ++offset;
                return true;
            }

            void expect(const char expected, const std::string_view context) {
                if (!consume(expected)) {
                    fail("PY-AST-JSON", "canonical AST JSON expected " + std::string {context});
                }
            }

            bool literal(const std::string_view expected) {
                if (input.substr(offset, expected.size()) != expected) {
                    return false;
                }
                offset += expected.size();
                return true;
            }

            std::string string(const std::size_t maximum) {
                if (!consume('"')) {
                    fail("PY-AST-JSON", "canonical AST JSON expected a string");
                    return {};
                }
                std::string result;
                while (offset < input.size()) {
                    const auto raw = static_cast<unsigned char>(input[offset++]);
                    if (raw == static_cast<unsigned char>('"')) {
                        return result;
                    }
                    if (raw < 0x20U || raw > 0x7eU) {
                        fail("PY-AST-JSON", "canonical AST JSON strings must be ASCII encoded");
                        return {};
                    }
                    auto character = static_cast<char>(raw);
                    if (character == '\\') {
                        if (offset >= input.size() || (input[offset] != '"' && input[offset] != '\\')) {
                            fail("PY-AST-JSON", "canonical AST JSON contains a noncanonical string escape");
                            return {};
                        }
                        character = input[offset++];
                    }
                    if (result.size() == maximum) {
                        fail("PY-AST-LIMIT", "AST JSON string exceeds its configured limit");
                        return {};
                    }
                    result.push_back(character);
                }
                fail("PY-AST-JSON", "canonical AST JSON string is truncated");
                return {};
            }

            std::uint32_t unsigned_integer(const std::uint32_t maximum, const std::string_view context) {
                if (peek() < '0' || peek() > '9') {
                    fail("PY-AST-JSON", "canonical AST JSON expected " + std::string {context});
                    return 0U;
                }
                if (peek() == '0') {
                    ++offset;
                    if (peek() >= '0' && peek() <= '9') {
                        fail("PY-AST-JSON", "canonical AST JSON integers cannot contain leading zeroes");
                    }
                    return 0U;
                }
                std::uint64_t value {};
                while (peek() >= '0' && peek() <= '9') {
                    const auto digit = static_cast<std::uint64_t>(peek() - '0');
                    if (digit > maximum || value > (static_cast<std::uint64_t>(maximum) - digit) / 10U) {
                        fail("PY-AST-LIMIT", "AST JSON integer exceeds its configured limit");
                        return 0U;
                    }
                    value = value * 10U + digit;
                    ++offset;
                }
                return static_cast<std::uint32_t>(value);
            }

            bool boolean() {
                if (literal("true")) {
                    return true;
                }
                if (literal("false")) {
                    return false;
                }
                fail("PY-AST-JSON", "canonical AST JSON expected a boolean");
                return false;
            }

            void expected_key(const std::string_view expected) {
                const auto key = string(maximum_ast_name_bytes);
                if (failure) {
                    return;
                }
                if (key != expected) {
                    fail("PY-AST-JSON-FIELD",
                         "AST JSON field '" + key + "' is duplicate, unknown, missing, or out of canonical order");
                    return;
                }
                expect(':', "':' after field name");
            }
        };

        int base64_digit(const char character, const bool urlsafe) noexcept {
            if (character >= 'A' && character <= 'Z') {
                return character - 'A';
            }
            if (character >= 'a' && character <= 'z') {
                return character - 'a' + 26;
            }
            if (character >= '0' && character <= '9') {
                return character - '0' + 52;
            }
            if (character == (urlsafe ? '-' : '+')) {
                return 62;
            }
            if (character == (urlsafe ? '_' : '/')) {
                return 63;
            }
            return -1;
        }

        std::optional<std::vector<std::byte>> decode_base64(const std::string_view text, const bool urlsafe,
                                                            const std::size_t maximum) {
            std::size_t padding {};
            if (!urlsafe) {
                while (padding < text.size() && text[text.size() - 1U - padding] == '=') { ++padding; }
                if (padding > 2U || text.size() % 4U != 0U) {
                    return std::nullopt;
                }
            } else if (text.find('=') != std::string_view::npos) {
                return std::nullopt;
            }
            const auto encoded_size = text.size() - padding;
            if (encoded_size % 4U == 1U || (!urlsafe && padding != (4U - encoded_size % 4U) % 4U)) {
                return std::nullopt;
            }
            const auto output_size = (encoded_size * 6U) / 8U;
            if (output_size > maximum) {
                return std::nullopt;
            }
            std::vector<std::byte> output;
            output.reserve(output_size);
            std::uint32_t accumulator {};
            std::uint32_t bits {};
            for (std::size_t index = 0; index < encoded_size; ++index) {
                const auto digit = base64_digit(text[index], urlsafe);
                if (digit < 0) {
                    return std::nullopt;
                }
                accumulator = (accumulator << 6U) | static_cast<std::uint32_t>(digit);
                bits += 6U;
                if (bits >= 8U) {
                    bits -= 8U;
                    output.push_back(static_cast<std::byte>((accumulator >> bits) & 0xffU));
                }
            }
            if (bits != 0U && (accumulator & ((1U << bits) - 1U)) != 0U) {
                return std::nullopt;
            }
            return output;
        }

        bool valid_wtf8(const std::span<const std::byte> bytes) noexcept {
            const auto continuation = [](const std::byte value) {
                const auto byte = std::to_integer<std::uint8_t>(value);
                return byte >= 0x80U && byte <= 0xbfU;
            };
            for (std::size_t index = 0; index < bytes.size();) {
                const auto lead = std::to_integer<std::uint8_t>(bytes[index]);
                if (lead <= 0x7fU) {
                    ++index;
                    continue;
                }
                if (lead >= 0xc2U && lead <= 0xdfU) {
                    if (index + 1U >= bytes.size() || !continuation(bytes[index + 1U])) {
                        return false;
                    }
                    index += 2U;
                    continue;
                }
                if (lead >= 0xe0U && lead <= 0xefU) {
                    if (index + 2U >= bytes.size() || !continuation(bytes[index + 1U]) ||
                        !continuation(bytes[index + 2U])) {
                        return false;
                    }
                    const auto second = std::to_integer<std::uint8_t>(bytes[index + 1U]);
                    if (lead == 0xe0U && second < 0xa0U) {
                        return false;
                    }
                    index += 3U;
                    continue;
                }
                if (lead >= 0xf0U && lead <= 0xf4U) {
                    if (index + 3U >= bytes.size() || !continuation(bytes[index + 1U]) ||
                        !continuation(bytes[index + 2U]) || !continuation(bytes[index + 3U])) {
                        return false;
                    }
                    const auto second = std::to_integer<std::uint8_t>(bytes[index + 1U]);
                    if ((lead == 0xf0U && second < 0x90U) || (lead == 0xf4U && second > 0x8fU)) {
                        return false;
                    }
                    index += 4U;
                    continue;
                }
                return false;
            }
            return true;
        }

        std::optional<std::string> decimal_integer(const std::vector<std::byte> &magnitude, const bool negative) {
            if (magnitude.size() > maximum_ast_integer_magnitude_bytes ||
                (!magnitude.empty() && magnitude.front() == std::byte {0})) {
                return std::nullopt;
            }
            if (magnitude.empty()) {
                return negative ? std::nullopt : std::optional<std::string> {"0"};
            }
            constexpr std::uint64_t limb_base = 1'000'000'000U;
            std::vector<std::uint32_t> limbs {0U};
            for (const auto raw : magnitude) {
                std::uint64_t carry = std::to_integer<std::uint8_t>(raw);
                for (auto &limb : limbs) {
                    const auto expanded = static_cast<std::uint64_t>(limb) * 256U + carry;
                    limb = static_cast<std::uint32_t>(expanded % limb_base);
                    carry = expanded / limb_base;
                }
                if (carry != 0U) {
                    limbs.push_back(static_cast<std::uint32_t>(carry));
                }
            }
            std::string result = negative ? "-" : "";
            result += std::to_string(limbs.back());
            for (auto iterator = limbs.rbegin() + 1; iterator != limbs.rend(); ++iterator) {
                const auto part = std::to_string(*iterator);
                result.append(9U - part.size(), '0');
                result += part;
            }
            return result;
        }

        struct RawSpan {
            std::uint32_t line {};
            std::uint32_t column {};
            std::uint32_t end_line {};
            std::uint32_t end_column {};
        };

        struct AstJsonParser {
            JsonReader reader;
            const VerifiedRulePack &pack;
            const SourceFile &source;
            std::vector<AstNode> nodes;
            std::vector<std::optional<AstNodeId>> parents;
            std::vector<std::optional<RawSpan>> spans;
            std::uint64_t value_count {};
            std::uint64_t token_count {};

            AstValue value(const std::optional<AstNodeId> parent, const std::uint32_t depth) {
                if (depth > maximum_ast_depth) {
                    reader.fail("PY-AST-DEPTH", "AST JSON value nesting exceeds 512");
                    return ast_none();
                }
                ++value_count;
                if (value_count > maximum_ast_values) {
                    reader.fail("PY-AST-LIMIT", "AST JSON value count exceeds its configured limit");
                    return ast_none();
                }
                if (reader.literal("null")) {
                    return ast_none();
                }
                if (reader.peek() == 't' || reader.peek() == 'f') {
                    return ast_bool(reader.boolean());
                }
                if (reader.peek() == '[') {
                    return sequence(parent, depth + 1U);
                }
                if (reader.peek() == '{') {
                    return tagged(parent, depth + 1U);
                }
                reader.fail("PY-AST-JSON", "AST JSON value has an unsupported canonical type");
                return ast_none();
            }

            AstValue sequence(const std::optional<AstNodeId> parent, const std::uint32_t depth) {
                reader.expect('[', "'[' for AST sequence");
                std::vector<AstValue> values;
                if (reader.consume(']')) {
                    return ast_sequence(std::move(values));
                }
                while (!reader.failure) {
                    if (values.size() >= balanced_v1.compile.ast_nodes) {
                        reader.fail("PY-AST-LIMIT", "AST JSON sequence exceeds the node budget");
                        break;
                    }
                    values.push_back(value(parent, depth));
                    if (!reader.consume(',')) {
                        break;
                    }
                }
                reader.expect(']', "']' after AST sequence");
                return ast_sequence(std::move(values));
            }

            AstValue tagged(const std::optional<AstNodeId> parent, const std::uint32_t depth) {
                reader.expect('{', "'{' for tagged AST value");
                reader.expected_key("$");
                const auto tag = reader.string(32U);
                if (tag == "ast") {
                    return ast_node(parent, depth);
                }
                if (tag == "str") {
                    reader.expect(',', "',' after AST string tag");
                    reader.expected_key("wtf8_base64");
                    const auto encoded = reader.string(maximum_ast_payload_bytes);
                    reader.expect('}', "'}' after AST string");
                    const auto decoded = decode_base64(encoded, true, maximum_ast_string_bytes);
                    if (!decoded) {
                        reader.fail("PY-AST-JSON", "AST string is not canonical bounded URL-safe base64");
                        return ast_none();
                    }
                    if (!valid_wtf8(*decoded)) {
                        reader.fail("PY-AST-STRING", "AST string is not valid WTF-8");
                        return ast_none();
                    }
                    auto text = std::string {};
                    if (!decoded->empty()) {
                        text.assign(reinterpret_cast<const char *>(decoded->data()), decoded->size());
                    }
                    return ast_string(std::move(text));
                }
                if (tag == "bytes") {
                    reader.expect(',', "',' after AST bytes tag");
                    reader.expected_key("base64");
                    const auto encoded = reader.string(maximum_ast_payload_bytes);
                    reader.expect('}', "'}' after AST bytes");
                    const auto decoded = decode_base64(encoded, false, maximum_ast_string_bytes);
                    if (!decoded) {
                        reader.fail("PY-AST-JSON", "AST bytes are not canonical bounded base64");
                        return ast_none();
                    }
                    return ast_bytes(*decoded);
                }
                if (tag == "int") {
                    reader.expect(',', "',' after AST integer tag");
                    reader.expected_key("negative");
                    const auto negative = reader.boolean();
                    reader.expect(',', "',' after AST integer sign");
                    reader.expected_key("magnitude_be");
                    const auto encoded = reader.string(maximum_ast_payload_bytes);
                    reader.expect('}', "'}' after AST integer");
                    const auto magnitude = decode_base64(encoded, true, maximum_ast_integer_magnitude_bytes);
                    const auto decimal = magnitude ? decimal_integer(*magnitude, negative) : std::nullopt;
                    if (!decimal) {
                        reader.fail("PY-AST-INTEGER", "AST integer magnitude is not canonical or bounded");
                        return ast_none();
                    }
                    return ast_integer(*decimal);
                }
                if (tag == "float64") {
                    reader.expect(',', "',' after AST float tag");
                    reader.expected_key("bits");
                    const auto encoded = reader.string(16U);
                    reader.expect('}', "'}' after AST float");
                    if (encoded.size() != 16U) {
                        reader.fail("PY-AST-JSON", "AST float bits must contain 16 lowercase hexadecimal digits");
                        return ast_none();
                    }
                    std::uint64_t bits {};
                    for (const auto character : encoded) {
                        std::uint8_t digit {};
                        if (character >= '0' && character <= '9') {
                            digit = static_cast<std::uint8_t>(character - '0');
                        } else if (character >= 'a' && character <= 'f') {
                            digit = static_cast<std::uint8_t>(character - 'a' + 10);
                        } else {
                            reader.fail("PY-AST-JSON", "AST float bits are not canonical lowercase hexadecimal");
                            return ast_none();
                        }
                        bits = (bits << 4U) | digit;
                    }
                    return ast_float_bits(bits);
                }
                if (tag == "ellipsis") {
                    reader.expect('}', "'}' after AST ellipsis");
                    reader.fail("PY-AST-VALUE", "Ellipsis is outside the supported static value model");
                    return ast_none();
                }
                reader.fail("PY-AST-JSON-FIELD", "AST JSON contains an unknown tagged value '" + tag + "'");
                return ast_none();
            }

            AstValue ast_node(const std::optional<AstNodeId> parent, const std::uint32_t depth) {
                reader.expect(',', "',' after AST node tag");
                reader.expected_key("kind");
                auto kind = reader.string(maximum_ast_name_bytes);
                const auto shape = std::ranges::lower_bound(ast_shapes, kind, {}, &AstShape::kind);
                if (shape == ast_shapes.end() || shape->kind != kind) {
                    reader.fail("PY-AST-NODE", "AST JSON node kind '" + kind + "' is unknown to CPython 3.14");
                    return ast_none();
                }
                if (nodes.size() >= balanced_v1.compile.ast_nodes ||
                    nodes.size() >= std::numeric_limits<AstNodeId>::max()) {
                    reader.fail("PY-AST-LIMIT", "AST JSON node count exceeds balanced.v1");
                    return ast_none();
                }
                const auto id = static_cast<AstNodeId>(nodes.size() + 1U);
                const auto node_index = nodes.size();
                nodes.push_back(AstNode {
                    .id = id,
                    .kind = std::move(kind),
                    .span = {.source = source.id, .begin_byte = 0U, .end_byte = 0U},
                    .fields = {},
                });
                parents.push_back(parent);
                spans.push_back(std::nullopt);

                reader.expect(',', "',' after AST node kind");
                reader.expected_key("fields");
                auto fields = node_fields(id, depth + 1U);
                if (!field_shape_matches(shape->fields, fields)) {
                    reader.fail("PY-AST-JSON-FIELD",
                                "AST JSON fields for '" + nodes[node_index].kind +
                                    "' are missing, unknown, duplicate, or out of canonical order");
                }
                reader.expect(',', "',' after AST node fields");
                reader.expected_key("span");
                auto raw_span = node_span();
                reader.expect('}', "'}' after AST node");
                nodes[node_index].fields = std::move(fields);
                spans[node_index] = raw_span;
                return ast_reference(id);
            }

            std::vector<AstField> node_fields(const AstNodeId parent, const std::uint32_t depth) {
                reader.expect('{', "'{' for AST node fields");
                std::vector<AstField> fields;
                std::set<std::string, std::less<>> names;
                if (reader.consume('}')) {
                    return fields;
                }
                while (!reader.failure) {
                    if (fields.size() >= 1024U) {
                        reader.fail("PY-AST-LIMIT", "AST JSON node field count exceeds 1024");
                        break;
                    }
                    auto name = reader.string(maximum_ast_name_bytes);
                    if (!names.insert(name).second) {
                        reader.fail("PY-AST-JSON-FIELD", "AST JSON node contains duplicate field '" + name + "'");
                        break;
                    }
                    reader.expect(':', "':' after AST node field");
                    fields.push_back(AstField {.name = std::move(name), .value = value(parent, depth)});
                    if (!reader.consume(',')) {
                        break;
                    }
                }
                reader.expect('}', "'}' after AST node fields");
                return fields;
            }

            std::optional<std::uint32_t> optional_position(const std::string_view context) {
                if (reader.literal("null")) {
                    return std::nullopt;
                }
                return reader.unsigned_integer(std::numeric_limits<std::uint32_t>::max(), context);
            }

            std::optional<RawSpan> node_span() {
                if (reader.literal("null")) {
                    return std::nullopt;
                }
                reader.expect('{', "'{' for AST span");
                reader.expected_key("col");
                const auto column = optional_position("AST span column");
                reader.expect(',', "',' after AST span column");
                reader.expected_key("end_col");
                const auto end_column = optional_position("AST span end column");
                reader.expect(',', "',' after AST span end column");
                reader.expected_key("end_line");
                const auto end_line = optional_position("AST span end line");
                reader.expect(',', "',' after AST span end line");
                reader.expected_key("line");
                const auto line = optional_position("AST span line");
                reader.expect('}', "'}' after AST span");
                if (!line || !column || !end_line || !end_column || *line == 0U || *end_line == 0U) {
                    reader.fail("PY-AST-SPAN", "AST JSON source span is incomplete");
                    return std::nullopt;
                }
                return RawSpan {.line = *line, .column = *column, .end_line = *end_line, .end_column = *end_column};
            }

            std::string token_string() {
                reader.expect('{', "'{' for token string");
                reader.expected_key("$");
                const auto tag = reader.string(16U);
                if (tag != "str") {
                    reader.fail("PY-AST-JSON-FIELD", "AST token string has an unknown tagged value");
                    return {};
                }
                reader.expect(',', "',' after token string tag");
                reader.expected_key("wtf8_base64");
                const auto encoded = reader.string(maximum_ast_payload_bytes);
                reader.expect('}', "'}' after token string");
                const auto decoded = decode_base64(encoded, true, maximum_ast_string_bytes);
                if (!decoded) {
                    reader.fail("PY-AST-JSON", "AST token string is not canonical bounded URL-safe base64");
                    return {};
                }
                if (!valid_wtf8(*decoded)) {
                    reader.fail("PY-AST-STRING", "AST token string is not valid WTF-8");
                    return {};
                }
                if (decoded->empty()) {
                    return {};
                }
                return {reinterpret_cast<const char *>(decoded->data()), decoded->size()};
            }

            std::array<std::uint32_t, 2> token_position() {
                reader.expect('[', "'[' for token position");
                const auto line = reader.unsigned_integer(std::numeric_limits<std::uint32_t>::max(), "token line");
                reader.expect(',', "',' in token position");
                const auto column = reader.unsigned_integer(std::numeric_limits<std::uint32_t>::max(), "token column");
                reader.expect(']', "']' after token position");
                return {line, column};
            }

            void token() {
                reader.expect('{', "'{' for token");
                reader.expected_key("end");
                const auto end = token_position();
                reader.expect(',', "',' after token end");
                reader.expected_key("start");
                const auto start = token_position();
                reader.expect(',', "',' after token start");
                reader.expected_key("string");
                static_cast<void>(token_string());
                reader.expect(',', "',' after token string");
                reader.expected_key("type");
                static_cast<void>(reader.unsigned_integer(std::numeric_limits<std::uint32_t>::max(), "token type"));
                reader.expect('}', "'}' after token");
                if (start[0] > end[0] || (start[0] == end[0] && start[1] > end[1])) {
                    reader.fail("PY-AST-JSON", "AST token range is reversed");
                }
            }

            void tokens() {
                reader.expect('[', "'[' for token table");
                if (reader.consume(']')) {
                    return;
                }
                while (!reader.failure) {
                    if (++token_count > balanced_v1.compile.ast_nodes) {
                        reader.fail("PY-AST-LIMIT", "AST token count exceeds balanced.v1");
                        break;
                    }
                    token();
                    if (!reader.consume(',')) {
                        break;
                    }
                }
                reader.expect(']', "']' after token table");
            }

            void worker() {
                reader.expect('{', "'{' for worker identity");
                reader.expected_key("build");
                const auto build = reader.string(64U);
                reader.expect(',', "',' after worker build");
                reader.expected_key("cache_tag");
                const auto cache_tag = reader.string(64U);
                reader.expect(',', "',' after worker cache tag");
                reader.expected_key("python");
                const auto runtime = reader.string(64U);
                reader.expect(',', "',' after worker runtime");
                reader.expected_key("unicode");
                const auto unicode = reader.string(64U);
                reader.expect('}', "'}' after worker identity");
                if (build != expected_worker_build || cache_tag != expected_worker_cache_tag ||
                    runtime != expected_worker_runtime || unicode != expected_worker_unicode) {
                    reader.fail("PY-AST-RUNTIME", "AST JSON worker identity is not the exact CPython 3.14.6 format");
                }
            }

            std::optional<std::uint32_t> byte_offset(const std::vector<std::size_t> &line_starts,
                                                     const std::uint32_t line, const std::uint32_t column) {
                if (line == 0U || line > line_starts.size()) {
                    return std::nullopt;
                }
                const auto start = line_starts[line - 1U];
                auto end = line == line_starts.size() ? source.utf8.size() : line_starts[line] - 1U;
                if (end < start || column > end - start || start + column > std::numeric_limits<std::uint32_t>::max()) {
                    return std::nullopt;
                }
                return static_cast<std::uint32_t>(start + column);
            }

            void resolve_spans() {
                std::vector<std::size_t> line_starts {0U};
                for (std::size_t index = 0; index < source.utf8.size(); ++index) {
                    if (source.utf8[index] == '\n') {
                        line_starts.push_back(index + 1U);
                    }
                }
                for (std::size_t index = 0; index < nodes.size() && !reader.failure; ++index) {
                    if (spans[index]) {
                        const auto begin = byte_offset(line_starts, spans[index]->line, spans[index]->column);
                        const auto end = byte_offset(line_starts, spans[index]->end_line, spans[index]->end_column);
                        if (!begin || !end || *begin > *end) {
                            reader.fail("PY-AST-SPAN", "AST JSON span is outside the verified UTF-8 source");
                            return;
                        }
                        nodes[index].span = {.source = source.id, .begin_byte = *begin, .end_byte = *end};
                        continue;
                    }
                    if (parents[index]) {
                        const auto parent_index = static_cast<std::size_t>(*parents[index] - 1U);
                        if (parent_index >= index) {
                            reader.fail("PY-AST-JSON", "AST JSON parent ordering is invalid");
                            return;
                        }
                        nodes[index].span = nodes[parent_index].span;
                        continue;
                    }
                    nodes[index].span = {.source = source.id,
                                         .begin_byte = 0U,
                                         .end_byte = static_cast<std::uint32_t>(source.utf8.size())};
                }
            }

            std::expected<AstEnvelope, DiagnosticSet> parse() {
                reader.expect('{', "'{' for AST envelope");
                reader.expected_key("ast");
                const auto root_value = value(std::nullopt, 0U);
                const auto *root = std::get_if<AstNodeReference>(&root_value.data);
                if (!root) {
                    reader.fail("PY-AST-ROOT", "AST JSON root must be a tagged Module node");
                }
                reader.expect(',', "',' after AST root");
                reader.expected_key("format");
                const auto format = reader.unsigned_integer(std::numeric_limits<std::uint32_t>::max(), "AST format");
                if (format != 1U) {
                    reader.fail("PY-AST-VERSION", "AST JSON format must be version 1");
                }
                reader.expect(',', "',' after AST format");
                reader.expected_key("schema");
                const auto schema = reader.string(64U);
                if (schema != ast_envelope_media_type) {
                    reader.fail("PY-AST-VERSION", "AST JSON schema must be rule-engine.ast/1");
                }
                reader.expect(',', "',' after AST schema");
                reader.expected_key("tokens");
                tokens();
                reader.expect(',', "',' after AST token table");
                reader.expected_key("worker");
                worker();
                reader.expect('}', "'}' after AST envelope");
                if (!reader.failure && reader.offset != reader.input.size()) {
                    reader.fail("PY-AST-JSON", "AST JSON envelope contains trailing bytes");
                }
                if (!reader.failure) {
                    resolve_spans();
                }
                if (reader.failure) {
                    return std::unexpected(DiagnosticSet {*std::move(reader.failure)});
                }
                AstEnvelope envelope {
                    .protocol_major = ast_envelope_protocol_major,
                    .protocol_minor = ast_envelope_protocol_minor,
                    .grammar_major = python_grammar_major,
                    .grammar_minor = python_grammar_minor,
                    .worker_runtime = std::string {expected_worker_runtime},
                    .source_digest = pack.closure_digest,
                    .modules = {{.name = source.module, .source = source.id, .root = root->id}},
                    .nodes = std::move(nodes),
                };
                return detail::finish_ast_envelope(std::move(envelope), pack);
            }
        };

    } // namespace

    std::expected<AstEnvelope, DiagnosticSet> decode_worker_ast_json(const std::span<const std::byte> payload,
                                                                     const VerifiedRulePack &pack,
                                                                     const SourceFile &source,
                                                                     const SourceDigest &payload_source_digest) {
        if (payload.size() > maximum_ast_payload_bytes) {
            return std::unexpected(DiagnosticSet {json_diagnostic("PY-AST-LIMIT", "AST JSON exceeds 64 MiB")});
        }
        if (source.utf8.size() > balanced_v1.compile.source_closure_bytes ||
            source.utf8.size() > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected(DiagnosticSet {json_diagnostic("PY-AST-LIMIT", "AST source exceeds balanced.v1")});
        }
        if (source.utf8.starts_with("\xEF\xBB\xBF") || source.utf8.find('\r') != std::string::npos) {
            return std::unexpected(DiagnosticSet {
                json_diagnostic("PY-AST-SOURCE", "AST source must be canonical UTF-8 without BOM or CR bytes")});
        }
        const auto source_bytes = std::as_bytes(std::span {source.utf8.data(), source.utf8.size()});
        const SourceDigest actual_digest {"sha256:" + packaging::sha256_hex(source_bytes)};
        const auto source_is_verified = std::ranges::any_of(pack.sources, [&](const SourceFile &candidate) {
            return candidate.id == source.id && candidate.module == source.module && candidate.utf8 == source.utf8 &&
                   candidate.digest == source.digest;
        });
        if (!source_is_verified || payload_source_digest != source.digest || actual_digest != source.digest) {
            return std::unexpected(DiagnosticSet {
                json_diagnostic("PY-AST-SOURCE", "AST JSON digest does not match the verified module bytes")});
        }
        const auto text = payload.empty() ?
                              std::string_view {} :
                              std::string_view {reinterpret_cast<const char *>(payload.data()), payload.size()};
        AstJsonParser parser {
            .reader = {.input = text, .offset = 0U, .failure = std::nullopt},
            .pack = pack,
            .source = source,
            .nodes = {},
            .parents = {},
            .spans = {},
            .value_count = 0U,
            .token_count = 0U,
        };
        return parser.parse();
    }

} // namespace rule_engine::python::compiler
