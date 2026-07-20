#include "rule_engine/python/compiler/ast.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <type_traits>
#include <utility>

namespace rule_engine::python::compiler {
    namespace {

        constexpr std::string_view expected_worker_runtime = "3.14.6";

        Diagnostic diagnostic(std::string code, std::string message, std::optional<SourceSpan> span = std::nullopt) {
            return Diagnostic {
                .code = std::move(code),
                .severity = DiagnosticSeverity::error,
                .message = std::move(message),
                .span = std::move(span),
                .related = {},
            };
        }

        struct Writer {
            std::vector<std::byte> bytes;
            DiagnosticSet diagnostics;

            void raw(const std::string_view value) {
                bytes.reserve(bytes.size() + value.size());
                for (const auto character : value) {
                    bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
                }
            }

            void u8(const std::uint8_t value) { bytes.push_back(static_cast<std::byte>(value)); }

            void u16(const std::uint16_t value) {
                u8(static_cast<std::uint8_t>(value & 0xffU));
                u8(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
            }

            void u32(const std::uint32_t value) {
                for (auto shift = 0U; shift < 32U; shift += 8U) {
                    u8(static_cast<std::uint8_t>((value >> shift) & 0xffU));
                }
            }

            void u64(const std::uint64_t value) {
                for (auto shift = 0U; shift < 64U; shift += 8U) {
                    u8(static_cast<std::uint8_t>((value >> shift) & 0xffU));
                }
            }

            void string(const std::string_view value) {
                if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
                    diagnostics.push_back(diagnostic("PY-AST-LIMIT", "AST envelope string exceeds the wire limit"));
                    return;
                }
                u32(static_cast<std::uint32_t>(value.size()));
                raw(value);
            }

            void byte_string(const std::vector<std::byte> &value) {
                if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
                    diagnostics.push_back(diagnostic("PY-AST-LIMIT", "AST byte constant exceeds the wire limit"));
                    return;
                }
                u32(static_cast<std::uint32_t>(value.size()));
                bytes.insert(bytes.end(), value.begin(), value.end());
            }
        };

        bool encode_value(Writer &writer, const AstValue &value, const std::uint32_t depth) {
            if (depth > maximum_ast_depth) {
                writer.diagnostics.push_back(diagnostic("PY-AST-DEPTH", "AST value nesting exceeds 512"));
                return false;
            }

            std::visit(
                [&writer, depth](const auto &item) {
                    using Item = std::remove_cvref_t<decltype(item)>;
                    if constexpr (std::is_same_v<Item, std::monostate>) {
                        writer.u8(0);
                    } else if constexpr (std::is_same_v<Item, bool>) {
                        writer.u8(item ? 2 : 1);
                    } else if constexpr (std::is_same_v<Item, IntegerValue>) {
                        writer.u8(3);
                        writer.string(item.decimal);
                    } else if constexpr (std::is_same_v<Item, AstFloatBits>) {
                        writer.u8(4);
                        writer.u64(item.bits);
                    } else if constexpr (std::is_same_v<Item, UnicodeValue>) {
                        writer.u8(5);
                        writer.string(item.utf8);
                    } else if constexpr (std::is_same_v<Item, BytesValue>) {
                        writer.u8(6);
                        writer.byte_string(item.bytes);
                    } else if constexpr (std::is_same_v<Item, AstNodeReference>) {
                        writer.u8(7);
                        writer.u32(item.id);
                    } else if constexpr (std::is_same_v<Item, AstValue::Sequence>) {
                        writer.u8(8);
                        if (!item) {
                            writer.diagnostics.push_back(diagnostic("PY-AST-SEQUENCE", "AST sequence handle is empty"));
                            writer.u32(0);
                            return;
                        }
                        if (item->values.size() > balanced_v1.compile.ast_nodes) {
                            writer.diagnostics.push_back(
                                diagnostic("PY-AST-LIMIT", "AST sequence exceeds the node budget"));
                            writer.u32(0);
                            return;
                        }
                        writer.u32(static_cast<std::uint32_t>(item->values.size()));
                        for (const auto &child : item->values) { encode_value(writer, child, depth + 1); }
                    }
                },
                value.data);
            return writer.diagnostics.empty();
        }

        struct Reader {
            std::span<const std::byte> bytes;
            std::size_t offset {};
            std::optional<Diagnostic> failure;

            [[nodiscard]] bool remaining(const std::size_t count) const noexcept {
                return count <= bytes.size() - std::min(offset, bytes.size());
            }

            std::uint8_t u8() {
                if (!remaining(1)) {
                    fail("PY-AST-TRUNCATED", "AST envelope ended unexpectedly");
                    return 0;
                }
                return std::to_integer<std::uint8_t>(bytes[offset++]);
            }

            std::uint16_t u16() {
                const auto low = u8();
                const auto high = u8();
                return static_cast<std::uint16_t>(low | static_cast<std::uint16_t>(high << 8U));
            }

            std::uint32_t u32() {
                std::uint32_t value {};
                for (auto shift = 0U; shift < 32U; shift += 8U) { value |= static_cast<std::uint32_t>(u8()) << shift; }
                return value;
            }

            std::uint64_t u64() {
                std::uint64_t value {};
                for (auto shift = 0U; shift < 64U; shift += 8U) { value |= static_cast<std::uint64_t>(u8()) << shift; }
                return value;
            }

            std::string string(const std::size_t maximum = 16 * mebibyte) {
                const auto size = static_cast<std::size_t>(u32());
                if (failure) {
                    return {};
                }
                if (size > maximum) {
                    fail("PY-AST-LIMIT", "AST envelope string exceeds its configured limit");
                    return {};
                }
                if (!remaining(size)) {
                    fail("PY-AST-TRUNCATED", "AST envelope string extends past the payload");
                    return {};
                }
                std::string result;
                result.reserve(size);
                for (std::size_t index = 0; index < size; ++index) {
                    result.push_back(static_cast<char>(std::to_integer<unsigned char>(bytes[offset + index])));
                }
                offset += size;
                return result;
            }

            std::vector<std::byte> byte_string() {
                const auto size = static_cast<std::size_t>(u32());
                if (failure) {
                    return {};
                }
                if (size > 16 * mebibyte || !remaining(size)) {
                    fail(size > 16 * mebibyte ? "PY-AST-LIMIT" : "PY-AST-TRUNCATED",
                         size > 16 * mebibyte ? "AST byte constant exceeds its configured limit" :
                                                "AST byte constant extends past the payload");
                    return {};
                }
                std::vector<std::byte> result(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                              bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
                offset += size;
                return result;
            }

            void fail(std::string code, std::string message) {
                if (!failure) {
                    failure = diagnostic(std::move(code), std::move(message));
                }
            }
        };

        AstValue decode_value(Reader &reader, const std::uint32_t depth) {
            if (depth > maximum_ast_depth) {
                reader.fail("PY-AST-DEPTH", "AST value nesting exceeds 512");
                return ast_none();
            }
            switch (reader.u8()) {
                case 0: return ast_none();
                case 1: return ast_bool(false);
                case 2: return ast_bool(true);
                case 3: return ast_integer(reader.string());
                case 4: return ast_float_bits(reader.u64());
                case 5: return ast_string(reader.string());
                case 6: return ast_bytes(reader.byte_string());
                case 7: return ast_reference(reader.u32());
                case 8: {
                    const auto count = reader.u32();
                    if (count > balanced_v1.compile.ast_nodes) {
                        reader.fail("PY-AST-LIMIT", "AST sequence exceeds the node budget");
                        return ast_sequence({});
                    }
                    std::vector<AstValue> values;
                    values.reserve(count);
                    for (std::uint32_t index = 0; index < count && !reader.failure; ++index) {
                        values.push_back(decode_value(reader, depth + 1));
                    }
                    return ast_sequence(std::move(values));
                }
                default: reader.fail("PY-AST-TAG", "AST envelope contains an unknown value tag"); return ast_none();
            }
        }

        bool valid_utf8(const std::string_view text) {
            for (std::size_t index = 0; index < text.size();) {
                const auto lead = static_cast<unsigned char>(text[index]);
                std::size_t length {};
                std::uint32_t codepoint {};
                if (lead <= 0x7fU) {
                    length = 1;
                    codepoint = lead;
                } else if ((lead & 0xe0U) == 0xc0U) {
                    length = 2;
                    codepoint = lead & 0x1fU;
                } else if ((lead & 0xf0U) == 0xe0U) {
                    length = 3;
                    codepoint = lead & 0x0fU;
                } else if ((lead & 0xf8U) == 0xf0U) {
                    length = 4;
                    codepoint = lead & 0x07U;
                } else {
                    return false;
                }
                if (index + length > text.size()) {
                    return false;
                }
                for (std::size_t part = 1; part < length; ++part) {
                    const auto next = static_cast<unsigned char>(text[index + part]);
                    if ((next & 0xc0U) != 0x80U) {
                        return false;
                    }
                    codepoint = (codepoint << 6U) | (next & 0x3fU);
                }
                if ((length == 2 && codepoint < 0x80U) || (length == 3 && codepoint < 0x800U) ||
                    (length == 4 && codepoint < 0x10000U) || (codepoint >= 0xd800U && codepoint <= 0xdfffU) ||
                    codepoint > 0x10ffffU) {
                    return false;
                }
                index += length;
            }
            return true;
        }

        bool utf8_boundary(const std::string_view text, const std::uint32_t offset) {
            if (offset > text.size()) {
                return false;
            }
            if (offset == 0 || offset == text.size()) {
                return true;
            }
            return (static_cast<unsigned char>(text[offset]) & 0xc0U) != 0x80U;
        }

        bool canonical_integer(const std::string_view decimal) {
            if (decimal == "0") {
                return true;
            }
            std::size_t position {};
            if (decimal.starts_with('-')) {
                position = 1U;
            }
            if (position == decimal.size() || decimal[position] < '1' || decimal[position] > '9') {
                return false;
            }
            return std::ranges::all_of(decimal.substr(position + 1U),
                                       [](const char character) { return character >= '0' && character <= '9'; });
        }

        void collect_references(const AstValue &value, std::vector<AstNodeId> &references, DiagnosticSet &diagnostics,
                                const std::uint32_t depth) {
            if (depth > maximum_ast_depth) {
                diagnostics.push_back(diagnostic("PY-AST-DEPTH", "AST value nesting exceeds 512"));
                return;
            }
            if (const auto *reference = std::get_if<AstNodeReference>(&value.data)) {
                references.push_back(reference->id);
                return;
            }
            if (const auto *integer = std::get_if<IntegerValue>(&value.data)) {
                if (integer->decimal.size() > mebibyte || !canonical_integer(integer->decimal)) {
                    diagnostics.push_back(
                        diagnostic("PY-AST-INTEGER", "AST integer is not a bounded canonical base-ten value"));
                }
                return;
            }
            if (const auto *unicode = std::get_if<UnicodeValue>(&value.data)) {
                if (!valid_utf8(unicode->utf8)) {
                    diagnostics.push_back(diagnostic("PY-AST-UNICODE", "AST Unicode value is not canonical UTF-8"));
                }
                return;
            }
            const auto *sequence = std::get_if<AstValue::Sequence>(&value.data);
            if (!sequence) {
                return;
            }
            if (!*sequence) {
                diagnostics.push_back(diagnostic("PY-AST-SEQUENCE", "AST sequence handle is empty"));
                return;
            }
            for (const auto &child : (*sequence)->values) {
                collect_references(child, references, diagnostics, depth + 1);
            }
        }

        DiagnosticSet validate_envelope(AstEnvelope &envelope, const VerifiedRulePack &pack) {
            DiagnosticSet diagnostics;
            if (envelope.protocol_major != ast_envelope_protocol_major ||
                envelope.protocol_minor != ast_envelope_protocol_minor) {
                diagnostics.push_back(diagnostic("PY-AST-VERSION", "AST envelope protocol must be rule-engine.ast/1"));
            }
            if (envelope.grammar_major != python_grammar_major || envelope.grammar_minor != python_grammar_minor ||
                envelope.worker_runtime != expected_worker_runtime) {
                diagnostics.push_back(
                    diagnostic("PY-AST-RUNTIME", "AST envelope must come from bundled CPython 3.14.6"));
            }
            if (envelope.source_digest != pack.closure_digest) {
                diagnostics.push_back(
                    diagnostic("PY-AST-SOURCE", "AST envelope source digest does not match the pack"));
            }
            if (envelope.nodes.size() > balanced_v1.compile.ast_nodes) {
                diagnostics.push_back(diagnostic("PY-AST-LIMIT", "AST node count exceeds balanced.v1"));
                return diagnostics;
            }

            std::map<std::string, const SourceFile *, std::less<>> sources;
            for (const auto &source : pack.sources) {
                if (!valid_utf8(source.utf8)) {
                    diagnostics.push_back(diagnostic("PY-AST-SOURCE", "pack source is not valid UTF-8"));
                }
                sources.emplace(source.id.value, &source);
            }

            std::ranges::sort(envelope.modules, {}, [](const AstModule &module) { return module.name; });
            std::set<std::string, std::less<>> module_names;
            for (const auto &module : envelope.modules) {
                if (module.name.empty() || !module_names.insert(module.name).second) {
                    diagnostics.push_back(diagnostic("PY-AST-MODULE", "AST module names must be non-empty and unique"));
                }
                const auto source = sources.find(module.source.value);
                if (source == sources.end() || source->second->module != module.name) {
                    diagnostics.push_back(
                        diagnostic("PY-AST-SOURCE", "AST module does not match a verified pack source"));
                }
            }

            std::ranges::sort(envelope.nodes, {}, [](const AstNode &node) { return node.id; });
            std::map<AstNodeId, std::size_t> node_indexes;
            std::map<AstNodeId, std::vector<AstNodeId>> edges;
            for (std::size_t index = 0; index < envelope.nodes.size(); ++index) {
                const auto &node = envelope.nodes[index];
                if (node.id == 0 || !node_indexes.emplace(node.id, index).second) {
                    diagnostics.push_back(
                        diagnostic("PY-AST-NODE", "AST node IDs must be nonzero and unique", node.span));
                }
                if (node.kind.empty()) {
                    diagnostics.push_back(diagnostic("PY-AST-NODE", "AST node kind cannot be empty", node.span));
                } else if (!valid_utf8(node.kind)) {
                    diagnostics.push_back(diagnostic("PY-AST-NODE", "AST node kind is not valid UTF-8", node.span));
                }
                const auto source = sources.find(node.span.source.value);
                if (!node.span.valid() || source == sources.end() ||
                    !utf8_boundary(source->second->utf8, node.span.begin_byte) ||
                    !utf8_boundary(source->second->utf8, node.span.end_byte)) {
                    diagnostics.push_back(
                        diagnostic("PY-AST-SPAN", "AST span is not a valid UTF-8 byte range", node.span));
                }
                std::set<std::string, std::less<>> fields;
                for (const auto &field : node.fields) {
                    if (field.name.empty() || !fields.insert(field.name).second) {
                        diagnostics.push_back(
                            diagnostic("PY-AST-FIELD", "AST field names must be non-empty and unique", node.span));
                    } else if (!valid_utf8(field.name)) {
                        diagnostics.push_back(
                            diagnostic("PY-AST-FIELD", "AST field name is not valid UTF-8", node.span));
                    }
                    collect_references(field.value, edges[node.id], diagnostics, 0);
                }
            }

            for (const auto &[from, references] : edges) {
                for (const auto target : references) {
                    if (!node_indexes.contains(target)) {
                        const auto source_node = node_indexes.find(from);
                        diagnostics.push_back(
                            diagnostic("PY-AST-REFERENCE", "AST field references an unknown node",
                                       source_node == node_indexes.end() ?
                                           std::nullopt :
                                           std::optional<SourceSpan> {envelope.nodes[source_node->second].span}));
                    }
                }
            }

            std::map<AstNodeId, std::uint8_t> colors;
            std::set<AstNodeId> reached;
            std::function<void(AstNodeId, std::uint32_t)> visit = [&](const AstNodeId id, const std::uint32_t depth) {
                if (depth > maximum_ast_depth) {
                    diagnostics.push_back(diagnostic("PY-AST-DEPTH", "AST node depth exceeds 512"));
                    return;
                }
                const auto color = colors[id];
                if (color == 1) {
                    diagnostics.push_back(diagnostic("PY-AST-CYCLE", "AST node graph contains a cycle"));
                    return;
                }
                if (color == 2) {
                    diagnostics.push_back(diagnostic("PY-AST-SHARED", "AST node is referenced more than once"));
                    return;
                }
                colors[id] = 1;
                reached.insert(id);
                for (const auto child : edges[id]) {
                    if (node_indexes.contains(child)) {
                        visit(child, depth + 1);
                    }
                }
                colors[id] = 2;
            };

            for (const auto &module : envelope.modules) {
                const auto root = node_indexes.find(module.root);
                if (root == node_indexes.end()) {
                    diagnostics.push_back(diagnostic("PY-AST-ROOT", "AST module root does not exist"));
                    continue;
                }
                if (envelope.nodes[root->second].kind != "Module") {
                    diagnostics.push_back(diagnostic("PY-AST-ROOT", "AST module root must have kind Module",
                                                     envelope.nodes[root->second].span));
                }
                visit(module.root, 0);
            }
            if (reached.size() != envelope.nodes.size()) {
                diagnostics.push_back(diagnostic("PY-AST-UNREACHABLE", "AST envelope contains unreachable nodes"));
            }
            return diagnostics;
        }

    } // namespace

    AstValue ast_none() { return AstValue {.data = std::monostate {}}; }
    AstValue ast_bool(const bool value) { return AstValue {.data = value}; }
    AstValue ast_integer(std::string decimal) { return AstValue {.data = IntegerValue {std::move(decimal)}}; }
    AstValue ast_float_bits(const std::uint64_t bits) { return AstValue {.data = AstFloatBits {bits}}; }
    AstValue ast_string(std::string utf8) { return AstValue {.data = UnicodeValue {std::move(utf8)}}; }
    AstValue ast_bytes(std::vector<std::byte> bytes) { return AstValue {.data = BytesValue {std::move(bytes)}}; }
    AstValue ast_reference(const AstNodeId id) { return AstValue {.data = AstNodeReference {id}}; }
    AstValue ast_sequence(std::vector<AstValue> values) {
        return AstValue {.data = std::make_shared<const AstSequence>(AstSequence {.values = std::move(values)})};
    }

    std::expected<std::vector<std::byte>, DiagnosticSet> encode_ast_envelope(const AstEnvelope &input) {
        auto envelope = input;
        std::ranges::sort(envelope.modules, {}, [](const AstModule &module) { return module.name; });
        std::ranges::sort(envelope.nodes, {}, [](const AstNode &node) { return node.id; });

        DiagnosticSet limits;
        if (envelope.modules.size() > balanced_v1.compile.ast_nodes ||
            envelope.nodes.size() > balanced_v1.compile.ast_nodes) {
            limits.push_back(diagnostic("PY-AST-LIMIT", "AST envelope exceeds the balanced.v1 node budget"));
        }
        for (const auto &node : envelope.nodes) {
            if (node.fields.size() > 1024) {
                limits.push_back(diagnostic("PY-AST-LIMIT", "AST node field count exceeds 1024", node.span));
            }
        }
        if (!limits.empty()) {
            return std::unexpected(std::move(limits));
        }

        Writer writer;
        writer.raw(ast_envelope_media_type);
        writer.u16(envelope.protocol_major);
        writer.u16(envelope.protocol_minor);
        writer.u16(envelope.grammar_major);
        writer.u16(envelope.grammar_minor);
        writer.string(envelope.worker_runtime);
        writer.string(envelope.source_digest.value);
        writer.u32(static_cast<std::uint32_t>(envelope.modules.size()));
        for (const auto &module : envelope.modules) {
            writer.string(module.name);
            writer.string(module.source.value);
            writer.u32(module.root);
        }
        writer.u32(static_cast<std::uint32_t>(envelope.nodes.size()));
        for (const auto &node : envelope.nodes) {
            writer.u32(node.id);
            writer.string(node.kind);
            writer.string(node.span.source.value);
            writer.u32(node.span.begin_byte);
            writer.u32(node.span.end_byte);
            auto fields = node.fields;
            std::ranges::sort(fields, {}, [](const AstField &field) { return field.name; });
            writer.u32(static_cast<std::uint32_t>(fields.size()));
            for (const auto &field : fields) {
                writer.string(field.name);
                encode_value(writer, field.value, 0);
            }
        }
        if (writer.bytes.size() > maximum_ast_payload_bytes) {
            writer.diagnostics.push_back(diagnostic("PY-AST-LIMIT", "AST envelope exceeds 64 MiB"));
        }
        if (!writer.diagnostics.empty()) {
            return std::unexpected(std::move(writer.diagnostics));
        }
        return std::move(writer.bytes);
    }

    std::expected<AstEnvelope, DiagnosticSet> decode_ast_envelope(const std::span<const std::byte> payload,
                                                                  const VerifiedRulePack &pack) {
        if (payload.size() > maximum_ast_payload_bytes) {
            return std::unexpected(DiagnosticSet {diagnostic("PY-AST-LIMIT", "AST envelope exceeds 64 MiB")});
        }
        if (payload.size() < ast_envelope_media_type.size()) {
            return std::unexpected(
                DiagnosticSet {diagnostic("PY-AST-TRUNCATED", "AST envelope is shorter than its media tag")});
        }

        Reader reader {.bytes = payload, .offset = 0, .failure = std::nullopt};
        std::string tag;
        tag.reserve(ast_envelope_media_type.size());
        for (std::size_t index = 0; index < ast_envelope_media_type.size(); ++index) {
            tag.push_back(static_cast<char>(reader.u8()));
        }
        if (tag != ast_envelope_media_type) {
            return std::unexpected(
                DiagnosticSet {diagnostic("PY-AST-MAGIC", "AST envelope media tag must be rule-engine.ast/1")});
        }

        AstEnvelope envelope;
        envelope.protocol_major = reader.u16();
        envelope.protocol_minor = reader.u16();
        envelope.grammar_major = reader.u16();
        envelope.grammar_minor = reader.u16();
        envelope.worker_runtime = reader.string(64);
        envelope.source_digest = SourceDigest {reader.string(256)};
        const auto module_count = reader.u32();
        if (module_count > balanced_v1.compile.ast_nodes) {
            reader.fail("PY-AST-LIMIT", "AST module count exceeds balanced.v1");
        }
        if (reader.failure) {
            return std::unexpected(DiagnosticSet {*std::move(reader.failure)});
        }
        envelope.modules.reserve(module_count);
        for (std::uint32_t index = 0; index < module_count && !reader.failure; ++index) {
            envelope.modules.push_back(AstModule {
                .name = reader.string(1024),
                .source = SourceId {reader.string(1024)},
                .root = reader.u32(),
            });
        }
        const auto node_count = reader.u32();
        if (node_count > balanced_v1.compile.ast_nodes) {
            reader.fail("PY-AST-LIMIT", "AST node count exceeds balanced.v1");
        }
        if (reader.failure) {
            return std::unexpected(DiagnosticSet {*std::move(reader.failure)});
        }
        envelope.nodes.reserve(node_count);
        for (std::uint32_t index = 0; index < node_count && !reader.failure; ++index) {
            AstNode node {
                .id = reader.u32(),
                .kind = reader.string(128),
                .span = {.source = SourceId {reader.string(1024)},
                         .begin_byte = reader.u32(),
                         .end_byte = reader.u32()},
                .fields = {},
            };
            const auto field_count = reader.u32();
            if (field_count > 1024) {
                reader.fail("PY-AST-LIMIT", "AST node field count exceeds 1024");
            }
            if (!reader.failure) {
                node.fields.reserve(field_count);
            }
            for (std::uint32_t field = 0; field < field_count && !reader.failure; ++field) {
                node.fields.push_back(AstField {
                    .name = reader.string(128),
                    .value = decode_value(reader, 0),
                });
            }
            envelope.nodes.push_back(std::move(node));
        }
        if (reader.failure) {
            return std::unexpected(DiagnosticSet {*std::move(reader.failure)});
        }
        if (reader.offset != payload.size()) {
            return std::unexpected(DiagnosticSet {diagnostic("PY-AST-TRAILING", "AST envelope has trailing bytes")});
        }

        auto diagnostics = validate_envelope(envelope, pack);
        if (!diagnostics.empty()) {
            return std::unexpected(std::move(diagnostics));
        }
        return envelope;
    }

} // namespace rule_engine::python::compiler
