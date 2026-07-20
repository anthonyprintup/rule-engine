#include "rule_engine/python/compiler/worker_adapter.hpp"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

namespace rule_engine::python::compiler {
    namespace {

        [[nodiscard]] Diagnostic worker_error(std::string code, std::string message,
                                              std::optional<SourceSpan> span = std::nullopt) {
            return Diagnostic {.code = std::move(code),
                               .severity = DiagnosticSeverity::error,
                               .message = std::move(message),
                               .span = std::move(span),
                               .related = {}};
        }

        [[nodiscard]] std::vector<std::byte> source_bytes(const std::string_view source) {
            std::vector<std::byte> bytes;
            bytes.reserve(source.size());
            for (const auto character : source) {
                bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
            }
            return bytes;
        }

        void rebase_value(AstValue &value, const AstNodeId offset, const std::uint32_t depth = 0U) {
            if (depth > maximum_ast_depth) {
                return;
            }
            if (auto *reference = std::get_if<AstNodeReference>(&value.data)) {
                reference->id += offset;
                return;
            }
            auto *sequence = std::get_if<AstValue::Sequence>(&value.data);
            if (sequence == nullptr || !*sequence) {
                return;
            }
            auto rebased = (*sequence)->values;
            for (auto &child : rebased) { rebase_value(child, offset, depth + 1U); }
            value = ast_sequence(std::move(rebased));
        }

        void rebase(AstEnvelope &envelope, const AstNodeId offset) {
            for (auto &module : envelope.modules) { module.root += offset; }
            for (auto &node : envelope.nodes) {
                node.id += offset;
                for (auto &field : node.fields) { rebase_value(field.value, offset); }
            }
        }

    } // namespace

    std::expected<std::vector<std::byte>, DiagnosticSet> WorkerAstEnvelopeProvider::load(const VerifiedRulePack &pack) {
        if (pack.sources.empty()) {
            return std::unexpected(
                DiagnosticSet {worker_error("PY-WORKER-SOURCE", "verified pack has no Python modules")});
        }

        auto sources = pack.sources;
        std::ranges::sort(sources, [](const SourceFile &left, const SourceFile &right) {
            return std::tie(left.module, left.id.value) < std::tie(right.module, right.id.value);
        });
        AstEnvelope merged {
            .protocol_major = ast_envelope_protocol_major,
            .protocol_minor = ast_envelope_protocol_minor,
            .grammar_major = python_grammar_major,
            .grammar_minor = python_grammar_minor,
            .worker_runtime = "3.14.6",
            .source_digest = pack.closure_digest,
            .modules = {},
            .nodes = {},
        };

        AstNodeId next_offset {};
        ++request_generation_;
        for (std::size_t index = 0; index < sources.size(); ++index) {
            const auto &source = sources[index];
            const auto request_id =
                RequestId {"compiler-ast:" + std::to_string(request_generation_) + ":" + std::to_string(index)};
            const packaging::WorkerRequest request {
                .protocol = packaging::python_worker_protocol_v1,
                .request_id = request_id,
                .mode = packaging::WorkerMode::static_parse,
                .runtime = client_.runtime.descriptor,
                .payload = {.schema = std::string {packaging::static_source_schema_v1},
                            .source = source.id,
                            .source_digest = pack.closure_digest,
                            .bytes = source_bytes(source.utf8)},
                .hash_seed = 0U,
                .generator_execution_authorized = false,
            };
            const auto response = client_.invoke(request);
            if (!response) {
                return std::unexpected(DiagnosticSet {
                    worker_error("PY-WORKER", "private Python parser worker failed: " + response.error().message,
                                 SourceSpan {.source = source.id, .begin_byte = 0U, .end_byte = 0U})});
            }
            auto decoded = decode_ast_envelope(response->payload.bytes, pack);
            if (!decoded) {
                return std::unexpected(std::move(decoded.error()));
            }
            if (decoded->modules.size() != 1U || decoded->modules.front().source != source.id ||
                decoded->modules.front().name != source.module) {
                return std::unexpected(DiagnosticSet {worker_error(
                    "PY-WORKER-MODULE", "parser worker AST module identity does not match the requested source",
                    SourceSpan {.source = source.id, .begin_byte = 0U, .end_byte = 0U})});
            }
            if (decoded->nodes.size() > balanced_v1.compile.ast_nodes - merged.nodes.size()) {
                return std::unexpected(DiagnosticSet {
                    worker_error("PY-WORKER-AST-LIMIT", "merged parser worker AST exceeds the pack node budget",
                                 SourceSpan {.source = source.id, .begin_byte = 0U, .end_byte = 0U})});
            }
            const auto maximum_id = decoded->nodes.empty() ? 0U : decoded->nodes.back().id;
            if (maximum_id > std::numeric_limits<AstNodeId>::max() - next_offset) {
                return std::unexpected(DiagnosticSet {worker_error(
                    "PY-WORKER-AST-LIMIT", "merged parser worker AST node IDs overflow the envelope encoding",
                    SourceSpan {.source = source.id, .begin_byte = 0U, .end_byte = 0U})});
            }
            rebase(*decoded, next_offset);
            merged.modules.insert(merged.modules.end(), std::make_move_iterator(decoded->modules.begin()),
                                  std::make_move_iterator(decoded->modules.end()));
            merged.nodes.insert(merged.nodes.end(), std::make_move_iterator(decoded->nodes.begin()),
                                std::make_move_iterator(decoded->nodes.end()));
            if (!merged.nodes.empty()) {
                next_offset = merged.nodes.back().id;
            }
        }
        return encode_ast_envelope(merged);
    }

} // namespace rule_engine::python::compiler
