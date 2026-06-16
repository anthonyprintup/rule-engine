#include <rule_engine/trace.hpp>

#include <rule_engine/protocol.hpp>

#include <cstdint>
#include <limits>
#include <string_view>
#include <utility>

namespace {
    constexpr std::uint32_t trace_version {2};
    constexpr std::uint32_t max_trace_collection_count {65536};

    void append_u8(std::vector<std::byte> &out, const std::uint8_t value) {
        out.push_back(static_cast<std::byte>(value));
    }

    void append_u32(std::vector<std::byte> &out, const std::uint32_t value) {
        out.push_back(static_cast<std::byte>(value & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 8u) & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 16u) & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 24u) & 0xffu));
    }

    void append_u64(std::vector<std::byte> &out, const std::uint64_t value) {
        for (std::uint32_t shift = 0; shift < 64u; shift += 8u) {
            out.push_back(static_cast<std::byte>((value >> shift) & 0xffu));
        }
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet> append_string(std::vector<std::byte> &out,
                                                                           const std::string_view value) {
        if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected(rule_engine::single_error("trace", "string exceeds v1 trace size"));
        }
        append_u32(out, static_cast<std::uint32_t>(value.size()));
        for (const auto ch : value) {
            out.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
        }
        return {};
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet> append_bytes(std::vector<std::byte> &out,
                                                                          const std::span<const std::byte> value) {
        if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected(rule_engine::single_error("trace", "byte vector exceeds v1 trace size"));
        }
        append_u32(out, static_cast<std::uint32_t>(value.size()));
        out.insert(out.end(), value.begin(), value.end());
        return {};
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet> validate_count(const std::uint32_t count,
                                                                            const std::string_view what) {
        if (count > max_trace_collection_count) {
            return std::unexpected(rule_engine::single_error("trace",
                                                             std::string {what} + " count exceeds v1 limit"));
        }
        return {};
    }

    struct Reader {
        std::span<const std::byte> bytes;
        std::size_t offset {};

        [[nodiscard]] bool read_u8(std::uint8_t &out) noexcept {
            if (offset + 1u > bytes.size()) {
                return false;
            }
            out = static_cast<std::uint8_t>(bytes[offset]);
            ++offset;
            return true;
        }

        [[nodiscard]] bool read_u32(std::uint32_t &out) noexcept {
            if (offset + 4u > bytes.size()) {
                return false;
            }
            out = static_cast<std::uint32_t>(bytes[offset]) |
                  (static_cast<std::uint32_t>(bytes[offset + 1u]) << 8u) |
                  (static_cast<std::uint32_t>(bytes[offset + 2u]) << 16u) |
                  (static_cast<std::uint32_t>(bytes[offset + 3u]) << 24u);
            offset += 4u;
            return true;
        }

        [[nodiscard]] bool read_u64(std::uint64_t &out) noexcept {
            if (offset + 8u > bytes.size()) {
                return false;
            }
            out = {};
            for (std::uint32_t shift = 0; shift < 64u; shift += 8u) {
                out |= static_cast<std::uint64_t>(bytes[offset]) << shift;
                ++offset;
            }
            return true;
        }

        [[nodiscard]] bool read_string(std::string &out) {
            std::uint32_t size {};
            if (!read_u32(size) || offset + size > bytes.size()) {
                return false;
            }
            const auto *first = reinterpret_cast<const char *>(bytes.data() + offset);
            out.assign(first, first + size);
            offset += size;
            return true;
        }

        [[nodiscard]] bool read_bytes(std::vector<std::byte> &out) {
            std::uint32_t size {};
            if (!read_u32(size) || offset + size > bytes.size()) {
                return false;
            }
            out.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                       bytes.begin() + static_cast<std::ptrdiff_t>(offset + size));
            offset += size;
            return true;
        }
    };

    [[nodiscard]] std::uint8_t state_to_wire(const rule_engine::EvaluationState state) noexcept {
        return state == rule_engine::EvaluationState::waiting_for_facts ? 0u : 1u;
    }

    [[nodiscard]] std::optional<rule_engine::EvaluationState> state_from_wire(const std::uint8_t value) noexcept {
        if (value == 0u) {
            return rule_engine::EvaluationState::waiting_for_facts;
        }
        if (value == 1u) {
            return rule_engine::EvaluationState::complete;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::uint8_t trace_status_to_wire(const rule_engine::ExpressionTraceStatus status) noexcept {
        switch (status) {
            case rule_engine::ExpressionTraceStatus::value: return 0u;
            case rule_engine::ExpressionTraceStatus::missing: return 1u;
            case rule_engine::ExpressionTraceStatus::diagnostic: return 2u;
            default: return 0u;
        }
    }

    [[nodiscard]] std::optional<rule_engine::ExpressionTraceStatus>
    trace_status_from_wire(const std::uint8_t value) noexcept {
        switch (value) {
            case 0u: return rule_engine::ExpressionTraceStatus::value;
            case 1u: return rule_engine::ExpressionTraceStatus::missing;
            case 2u: return rule_engine::ExpressionTraceStatus::diagnostic;
            default: return std::nullopt;
        }
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    append_request(std::vector<std::byte> &out, const rule_engine::FactRequestBatch &request) {
        if (auto result = append_string(out, request.route); !result) {
            return result;
        }
        append_u32(out, static_cast<std::uint32_t>(request.timeout.count()));
        append_u32(out, static_cast<std::uint32_t>(request.keys.size()));
        for (const auto &key : request.keys) {
            if (auto result = append_string(out, key); !result) {
                return result;
            }
        }
        return {};
    }

    [[nodiscard]] std::expected<rule_engine::FactRequestBatch, rule_engine::ErrorSet> read_request(Reader &reader) {
        rule_engine::FactRequestBatch out;
        std::uint32_t timeout {};
        std::uint32_t key_count {};
        if (!reader.read_string(out.route) || !reader.read_u32(timeout) || !reader.read_u32(key_count)) {
            return std::unexpected(rule_engine::single_error("trace", "truncated trace request"));
        }
        out.timeout = std::chrono::seconds {timeout};
        if (auto count_ok = validate_count(key_count, "trace request key"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.keys.reserve(key_count);
        for (std::uint32_t index = 0; index < key_count; ++index) {
            std::string key;
            if (!reader.read_string(key)) {
                return std::unexpected(rule_engine::single_error("trace", "truncated trace request key"));
            }
            out.keys.push_back(std::move(key));
        }
        return out;
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    append_diagnostic(std::vector<std::byte> &out, const rule_engine::Diagnostic &diagnostic) {
        if (auto result = append_string(out, diagnostic.source); !result) {
            return result;
        }
        append_u32(out, diagnostic.span.source_id);
        append_u64(out, static_cast<std::uint64_t>(diagnostic.span.start));
        append_u64(out, static_cast<std::uint64_t>(diagnostic.span.end));
        if (auto result = append_string(out, diagnostic.span.source); !result) {
            return result;
        }
        return append_string(out, diagnostic.message);
    }

    [[nodiscard]] std::expected<rule_engine::Diagnostic, rule_engine::ErrorSet> read_diagnostic(Reader &reader) {
        rule_engine::Diagnostic out;
        std::uint32_t source_id {};
        std::uint64_t start {};
        std::uint64_t end {};
        if (!reader.read_string(out.source) || !reader.read_u32(source_id) || !reader.read_u64(start) ||
            !reader.read_u64(end) || !reader.read_string(out.span.source) || !reader.read_string(out.message)) {
            return std::unexpected(rule_engine::single_error("trace", "truncated trace diagnostic"));
        }
        out.span.source_id = source_id;
        out.span.start = static_cast<std::size_t>(start);
        out.span.end = static_cast<std::size_t>(end);
        return out;
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    append_rule_result(std::vector<std::byte> &out, const rule_engine::RuleResult &result) {
        if (auto append_result = append_string(out, result.identifier); !append_result) {
            return append_result;
        }
        append_u8(out, result.matched ? 1u : 0u);
        append_u32(out, static_cast<std::uint32_t>(result.diagnostics.size()));
        for (const auto &diagnostic : result.diagnostics) {
            if (auto append_result = append_diagnostic(out, diagnostic); !append_result) {
                return append_result;
            }
        }
        return {};
    }

    [[nodiscard]] std::expected<rule_engine::RuleResult, rule_engine::ErrorSet> read_rule_result(Reader &reader) {
        rule_engine::RuleResult out;
        std::uint8_t matched {};
        std::uint32_t diagnostic_count {};
        if (!reader.read_string(out.identifier) || !reader.read_u8(matched) || !reader.read_u32(diagnostic_count)) {
            return std::unexpected(rule_engine::single_error("trace", "truncated trace rule result"));
        }
        out.matched = matched != 0u;
        if (auto count_ok = validate_count(diagnostic_count, "trace diagnostic"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.diagnostics.reserve(diagnostic_count);
        for (std::uint32_t index = 0; index < diagnostic_count; ++index) {
            auto diagnostic = read_diagnostic(reader);
            if (!diagnostic) {
                return std::unexpected(std::move(diagnostic.error()));
            }
            out.diagnostics.push_back(std::move(*diagnostic));
        }
        return out;
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    append_expression_trace(std::vector<std::byte> &out, const rule_engine::ExpressionTraceEvent &event) {
        if (auto result = append_string(out, event.rule_identifier); !result) {
            return result;
        }
        append_u32(out, static_cast<std::uint32_t>(event.expression_kind));
        append_u32(out, event.span.source_id);
        append_u64(out, static_cast<std::uint64_t>(event.span.start));
        append_u64(out, static_cast<std::uint64_t>(event.span.end));
        if (auto result = append_string(out, event.span.source); !result) {
            return result;
        }
        if (auto result = append_string(out, event.text); !result) {
            return result;
        }
        append_u8(out, trace_status_to_wire(event.status));
        if (auto result = append_string(out, event.value_summary); !result) {
            return result;
        }
        return append_string(out, event.detail);
    }

    [[nodiscard]] std::expected<rule_engine::ExpressionTraceEvent, rule_engine::ErrorSet>
    read_expression_trace(Reader &reader) {
        rule_engine::ExpressionTraceEvent out;
        std::uint32_t expression_kind {};
        std::uint32_t source_id {};
        std::uint64_t start {};
        std::uint64_t end {};
        std::uint8_t status {};
        if (!reader.read_string(out.rule_identifier) || !reader.read_u32(expression_kind) ||
            !reader.read_u32(source_id) || !reader.read_u64(start) || !reader.read_u64(end) ||
            !reader.read_string(out.span.source) || !reader.read_string(out.text) || !reader.read_u8(status) ||
            !reader.read_string(out.value_summary) || !reader.read_string(out.detail)) {
            return std::unexpected(rule_engine::single_error("trace", "truncated expression trace event"));
        }
        const auto parsed_status = trace_status_from_wire(status);
        if (!parsed_status.has_value()) {
            return std::unexpected(rule_engine::single_error("trace", "unknown expression trace status"));
        }
        out.expression_kind = static_cast<rule_engine::ExpressionKind>(expression_kind);
        out.span.source_id = source_id;
        out.span.start = static_cast<std::size_t>(start);
        out.span.end = static_cast<std::size_t>(end);
        out.status = *parsed_status;
        return out;
    }
} // namespace

namespace rule_engine {
    EvaluationTrace capture_evaluation_trace(const VerifiedProgram &program,
                                             const Subject &subject,
                                             const FactCache &facts) {
        EvaluationTrace out;
        out.subject = subject;
        out.facts = facts.snapshot_for_subject(subject.id);

        const Evaluator evaluator {program, facts, EvaluationOptions {.trace_expressions = true}};
        out.final_step = evaluator.step(subject);
        return out;
    }

    std::expected<std::vector<std::byte>, ErrorSet> encode_evaluation_trace(const EvaluationTrace &trace) {
        std::vector<std::byte> out;
        out.push_back(static_cast<std::byte>('R'));
        out.push_back(static_cast<std::byte>('E'));
        out.push_back(static_cast<std::byte>('T'));
        out.push_back(static_cast<std::byte>('R'));
        append_u32(out, trace_version);
        if (auto result = append_string(out, trace.subject.kind); !result) {
            return std::unexpected(std::move(result.error()));
        }
        if (auto result = append_string(out, trace.subject.id); !result) {
            return std::unexpected(std::move(result.error()));
        }

        auto facts = protocol::encode_fact_batch_response(protocol::FactBatchResponseMessage {
            .route = "trace.facts",
            .values = trace.facts,
        });
        if (!facts) {
            return std::unexpected(std::move(facts.error()));
        }
        if (auto result = append_bytes(out, *facts); !result) {
            return std::unexpected(std::move(result.error()));
        }

        append_u8(out, state_to_wire(trace.final_step.state));
        append_u32(out, static_cast<std::uint32_t>(trace.final_step.requests.size()));
        for (const auto &request : trace.final_step.requests) {
            if (auto result = append_request(out, request); !result) {
                return std::unexpected(std::move(result.error()));
            }
        }
        append_u32(out, static_cast<std::uint32_t>(trace.final_step.rule_results.size()));
        for (const auto &result : trace.final_step.rule_results) {
            if (auto append_result = append_rule_result(out, result); !append_result) {
                return std::unexpected(std::move(append_result.error()));
            }
        }
        append_u32(out, static_cast<std::uint32_t>(trace.final_step.expression_traces.size()));
        for (const auto &event : trace.final_step.expression_traces) {
            if (auto result = append_expression_trace(out, event); !result) {
                return std::unexpected(std::move(result.error()));
            }
        }
        return out;
    }

    std::expected<EvaluationTrace, ErrorSet> decode_evaluation_trace(const std::span<const std::byte> artifact) {
        if (artifact.size() < 8u || artifact[0] != static_cast<std::byte>('R') ||
            artifact[1] != static_cast<std::byte>('E') || artifact[2] != static_cast<std::byte>('T') ||
            artifact[3] != static_cast<std::byte>('R')) {
            return std::unexpected(single_error("trace", "invalid trace artifact header"));
        }

        Reader reader {.bytes = artifact, .offset = 4u};
        std::uint32_t version {};
        if (!reader.read_u32(version)) {
            return std::unexpected(single_error("trace", "truncated trace artifact version"));
        }
        if (version != trace_version) {
            return std::unexpected(single_error("trace", "unsupported trace artifact version"));
        }

        EvaluationTrace out;
        if (!reader.read_string(out.subject.kind) || !reader.read_string(out.subject.id)) {
            return std::unexpected(single_error("trace", "truncated trace subject"));
        }

        std::vector<std::byte> fact_payload;
        if (!reader.read_bytes(fact_payload)) {
            return std::unexpected(single_error("trace", "truncated trace facts"));
        }
        auto decoded_facts = protocol::decode_fact_batch_response(fact_payload);
        if (!decoded_facts) {
            return std::unexpected(std::move(decoded_facts.error()));
        }
        out.facts = std::move(decoded_facts->values);

        std::uint8_t state {};
        std::uint32_t request_count {};
        if (!reader.read_u8(state) || !reader.read_u32(request_count)) {
            return std::unexpected(single_error("trace", "truncated trace final step"));
        }
        const auto parsed_state = state_from_wire(state);
        if (!parsed_state.has_value()) {
            return std::unexpected(single_error("trace", "unknown trace evaluation state"));
        }
        out.final_step.state = *parsed_state;

        if (auto count_ok = validate_count(request_count, "trace request"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.final_step.requests.reserve(request_count);
        for (std::uint32_t index = 0; index < request_count; ++index) {
            auto request = read_request(reader);
            if (!request) {
                return std::unexpected(std::move(request.error()));
            }
            out.final_step.requests.push_back(std::move(*request));
        }

        std::uint32_t result_count {};
        if (!reader.read_u32(result_count)) {
            return std::unexpected(single_error("trace", "truncated trace result count"));
        }
        if (auto count_ok = validate_count(result_count, "trace result"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.final_step.rule_results.reserve(result_count);
        for (std::uint32_t index = 0; index < result_count; ++index) {
            auto result = read_rule_result(reader);
            if (!result) {
                return std::unexpected(std::move(result.error()));
            }
            out.final_step.rule_results.push_back(std::move(*result));
        }
        std::uint32_t expression_trace_count {};
        if (!reader.read_u32(expression_trace_count)) {
            return std::unexpected(single_error("trace", "truncated trace expression event count"));
        }
        if (auto count_ok = validate_count(expression_trace_count, "trace expression event"); !count_ok) {
            return std::unexpected(std::move(count_ok.error()));
        }
        out.final_step.expression_traces.reserve(expression_trace_count);
        for (std::uint32_t index = 0; index < expression_trace_count; ++index) {
            auto event = read_expression_trace(reader);
            if (!event) {
                return std::unexpected(std::move(event.error()));
            }
            out.final_step.expression_traces.push_back(std::move(*event));
        }
        return out;
    }

    std::expected<EvaluationStep, ErrorSet> replay_evaluation_trace(const VerifiedProgram &program,
                                                                    const EvaluationTrace &trace) {
        FactCache facts;
        for (const auto &fact : trace.facts) {
            facts.store(fact);
        }
        const Evaluator evaluator {program, facts};
        return evaluator.step(trace.subject);
    }
} // namespace rule_engine
