#include <rule_engine/server_output.hpp>

#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace {
    [[nodiscard]] std::string_view status_name(const rule_engine::FactStatus status) noexcept {
        switch (status) {
            case rule_engine::FactStatus::missing: return "missing";
            case rule_engine::FactStatus::available: return "available";
            case rule_engine::FactStatus::unavailable: return "unavailable";
            case rule_engine::FactStatus::access_denied: return "access_denied";
            case rule_engine::FactStatus::timed_out: return "timed_out";
            default: return "unknown";
        }
    }

    [[nodiscard]] std::string_view state_name(const rule_engine::EvaluationState state) noexcept {
        switch (state) {
            case rule_engine::EvaluationState::waiting_for_facts: return "waiting_for_facts";
            case rule_engine::EvaluationState::complete: return "complete";
            default: return "unknown";
        }
    }

    [[nodiscard]] std::string_view value_type_name(const rule_engine::ValueType type) noexcept {
        switch (type) {
            case rule_engine::ValueType::boolean: return "boolean";
            case rule_engine::ValueType::integer: return "integer";
            case rule_engine::ValueType::floating: return "floating";
            case rule_engine::ValueType::string: return "string";
            case rule_engine::ValueType::bytes: return "bytes";
            case rule_engine::ValueType::array: return "array";
            case rule_engine::ValueType::object: return "object";
            case rule_engine::ValueType::pattern: return "pattern";
            case rule_engine::ValueType::undefined: return "undefined";
            default: return "unknown";
        }
    }

    [[nodiscard]] std::string_view value_kind(const rule_engine::Value &value) noexcept {
        if (value.is_undefined()) {
            return "undefined";
        }
        if (value.as_bool().has_value()) {
            return "boolean";
        }
        if (value.as_i64().has_value()) {
            return "integer";
        }
        if (value.as_f64().has_value()) {
            return "floating";
        }
        if (value.as_string() != nullptr) {
            return "string";
        }
        if (value.as_bytes() != nullptr) {
            return "bytes";
        }
        if (value.as_pattern() != nullptr) {
            return "pattern";
        }
        if (value.as_array() != nullptr) {
            return "array";
        }
        if (value.as_object() != nullptr) {
            return "object";
        }
        return "unknown";
    }

    void append_u64(std::string &out, const std::uint64_t value) { out += std::to_string(value); }

    void append_i64(std::string &out, const std::int64_t value) { out += std::to_string(value); }

    void append_size(std::string &out, const std::size_t value) { out += std::to_string(value); }

    void append_double(std::string &out, const double value) {
        if (!std::isfinite(value)) {
            out += "null";
            return;
        }

        char buffer[64] {};
        const auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), value);
        if (ec != std::errc {}) {
            out += "null";
            return;
        }
        out.append(buffer, ptr);
    }

    void append_hex_byte(std::string &out, const std::byte byte) {
        constexpr char digits[] = "0123456789abcdef";
        const auto value = static_cast<unsigned int>(std::to_integer<unsigned char>(byte));
        out.push_back(digits[(value >> 4u) & 0x0fu]);
        out.push_back(digits[value & 0x0fu]);
    }

    void append_hex_bytes(std::string &out, const std::vector<std::byte> &bytes) {
        out.push_back('"');
        for (const auto byte : bytes) {
            append_hex_byte(out, byte);
        }
        out.push_back('"');
    }

    void append_json_string(std::string &out, const std::string_view value) {
        out.push_back('"');
        for (const auto raw : value) {
            const auto ch = static_cast<unsigned char>(raw);
            switch (ch) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (ch < 0x20u) {
                        out += "\\u00";
                        constexpr char digits[] = "0123456789abcdef";
                        out.push_back(digits[(ch >> 4u) & 0x0fu]);
                        out.push_back(digits[ch & 0x0fu]);
                        break;
                    }
                    out.push_back(static_cast<char>(ch));
                    break;
            }
        }
        out.push_back('"');
    }

    void append_key(std::string &out, const std::string_view key) {
        append_json_string(out, key);
        out.push_back(':');
    }

    void append_key_string(std::string &out, const std::string_view key, const std::string_view value) {
        append_key(out, key);
        append_json_string(out, value);
    }

    void append_key_bool(std::string &out, const std::string_view key, const bool value) {
        append_key(out, key);
        out += value ? "true" : "false";
    }

    void append_key_size(std::string &out, const std::string_view key, const std::size_t value) {
        append_key(out, key);
        append_size(out, value);
    }

    void append_key_u64(std::string &out, const std::string_view key, const std::uint64_t value) {
        append_key(out, key);
        append_u64(out, value);
    }

    void append_value(std::string &out, const rule_engine::Value &value);

    void append_pattern(std::string &out, const rule_engine::PatternValue &pattern) {
        out.push_back('{');
        append_key_bool(out, "matched", pattern.matched);
        out.push_back(',');
        append_key_size(out, "matchCount", pattern.matches.size());
        out.push_back(',');
        append_key(out, "matches");
        out.push_back('[');
        for (std::size_t index = 0; index < pattern.matches.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &match = pattern.matches[index];
            out.push_back('{');
            append_key_u64(out, "offset", match.offset);
            out.push_back(',');
            append_key_u64(out, "length", match.length);
            out.push_back(',');
            append_key(out, "bytes");
            append_hex_bytes(out, match.bytes);
            out.push_back(',');
            append_key(out, "before");
            append_hex_bytes(out, match.before);
            out.push_back(',');
            append_key(out, "after");
            append_hex_bytes(out, match.after);
            out.push_back(',');
            append_key_string(out, "scanSpace", match.scan_space);
            out.push_back(',');
            append_key_string(out, "regionPermissions", match.region_permissions);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back('}');
    }

    void append_array(std::string &out, const rule_engine::ArrayValue &array) {
        out.push_back('[');
        for (std::size_t index = 0; index < array.values.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            append_value(out, array.values[index]);
        }
        out.push_back(']');
    }

    void append_object(std::string &out, const rule_engine::ObjectValue &object) {
        out.push_back('{');
        for (std::size_t index = 0; index < object.entries.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            append_key(out, object.entries[index].key);
            append_value(out, object.entries[index].value);
        }
        out.push_back('}');
    }

    void append_value(std::string &out, const rule_engine::Value &value) {
        if (value.is_undefined()) {
            out += "null";
            return;
        }
        if (const auto boolean = value.as_bool(); boolean.has_value()) {
            out += *boolean ? "true" : "false";
            return;
        }
        if (const auto integer = value.as_i64(); integer.has_value()) {
            append_i64(out, *integer);
            return;
        }
        if (const auto floating = value.as_f64(); floating.has_value()) {
            append_double(out, *floating);
            return;
        }
        if (const auto *text = value.as_string(); text != nullptr) {
            append_json_string(out, *text);
            return;
        }
        if (const auto *bytes = value.as_bytes(); bytes != nullptr) {
            append_hex_bytes(out, *bytes);
            return;
        }
        if (const auto *pattern = value.as_pattern(); pattern != nullptr) {
            append_pattern(out, *pattern);
            return;
        }
        if (const auto *array = value.as_array(); array != nullptr) {
            append_array(out, *array);
            return;
        }
        if (const auto *object = value.as_object(); object != nullptr) {
            append_object(out, *object);
            return;
        }
        out += "null";
    }

    void append_capabilities(std::string &out, const std::vector<rule_engine::protocol::Capability> &capabilities) {
        out.push_back('[');
        for (std::size_t index = 0; index < capabilities.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            out.push_back('{');
            append_key_string(out, "route", capabilities[index].route);
            out.push_back('}');
        }
        out.push_back(']');
    }

    void append_diagnostics(std::string &out, const std::vector<rule_engine::Diagnostic> &diagnostics) {
        out.push_back('[');
        for (std::size_t index = 0; index < diagnostics.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &diagnostic = diagnostics[index];
            out.push_back('{');
            append_key_string(out, "source", diagnostic.source);
            out.push_back(',');
            append_key_u64(out, "sourceId", diagnostic.span.source_id);
            out.push_back(',');
            append_key_size(out, "spanStart", diagnostic.span.start);
            out.push_back(',');
            append_key_size(out, "spanEnd", diagnostic.span.end);
            out.push_back(',');
            append_key_string(out, "message", diagnostic.message);
            out.push_back('}');
        }
        out.push_back(']');
    }

    void append_requests(std::string &out, const std::vector<rule_engine::FactRequestBatch> &requests) {
        out.push_back('[');
        for (std::size_t request_index = 0; request_index < requests.size(); ++request_index) {
            if (request_index != 0u) {
                out.push_back(',');
            }
            const auto &request = requests[request_index];
            out.push_back('{');
            append_key_string(out, "route", request.route);
            out.push_back(',');
            append_key_u64(out, "timeoutSeconds", static_cast<std::uint64_t>(request.timeout.count()));
            out.push_back(',');
            append_key(out, "keys");
            out.push_back('[');
            for (std::size_t key_index = 0; key_index < request.keys.size(); ++key_index) {
                if (key_index != 0u) {
                    out.push_back(',');
                }
                out.push_back('{');
                append_key_string(out, "key", request.keys[key_index]);
                if (key_index < request.types.size()) {
                    out.push_back(',');
                    append_key_string(out, "expectedType", value_type_name(request.types[key_index]));
                }
                out.push_back('}');
            }
            out.push_back(']');
            out.push_back('}');
        }
        out.push_back(']');
    }

    void append_rules(std::string &out, const std::vector<rule_engine::RuleResult> &results) {
        out.push_back('[');
        for (std::size_t index = 0; index < results.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &result = results[index];
            out.push_back('{');
            append_key_string(out, "identifier", result.identifier);
            out.push_back(',');
            append_key_bool(out, "matched", result.matched);
            out.push_back(',');
            append_key(out, "diagnostics");
            append_diagnostics(out, result.diagnostics);
            out.push_back('}');
        }
        out.push_back(']');
    }

    void append_fact(std::string &out, const rule_engine::Fact &fact) {
        out.push_back('{');
        append_key_string(out, "subjectId", fact.subject_id);
        out.push_back(',');
        append_key_string(out, "key", fact.key);
        out.push_back(',');
        append_key_string(out, "status", status_name(fact.status));
        out.push_back(',');
        append_key_string(out, "valueKind", value_kind(fact.value));
        out.push_back(',');
        append_key(out, "value");
        append_value(out, fact.value);
        out.push_back(',');
        append_key_string(out, "diagnostic", fact.diagnostic);
        out.push_back(',');
        append_key_u64(out, "ttlSeconds", static_cast<std::uint64_t>(fact.ttl.count()));
        out.push_back('}');
    }

    void append_common_prefix(std::string &out,
                              const std::string_view host,
                              const std::uint16_t port,
                              const rule_engine::protocol::HandshakeMessage &handshake,
                              const std::size_t advertised_subjects) {
        out.push_back('{');
        append_key_string(out, "host", host);
        out.push_back(',');
        append_key_u64(out, "port", port);
        out.push_back(',');
        append_key_string(out, "protocol", handshake.protocol);
        out.push_back(',');
        append_key_u64(out, "version", handshake.version);
        out.push_back(',');
        append_key_size(out, "subjectsAdvertised", advertised_subjects);
        out.push_back(',');
        append_key(out, "capabilities");
        append_capabilities(out, handshake.capabilities);
    }
} // namespace

namespace rule_engine::server_output {
    std::string evaluation_session_json(const std::string_view host,
                                        const std::uint16_t port,
                                        const client_protocol::ClientMultiEvaluationSession &session) {
        std::string out;
        out.reserve(1024u);
        append_common_prefix(out, host, port, session.handshake, session.subjects.subjects.size());
        out.push_back(',');
        append_key_size(out, "evaluated", session.evaluations.size());
        out.push_back(',');
        append_key(out, "subjects");
        out.push_back('[');
        for (std::size_t index = 0; index < session.evaluations.size(); ++index) {
            if (index != 0u) {
                out.push_back(',');
            }
            const auto &evaluation = session.evaluations[index];
            out.push_back('{');
            append_key_string(out, "kind", evaluation.subject.kind);
            out.push_back(',');
            append_key_string(out, "id", evaluation.subject.id);
            out.push_back(',');
            append_key_string(out, "state", state_name(evaluation.final_step.state));
            out.push_back(',');
            append_key(out, "requests");
            append_requests(out, evaluation.final_step.requests);
            out.push_back(',');
            append_key(out, "rules");
            append_rules(out, evaluation.final_step.rule_results);
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back('}');
        return out;
    }

    std::string client_session_json(const std::string_view host,
                                    const std::uint16_t port,
                                    const client_protocol::ClientSession &session) {
        std::string out;
        out.reserve(1024u);
        append_common_prefix(out, host, port, session.handshake, session.subjects.subjects.size());
        out.push_back(',');
        append_key(out, "responses");
        out.push_back('[');
        for (std::size_t response_index = 0; response_index < session.responses.size(); ++response_index) {
            if (response_index != 0u) {
                out.push_back(',');
            }
            const auto &response = session.responses[response_index];
            out.push_back('{');
            append_key_string(out, "route", response.route);
            out.push_back(',');
            append_key(out, "facts");
            out.push_back('[');
            for (std::size_t fact_index = 0; fact_index < response.values.size(); ++fact_index) {
                if (fact_index != 0u) {
                    out.push_back(',');
                }
                append_fact(out, response.values[fact_index]);
            }
            out.push_back(']');
            out.push_back('}');
        }
        out.push_back(']');
        out.push_back('}');
        return out;
    }
} // namespace rule_engine::server_output
