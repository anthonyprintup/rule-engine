#if !defined(RULE_ENGINE_RE2_BRIDGE_BUILD)
#define RULE_ENGINE_RE2_BRIDGE_BUILD 1
#endif
#include "re2_bridge.hpp"

#include <re2/re2.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <type_traits>

struct rule_engine_re2_bridge_pattern {
    rule_engine_re2_bridge_pattern(const absl::string_view pattern, const re2::RE2::Options &options):
        expression {pattern, options} {}

    re2::RE2 expression;
};

namespace {

    constexpr char empty_data {'\0'};

    static_assert(std::is_standard_layout_v<rule_engine_re2_bridge_options>);
    static_assert(std::is_trivially_copyable_v<rule_engine_re2_bridge_options>);
    static_assert(sizeof(rule_engine_re2_bridge_options) == 16);
    static_assert(std::is_standard_layout_v<rule_engine_re2_bridge_diagnostic>);
    static_assert(std::is_trivially_copyable_v<rule_engine_re2_bridge_diagnostic>);
    static_assert(sizeof(rule_engine_re2_bridge_diagnostic) == 40);
    static_assert(std::is_standard_layout_v<rule_engine_re2_bridge_match>);
    static_assert(std::is_trivially_copyable_v<rule_engine_re2_bridge_match>);
    static_assert(sizeof(rule_engine_re2_bridge_match) == 16);

    [[nodiscard]] bool diagnostic_storage_valid(const rule_engine_re2_bridge_diagnostic *diagnostic) noexcept {
        return diagnostic == nullptr || diagnostic->message_capacity == 0 || diagnostic->message_data != nullptr;
    }

    void clear_diagnostic(rule_engine_re2_bridge_diagnostic *diagnostic) noexcept {
        if (diagnostic == nullptr) {
            return;
        }
        diagnostic->message_size = 0;
        diagnostic->pattern_offset = RULE_ENGINE_RE2_BRIDGE_NO_PATTERN_OFFSET;
        diagnostic->message_truncated = 0;
        std::fill(std::begin(diagnostic->reserved), std::end(diagnostic->reserved), uint8_t {});
        if (diagnostic->message_capacity != 0 && diagnostic->message_data != nullptr) {
            diagnostic->message_data[0] = '\0';
        }
    }

    void write_diagnostic(rule_engine_re2_bridge_diagnostic *diagnostic, const char *message,
                          const std::size_t message_size,
                          const uint64_t pattern_offset = RULE_ENGINE_RE2_BRIDGE_NO_PATTERN_OFFSET) noexcept {
        if (diagnostic == nullptr) {
            return;
        }

        clear_diagnostic(diagnostic);
        diagnostic->message_size = static_cast<uint64_t>(message_size);
        diagnostic->pattern_offset = pattern_offset;
        diagnostic->message_truncated = static_cast<uint8_t>(
            message_size != 0 && (diagnostic->message_capacity == 0 || diagnostic->message_capacity <= message_size));
        if (diagnostic->message_capacity == 0 || diagnostic->message_data == nullptr) {
            return;
        }

        const auto copy_size = std::min<uint64_t>(message_size, diagnostic->message_capacity - 1U);
        if (copy_size != 0) {
            std::memcpy(diagnostic->message_data, message, static_cast<std::size_t>(copy_size));
        }
        diagnostic->message_data[copy_size] = '\0';
    }

    template<std::size_t Size>
    void write_diagnostic(rule_engine_re2_bridge_diagnostic *diagnostic, const char (&message)[Size]) noexcept {
        write_diagnostic(diagnostic, message, Size - 1U);
    }

    template<typename Size> [[nodiscard]] bool size_representable_as(const uint64_t size) noexcept {
        if constexpr (sizeof(Size) >= sizeof(uint64_t)) {
            static_cast<void>(size);
            return true;
        } else {
            return size <= static_cast<uint64_t>(std::numeric_limits<Size>::max());
        }
    }

    [[nodiscard]] bool size_representable(const uint64_t size) noexcept {
        return size_representable_as<std::size_t>(size);
    }

    [[nodiscard]] absl::string_view byte_view(const uint8_t *data, const uint64_t size) noexcept {
        const auto *characters = size == 0 ? &empty_data : reinterpret_cast<const char *>(data);
        return {characters, static_cast<std::size_t>(size)};
    }

    [[nodiscard]] bool boolean_option_valid(const uint8_t value) noexcept { return value <= UINT8_C(1); }

    [[nodiscard]] rule_engine_re2_bridge_status make_options(const rule_engine_re2_bridge_options *source,
                                                             re2::RE2::Options &destination,
                                                             rule_engine_re2_bridge_diagnostic *diagnostic) noexcept {
        if (source == nullptr) {
            write_diagnostic(diagnostic, "RE2 bridge options are required");
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT;
        }
        if (source->structure_size != sizeof(rule_engine_re2_bridge_options) ||
            source->abi_version != RULE_ENGINE_RE2_BRIDGE_ABI_VERSION) {
            write_diagnostic(diagnostic, "RE2 bridge option ABI does not match");
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_OPTIONS;
        }
        if (source->encoding != RULE_ENGINE_RE2_BRIDGE_ENCODING_UTF8 &&
            source->encoding != RULE_ENGINE_RE2_BRIDGE_ENCODING_LATIN1) {
            write_diagnostic(diagnostic, "RE2 encoding must be UTF-8 or Latin-1");
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_OPTIONS;
        }
        if (!boolean_option_valid(source->case_sensitive) || !boolean_option_valid(source->dot_nl) ||
            !boolean_option_valid(source->multiline) ||
            std::any_of(std::begin(source->reserved), std::end(source->reserved),
                        [](const uint8_t value) { return value != 0; })) {
            write_diagnostic(diagnostic, "RE2 boolean and reserved option bytes are invalid");
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_OPTIONS;
        }

        destination.set_log_errors(false);
        destination.set_never_capture(true);
        destination.set_max_mem(static_cast<int64_t>(RULE_ENGINE_RE2_BRIDGE_MAX_MEMORY_BYTES));
        destination.set_encoding(source->encoding == RULE_ENGINE_RE2_BRIDGE_ENCODING_UTF8 ?
                                     re2::RE2::Options::EncodingUTF8 :
                                     re2::RE2::Options::EncodingLatin1);
        destination.set_case_sensitive(source->case_sensitive != 0);
        destination.set_dot_nl(source->dot_nl != 0);
        return RULE_ENGINE_RE2_BRIDGE_STATUS_OK;
    }

    [[nodiscard]] uint64_t find_error_offset(const absl::string_view pattern,
                                             const std::string &error_argument) noexcept {
        if (error_argument.empty()) {
            return RULE_ENGINE_RE2_BRIDGE_NO_PATTERN_OFFSET;
        }
        const auto offset = pattern.find(error_argument);
        if (offset == absl::string_view::npos) {
            return RULE_ENGINE_RE2_BRIDGE_NO_PATTERN_OFFSET;
        }
        return static_cast<uint64_t>(offset);
    }

    [[nodiscard]] rule_engine_re2_bridge_status
    report_regex_error(const re2::RE2 &expression, const absl::string_view pattern,
                       rule_engine_re2_bridge_diagnostic *diagnostic) noexcept {
        const auto &message = expression.error();
        write_diagnostic(diagnostic, message.data(), message.size(),
                         find_error_offset(pattern, expression.error_arg()));
        return RULE_ENGINE_RE2_BRIDGE_STATUS_REGEX_SYNTAX;
    }

    [[nodiscard]] rule_engine_re2_bridge_status
    validate_common_arguments(const uint8_t *pattern_data, const uint64_t pattern_size,
                              rule_engine_re2_bridge_diagnostic *diagnostic) noexcept {
        if (!diagnostic_storage_valid(diagnostic)) {
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT;
        }
        clear_diagnostic(diagnostic);
        if (pattern_data == nullptr && pattern_size != 0) {
            write_diagnostic(diagnostic, "RE2 pattern pointer is null for a non-empty pattern");
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT;
        }
        if (!size_representable(pattern_size)) {
            write_diagnostic(diagnostic, "RE2 pattern size does not fit the bridge address space");
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT;
        }
        return RULE_ENGINE_RE2_BRIDGE_STATUS_OK;
    }

    [[nodiscard]] rule_engine_re2_bridge_status find_next(const re2::RE2 &expression, const uint8_t *input_data,
                                                          const uint64_t input_size, const uint64_t start_offset,
                                                          rule_engine_re2_bridge_match *match,
                                                          rule_engine_re2_bridge_diagnostic *diagnostic) noexcept {
        if (!diagnostic_storage_valid(diagnostic)) {
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT;
        }
        clear_diagnostic(diagnostic);
        if (match == nullptr) {
            write_diagnostic(diagnostic, "RE2 match output is required");
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT;
        }
        match->offset = 0;
        match->length = 0;
        if (input_data == nullptr && input_size != 0) {
            write_diagnostic(diagnostic, "RE2 input pointer is null for non-empty input");
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT;
        }
        if (!size_representable(input_size) || start_offset > input_size) {
            write_diagnostic(diagnostic, "RE2 input size or start offset is outside the bridge address space");
            return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT;
        }

        const auto input = byte_view(input_data, input_size);
        absl::string_view re2_match;
        if (!expression.Match(input, static_cast<std::size_t>(start_offset), input.size(), re2::RE2::UNANCHORED,
                              &re2_match, 1)) {
            return RULE_ENGINE_RE2_BRIDGE_STATUS_NO_MATCH;
        }

        if (re2_match.data() == nullptr) {
            match->offset = start_offset;
            return RULE_ENGINE_RE2_BRIDGE_STATUS_OK;
        }
        match->offset = static_cast<uint64_t>(re2_match.data() - input.data());
        match->length = static_cast<uint64_t>(re2_match.size());
        return RULE_ENGINE_RE2_BRIDGE_STATUS_OK;
    }

} // namespace

rule_engine_re2_bridge_status RULE_ENGINE_RE2_BRIDGE_CALL rule_engine_re2_bridge_validate_pattern(
    const uint8_t *pattern_data, const uint64_t pattern_size, const rule_engine_re2_bridge_options *options,
    rule_engine_re2_bridge_diagnostic *diagnostic) noexcept {
    rule_engine_re2_bridge_pattern *compiled {};
    const auto status =
        rule_engine_re2_bridge_compile_pattern(pattern_data, pattern_size, options, &compiled, diagnostic);
    rule_engine_re2_bridge_destroy_pattern(compiled);
    return status;
}

rule_engine_re2_bridge_status RULE_ENGINE_RE2_BRIDGE_CALL rule_engine_re2_bridge_compile_pattern(
    const uint8_t *pattern_data, const uint64_t pattern_size, const rule_engine_re2_bridge_options *options,
    rule_engine_re2_bridge_pattern **compiled_pattern, rule_engine_re2_bridge_diagnostic *diagnostic) noexcept {
    const auto arguments = validate_common_arguments(pattern_data, pattern_size, diagnostic);
    if (arguments != RULE_ENGINE_RE2_BRIDGE_STATUS_OK) {
        return arguments;
    }
    if (compiled_pattern == nullptr) {
        write_diagnostic(diagnostic, "RE2 compiled pattern output is required");
        return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT;
    }
    *compiled_pattern = nullptr;

    re2::RE2::Options re2_options;
    const auto option_status = make_options(options, re2_options, diagnostic);
    if (option_status != RULE_ENGINE_RE2_BRIDGE_STATUS_OK) {
        return option_status;
    }

    const auto pattern = byte_view(pattern_data, pattern_size);
    std::string multiline_pattern;
    auto compiled_source = pattern;
    if (options->multiline != 0) {
        if (pattern.size() > std::numeric_limits<std::size_t>::max() - 4U) {
            write_diagnostic(diagnostic, "RE2 multiline pattern size overflows");
            return RULE_ENGINE_RE2_BRIDGE_STATUS_RESOURCE_EXHAUSTED;
        }
        multiline_pattern.reserve(pattern.size() + 4U);
        multiline_pattern.append("(?m)");
        multiline_pattern.append(pattern.data(), pattern.size());
        compiled_source = multiline_pattern;
    }
    auto *compiled = new (std::nothrow) rule_engine_re2_bridge_pattern {compiled_source, re2_options};
    if (compiled == nullptr) {
        write_diagnostic(diagnostic, "RE2 compiled pattern allocation failed");
        return RULE_ENGINE_RE2_BRIDGE_STATUS_RESOURCE_EXHAUSTED;
    }
    if (!compiled->expression.ok()) {
        const auto status = report_regex_error(compiled->expression, pattern, diagnostic);
        delete compiled;
        return status;
    }
    *compiled_pattern = compiled;
    return RULE_ENGINE_RE2_BRIDGE_STATUS_OK;
}

void RULE_ENGINE_RE2_BRIDGE_CALL
rule_engine_re2_bridge_destroy_pattern(rule_engine_re2_bridge_pattern *compiled_pattern) noexcept {
    delete compiled_pattern;
}

rule_engine_re2_bridge_status RULE_ENGINE_RE2_BRIDGE_CALL rule_engine_re2_bridge_find_next_compiled(
    const rule_engine_re2_bridge_pattern *compiled_pattern, const uint8_t *input_data, const uint64_t input_size,
    const uint64_t start_offset, rule_engine_re2_bridge_match *match,
    rule_engine_re2_bridge_diagnostic *diagnostic) noexcept {
    if (compiled_pattern == nullptr) {
        if (diagnostic_storage_valid(diagnostic)) {
            clear_diagnostic(diagnostic);
            write_diagnostic(diagnostic, "RE2 compiled pattern is required");
        }
        return RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT;
    }
    return find_next(compiled_pattern->expression, input_data, input_size, start_offset, match, diagnostic);
}

rule_engine_re2_bridge_status RULE_ENGINE_RE2_BRIDGE_CALL rule_engine_re2_bridge_find_next(
    const uint8_t *pattern_data, const uint64_t pattern_size, const rule_engine_re2_bridge_options *options,
    const uint8_t *input_data, const uint64_t input_size, const uint64_t start_offset,
    rule_engine_re2_bridge_match *match, rule_engine_re2_bridge_diagnostic *diagnostic) noexcept {
    rule_engine_re2_bridge_pattern *compiled {};
    const auto compile_status =
        rule_engine_re2_bridge_compile_pattern(pattern_data, pattern_size, options, &compiled, diagnostic);
    if (compile_status != RULE_ENGINE_RE2_BRIDGE_STATUS_OK) {
        return compile_status;
    }
    const auto match_status =
        rule_engine_re2_bridge_find_next_compiled(compiled, input_data, input_size, start_offset, match, diagnostic);
    rule_engine_re2_bridge_destroy_pattern(compiled);
    return match_status;
}
