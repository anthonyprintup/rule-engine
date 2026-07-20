#include "rule_engine/python/optimizer/scanner.hpp"

#if defined(RULE_ENGINE_PYTHON_OPTIMIZER_HAS_RE2)
#include <re2/re2.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::optimizer {
    namespace {

        [[nodiscard]] ScanError error(const ScanErrorCode code, std::string message, std::string pattern_id = {},
                                      const std::size_t input_offset = 0) {
            return ScanError {
                .code = code,
                .pattern_id = std::move(pattern_id),
                .input_offset = input_offset,
                .message = std::move(message),
            };
        }

        [[nodiscard]] std::byte ascii_lower(const std::byte value) noexcept {
            const auto number = std::to_integer<unsigned int>(value);
            if (number >= static_cast<unsigned int>('A') && number <= static_cast<unsigned int>('Z')) {
                return static_cast<std::byte>(number + static_cast<unsigned int>('a' - 'A'));
            }
            return value;
        }

        [[nodiscard]] bool is_continuation(const unsigned char value) noexcept { return (value & 0xC0U) == 0x80U; }

        [[nodiscard]] std::expected<std::uint32_t, ScanError>
        decode_utf8_code_point(const std::string_view input, std::size_t &offset, const std::string &pattern_id) {
            const auto start = offset;
            const auto first = static_cast<unsigned char>(input[offset]);
            if (first <= 0x7FU) {
                ++offset;
                return first;
            }

            std::size_t width {};
            std::uint32_t value {};
            std::uint32_t minimum {};
            if ((first & 0xE0U) == 0xC0U) {
                width = 2;
                value = first & 0x1FU;
                minimum = 0x80U;
            } else if ((first & 0xF0U) == 0xE0U) {
                width = 3;
                value = first & 0x0FU;
                minimum = 0x800U;
            } else if ((first & 0xF8U) == 0xF0U) {
                width = 4;
                value = first & 0x07U;
                minimum = 0x10000U;
            } else {
                return std::unexpected(
                    error(ScanErrorCode::invalid_utf8, "invalid UTF-8 leading byte", pattern_id, start));
            }

            if (width > input.size() - offset) {
                return std::unexpected(
                    error(ScanErrorCode::invalid_utf8, "truncated UTF-8 sequence", pattern_id, start));
            }
            for (std::size_t index = 1; index < width; ++index) {
                const auto next = static_cast<unsigned char>(input[offset + index]);
                if (!is_continuation(next)) {
                    return std::unexpected(error(ScanErrorCode::invalid_utf8, "invalid UTF-8 continuation byte",
                                                 pattern_id, offset + index));
                }
                value = (value << 6U) | (next & 0x3FU);
            }
            offset += width;
            if (value < minimum || value > 0x10FFFFU || (value >= 0xD800U && value <= 0xDFFFU)) {
                return std::unexpected(
                    error(ScanErrorCode::invalid_utf8, "non-canonical UTF-8 scalar", pattern_id, start));
            }
            return value;
        }

        void append_u16(std::vector<std::byte> &output, const std::uint16_t value, const TextEncoding encoding) {
            const auto low = static_cast<std::byte>(value & 0xFFU);
            const auto high = static_cast<std::byte>((value >> 8U) & 0xFFU);
            if (encoding == TextEncoding::utf16_little_endian) {
                output.push_back(low);
                output.push_back(high);
                return;
            }
            output.push_back(high);
            output.push_back(low);
        }

        [[nodiscard]] std::expected<std::vector<std::byte>, ScanError>
        encode_text(const std::string_view utf8, const TextEncoding encoding, const std::string &pattern_id) {
            std::vector<std::byte> result;
            if (encoding == TextEncoding::utf8) {
                result.reserve(utf8.size());
                std::size_t offset {};
                while (offset < utf8.size()) {
                    const auto scalar = decode_utf8_code_point(utf8, offset, pattern_id);
                    if (!scalar.has_value()) {
                        return std::unexpected(scalar.error());
                    }
                }
                for (const char value : utf8) {
                    result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
                }
                return result;
            }

            result.reserve(utf8.size() * 2U);
            std::size_t offset {};
            while (offset < utf8.size()) {
                const auto scalar = decode_utf8_code_point(utf8, offset, pattern_id);
                if (!scalar.has_value()) {
                    return std::unexpected(scalar.error());
                }
                if (*scalar <= 0xFFFFU) {
                    append_u16(result, static_cast<std::uint16_t>(*scalar), encoding);
                    continue;
                }
                const auto adjusted = *scalar - 0x10000U;
                append_u16(result, static_cast<std::uint16_t>(0xD800U + (adjusted >> 10U)), encoding);
                append_u16(result, static_cast<std::uint16_t>(0xDC00U + (adjusted & 0x3FFU)), encoding);
            }
            return result;
        }

        [[nodiscard]] std::optional<std::uint8_t> hex_nibble(const char value) noexcept {
            if (value >= '0' && value <= '9') {
                return static_cast<std::uint8_t>(value - '0');
            }
            if (value >= 'a' && value <= 'f') {
                return static_cast<std::uint8_t>(10 + value - 'a');
            }
            if (value >= 'A' && value <= 'F') {
                return static_cast<std::uint8_t>(10 + value - 'A');
            }
            return std::nullopt;
        }

        [[nodiscard]] bool byte_matches(const StaticScanPattern &pattern, const std::span<const std::byte> input,
                                        const std::size_t offset) noexcept {
            if (pattern.bytes.size() > input.size() - offset) {
                return false;
            }
            for (std::size_t index = 0; index < pattern.bytes.size(); ++index) {
                auto actual = input[offset + index];
                auto expected = pattern.bytes[index];
                if (pattern.ascii_case_insensitive) {
                    actual = ascii_lower(actual);
                    expected = ascii_lower(expected);
                }
                const auto mask = pattern.mask.empty() ? std::byte {0xFF} : pattern.mask[index];
                if ((actual & mask) != (expected & mask)) {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] std::vector<std::byte> copy_range(const std::span<const std::byte> source,
                                                        const std::size_t begin, const std::size_t end) {
            return std::vector<std::byte> {source.begin() + static_cast<std::ptrdiff_t>(begin),
                                           source.begin() + static_cast<std::ptrdiff_t>(end)};
        }

        [[nodiscard]] std::expected<void, ScanError> append_match(MatchSet &result, const ExplicitScanSpace &space,
                                                                  const TypedScanPlan &plan,
                                                                  const std::span<const std::byte> input,
                                                                  const StaticScanPattern &pattern,
                                                                  const std::size_t offset, const std::size_t length) {
            if (result.matches.size() >= plan.maximum_matches) {
                return std::unexpected(error(ScanErrorCode::match_budget_exceeded,
                                             "complete MatchSet exceeds maximum_matches", pattern.pattern_id, offset));
            }
            if (offset > std::numeric_limits<std::uint64_t>::max() - space.begin) {
                return std::unexpected(error(ScanErrorCode::arithmetic_overflow, "match absolute address overflows",
                                             pattern.pattern_id, offset));
            }
            const auto before_count = std::min<std::size_t>(plan.context_bytes_before, offset);
            const auto after_start = offset + length;
            const auto after_count = std::min<std::size_t>(plan.context_bytes_after, input.size() - after_start);
            result.matches.push_back(TypedScanMatch {
                .pattern_id = pattern.pattern_id,
                .scan_space_identity = space.identity,
                .offset = static_cast<std::uint64_t>(offset),
                .absolute_address = space.begin + static_cast<std::uint64_t>(offset),
                .length = static_cast<std::uint64_t>(length),
                .permissions = space.permissions,
                .context_before = copy_range(input, offset - before_count, offset),
                .context_after = copy_range(input, after_start, after_start + after_count),
            });
            return {};
        }

        [[nodiscard]] std::expected<void, ScanError>
        scan_fixed_pattern(MatchSet &result, const ExplicitScanSpace &space, const TypedScanPlan &plan,
                           const std::span<const std::byte> input, const StaticScanPattern &pattern) {
            if (pattern.bytes.empty() || (!pattern.mask.empty() && pattern.mask.size() != pattern.bytes.size())) {
                return std::unexpected(error(ScanErrorCode::invalid_pattern,
                                             "literal/masked pattern has invalid byte and mask sizes",
                                             pattern.pattern_id));
            }
            if (pattern.bytes.size() > input.size()) {
                return {};
            }
            const auto final_offset = input.size() - pattern.bytes.size();
            for (std::size_t offset = 0; offset <= final_offset; ++offset) {
                if (!byte_matches(pattern, input, offset)) {
                    continue;
                }
                const auto appended = append_match(result, space, plan, input, pattern, offset, pattern.bytes.size());
                if (!appended.has_value()) {
                    return appended;
                }
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ScanError>
        scan_regex_pattern(MatchSet &result, const ExplicitScanSpace &space, const TypedScanPlan &plan,
                           const std::span<const std::byte> input, const StaticScanPattern &pattern) {
#if defined(RULE_ENGINE_PYTHON_OPTIMIZER_HAS_RE2)
            re2::RE2::Options options;
            options.set_log_errors(false);
            options.set_never_capture(true);
            options.set_case_sensitive(pattern.regex_options.case_sensitive);
            options.set_dot_nl(pattern.regex_options.dot_matches_newline);
            options.set_one_line(pattern.regex_options.one_line);
            options.set_encoding(pattern.regex_options.encoding == RegexEncoding::utf8 ?
                                     re2::RE2::Options::EncodingUTF8 :
                                     re2::RE2::Options::EncodingLatin1);
            const re2::RE2 expression {pattern.regex_source, options};
            if (!expression.ok()) {
                const auto source_begin = reinterpret_cast<std::uintptr_t>(pattern.regex_source.data());
                const auto source_end = source_begin + pattern.regex_source.size();
                const auto argument = reinterpret_cast<std::uintptr_t>(expression.error_arg().data());
                const auto error_offset = argument >= source_begin && argument <= source_end ?
                                              static_cast<std::size_t>(argument - source_begin) :
                                              0U;
                return std::unexpected(
                    error(ScanErrorCode::regex_syntax, expression.error(), pattern.pattern_id, error_offset));
            }

            const auto *characters = reinterpret_cast<const char *>(input.data());
            const re2::StringPiece text {characters, input.size()};
            std::size_t cursor {};
            while (cursor <= input.size()) {
                std::array<re2::StringPiece, 1> match;
                if (!expression.Match(text, cursor, input.size(), re2::RE2::UNANCHORED, match.data(), 1)) {
                    break;
                }
                const auto offset = static_cast<std::size_t>(match.front().data() - characters);
                const auto length = match.front().size();
                const auto appended = append_match(result, space, plan, input, pattern, offset, length);
                if (!appended.has_value()) {
                    return appended;
                }
                if (length == 0) {
                    if (offset == input.size()) {
                        break;
                    }
                    cursor = offset + 1U;
                } else {
                    cursor = offset + length;
                }
            }
            return {};
#else
            static_cast<void>(result);
            static_cast<void>(space);
            static_cast<void>(plan);
            static_cast<void>(input);
            return std::unexpected(
                error(ScanErrorCode::regex_engine_unavailable, "RE2 support is not linked", pattern.pattern_id));
#endif
        }

        [[nodiscard]] std::expected<void, ScanError> validate_plan(const ExplicitScanSpace &space,
                                                                   const TypedScanPlan &plan) {
            if (space.identity.empty() || space.size == 0 || (space.permissions & scan_permission_read) == 0) {
                return std::unexpected(error(ScanErrorCode::invalid_space,
                                             "scan space must have identity, non-zero size, and read permission"));
            }
            switch (space.kind) {
                case ScanSpaceKind::image_file:
                case ScanSpaceKind::mapped_image:
                case ScanSpaceKind::mapped_section:
                case ScanSpaceKind::readable_memory: break;
                default: return std::unexpected(error(ScanErrorCode::invalid_space, "scan space kind is unknown"));
            }
            if (space.size > std::numeric_limits<std::uint64_t>::max() - space.begin) {
                return std::unexpected(
                    error(ScanErrorCode::arithmetic_overflow, "absolute scan space range overflows"));
            }
            if (plan.plan_id.empty() || plan.patterns.empty() || plan.maximum_bytes == 0 || plan.maximum_matches == 0) {
                return std::unexpected(
                    error(ScanErrorCode::invalid_plan, "scan plan requires identity, patterns, and non-zero limits"));
            }
            if (space.size > plan.maximum_bytes) {
                return std::unexpected(error(ScanErrorCode::byte_budget_exceeded, "scan space exceeds maximum_bytes"));
            }

            std::vector<std::string_view> pattern_ids;
            pattern_ids.reserve(plan.patterns.size());
            for (const auto &pattern : plan.patterns) {
                if (pattern.pattern_id.empty()) {
                    return std::unexpected(error(ScanErrorCode::invalid_pattern, "scan pattern ID cannot be empty"));
                }
                if (pattern.origin != PatternOrigin::compile_time &&
                    pattern.origin != PatternOrigin::template_binding) {
                    return std::unexpected(error(ScanErrorCode::invalid_pattern,
                                                 "scan pattern origin is not static or template-bound",
                                                 pattern.pattern_id));
                }
                switch (pattern.kind) {
                    case StaticPatternKind::byte_literal:
                    case StaticPatternKind::text_literal:
                        if (pattern.bytes.empty() || !pattern.mask.empty() || !pattern.regex_source.empty()) {
                            return std::unexpected(error(ScanErrorCode::invalid_pattern,
                                                         "literal pattern representation is inconsistent",
                                                         pattern.pattern_id));
                        }
                        break;
                    case StaticPatternKind::masked_bytes:
                        if (pattern.bytes.empty() || pattern.mask.size() != pattern.bytes.size() ||
                            !pattern.regex_source.empty()) {
                            return std::unexpected(error(ScanErrorCode::invalid_pattern,
                                                         "masked pattern representation is inconsistent",
                                                         pattern.pattern_id));
                        }
                        break;
                    case StaticPatternKind::re2_regex:
                        if (!pattern.bytes.empty() || !pattern.mask.empty() || pattern.regex_source.empty()) {
                            return std::unexpected(error(ScanErrorCode::invalid_pattern,
                                                         "regex pattern representation is inconsistent",
                                                         pattern.pattern_id));
                        }
                        if (pattern.regex_options.encoding != RegexEncoding::utf8 &&
                            pattern.regex_options.encoding != RegexEncoding::latin1) {
                            return std::unexpected(
                                error(ScanErrorCode::invalid_pattern, "regex encoding is unknown", pattern.pattern_id));
                        }
                        break;
                    default:
                        return std::unexpected(
                            error(ScanErrorCode::invalid_pattern, "scan pattern kind is unknown", pattern.pattern_id));
                }
                pattern_ids.push_back(pattern.pattern_id);
            }
            std::ranges::sort(pattern_ids);
            if (std::ranges::adjacent_find(pattern_ids) != pattern_ids.end()) {
                return std::unexpected(
                    error(ScanErrorCode::duplicate_pattern_id, "scan plan pattern IDs must be unique"));
            }
            return {};
        }

    } // namespace

    std::expected<StaticScanPattern, ScanError>
    make_byte_pattern(std::string pattern_id, const std::span<const std::byte> bytes, const PatternOrigin origin) {
        if (pattern_id.empty() || bytes.empty()) {
            return std::unexpected(error(ScanErrorCode::invalid_pattern, "byte pattern requires non-empty ID and bytes",
                                         std::move(pattern_id)));
        }
        return StaticScanPattern {
            .pattern_id = std::move(pattern_id),
            .kind = StaticPatternKind::byte_literal,
            .origin = origin,
            .bytes = std::vector<std::byte> {bytes.begin(), bytes.end()},
            .mask = {},
            .ascii_case_insensitive = false,
            .regex_source = {},
            .regex_options = {},
        };
    }

    std::expected<StaticScanPattern, ScanError> make_text_pattern(std::string pattern_id, const std::string_view utf8,
                                                                  const TextEncoding encoding, const TextCase text_case,
                                                                  const PatternOrigin origin) {
        if (pattern_id.empty() || utf8.empty()) {
            return std::unexpected(error(ScanErrorCode::invalid_pattern, "text pattern requires non-empty ID and text",
                                         std::move(pattern_id)));
        }
        auto encoded = encode_text(utf8, encoding, pattern_id);
        if (!encoded.has_value()) {
            return std::unexpected(std::move(encoded.error()));
        }
        return StaticScanPattern {
            .pattern_id = std::move(pattern_id),
            .kind = StaticPatternKind::text_literal,
            .origin = origin,
            .bytes = std::move(*encoded),
            .mask = {},
            .ascii_case_insensitive = text_case == TextCase::ascii_insensitive,
            .regex_source = {},
            .regex_options = {},
        };
    }

    std::expected<StaticScanPattern, ScanError>
    make_masked_pattern(std::string pattern_id, const std::string_view masked, const PatternOrigin origin) {
        if (pattern_id.empty()) {
            return std::unexpected(
                error(ScanErrorCode::invalid_pattern, "masked pattern ID cannot be empty", std::move(pattern_id)));
        }

        std::vector<std::byte> bytes;
        std::vector<std::byte> mask;
        std::size_t offset {};
        while (offset < masked.size()) {
            while (offset < masked.size() && std::isspace(static_cast<unsigned char>(masked[offset])) != 0) {
                ++offset;
            }
            if (offset == masked.size()) {
                break;
            }
            const auto token_offset = offset;
            const auto token_end = masked.find_first_of(" \t\r\n\f\v", offset);
            const auto end = token_end == std::string_view::npos ? masked.size() : token_end;
            const auto token = masked.substr(offset, end - offset);
            if (token.size() != 2) {
                return std::unexpected(error(ScanErrorCode::invalid_masked_pattern,
                                             "masked byte token must have two nibbles", pattern_id, token_offset));
            }

            std::uint8_t value {};
            std::uint8_t value_mask {};
            for (std::size_t nibble_index = 0; nibble_index < 2; ++nibble_index) {
                if (token[nibble_index] == '?') {
                    continue;
                }
                const auto nibble = hex_nibble(token[nibble_index]);
                if (!nibble.has_value()) {
                    return std::unexpected(error(ScanErrorCode::invalid_masked_pattern,
                                                 "masked byte token contains a non-hex nibble", pattern_id,
                                                 token_offset + nibble_index));
                }
                const auto shift = nibble_index == 0 ? 4U : 0U;
                value |= static_cast<std::uint8_t>(*nibble << shift);
                value_mask |= static_cast<std::uint8_t>(0x0FU << shift);
            }
            bytes.push_back(static_cast<std::byte>(value));
            mask.push_back(static_cast<std::byte>(value_mask));
            offset = end;
        }
        if (bytes.empty()) {
            return std::unexpected(error(ScanErrorCode::invalid_masked_pattern,
                                         "masked pattern requires at least one byte", std::move(pattern_id)));
        }
        return StaticScanPattern {
            .pattern_id = std::move(pattern_id),
            .kind = StaticPatternKind::masked_bytes,
            .origin = origin,
            .bytes = std::move(bytes),
            .mask = std::move(mask),
            .ascii_case_insensitive = false,
            .regex_source = {},
            .regex_options = {},
        };
    }

    std::expected<StaticScanPattern, ScanError> make_re2_pattern(std::string pattern_id,
                                                                 const std::string_view expression,
                                                                 const RegexOptions options,
                                                                 const PatternOrigin origin) {
        if (pattern_id.empty() || expression.empty()) {
            return std::unexpected(error(ScanErrorCode::invalid_pattern,
                                         "regex pattern requires non-empty ID and expression", std::move(pattern_id)));
        }
#if defined(RULE_ENGINE_PYTHON_OPTIMIZER_HAS_RE2)
        re2::RE2::Options re2_options;
        re2_options.set_log_errors(false);
        re2_options.set_never_capture(true);
        re2_options.set_case_sensitive(options.case_sensitive);
        re2_options.set_dot_nl(options.dot_matches_newline);
        re2_options.set_one_line(options.one_line);
        re2_options.set_encoding(options.encoding == RegexEncoding::utf8 ? re2::RE2::Options::EncodingUTF8 :
                                                                           re2::RE2::Options::EncodingLatin1);
        const re2::RE2 compiled {expression, re2_options};
        if (!compiled.ok()) {
            const auto source_begin = reinterpret_cast<std::uintptr_t>(expression.data());
            const auto source_end = source_begin + expression.size();
            const auto argument = reinterpret_cast<std::uintptr_t>(compiled.error_arg().data());
            const auto error_offset = argument >= source_begin && argument <= source_end ?
                                          static_cast<std::size_t>(argument - source_begin) :
                                          0U;
            return std::unexpected(error(ScanErrorCode::regex_syntax, compiled.error(), pattern_id, error_offset));
        }
        return StaticScanPattern {
            .pattern_id = std::move(pattern_id),
            .kind = StaticPatternKind::re2_regex,
            .origin = origin,
            .bytes = {},
            .mask = {},
            .ascii_case_insensitive = false,
            .regex_source = std::string {expression},
            .regex_options = options,
        };
#else
        static_cast<void>(options);
        static_cast<void>(origin);
        return std::unexpected(
            error(ScanErrorCode::regex_engine_unavailable, "RE2 support is not linked", std::move(pattern_id)));
#endif
    }

    bool re2_engine_available() noexcept {
#if defined(RULE_ENGINE_PYTHON_OPTIMIZER_HAS_RE2)
        return true;
#else
        return false;
#endif
    }

    std::expected<MatchSet, ScanError> execute_scan(const ExplicitScanSpace &space, const TypedScanPlan &plan,
                                                    const std::span<const std::byte> source,
                                                    const std::uint64_t source_origin) {
        const auto plan_validation = validate_plan(space, plan);
        if (!plan_validation.has_value()) {
            return std::unexpected(plan_validation.error());
        }
        if (space.begin < source_origin) {
            return std::unexpected(
                error(ScanErrorCode::space_out_of_bounds, "scan space begins before provided source"));
        }
        const auto relative_begin_u64 = space.begin - source_origin;
        if (relative_begin_u64 > source.size()) {
            return std::unexpected(
                error(ScanErrorCode::space_out_of_bounds, "scan space begins after provided source"));
        }
        if (space.size > std::numeric_limits<std::uint64_t>::max() - relative_begin_u64) {
            return std::unexpected(error(ScanErrorCode::arithmetic_overflow, "scan space range overflows"));
        }
        const auto relative_end_u64 = relative_begin_u64 + space.size;
        if (relative_end_u64 > source.size()) {
            return std::unexpected(error(ScanErrorCode::space_out_of_bounds, "scan space exceeds provided source"));
        }

        const auto relative_begin = static_cast<std::size_t>(relative_begin_u64);
        const auto relative_end = static_cast<std::size_t>(relative_end_u64);
        const auto input = source.subspan(relative_begin, relative_end - relative_begin);
        MatchSet result;
        for (const auto &pattern : plan.patterns) {
            const auto scanned = pattern.kind == StaticPatternKind::re2_regex ?
                                     scan_regex_pattern(result, space, plan, input, pattern) :
                                     scan_fixed_pattern(result, space, plan, input, pattern);
            if (!scanned.has_value()) {
                return std::unexpected(scanned.error());
            }
        }
        std::ranges::sort(result.matches, [](const TypedScanMatch &left, const TypedScanMatch &right) {
            if (left.offset != right.offset) {
                return left.offset < right.offset;
            }
            if (left.pattern_id != right.pattern_id) {
                return left.pattern_id < right.pattern_id;
            }
            return left.length < right.length;
        });
        return result;
    }

} // namespace rule_engine::python::optimizer
