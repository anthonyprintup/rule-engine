#include "rule_engine/python/optimizer/scan_wire.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <functional>
#include <limits>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace rule_engine::python::optimizer {
    namespace {

        constexpr std::string_view wire_magic = "rsp1;";
        constexpr std::uint32_t known_permissions =
            scan_permission_read | scan_permission_write | scan_permission_execute;

        [[nodiscard]] ScanWireError wire_error(const ScanWireErrorCode code, std::string message,
                                               const std::size_t byte_offset = 0) {
            return ScanWireError {.code = code, .byte_offset = byte_offset, .message = std::move(message)};
        }

        [[nodiscard]] bool checked_accumulate(std::size_t &total, const std::size_t value,
                                              const std::size_t maximum) noexcept {
            if (value > maximum || total > maximum - value) {
                return false;
            }
            total += value;
            return true;
        }

        [[nodiscard]] std::expected<void, ScanWireError> validate_limits(const ScanWireLimits &limits) {
            if (limits.maximum_encoded_plan_bytes < wire_magic.size() || limits.maximum_identifier_bytes == 0 ||
                limits.maximum_patterns == 0 || limits.maximum_pattern_bytes == 0 ||
                limits.maximum_total_pattern_bytes == 0 || limits.maximum_regex_source_bytes == 0 ||
                limits.maximum_scan_bytes == 0 || limits.maximum_scan_matches == 0 ||
                limits.maximum_result_payload_bytes == 0 || limits.maximum_label_categories == 0 ||
                limits.maximum_label_bytes == 0 || limits.maximum_subject_depth == 0 ||
                limits.maximum_identity_fields == 0 || limits.maximum_subject_component_bytes == 0 ||
                limits.maximum_subject_bytes == 0) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::invalid_limits, "scan wire limits must be non-zero"));
            }
            return {};
        }

        [[nodiscard]] bool valid_utf8(const std::string_view text) noexcept {
            std::size_t offset {};
            while (offset < text.size()) {
                const auto first = static_cast<unsigned char>(text[offset]);
                std::size_t count {};
                std::uint32_t scalar {};
                if (first <= 0x7FU) {
                    count = 1;
                    scalar = first;
                } else if (first >= 0xC2U && first <= 0xDFU) {
                    count = 2;
                    scalar = first & 0x1FU;
                } else if (first >= 0xE0U && first <= 0xEFU) {
                    count = 3;
                    scalar = first & 0x0FU;
                } else if (first >= 0xF0U && first <= 0xF4U) {
                    count = 4;
                    scalar = first & 0x07U;
                } else {
                    return false;
                }
                if (count > text.size() - offset) {
                    return false;
                }
                for (std::size_t index = 1; index < count; ++index) {
                    const auto continuation = static_cast<unsigned char>(text[offset + index]);
                    if ((continuation & 0xC0U) != 0x80U) {
                        return false;
                    }
                    scalar = (scalar << 6U) | (continuation & 0x3FU);
                }
                if ((count == 2 && scalar < 0x80U) || (count == 3 && scalar < 0x800U) ||
                    (count == 4 && scalar < 0x10000U) || scalar > 0x10FFFFU ||
                    (scalar >= 0xD800U && scalar <= 0xDFFFU)) {
                    return false;
                }
                offset += count;
            }
            return true;
        }

        [[nodiscard]] std::uint16_t read_u16(const std::span<const std::byte> input, const std::size_t offset,
                                             const TextEncoding encoding) noexcept {
            const auto first = std::to_integer<std::uint16_t>(input[offset]);
            const auto second = std::to_integer<std::uint16_t>(input[offset + 1U]);
            return encoding == TextEncoding::utf16_little_endian ? static_cast<std::uint16_t>(first | (second << 8U)) :
                                                                   static_cast<std::uint16_t>((first << 8U) | second);
        }

        [[nodiscard]] bool valid_encoded_text(const std::span<const std::byte> bytes,
                                              const TextEncoding encoding) noexcept {
            if (encoding == TextEncoding::utf8) {
                return valid_utf8(std::string_view {reinterpret_cast<const char *>(bytes.data()), bytes.size()});
            }
            if ((encoding != TextEncoding::utf16_little_endian && encoding != TextEncoding::utf16_big_endian) ||
                (bytes.size() & 1U) != 0U) {
                return false;
            }
            for (std::size_t offset = 0; offset < bytes.size(); offset += 2U) {
                const auto unit = read_u16(bytes, offset, encoding);
                if (unit >= 0xDC00U && unit <= 0xDFFFU) {
                    return false;
                }
                if (unit < 0xD800U || unit > 0xDBFFU) {
                    continue;
                }
                if (offset + 3U >= bytes.size()) {
                    return false;
                }
                const auto low = read_u16(bytes, offset + 2U, encoding);
                if (low < 0xDC00U || low > 0xDFFFU) {
                    return false;
                }
                offset += 2U;
            }
            return true;
        }

        [[nodiscard]] bool canonical_integer(const std::string_view decimal) noexcept {
            if (decimal.empty() || decimal == "-" || (decimal.front() == '-' && decimal[1] == '0')) {
                return false;
            }
            std::size_t offset = decimal.front() == '-' ? 1U : 0U;
            if (decimal[offset] == '0') {
                return offset + 1U == decimal.size();
            }
            if (decimal[offset] < '1' || decimal[offset] > '9') {
                return false;
            }
            return std::all_of(decimal.begin() + static_cast<std::ptrdiff_t>(offset + 1U), decimal.end(),
                               [](const char value) { return value >= '0' && value <= '9'; });
        }

        [[nodiscard]] std::expected<void, ScanWireError> validate_identifier(const std::string_view value,
                                                                             const ScanWireLimits &limits,
                                                                             const std::string_view description) {
            if (value.empty() || value.size() > limits.maximum_identifier_bytes || !valid_utf8(value)) {
                return std::unexpected(wire_error(
                    ScanWireErrorCode::limit_exceeded,
                    std::string {description} + " must be non-empty canonical UTF-8 within the identifier limit"));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ScanWireError> validate_subject(const SubjectKey &subject,
                                                                          const ScanWireLimits &limits) {
            std::size_t depth {};
            std::size_t total_bytes {};
            std::vector<const SubjectKey *> seen;
            for (auto current = &subject; current != nullptr; current = current->parent.get()) {
                if (++depth > limits.maximum_subject_depth ||
                    current->identity.size() > limits.maximum_identity_fields) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::limit_exceeded, "scan request subject exceeds shape limits"));
                }
                if (std::ranges::find(seen, current) != seen.end() || current->peer != subject.peer ||
                    current->peer.empty() || current->descriptor.empty() || current->identity.empty()) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::invalid_subject, "scan request subject is invalid"));
                }
                seen.push_back(current);
                if (current->peer.value.size() > limits.maximum_subject_component_bytes ||
                    current->descriptor.value.size() > limits.maximum_subject_component_bytes ||
                    !valid_utf8(current->peer.value) || !valid_utf8(current->descriptor.value) ||
                    !checked_accumulate(total_bytes, current->peer.value.size(), limits.maximum_subject_bytes) ||
                    !checked_accumulate(total_bytes, current->descriptor.value.size(), limits.maximum_subject_bytes)) {
                    return std::unexpected(wire_error(ScanWireErrorCode::limit_exceeded,
                                                      "scan request subject identity exceeds byte limits"));
                }
                std::uint32_t previous_field {};
                for (const auto &field : current->identity) {
                    if (field.field_id == 0 || field.field_id <= previous_field) {
                        return std::unexpected(wire_error(ScanWireErrorCode::invalid_subject,
                                                          "scan request subject field IDs are not canonical"));
                    }
                    previous_field = field.field_id;
                    const auto valid = std::visit(
                        [&limits, &total_bytes](const auto &value) {
                            using Value = std::remove_cvref_t<decltype(value)>;
                            if constexpr (std::is_same_v<Value, bool> || std::is_same_v<Value, std::int64_t> ||
                                          std::is_same_v<Value, std::uint64_t>) {
                                return true;
                            } else if constexpr (std::is_same_v<Value, IntegerValue>) {
                                return canonical_integer(value.decimal) &&
                                       value.decimal.size() <= limits.maximum_subject_component_bytes &&
                                       checked_accumulate(total_bytes, value.decimal.size(),
                                                          limits.maximum_subject_bytes);
                            } else if constexpr (std::is_same_v<Value, UnicodeValue>) {
                                return valid_utf8(value.utf8) &&
                                       value.utf8.size() <= limits.maximum_subject_component_bytes &&
                                       checked_accumulate(total_bytes, value.utf8.size(), limits.maximum_subject_bytes);
                            } else {
                                return value.bytes.size() <= limits.maximum_subject_component_bytes &&
                                       checked_accumulate(total_bytes, value.bytes.size(),
                                                          limits.maximum_subject_bytes);
                            }
                        },
                        field.value);
                    if (!valid) {
                        return std::unexpected(
                            wire_error(ScanWireErrorCode::invalid_subject,
                                       "scan request subject has an invalid or over-limit identity"));
                    }
                }
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ScanWireError> validate_label(const DataLabel &label,
                                                                        const ScanWireLimits &limits) {
            if (label.classification > Classification::secret ||
                label.categories.size() > limits.maximum_label_categories ||
                !std::ranges::is_sorted(label.categories) ||
                std::ranges::adjacent_find(label.categories) != label.categories.end()) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::invalid_label, "scan data label is not canonical"));
            }
            std::size_t total_bytes {};
            for (const auto &category : label.categories) {
                if (category.empty() || category.size() > limits.maximum_identifier_bytes || !valid_utf8(category)) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::invalid_label, "scan data label category is invalid"));
                }
                if (!checked_accumulate(total_bytes, category.size(), limits.maximum_label_bytes)) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::limit_exceeded, "scan data label exceeds the byte limit"));
                }
            }
            return {};
        }

        [[nodiscard]] std::string_view space_kind_name(const ScanSpaceKind kind) noexcept {
            switch (kind) {
                case ScanSpaceKind::image_file: return "file";
                case ScanSpaceKind::mapped_section: return "mapped_section";
                case ScanSpaceKind::readable_memory: return "readable_memory";
                case ScanSpaceKind::mapped_image: return "mapped_image";
                default: return {};
            }
        }

        [[nodiscard]] std::expected<ScanSpaceKind, ScanWireError> parse_space_kind(const std::string_view kind) {
            if (kind == "file") {
                return ScanSpaceKind::image_file;
            }
            if (kind == "mapped_section") {
                return ScanSpaceKind::mapped_section;
            }
            if (kind == "readable_memory") {
                return ScanSpaceKind::readable_memory;
            }
            if (kind == "mapped_image") {
                return ScanSpaceKind::mapped_image;
            }
            return std::unexpected(wire_error(ScanWireErrorCode::unsupported_space_kind,
                                              "scan space kind must be file, mapped_section, readable_memory, or "
                                              "mapped_image"));
        }

        [[nodiscard]] bool default_regex_options(const RegexOptions &options) noexcept {
            return options.encoding == RegexEncoding::utf8 && options.case_sensitive && !options.dot_matches_newline &&
                   !options.multiline;
        }

        [[nodiscard]] std::expected<void, ScanWireError> validate_space_and_plan(const ExplicitScanSpace &space,
                                                                                 const TypedScanPlan &plan,
                                                                                 const ScanWireLimits &limits) {
            if (auto valid = validate_identifier(space.identity, limits, "scan space identity"); !valid) {
                return valid;
            }
            if (space_kind_name(space.kind).empty()) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::unsupported_space_kind, "scan space kind is unknown"));
            }
            if (space.subject_generation == 0 || space.size == 0 || (space.permissions & scan_permission_read) == 0 ||
                (space.permissions & ~known_permissions) != 0) {
                return std::unexpected(wire_error(ScanWireErrorCode::invalid_space,
                                                  "scan space requires a generation, size, and known read permission"));
            }
            if (space.size > std::numeric_limits<std::uint64_t>::max() - space.begin) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::arithmetic_overflow, "scan space range overflows uint64"));
            }
            if (space.size > limits.maximum_scan_bytes) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::limit_exceeded, "scan space exceeds the byte limit"));
            }
            if (auto valid = validate_label(space.label, limits); !valid) {
                return valid;
            }
            if (auto valid = validate_identifier(plan.plan_id, limits, "scan plan ID"); !valid) {
                return valid;
            }
            if (plan.patterns.empty() || plan.patterns.size() > limits.maximum_patterns || plan.maximum_bytes == 0 ||
                plan.maximum_bytes > limits.maximum_scan_bytes || plan.maximum_bytes < space.size ||
                plan.maximum_matches == 0 || plan.maximum_matches > limits.maximum_scan_matches ||
                plan.context_bytes_before > limits.maximum_context_bytes ||
                plan.context_bytes_after > limits.maximum_context_bytes) {
                return std::unexpected(wire_error(ScanWireErrorCode::invalid_plan,
                                                  "scan plan patterns, budgets, or context limits are invalid"));
            }
            if (plan.result_mode != ScanResultMode::exact_complete && plan.result_mode != ScanResultMode::existential) {
                return std::unexpected(wire_error(ScanWireErrorCode::invalid_plan, "scan plan result mode is unknown"));
            }

            std::set<std::string_view> pattern_ids;
            std::size_t total_pattern_bytes {};
            for (const auto &pattern : plan.patterns) {
                if (auto valid = validate_identifier(pattern.pattern_id, limits, "scan pattern ID"); !valid) {
                    return valid;
                }
                if (!pattern_ids.insert(pattern.pattern_id).second) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::duplicate_pattern_id, "scan pattern IDs must be unique"));
                }
                if (pattern.origin != PatternOrigin::compile_time &&
                    pattern.origin != PatternOrigin::template_binding) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::invalid_pattern, "scan pattern origin is invalid"));
                }
                if (pattern.bytes.size() > limits.maximum_pattern_bytes ||
                    pattern.mask.size() > limits.maximum_pattern_bytes ||
                    pattern.regex_source.size() > limits.maximum_regex_source_bytes ||
                    !checked_accumulate(total_pattern_bytes, pattern.bytes.size(),
                                        limits.maximum_total_pattern_bytes) ||
                    !checked_accumulate(total_pattern_bytes, pattern.mask.size(), limits.maximum_total_pattern_bytes) ||
                    !checked_accumulate(total_pattern_bytes, pattern.regex_source.size(),
                                        limits.maximum_total_pattern_bytes)) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::limit_exceeded, "scan pattern payload exceeds wire limits"));
                }

                switch (pattern.kind) {
                    case StaticPatternKind::byte_literal:
                        if (pattern.bytes.empty() || !pattern.mask.empty() || !pattern.regex_source.empty() ||
                            pattern.text_encoding != TextEncoding::utf8 || pattern.ascii_case_insensitive ||
                            !default_regex_options(pattern.regex_options)) {
                            return std::unexpected(wire_error(ScanWireErrorCode::invalid_pattern,
                                                              "byte literal representation is not canonical"));
                        }
                        break;
                    case StaticPatternKind::text_literal:
                        if (pattern.bytes.empty() || !pattern.mask.empty() || !pattern.regex_source.empty() ||
                            !default_regex_options(pattern.regex_options) ||
                            !valid_encoded_text(pattern.bytes, pattern.text_encoding)) {
                            return std::unexpected(wire_error(ScanWireErrorCode::invalid_pattern,
                                                              "text literal representation is not canonical"));
                        }
                        break;
                    case StaticPatternKind::masked_bytes:
                        if (pattern.bytes.empty() || pattern.mask.size() != pattern.bytes.size() ||
                            !pattern.regex_source.empty() || pattern.ascii_case_insensitive ||
                            pattern.text_encoding != TextEncoding::utf8 ||
                            !default_regex_options(pattern.regex_options)) {
                            return std::unexpected(wire_error(ScanWireErrorCode::invalid_pattern,
                                                              "masked pattern representation is not canonical"));
                        }
                        for (std::size_t index = 0; index < pattern.mask.size(); ++index) {
                            const auto mask = std::to_integer<std::uint8_t>(pattern.mask[index]);
                            const auto byte = std::to_integer<std::uint8_t>(pattern.bytes[index]);
                            if ((mask != 0U && mask != 0x0FU && mask != 0xF0U && mask != 0xFFU) ||
                                (byte & static_cast<std::uint8_t>(~mask)) != 0U) {
                                return std::unexpected(
                                    wire_error(ScanWireErrorCode::invalid_pattern,
                                               "masked pattern contains a noncanonical nibble mask"));
                            }
                        }
                        break;
                    case StaticPatternKind::re2_regex:
                        if (!pattern.bytes.empty() || !pattern.mask.empty() || pattern.regex_source.empty() ||
                            pattern.text_encoding != TextEncoding::utf8 || pattern.ascii_case_insensitive ||
                            (pattern.regex_options.encoding != RegexEncoding::utf8 &&
                             pattern.regex_options.encoding != RegexEncoding::latin1) ||
                            (pattern.regex_options.encoding == RegexEncoding::utf8 &&
                             !valid_utf8(pattern.regex_source))) {
                            return std::unexpected(wire_error(ScanWireErrorCode::invalid_pattern,
                                                              "RE2 pattern representation is invalid"));
                        }
                        if (const auto validated = make_re2_pattern(pattern.pattern_id, pattern.regex_source,
                                                                    pattern.regex_options, pattern.origin);
                            !validated.has_value()) {
                            return std::unexpected(
                                wire_error(ScanWireErrorCode::invalid_pattern,
                                           "RE2 pattern fails dialect validation: " + validated.error().message));
                        }
                        break;
                    default:
                        return std::unexpected(
                            wire_error(ScanWireErrorCode::invalid_pattern, "scan pattern kind is unknown"));
                }
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ScanWireError> validate_provider_request(const ProviderScanRequest &request,
                                                                                   const ScanWireLimits &limits) {
            if (auto valid = validate_limits(limits); !valid) {
                return valid;
            }
            if (auto valid = validate_identifier(request.request_id.value, limits, "scan request ID"); !valid) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::invalid_request, std::move(valid.error().message)));
            }
            if (auto valid = validate_subject(request.subject, limits); !valid) {
                return valid;
            }
            if (request.deadline_unix_ms == 0) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::invalid_deadline, "scan request deadline must be non-zero"));
            }
            if (auto valid = validate_space_and_plan(request.space, request.plan, limits); !valid) {
                return valid;
            }
            return {};
        }

        class WireWriter {
        public:
            explicit WireWriter(const std::size_t maximum): maximum_ {maximum} {}

            [[nodiscard]] std::expected<void, ScanWireError> append_raw(const std::string_view value) {
                if (value.size() > maximum_ - output_.size()) {
                    return std::unexpected(wire_error(ScanWireErrorCode::limit_exceeded,
                                                      "encoded scan plan exceeds the wire limit", output_.size()));
                }
                output_.append(value);
                return {};
            }

            [[nodiscard]] std::expected<void, ScanWireError> append_token(const std::string_view value) {
                auto started = start_token(value.size());
                if (!started) {
                    return started;
                }
                output_.append(value);
                output_.push_back(';');
                return {};
            }

            [[nodiscard]] std::expected<void, ScanWireError> append_number(const std::uint64_t value) {
                std::array<char, 32> text {};
                const auto [end, status] = std::to_chars(text.data(), text.data() + text.size(), value);
                if (status != std::errc {}) {
                    return std::unexpected(wire_error(ScanWireErrorCode::arithmetic_overflow,
                                                      "cannot encode scan plan integer", output_.size()));
                }
                return append_token(std::string_view {text.data(), end});
            }

            [[nodiscard]] std::expected<void, ScanWireError> append_boolean(const bool value) {
                return append_token(value ? "1" : "0");
            }

            [[nodiscard]] std::expected<void, ScanWireError> append_hex(const std::span<const std::byte> bytes) {
                if (bytes.size() > std::numeric_limits<std::size_t>::max() / 2U) {
                    return std::unexpected(wire_error(ScanWireErrorCode::arithmetic_overflow,
                                                      "hex-encoded scan plan field overflows", output_.size()));
                }
                const auto encoded_size = bytes.size() * 2U;
                auto started = start_token(encoded_size);
                if (!started) {
                    return started;
                }
                constexpr std::string_view digits = "0123456789abcdef";
                for (const auto byte : bytes) {
                    const auto value = std::to_integer<std::uint8_t>(byte);
                    output_.push_back(digits[value >> 4U]);
                    output_.push_back(digits[value & 0x0FU]);
                }
                output_.push_back(';');
                return {};
            }

            [[nodiscard]] std::expected<void, ScanWireError> append_hex(const std::string_view bytes) {
                if (bytes.size() > std::numeric_limits<std::size_t>::max() / 2U) {
                    return std::unexpected(wire_error(ScanWireErrorCode::arithmetic_overflow,
                                                      "hex-encoded scan plan field overflows", output_.size()));
                }
                const auto encoded_size = bytes.size() * 2U;
                auto started = start_token(encoded_size);
                if (!started) {
                    return started;
                }
                constexpr std::string_view digits = "0123456789abcdef";
                for (const char character : bytes) {
                    const auto value = static_cast<unsigned char>(character);
                    output_.push_back(digits[value >> 4U]);
                    output_.push_back(digits[value & 0x0FU]);
                }
                output_.push_back(';');
                return {};
            }

            [[nodiscard]] const std::string &value() const noexcept { return output_; }
            [[nodiscard]] std::string take() && { return std::move(output_); }

        private:
            [[nodiscard]] std::expected<void, ScanWireError> start_token(const std::size_t payload_size) {
                std::array<char, 32> length {};
                const auto [end, status] = std::to_chars(length.data(), length.data() + length.size(), payload_size);
                if (status != std::errc {}) {
                    return std::unexpected(wire_error(ScanWireErrorCode::arithmetic_overflow,
                                                      "scan plan field length overflows", output_.size()));
                }
                const auto length_size = static_cast<std::size_t>(end - length.data());
                if (length_size > maximum_ - output_.size() || payload_size > maximum_ - output_.size() - length_size ||
                    2U > maximum_ - output_.size() - length_size - payload_size) {
                    return std::unexpected(wire_error(ScanWireErrorCode::limit_exceeded,
                                                      "encoded scan plan exceeds the wire limit", output_.size()));
                }
                output_.append(length.data(), end);
                output_.push_back(':');
                return {};
            }

            std::size_t maximum_ {};
            std::string output_;
        };

        [[nodiscard]] std::uint32_t checksum(const std::string_view bytes) noexcept {
            std::uint32_t result {0xFFFFFFFFU};
            for (const char character : bytes) {
                result ^= static_cast<unsigned char>(character);
                for (std::uint8_t bit = 0; bit < 8U; ++bit) {
                    const auto mask = static_cast<std::uint32_t>(0U - (result & 1U));
                    result = (result >> 1U) ^ (0xEDB88320U & mask);
                }
            }
            return ~result;
        }

        [[nodiscard]] std::string checksum_text(const std::uint32_t value) {
            constexpr std::string_view digits = "0123456789abcdef";
            std::string result(8U, '0');
            for (std::size_t index = 0; index < result.size(); ++index) {
                const auto shift = static_cast<unsigned int>((result.size() - index - 1U) * 4U);
                result[index] = digits[(value >> shift) & 0x0FU];
            }
            return result;
        }

        class WireReader {
        public:
            explicit WireReader(const std::string_view input): input_ {input}, offset_ {wire_magic.size()} {}

            [[nodiscard]] std::expected<std::string_view, ScanWireError> token() {
                const auto token_offset = offset_;
                if (offset_ >= input_.size()) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::truncated, "scan plan token is missing", offset_));
                }
                const auto length_begin = offset_;
                while (offset_ < input_.size() && input_[offset_] != ':') {
                    if (input_[offset_] < '0' || input_[offset_] > '9') {
                        return std::unexpected(
                            wire_error(ScanWireErrorCode::malformed, "scan plan token length is not decimal", offset_));
                    }
                    ++offset_;
                }
                if (offset_ == input_.size()) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::truncated, "scan plan token length is truncated", token_offset));
                }
                const auto length_text = input_.substr(length_begin, offset_ - length_begin);
                if (length_text.empty() || (length_text.size() > 1U && length_text.front() == '0')) {
                    return std::unexpected(wire_error(ScanWireErrorCode::malformed,
                                                      "scan plan token length is not canonical", length_begin));
                }
                std::size_t length {};
                const auto [end, status] =
                    std::from_chars(length_text.data(), length_text.data() + length_text.size(), length);
                if (status == std::errc::result_out_of_range) {
                    return std::unexpected(wire_error(ScanWireErrorCode::arithmetic_overflow,
                                                      "scan plan token length overflows", length_begin));
                }
                if (status != std::errc {} || end != length_text.data() + length_text.size()) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::malformed, "scan plan token length is invalid", length_begin));
                }
                ++offset_;
                if (length > input_.size() - offset_) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::truncated, "scan plan token payload is truncated", offset_));
                }
                const auto value = input_.substr(offset_, length);
                offset_ += length;
                if (offset_ == input_.size()) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::truncated, "scan plan token delimiter is missing", offset_));
                }
                if (input_[offset_] != ';') {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::malformed, "scan plan token delimiter is invalid", offset_));
                }
                ++offset_;
                return value;
            }

            [[nodiscard]] std::size_t offset() const noexcept { return offset_; }
            [[nodiscard]] bool eof() const noexcept { return offset_ == input_.size(); }

        private:
            std::string_view input_;
            std::size_t offset_ {};
        };

        [[nodiscard]] std::expected<std::uint64_t, ScanWireError> parse_number(const std::string_view text,
                                                                               const std::size_t offset) {
            if (text.empty() || (text.size() > 1U && text.front() == '0')) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::malformed, "scan plan integer is not canonical", offset));
            }
            std::uint64_t result {};
            const auto [end, status] = std::from_chars(text.data(), text.data() + text.size(), result);
            if (status == std::errc::result_out_of_range) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::arithmetic_overflow, "scan plan integer overflows", offset));
            }
            if (status != std::errc {} || end != text.data() + text.size()) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::malformed, "scan plan integer is invalid", offset));
            }
            return result;
        }

        [[nodiscard]] std::expected<bool, ScanWireError> parse_boolean(const std::string_view text,
                                                                       const std::size_t offset) {
            if (text == "0") {
                return false;
            }
            if (text == "1") {
                return true;
            }
            return std::unexpected(
                wire_error(ScanWireErrorCode::malformed, "scan plan boolean must be zero or one", offset));
        }

        [[nodiscard]] std::expected<std::vector<std::byte>, ScanWireError>
        decode_hex_bytes(const std::string_view text, const std::size_t maximum, const std::size_t offset) {
            if ((text.size() & 1U) != 0U) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::malformed, "hex scan plan field has odd length", offset));
            }
            const auto decoded_size = text.size() / 2U;
            if (decoded_size > maximum) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::limit_exceeded, "hex scan plan field exceeds its limit", offset));
            }
            const auto nibble = [](const char value) -> std::optional<std::uint8_t> {
                if (value >= '0' && value <= '9') {
                    return static_cast<std::uint8_t>(value - '0');
                }
                if (value >= 'a' && value <= 'f') {
                    return static_cast<std::uint8_t>(10 + value - 'a');
                }
                return std::nullopt;
            };
            std::vector<std::byte> result;
            result.reserve(decoded_size);
            for (std::size_t index = 0; index < text.size(); index += 2U) {
                const auto high = nibble(text[index]);
                const auto low = nibble(text[index + 1U]);
                if (!high || !low) {
                    return std::unexpected(wire_error(ScanWireErrorCode::malformed,
                                                      "scan plan hex must use lowercase hexadecimal", offset + index));
                }
                result.push_back(static_cast<std::byte>((*high << 4U) | *low));
            }
            return result;
        }

        [[nodiscard]] std::expected<std::string, ScanWireError>
        decode_hex_string(const std::string_view text, const std::size_t maximum, const std::size_t offset) {
            auto bytes = decode_hex_bytes(text, maximum, offset);
            if (!bytes) {
                return std::unexpected(std::move(bytes.error()));
            }
            std::string result;
            result.reserve(bytes->size());
            for (const auto byte : *bytes) {
                result.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
            }
            return result;
        }

        template<typename Value> [[nodiscard]] std::expected<Value, ScanWireError> read_number(WireReader &reader) {
            const auto offset = reader.offset();
            auto token = reader.token();
            if (!token) {
                return std::unexpected(std::move(token.error()));
            }
            auto number = parse_number(*token, offset);
            if (!number) {
                return std::unexpected(std::move(number.error()));
            }
            if (*number > std::numeric_limits<Value>::max()) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::arithmetic_overflow, "scan plan integer target overflows", offset));
            }
            return static_cast<Value>(*number);
        }

        [[nodiscard]] std::expected<bool, ScanWireError> read_boolean(WireReader &reader) {
            const auto offset = reader.offset();
            auto token = reader.token();
            if (!token) {
                return std::unexpected(std::move(token.error()));
            }
            return parse_boolean(*token, offset);
        }

        [[nodiscard]] std::expected<std::string, ScanWireError> read_hex_string(WireReader &reader,
                                                                                const std::size_t maximum) {
            const auto offset = reader.offset();
            auto token = reader.token();
            if (!token) {
                return std::unexpected(std::move(token.error()));
            }
            return decode_hex_string(*token, maximum, offset);
        }

        [[nodiscard]] std::expected<std::vector<std::byte>, ScanWireError> read_hex_bytes(WireReader &reader,
                                                                                          const std::size_t maximum) {
            const auto offset = reader.offset();
            auto token = reader.token();
            if (!token) {
                return std::unexpected(std::move(token.error()));
            }
            return decode_hex_bytes(*token, maximum, offset);
        }

        [[nodiscard]] std::expected<void, ScanWireError> write_pattern(WireWriter &writer,
                                                                       const StaticScanPattern &pattern) {
            if (auto result = writer.append_hex(pattern.pattern_id); !result) {
                return result;
            }
            if (auto result = writer.append_number(static_cast<std::uint8_t>(pattern.kind)); !result) {
                return result;
            }
            if (auto result = writer.append_number(static_cast<std::uint8_t>(pattern.origin)); !result) {
                return result;
            }
            if (auto result = writer.append_number(static_cast<std::uint8_t>(pattern.text_encoding)); !result) {
                return result;
            }
            if (auto result = writer.append_hex(pattern.bytes); !result) {
                return result;
            }
            if (auto result = writer.append_hex(pattern.mask); !result) {
                return result;
            }
            if (auto result = writer.append_boolean(pattern.ascii_case_insensitive); !result) {
                return result;
            }
            if (auto result = writer.append_hex(pattern.regex_source); !result) {
                return result;
            }
            if (auto result = writer.append_number(static_cast<std::uint8_t>(pattern.regex_options.encoding));
                !result) {
                return result;
            }
            if (auto result = writer.append_boolean(pattern.regex_options.case_sensitive); !result) {
                return result;
            }
            if (auto result = writer.append_boolean(pattern.regex_options.dot_matches_newline); !result) {
                return result;
            }
            return writer.append_boolean(pattern.regex_options.multiline);
        }

        [[nodiscard]] std::expected<StaticScanPattern, ScanWireError>
        read_pattern(WireReader &reader, const ScanWireLimits &limits, std::size_t &total_payload) {
            auto pattern_id = read_hex_string(reader, limits.maximum_identifier_bytes);
            auto kind = read_number<std::uint8_t>(reader);
            auto origin = read_number<std::uint8_t>(reader);
            auto text_encoding = read_number<std::uint8_t>(reader);
            auto bytes = read_hex_bytes(reader, limits.maximum_pattern_bytes);
            auto mask = read_hex_bytes(reader, limits.maximum_pattern_bytes);
            auto ascii_case_insensitive = read_boolean(reader);
            auto regex_source = read_hex_string(reader, limits.maximum_regex_source_bytes);
            auto regex_encoding = read_number<std::uint8_t>(reader);
            auto regex_case_sensitive = read_boolean(reader);
            auto dot_matches_newline = read_boolean(reader);
            auto multiline = read_boolean(reader);
            if (!pattern_id || !kind || !origin || !text_encoding || !bytes || !mask || !ascii_case_insensitive ||
                !regex_source || !regex_encoding || !regex_case_sensitive || !dot_matches_newline || !multiline) {
                if (!pattern_id)
                    return std::unexpected(std::move(pattern_id.error()));
                if (!kind)
                    return std::unexpected(std::move(kind.error()));
                if (!origin)
                    return std::unexpected(std::move(origin.error()));
                if (!text_encoding)
                    return std::unexpected(std::move(text_encoding.error()));
                if (!bytes)
                    return std::unexpected(std::move(bytes.error()));
                if (!mask)
                    return std::unexpected(std::move(mask.error()));
                if (!ascii_case_insensitive)
                    return std::unexpected(std::move(ascii_case_insensitive.error()));
                if (!regex_source)
                    return std::unexpected(std::move(regex_source.error()));
                if (!regex_encoding)
                    return std::unexpected(std::move(regex_encoding.error()));
                if (!regex_case_sensitive)
                    return std::unexpected(std::move(regex_case_sensitive.error()));
                if (!dot_matches_newline)
                    return std::unexpected(std::move(dot_matches_newline.error()));
                return std::unexpected(std::move(multiline.error()));
            }
            if (*kind > static_cast<std::uint8_t>(StaticPatternKind::re2_regex) ||
                *origin > static_cast<std::uint8_t>(PatternOrigin::template_binding) ||
                *text_encoding > static_cast<std::uint8_t>(TextEncoding::utf16_big_endian) ||
                *regex_encoding > static_cast<std::uint8_t>(RegexEncoding::latin1)) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::malformed, "scan pattern enum value is unknown", reader.offset()));
            }
            if (!checked_accumulate(total_payload, bytes->size(), limits.maximum_total_pattern_bytes) ||
                !checked_accumulate(total_payload, mask->size(), limits.maximum_total_pattern_bytes) ||
                !checked_accumulate(total_payload, regex_source->size(), limits.maximum_total_pattern_bytes)) {
                return std::unexpected(wire_error(ScanWireErrorCode::limit_exceeded,
                                                  "decoded scan pattern payload exceeds the total limit",
                                                  reader.offset()));
            }
            return StaticScanPattern {
                .pattern_id = std::move(*pattern_id),
                .kind = static_cast<StaticPatternKind>(*kind),
                .origin = static_cast<PatternOrigin>(*origin),
                .bytes = std::move(*bytes),
                .mask = std::move(*mask),
                .text_encoding = static_cast<TextEncoding>(*text_encoding),
                .ascii_case_insensitive = *ascii_case_insensitive,
                .regex_source = std::move(*regex_source),
                .regex_options =
                    RegexOptions {
                        .encoding = static_cast<RegexEncoding>(*regex_encoding),
                        .case_sensitive = *regex_case_sensitive,
                        .dot_matches_newline = *dot_matches_newline,
                        .multiline = *multiline,
                    },
            };
        }

        [[nodiscard]] bool same_subject(const SubjectKey &left, const SubjectKey &right) {
            const auto left_key = canonical_subject_key(left);
            return !left_key.empty() && left_key == canonical_subject_key(right);
        }

        struct MatchView {
            std::string_view pattern_id;
            std::string_view scan_space_identity;
            std::uint64_t offset {};
            std::uint64_t absolute_address {};
            std::uint64_t length {};
            std::uint32_t permissions {};
            std::span<const std::byte> matched_bytes;
            std::span<const std::byte> context_before;
            std::span<const std::byte> context_after;
            const DataLabel *label {};
            std::uint64_t subject_generation {};
        };

        [[nodiscard]] MatchView view_of(const TypedScanMatch &match) noexcept {
            return MatchView {
                .pattern_id = match.pattern_id,
                .scan_space_identity = match.scan_space_identity,
                .offset = match.offset,
                .absolute_address = match.absolute_address,
                .length = match.length,
                .permissions = match.permissions,
                .matched_bytes = match.matched_bytes,
                .context_before = match.context_before,
                .context_after = match.context_after,
                .label = &match.label,
                .subject_generation = match.subject_generation,
            };
        }

        [[nodiscard]] MatchView view_of(const ScanMatch &match) noexcept {
            return MatchView {
                .pattern_id = match.pattern_id,
                .scan_space_identity = match.scan_space_id,
                .offset = match.offset,
                .absolute_address = match.absolute_address,
                .length = match.length,
                .permissions = match.permission_snapshot,
                .matched_bytes = match.matched_bytes,
                .context_before = match.before_bytes,
                .context_after = match.after_bytes,
                .label = &match.label,
                .subject_generation = match.subject_generation,
            };
        }

        [[nodiscard]] const StaticScanPattern *find_pattern(const ProviderScanRequest &request,
                                                            const std::string_view pattern_id) noexcept {
            const auto found = std::ranges::find(request.plan.patterns, pattern_id, &StaticScanPattern::pattern_id);
            return found == request.plan.patterns.end() ? nullptr : &*found;
        }

        [[nodiscard]] std::byte ascii_lower(std::byte value) noexcept {
            const auto byte = std::to_integer<std::uint8_t>(value);
            return byte >= static_cast<std::uint8_t>('A') && byte <= static_cast<std::uint8_t>('Z') ?
                       static_cast<std::byte>(byte + static_cast<std::uint8_t>('a' - 'A')) :
                       value;
        }

        [[nodiscard]] bool fixed_payload_matches(const StaticScanPattern &pattern,
                                                 const std::span<const std::byte> payload) noexcept {
            if (pattern.kind == StaticPatternKind::re2_regex) {
                return true;
            }
            if (payload.size() != pattern.bytes.size()) {
                return false;
            }
            if (pattern.kind == StaticPatternKind::text_literal && pattern.ascii_case_insensitive &&
                pattern.text_encoding != TextEncoding::utf8) {
                for (std::size_t index = 0; index < pattern.bytes.size(); index += 2U) {
                    auto actual = read_u16(payload, index, pattern.text_encoding);
                    auto expected = read_u16(pattern.bytes, index, pattern.text_encoding);
                    if (actual >= static_cast<std::uint16_t>('A') && actual <= static_cast<std::uint16_t>('Z')) {
                        actual = static_cast<std::uint16_t>(actual + static_cast<std::uint16_t>('a' - 'A'));
                    }
                    if (expected >= static_cast<std::uint16_t>('A') && expected <= static_cast<std::uint16_t>('Z')) {
                        expected = static_cast<std::uint16_t>(expected + static_cast<std::uint16_t>('a' - 'A'));
                    }
                    if (actual != expected) {
                        return false;
                    }
                }
                return true;
            }
            for (std::size_t index = 0; index < pattern.bytes.size(); ++index) {
                auto actual = payload[index];
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

        [[nodiscard]] std::expected<void, ScanWireError> validate_match(const ProviderScanRequest &request,
                                                                        const MatchView match,
                                                                        const ScanWireLimits &limits,
                                                                        std::size_t &total_payload_bytes) {
            const auto *pattern = find_pattern(request, match.pattern_id);
            if (pattern == nullptr) {
                return std::unexpected(wire_error(ScanWireErrorCode::mismatched_response,
                                                  "scan match pattern is not in the requested plan"));
            }
            if (match.offset > request.space.size || match.length > request.space.size - match.offset) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::mismatched_response, "scan match is outside the requested space"));
            }
            if (pattern->kind != StaticPatternKind::re2_regex && match.length != pattern->bytes.size()) {
                return std::unexpected(wire_error(ScanWireErrorCode::mismatched_response,
                                                  "fixed scan match length does not equal its pattern length"));
            }
            if (match.matched_bytes.size() != match.length || !fixed_payload_matches(*pattern, match.matched_bytes)) {
                return std::unexpected(wire_error(ScanWireErrorCode::mismatched_response,
                                                  "scan match bytes do not satisfy the requested pattern"));
            }
            if (match.scan_space_identity != request.space.identity || match.permissions != request.space.permissions ||
                match.label == nullptr || *match.label != request.space.label ||
                match.subject_generation != request.space.subject_generation) {
                return std::unexpected(wire_error(ScanWireErrorCode::mismatched_response,
                                                  "scan match attribution does not match its request"));
            }
            if (auto valid = validate_label(*match.label, limits); !valid) {
                return valid;
            }
            if (match.offset > std::numeric_limits<std::uint64_t>::max() - request.space.begin ||
                match.absolute_address != request.space.begin + match.offset) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::mismatched_response, "scan match absolute address is invalid"));
            }
            const auto remaining = request.space.size - match.offset - match.length;
            const auto expected_before = std::min<std::uint64_t>(request.plan.context_bytes_before, match.offset);
            const auto expected_after = std::min<std::uint64_t>(request.plan.context_bytes_after, remaining);
            if (match.context_before.size() != expected_before || match.context_after.size() != expected_after) {
                return std::unexpected(wire_error(ScanWireErrorCode::mismatched_response,
                                                  "scan match context is incomplete or exceeds its request"));
            }
            if (!checked_accumulate(total_payload_bytes, match.pattern_id.size(),
                                    limits.maximum_result_payload_bytes) ||
                !checked_accumulate(total_payload_bytes, match.scan_space_identity.size(),
                                    limits.maximum_result_payload_bytes) ||
                !checked_accumulate(total_payload_bytes, match.matched_bytes.size(),
                                    limits.maximum_result_payload_bytes) ||
                !checked_accumulate(total_payload_bytes, match.context_before.size(),
                                    limits.maximum_result_payload_bytes) ||
                !checked_accumulate(total_payload_bytes, match.context_after.size(),
                                    limits.maximum_result_payload_bytes)) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::limit_exceeded, "scan result payload exceeds the byte limit"));
            }
            for (const auto &category : match.label->categories) {
                if (!checked_accumulate(total_payload_bytes, category.size(), limits.maximum_result_payload_bytes)) {
                    return std::unexpected(
                        wire_error(ScanWireErrorCode::limit_exceeded, "scan result payload exceeds the byte limit"));
                }
            }
            return {};
        }

    } // namespace

    std::expected<ScanPlan, ScanWireError>
    serialize_scan_plan(const ExplicitScanSpace &space, const TypedScanPlan &plan, const ScanWireLimits &limits) {
        if (auto valid = validate_limits(limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        if (auto valid = validate_space_and_plan(space, plan, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }

        WireWriter writer {limits.maximum_encoded_plan_bytes};
        if (auto result = writer.append_raw(wire_magic); !result) {
            return std::unexpected(std::move(result.error()));
        }
        if (auto result = writer.append_hex(space.identity); !result) {
            return std::unexpected(std::move(result.error()));
        }
        if (auto result = writer.append_number(space.subject_generation); !result) {
            return std::unexpected(std::move(result.error()));
        }
        if (auto result = writer.append_number(static_cast<std::uint8_t>(space.kind)); !result) {
            return std::unexpected(std::move(result.error()));
        }
        if (auto result = writer.append_number(plan.context_bytes_before); !result) {
            return std::unexpected(std::move(result.error()));
        }
        if (auto result = writer.append_number(plan.context_bytes_after); !result) {
            return std::unexpected(std::move(result.error()));
        }
        if (auto result = writer.append_number(plan.patterns.size()); !result) {
            return std::unexpected(std::move(result.error()));
        }
        for (const auto &pattern : plan.patterns) {
            if (auto result = write_pattern(writer, pattern); !result) {
                return std::unexpected(std::move(result.error()));
            }
        }
        const auto integrity = checksum_text(checksum(writer.value()));
        if (auto result = writer.append_token(integrity); !result) {
            return std::unexpected(std::move(result.error()));
        }

        std::vector<std::string> pattern_ids;
        pattern_ids.reserve(plan.patterns.size());
        for (const auto &pattern : plan.patterns) { pattern_ids.push_back(pattern.pattern_id); }
        return ScanPlan {
            .plan_id = plan.plan_id,
            .encoded_pattern = std::move(writer).take(),
            .maximum_bytes = plan.maximum_bytes,
            .maximum_matches = plan.maximum_matches,
            .context_bytes_before = plan.context_bytes_before,
            .context_bytes_after = plan.context_bytes_after,
            .result_mode = plan.result_mode,
            .pattern_ids = std::move(pattern_ids),
        };
    }

    std::expected<DecodedScanPlan, ScanWireError> deserialize_scan_plan(const ScanSpace &space, const ScanPlan &plan,
                                                                        const ScanWireLimits &limits) {
        if (auto valid = validate_limits(limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        auto kind = parse_space_kind(space.kind);
        if (!kind) {
            return std::unexpected(std::move(kind.error()));
        }
        if (auto valid = validate_identifier(space.identity, limits, "contract scan space identity"); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        if (auto valid = validate_label(space.label, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        if (space.subject_generation == 0 || space.size == 0 || (space.permissions & scan_permission_read) == 0 ||
            (space.permissions & ~known_permissions) != 0) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::invalid_space,
                           "contract scan space has invalid identity, generation, bounds, or permissions"));
        }
        if (space.size > std::numeric_limits<std::uint64_t>::max() - space.begin) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::arithmetic_overflow, "contract scan space range overflows uint64"));
        }
        if (plan.encoded_pattern.size() > limits.maximum_encoded_plan_bytes) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::limit_exceeded, "encoded scan plan exceeds the wire limit"));
        }
        if (!plan.encoded_pattern.starts_with(wire_magic)) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::malformed, "encoded scan plan has an unsupported magic"));
        }
        if (plan.context_bytes_before > limits.maximum_context_bytes ||
            plan.context_bytes_after > limits.maximum_context_bytes ||
            (plan.result_mode != ScanResultMode::exact_complete && plan.result_mode != ScanResultMode::existential) ||
            plan.pattern_ids.empty() || plan.pattern_ids.size() > limits.maximum_patterns) {
            return std::unexpected(wire_error(ScanWireErrorCode::invalid_plan,
                                              "contract scan plan context, result mode, or pattern IDs are invalid"));
        }
        std::set<std::string_view> contract_pattern_ids;
        for (const auto &pattern_id : plan.pattern_ids) {
            if (auto valid = validate_identifier(pattern_id, limits, "contract scan pattern ID"); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            if (!contract_pattern_ids.insert(pattern_id).second) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::duplicate_pattern_id, "contract scan pattern IDs must be unique"));
            }
        }

        WireReader reader {plan.encoded_pattern};
        auto identity = read_hex_string(reader, limits.maximum_identifier_bytes);
        auto generation = read_number<std::uint64_t>(reader);
        auto encoded_kind = read_number<std::uint8_t>(reader);
        auto context_before = read_number<std::uint32_t>(reader);
        auto context_after = read_number<std::uint32_t>(reader);
        auto pattern_count = read_number<std::size_t>(reader);
        if (!identity || !generation || !encoded_kind || !context_before || !context_after || !pattern_count) {
            if (!identity)
                return std::unexpected(std::move(identity.error()));
            if (!generation)
                return std::unexpected(std::move(generation.error()));
            if (!encoded_kind)
                return std::unexpected(std::move(encoded_kind.error()));
            if (!context_before)
                return std::unexpected(std::move(context_before.error()));
            if (!context_after)
                return std::unexpected(std::move(context_after.error()));
            return std::unexpected(std::move(pattern_count.error()));
        }
        if (*encoded_kind > static_cast<std::uint8_t>(ScanSpaceKind::readable_memory) ||
            static_cast<ScanSpaceKind>(*encoded_kind) != *kind) {
            return std::unexpected(wire_error(ScanWireErrorCode::malformed,
                                              "encoded and contract scan space kinds do not agree", reader.offset()));
        }
        if (*identity != space.identity || *generation != space.subject_generation ||
            *context_before != plan.context_bytes_before || *context_after != plan.context_bytes_after) {
            return std::unexpected(wire_error(ScanWireErrorCode::malformed,
                                              "encoded scan bindings do not agree with the typed contract fields",
                                              reader.offset()));
        }
        if (*pattern_count == 0 || *pattern_count > limits.maximum_patterns) {
            return std::unexpected(wire_error(ScanWireErrorCode::limit_exceeded,
                                              "encoded scan pattern count exceeds limits", reader.offset()));
        }

        std::vector<StaticScanPattern> patterns;
        std::size_t total_payload {};
        for (std::size_t index = 0; index < *pattern_count; ++index) {
            auto pattern = read_pattern(reader, limits, total_payload);
            if (!pattern) {
                return std::unexpected(std::move(pattern.error()));
            }
            patterns.push_back(std::move(*pattern));
        }
        if (patterns.size() != plan.pattern_ids.size() ||
            !std::ranges::equal(patterns, plan.pattern_ids, {}, &StaticScanPattern::pattern_id, std::identity {})) {
            return std::unexpected(wire_error(ScanWireErrorCode::malformed,
                                              "encoded scan patterns do not agree with the declared pattern IDs",
                                              reader.offset()));
        }

        const auto checksum_offset = reader.offset();
        auto integrity = reader.token();
        if (!integrity) {
            return std::unexpected(std::move(integrity.error()));
        }
        if (!reader.eof()) {
            return std::unexpected(wire_error(ScanWireErrorCode::trailing_data,
                                              "encoded scan plan contains trailing data", reader.offset()));
        }
        if (integrity->size() != 8U ||
            *integrity != checksum_text(checksum(std::string_view {plan.encoded_pattern}.substr(0, checksum_offset)))) {
            return std::unexpected(wire_error(ScanWireErrorCode::checksum_mismatch,
                                              "encoded scan plan integrity check failed", checksum_offset));
        }

        DecodedScanPlan result {
            .space =
                ExplicitScanSpace {
                    .identity = std::move(*identity),
                    .kind = *kind,
                    .begin = space.begin,
                    .size = space.size,
                    .permissions = space.permissions,
                    .label = space.label,
                    .subject_generation = *generation,
                },
            .plan =
                TypedScanPlan {
                    .plan_id = plan.plan_id,
                    .patterns = std::move(patterns),
                    .maximum_bytes = plan.maximum_bytes,
                    .maximum_matches = plan.maximum_matches,
                    .context_bytes_before = *context_before,
                    .context_bytes_after = *context_after,
                    .result_mode = plan.result_mode,
                },
        };
        if (auto valid = validate_space_and_plan(result.space, result.plan, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        return result;
    }

    std::expected<ScanRequest, ScanWireError> to_contract_scan_request(const ProviderScanRequest &request,
                                                                       const ScanWireLimits &limits) {
        if (auto valid = validate_provider_request(request, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        auto plan = serialize_scan_plan(request.space, request.plan, limits);
        if (!plan) {
            return std::unexpected(std::move(plan.error()));
        }
        return ScanRequest {
            .request_id = request.request_id,
            .subject = request.subject,
            .space =
                ScanSpace {
                    .kind = std::string {space_kind_name(request.space.kind)},
                    .begin = request.space.begin,
                    .size = request.space.size,
                    .permissions = request.space.permissions,
                    .identity = request.space.identity,
                    .label = request.space.label,
                    .subject_generation = request.space.subject_generation,
                },
            .plan = std::move(*plan),
            .deadline_unix_ms = request.deadline_unix_ms,
        };
    }

    std::expected<ProviderScanRequest, ScanWireError> from_contract_scan_request(const ScanRequest &request,
                                                                                 const ScanWireLimits &limits) {
        if (auto valid = validate_limits(limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        if (auto valid = validate_identifier(request.request_id.value, limits, "scan request ID"); !valid) {
            return std::unexpected(wire_error(ScanWireErrorCode::invalid_request, std::move(valid.error().message)));
        }
        if (auto valid = validate_subject(request.subject, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        if (request.deadline_unix_ms == 0) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::invalid_deadline, "scan request deadline must be non-zero"));
        }
        auto decoded = deserialize_scan_plan(request.space, request.plan, limits);
        if (!decoded) {
            return std::unexpected(std::move(decoded.error()));
        }
        ProviderScanRequest result {
            .request_id = request.request_id,
            .subject = request.subject,
            .space = std::move(decoded->space),
            .plan = std::move(decoded->plan),
            .deadline_unix_ms = request.deadline_unix_ms,
        };
        if (auto valid = validate_provider_request(result, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        return result;
    }

    std::expected<ScanResponse, ScanWireError> to_contract_scan_response(const ProviderScanRequest &request,
                                                                         const MatchSet &matches,
                                                                         const ScanWireLimits &limits) {
        if (auto valid = validate_provider_request(request, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        if (matches.matches.size() > request.plan.maximum_matches ||
            matches.matches.size() > limits.maximum_scan_matches ||
            (request.plan.result_mode == ScanResultMode::existential && matches.matches.size() > 1U)) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::limit_exceeded, "scan match set exceeds the requested limit"));
        }

        std::vector<ScanMatch> result_matches;
        result_matches.reserve(matches.matches.size());
        std::optional<std::tuple<std::uint64_t, std::string, std::uint64_t>> previous;
        std::size_t total_payload_bytes {};
        for (const auto &match : matches.matches) {
            if (auto valid = validate_match(request, view_of(match), limits, total_payload_bytes); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            const std::tuple key {match.offset, match.pattern_id, match.length};
            if (previous && key == *previous) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::duplicate_match, "typed scan match is duplicated"));
            }
            if (previous && key < *previous) {
                return std::unexpected(wire_error(ScanWireErrorCode::mismatched_response,
                                                  "typed scan matches are not deterministically ordered"));
            }
            previous = key;
            result_matches.push_back(ScanMatch {
                .offset = match.offset,
                .length = match.length,
                .pattern_id = match.pattern_id,
                .scan_space_id = match.scan_space_identity,
                .absolute_address = match.absolute_address,
                .permission_snapshot = match.permissions,
                .matched_bytes = match.matched_bytes,
                .before_bytes = match.context_before,
                .after_bytes = match.context_after,
                .label = match.label,
                .subject_generation = match.subject_generation,
            });
        }
        return ScanResponse {
            .request_id = request.request_id,
            .subject = request.subject,
            .status = FactTerminalStatus::value,
            .matches = std::move(result_matches),
            .truncated = false,
            .diagnostic = std::nullopt,
            .mode = request.plan.result_mode,
        };
    }

    std::expected<MatchSet, ScanWireError> from_contract_scan_response(const ProviderScanRequest &request,
                                                                       const ScanResponse &response,
                                                                       const ScanWireLimits &limits) {
        if (auto valid = validate_provider_request(request, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        if (auto valid = validate_identifier(response.request_id.value, limits, "scan response request ID"); !valid) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::mismatched_response, "scan response request ID is invalid"));
        }
        if (auto valid = validate_subject(response.subject, limits); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        if (response.request_id != request.request_id || !same_subject(response.subject, request.subject)) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::mismatched_response, "scan response request or subject does not match"));
        }
        if (response.status != FactTerminalStatus::value || response.truncated || response.diagnostic.has_value()) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::unsupported_shape,
                           "only complete successful contract scan responses can become MatchSet values"));
        }
        if (response.mode != request.plan.result_mode) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::mismatched_response, "scan response result mode does not match"));
        }
        if (response.matches.size() > request.plan.maximum_matches ||
            response.matches.size() > limits.maximum_scan_matches ||
            (response.mode == ScanResultMode::existential && response.matches.size() > 1U)) {
            return std::unexpected(
                wire_error(ScanWireErrorCode::limit_exceeded, "contract scan response exceeds match limits"));
        }

        std::vector<ScanMatch> ordered = response.matches;
        std::ranges::sort(ordered, [](const ScanMatch &left, const ScanMatch &right) {
            return std::tuple {left.offset, left.pattern_id, left.length} <
                   std::tuple {right.offset, right.pattern_id, right.length};
        });
        MatchSet result;
        result.matches.reserve(ordered.size());
        std::optional<std::tuple<std::uint64_t, std::string, std::uint64_t>> previous;
        std::size_t total_payload_bytes {};
        for (const auto &match : ordered) {
            if (auto valid = validate_match(request, view_of(match), limits, total_payload_bytes); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
            const std::tuple key {match.offset, match.pattern_id, match.length};
            if (previous && key == *previous) {
                return std::unexpected(
                    wire_error(ScanWireErrorCode::duplicate_match, "contract scan response duplicates a match"));
            }
            previous = key;
            result.matches.push_back(TypedScanMatch {
                .pattern_id = match.pattern_id,
                .scan_space_identity = match.scan_space_id,
                .offset = match.offset,
                .absolute_address = match.absolute_address,
                .length = match.length,
                .permissions = match.permission_snapshot,
                .matched_bytes = match.matched_bytes,
                .context_before = match.before_bytes,
                .context_after = match.after_bytes,
                .label = match.label,
                .subject_generation = match.subject_generation,
            });
        }
        return result;
    }

} // namespace rule_engine::python::optimizer
