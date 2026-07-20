#pragma once

#include "rule_engine/python/contract/subject.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::optimizer {

    enum struct ScanSpaceKind : std::uint8_t {
        image_file,
        mapped_image,
        mapped_section,
        readable_memory,
    };

    inline constexpr std::uint32_t scan_permission_read = 1U << 0U;
    inline constexpr std::uint32_t scan_permission_write = 1U << 1U;
    inline constexpr std::uint32_t scan_permission_execute = 1U << 2U;

    struct ExplicitScanSpace {
        std::string identity;
        ScanSpaceKind kind {ScanSpaceKind::image_file};
        std::uint64_t begin {};
        std::uint64_t size {};
        std::uint32_t permissions {scan_permission_read};
        std::uint64_t subject_generation {};
    };

    enum struct StaticPatternKind : std::uint8_t {
        byte_literal,
        text_literal,
        masked_bytes,
        re2_regex,
    };

    enum struct PatternOrigin : std::uint8_t {
        compile_time,
        template_binding,
    };

    enum struct TextEncoding : std::uint8_t {
        utf8,
        utf16_little_endian,
        utf16_big_endian,
    };

    enum struct TextCase : std::uint8_t {
        sensitive,
        ascii_insensitive,
    };

    enum struct RegexEncoding : std::uint8_t {
        utf8,
        latin1,
    };

    struct RegexOptions {
        RegexEncoding encoding {RegexEncoding::utf8};
        bool case_sensitive {true};
        bool dot_matches_newline {};
        bool one_line {};
    };

    struct StaticScanPattern {
        std::string pattern_id;
        StaticPatternKind kind {StaticPatternKind::byte_literal};
        PatternOrigin origin {PatternOrigin::compile_time};
        std::vector<std::byte> bytes;
        std::vector<std::byte> mask;
        bool ascii_case_insensitive {};
        std::string regex_source;
        RegexOptions regex_options;
    };

    enum struct ScanErrorCode : std::uint8_t {
        invalid_space,
        invalid_plan,
        invalid_pattern,
        invalid_utf8,
        invalid_masked_pattern,
        duplicate_pattern_id,
        regex_engine_unavailable,
        regex_syntax,
        space_out_of_bounds,
        byte_budget_exceeded,
        match_budget_exceeded,
        arithmetic_overflow,
    };

    struct ScanError {
        ScanErrorCode code {ScanErrorCode::invalid_plan};
        std::string pattern_id;
        std::size_t input_offset {};
        std::string message;
    };

    [[nodiscard]] std::expected<StaticScanPattern, ScanError>
    make_byte_pattern(std::string pattern_id, std::span<const std::byte> bytes,
                      PatternOrigin origin = PatternOrigin::compile_time);

    [[nodiscard]] std::expected<StaticScanPattern, ScanError>
    make_text_pattern(std::string pattern_id, std::string_view utf8, TextEncoding encoding,
                      TextCase text_case = TextCase::sensitive, PatternOrigin origin = PatternOrigin::compile_time);

    [[nodiscard]] std::expected<StaticScanPattern, ScanError>
    make_masked_pattern(std::string pattern_id, std::string_view masked,
                        PatternOrigin origin = PatternOrigin::compile_time);

    [[nodiscard]] std::expected<StaticScanPattern, ScanError>
    make_re2_pattern(std::string pattern_id, std::string_view expression, RegexOptions options = {},
                     PatternOrigin origin = PatternOrigin::compile_time);

    [[nodiscard]] bool re2_engine_available() noexcept;

    struct TypedScanPlan {
        std::string plan_id;
        std::vector<StaticScanPattern> patterns;
        std::uint64_t maximum_bytes {};
        std::uint32_t maximum_matches {};
        std::uint32_t context_bytes_before {};
        std::uint32_t context_bytes_after {};
    };

    // This is the complete provider-facing request. It contains an authenticated
    // subject, an explicit bounded space, and static scan data only. It has no
    // rule predicate, bytecode, effect policy, or verdict field.
    struct ProviderScanRequest {
        RequestId request_id;
        SubjectKey subject;
        ExplicitScanSpace space;
        TypedScanPlan plan;
        std::uint64_t deadline_unix_ms {};
    };

    struct TypedScanMatch {
        std::string pattern_id;
        std::string scan_space_identity;
        std::uint64_t offset {};
        std::uint64_t absolute_address {};
        std::uint64_t length {};
        std::uint32_t permissions {};
        std::vector<std::byte> context_before;
        std::vector<std::byte> context_after;
    };

    struct MatchSet {
        std::vector<TypedScanMatch> matches;

        [[nodiscard]] bool empty() const noexcept { return matches.empty(); }
        [[nodiscard]] bool exists() const noexcept { return !matches.empty(); }
        [[nodiscard]] std::size_t count() const noexcept { return matches.size(); }
    };

    // `source` represents bytes beginning at `source_origin`. The requested scan
    // space must be wholly contained in that range. A successful MatchSet is
    // always complete; exceeding maximum_matches returns an error rather than a
    // truncated exact-looking value.
    [[nodiscard]] std::expected<MatchSet, ScanError> execute_scan(const ExplicitScanSpace &space,
                                                                  const TypedScanPlan &plan,
                                                                  std::span<const std::byte> source,
                                                                  std::uint64_t source_origin = 0);

} // namespace rule_engine::python::optimizer
