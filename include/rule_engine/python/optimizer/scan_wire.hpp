#pragma once

#include "rule_engine/python/optimizer/scanner.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>

namespace rule_engine::python::optimizer {

    // Bounds both serialization and deserialization. The defaults fit the
    // protocol-v2 string/blob ceilings while leaving room for framing.
    struct ScanWireLimits {
        std::size_t maximum_encoded_plan_bytes {1U * 1024U * 1024U};
        std::size_t maximum_identifier_bytes {64U * 1024U};
        std::size_t maximum_patterns {4'096U};
        std::size_t maximum_pattern_bytes {512U * 1024U};
        std::size_t maximum_total_pattern_bytes {512U * 1024U};
        std::size_t maximum_regex_source_bytes {512U * 1024U};
        std::uint32_t maximum_context_bytes {64U * 1024U};
        std::uint64_t maximum_scan_bytes {16U * 1024U * 1024U};
        std::uint32_t maximum_scan_matches {100'000U};
        std::size_t maximum_subject_depth {32U};
        std::size_t maximum_identity_fields {64U};
        std::size_t maximum_subject_component_bytes {1U * 1024U * 1024U};
        std::size_t maximum_subject_bytes {16U * 1024U * 1024U};
    };

    enum struct ScanWireErrorCode : std::uint8_t {
        invalid_limits,
        invalid_request,
        invalid_subject,
        invalid_deadline,
        invalid_space,
        unsupported_space_kind,
        invalid_plan,
        invalid_pattern,
        duplicate_pattern_id,
        unsupported_shape,
        truncated,
        malformed,
        trailing_data,
        checksum_mismatch,
        limit_exceeded,
        arithmetic_overflow,
        mismatched_response,
        duplicate_match,
    };

    struct ScanWireError {
        ScanWireErrorCode code {ScanWireErrorCode::malformed};
        std::size_t byte_offset {};
        std::string message;
    };

    struct DecodedScanPlan {
        ExplicitScanSpace space;
        TypedScanPlan plan;
    };

    // `ScanPlan::encoded_pattern` uses the canonical ASCII-only rsp1 framing.
    // Identity, subject generation, contexts, and every pattern field are
    // carried there; plan identity and budgets use their dedicated fields.
    [[nodiscard]] std::expected<ScanPlan, ScanWireError>
    serialize_scan_plan(const ExplicitScanSpace &space, const TypedScanPlan &plan, const ScanWireLimits &limits = {});

    [[nodiscard]] std::expected<DecodedScanPlan, ScanWireError>
    deserialize_scan_plan(const ScanSpace &space, const ScanPlan &plan, const ScanWireLimits &limits = {});

    // The current protocol ScanMatch contains only offset and length. To keep
    // attribution lossless, request/result adaptation supports exactly one
    // pattern and no context. Local TypedScanPlan values remain multi-pattern.
    [[nodiscard]] std::expected<ScanRequest, ScanWireError> to_contract_scan_request(const ProviderScanRequest &request,
                                                                                     const ScanWireLimits &limits = {});

    [[nodiscard]] std::expected<ProviderScanRequest, ScanWireError>
    from_contract_scan_request(const ScanRequest &request, const ScanWireLimits &limits = {});

    [[nodiscard]] std::expected<ScanResponse, ScanWireError>
    to_contract_scan_response(const ProviderScanRequest &request, const MatchSet &matches,
                              const ScanWireLimits &limits = {});

    [[nodiscard]] std::expected<MatchSet, ScanWireError> from_contract_scan_response(const ProviderScanRequest &request,
                                                                                     const ScanResponse &response,
                                                                                     const ScanWireLimits &limits = {});

} // namespace rule_engine::python::optimizer
