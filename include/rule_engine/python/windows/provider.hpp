#pragma once

#include "rule_engine/python/contract.hpp"
#include "rule_engine/python/optimizer/scanner.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::windows {

    inline constexpr std::string_view provider_name = "windows";

    inline constexpr std::string_view process_schema = "windows.process.v1";
    inline constexpr std::string_view image_schema = "windows.image.v1";
    inline constexpr std::string_view memory_region_schema = "windows.memory-region.v1";
    inline constexpr std::string_view pe_section_schema = "windows.pe-section.v1";
    inline constexpr std::string_view pe_import_schema = "windows.pe-import.v1";
    inline constexpr std::string_view pe_export_schema = "windows.pe-export.v1";
    inline constexpr std::string_view pe_debug_schema = "windows.pe-debug.v1";
    inline constexpr std::string_view pe_resource_schema = "windows.pe-resource.v1";
    inline constexpr std::string_view pe_certificate_schema = "windows.pe-certificate.v1";
    inline constexpr std::string_view pe_tls_callback_schema = "windows.pe-tls-callback.v1";

    inline constexpr std::string_view signer_value_schema = "windows.signer-value.v1";
    inline constexpr std::string_view pe_value_schema = "windows.pe-value.v1";
    inline constexpr std::string_view process_user_value_schema = "windows.process-user-value.v1";
    inline constexpr std::string_view process_token_value_schema = "windows.process-token-value.v1";
    inline constexpr std::string_view process_memory_value_schema = "windows.process-memory-value.v1";

    enum struct ProviderErrorCode : std::uint8_t {
        invalid_request,
        invalid_subject,
        subject_changed,
        not_found,
        unsupported,
        access_denied,
        timed_out,
        unavailable,
        malformed,
        result_limit,
        arithmetic_overflow,
    };

    struct ProviderError {
        ProviderErrorCode code {ProviderErrorCode::unavailable};
        std::string operation;
        std::string message;
        std::uint32_t platform_code {};
    };

    struct SubjectObservation {
        SubjectKey subject;
        std::vector<FactRecordField> eager_fields;
    };

    // A provider-side authoritative inventory is publishable only when
    // `authoritative` is true. Invalid/partial inventories intentionally carry
    // no publishable items so a coordinator can retain its last-good snapshot.
    // Empty authoritative inventories are valid and have a deterministic
    // SHA-256 digest.
    struct InventorySnapshot {
        SnapshotBegin begin;
        std::vector<SubjectObservation> items;
        SnapshotCommit commit;
        FactTerminalStatus status {FactTerminalStatus::failed};
        bool authoritative {};
        std::optional<Diagnostic> diagnostic;
    };

    struct PeInventorySet {
        SubjectObservation image;
        FrozenValue value;
        InventorySnapshot sections;
        InventorySnapshot imports;
        InventorySnapshot exports;
        InventorySnapshot debug_entries;
        InventorySnapshot resources;
        InventorySnapshot certificates;
        InventorySnapshot tls_callbacks;
    };

    struct AcquiredScanSpace {
        optimizer::ExplicitScanSpace descriptor;
        std::vector<std::byte> bytes;
        std::uint64_t source_origin {};
    };

    [[nodiscard]] FactTerminalStatus terminal_status(ProviderErrorCode code) noexcept;
    [[nodiscard]] Diagnostic provider_diagnostic(const ProviderError &error);

    [[nodiscard]] SubjectKey process_subject(PeerId peer, std::uint32_t pid, std::uint64_t creation_time);
    [[nodiscard]] SubjectKey memory_region_subject(const SubjectKey &process, std::uint64_t allocation_base,
                                                   std::uint64_t base);
    [[nodiscard]] std::expected<SubjectKey, ProviderError> image_subject(const SubjectKey &process,
                                                                         const std::filesystem::path &path);

    [[nodiscard]] InventorySnapshot make_inventory_snapshot(PeerId peer, SchemaId schema,
                                                            std::optional<SubjectKey> parent, std::uint64_t generation,
                                                            std::vector<SubjectObservation> items);
    [[nodiscard]] InventorySnapshot invalid_inventory_snapshot(PeerId peer, SchemaId schema, std::uint64_t generation,
                                                               ProviderError error);

    [[nodiscard]] InventorySnapshot enumerate_process_inventory(PeerId peer, std::uint64_t generation,
                                                                std::uint64_t deadline_unix_ms = 0);
    [[nodiscard]] InventorySnapshot enumerate_memory_region_inventory(const SubjectKey &process,
                                                                      std::uint64_t generation,
                                                                      std::uint64_t deadline_unix_ms = 0);

    [[nodiscard]] std::expected<std::filesystem::path, ProviderError>
    resolve_process_image_path(const SubjectKey &process, std::uint64_t deadline_unix_ms = 0);
    [[nodiscard]] std::expected<FrozenValue, ProviderError> read_process_signer(const SubjectKey &process,
                                                                                std::uint64_t deadline_unix_ms = 0);
    [[nodiscard]] std::expected<FrozenValue, ProviderError> read_image_signer(const std::filesystem::path &path,
                                                                              std::uint64_t deadline_unix_ms = 0);

    [[nodiscard]] std::expected<PeInventorySet, ProviderError> inspect_pe_image(const SubjectKey &process,
                                                                                const std::filesystem::path &path,
                                                                                std::uint64_t generation,
                                                                                std::uint64_t deadline_unix_ms = 0);

    [[nodiscard]] FactResponse dispatch_fact(const FactRequest &request);
    [[nodiscard]] ScanResponse dispatch_scan(const ScanRequest &request);

    [[nodiscard]] std::expected<AcquiredScanSpace, ProviderError>
    acquire_scan_space(const SubjectKey &subject, const optimizer::ExplicitScanSpace &space,
                       std::uint64_t deadline_unix_ms = 0);
    [[nodiscard]] std::expected<optimizer::MatchSet, ProviderError>
    execute_scan(const optimizer::ProviderScanRequest &request);

    // Public only for deterministic tests and protocol canonicalization. It is
    // deliberately data-only and has no predicate/rule/verdict parameter.
    [[nodiscard]] FrozenValue freeze_provider_value(FactValue value, DataLabel label);
    [[nodiscard]] std::string canonical_provider_value(const FactValue &value);
    [[nodiscard]] std::string sha256_digest(std::span<const std::byte> bytes);
    [[nodiscard]] std::uint64_t unix_time_ms() noexcept;

} // namespace rule_engine::python::windows
