#pragma once

#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/tools/resident_service.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>

namespace rule_engine::python::tools {

    inline constexpr std::uint64_t maximum_pack_registry_bytes = 1ULL << 50U;

    struct FilesystemResidentPackUploadTestAccess;

    struct PackRegistryLimits {
        std::uint64_t maximum_published_bytes {};
        std::uint64_t maximum_tenant_bytes {};
        std::chrono::milliseconds partial_session_ttl {};
        std::chrono::milliseconds unreferenced_retention {};
    };

    // Bounded resumable upload spool. Partial bytes are never activation
    // evidence: finalize re-parses the canonical archive, verifies signer
    // policy, checks the authorized pack identity, and performs immutable
    // content-addressed publication.
    struct FilesystemResidentPackUploadBackend final: IResidentPackUploadBackend {
        [[nodiscard]] static std::expected<std::unique_ptr<FilesystemResidentPackUploadBackend>,
                                           protocol_v2::ProtocolError>
        create(std::filesystem::path registry_root, packaging::TrustPolicy trust_policy,
               std::filesystem::path crypto_library, PackRegistryLimits limits) noexcept;
        ~FilesystemResidentPackUploadBackend() override;

        FilesystemResidentPackUploadBackend(const FilesystemResidentPackUploadBackend &) = delete;
        FilesystemResidentPackUploadBackend &operator=(const FilesystemResidentPackUploadBackend &) = delete;

        [[nodiscard]] std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
        begin(const TenantId &tenant, const PackId &pack, std::string_view upload_id,
              std::uint64_t total_bytes) noexcept override;
        [[nodiscard]] std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
        append(const TenantId &tenant, const PackId &pack, std::string_view upload_id, std::uint64_t offset,
               std::span<const std::byte> payload) noexcept override;
        [[nodiscard]] std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
        finalize(const TenantId &tenant, const PackId &pack, std::string_view upload_id) noexcept override;
        [[nodiscard]] std::expected<ResidentPackRegistryMaintenanceReceipt, protocol_v2::ProtocolError>
        maintain(std::span<const SourceDigest> reachable_source_digests, std::uint64_t now_unix_ms) noexcept override;
        [[nodiscard]] std::expected<ResidentPackRegistryObservation, protocol_v2::ProtocolError>
        observe_maintenance() noexcept override;

    private:
        friend struct FilesystemResidentPackUploadTestAccess;

        struct Impl;
        explicit FilesystemResidentPackUploadBackend(std::unique_ptr<Impl> impl) noexcept;
        void set_maintenance_lock_hook_for_testing(void (*hook)(void *) noexcept, void *context) noexcept;
        std::unique_ptr<Impl> impl_;
    };

} // namespace rule_engine::python::tools
