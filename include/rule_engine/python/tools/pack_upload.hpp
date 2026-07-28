#pragma once

#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/tools/resident_service.hpp"

#include <filesystem>
#include <memory>

namespace rule_engine::python::tools {

    // Bounded resumable upload spool. Partial bytes are never activation
    // evidence: finalize re-parses the canonical archive, verifies signer
    // policy, checks the authorized pack identity, and performs immutable
    // content-addressed publication.
    struct FilesystemResidentPackUploadBackend final: IResidentPackUploadBackend {
        [[nodiscard]] static std::expected<std::unique_ptr<FilesystemResidentPackUploadBackend>,
                                           protocol_v2::ProtocolError>
        create(std::filesystem::path registry_root, packaging::TrustPolicy trust_policy,
               std::filesystem::path crypto_library) noexcept;
        ~FilesystemResidentPackUploadBackend() override;

        FilesystemResidentPackUploadBackend(const FilesystemResidentPackUploadBackend &) = delete;
        FilesystemResidentPackUploadBackend &operator=(const FilesystemResidentPackUploadBackend &) = delete;

        [[nodiscard]] std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
        begin(const PackId &pack, std::string_view upload_id, std::uint64_t total_bytes) noexcept override;
        [[nodiscard]] std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
        append(const PackId &pack, std::string_view upload_id, std::uint64_t offset,
               std::span<const std::byte> payload) noexcept override;
        [[nodiscard]] std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
        finalize(const PackId &pack, std::string_view upload_id) noexcept override;

    private:
        struct Impl;
        explicit FilesystemResidentPackUploadBackend(std::unique_ptr<Impl> impl) noexcept;
        std::unique_ptr<Impl> impl_;
    };

} // namespace rule_engine::python::tools
