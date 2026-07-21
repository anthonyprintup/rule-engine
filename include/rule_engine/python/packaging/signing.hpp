#pragma once

#include "rule_engine/python/packaging/source_pack.hpp"

#include <array>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::packaging {

    inline constexpr std::size_t ed25519_seed_bytes = 32U;
    inline constexpr std::size_t ed25519_public_key_bytes = 32U;
    inline constexpr std::size_t ed25519_signature_bytes = 64U;

    struct Ed25519Signer {
        virtual ~Ed25519Signer() = default;

        // Implementations must return secret-free errors: no key reference,
        // private bytes, provider credentials, or protected source content.
        [[nodiscard]] virtual std::array<std::byte, ed25519_public_key_bytes> public_key() const noexcept = 0;
        [[nodiscard]] virtual std::expected<std::array<std::byte, ed25519_signature_bytes>, PackagingError>
        sign(std::span<const std::byte> message) = 0;
    };

    struct SigningKeyProvider {
        virtual ~SigningKeyProvider() = default;

        // References are provider-defined and must never be echoed in errors.
        [[nodiscard]] virtual std::expected<std::unique_ptr<Ed25519Signer>, PackagingError>
        open_ed25519(std::string_view reference) = 0;
    };

    // Offline build/CI adapter. References must be absolute local-drive paths
    // in the form file:C:/path/to/seed. The file contains exactly one raw
    // 32-byte Ed25519 seed and is never copied into a source pack.
    struct OpenSsl3FileEd25519KeyProvider final: SigningKeyProvider {
        std::filesystem::path crypto_library;

        [[nodiscard]] std::expected<std::unique_ptr<Ed25519Signer>, PackagingError>
        open_ed25519(std::string_view reference) override;
    };

    struct SourcePackSigningRequest {
        std::string signer_reference;
        std::optional<std::string> requested_key_id;
    };

    // Validates the complete canonical pack structure without granting trust,
    // then returns the same domain-separated message used by verification.
    [[nodiscard]] std::expected<std::vector<std::byte>, PackagingError>
    canonical_source_pack_signature_message(const SourcePackArchive &unsigned_archive,
                                            const SourcePackLimits &limits = {});

    // Adds only META-INF/signature.json. The key reference and private seed are
    // never serialized into the returned archive.
    [[nodiscard]] std::expected<SourcePackArchive, PackagingError>
    sign_canonical_source_pack(const SourcePackArchive &unsigned_archive, const SourcePackSigningRequest &request,
                               SigningKeyProvider &key_provider, const SourcePackLimits &limits = {});

} // namespace rule_engine::python::packaging
