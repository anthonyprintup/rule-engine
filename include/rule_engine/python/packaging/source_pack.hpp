#pragma once

#include "rule_engine/python/contract/compiler.hpp"
#include "rule_engine/python/packaging/error.hpp"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rule_engine::python::packaging {

    enum struct PackKind { rules, library };
    enum struct ArchiveEntryKind { regular_file, directory, symbolic_link };
    enum struct ArchiveCompression { stored, deflated, other };

    struct ArchiveEntry {
        std::string path;
        std::vector<std::byte> bytes;
        ArchiveEntryKind kind {ArchiveEntryKind::regular_file};
        ArchiveCompression compression {ArchiveCompression::stored};
        bool encrypted {};
        bool canonical_metadata {true};
    };

    struct SourcePackArchive {
        std::vector<ArchiveEntry> entries;
    };

    struct SourcePackLimits {
        std::size_t maximum_entries {4'096};
        std::size_t maximum_path_bytes {512};
        std::size_t maximum_entry_bytes {64U * mebibyte};
        std::size_t maximum_archive_bytes {256U * mebibyte};
        std::size_t maximum_source_bytes {balanced_v1.compile.source_closure_bytes};
        std::size_t maximum_generator_input_bytes {balanced_v1.compile.generator_input_bytes};
        std::size_t maximum_dependencies {256};
        std::size_t maximum_dependency_depth {16};
        std::size_t maximum_dependency_packs {1'024};
        std::size_t maximum_dependency_bytes {256U * mebibyte};
    };

    struct PackDependency {
        std::string alias;
        PackId pack;
        SourceDigest digest;
        auto operator<=>(const PackDependency &) const = default;
    };

    enum struct GeneratorInputFormat { json, utf8, bytes };

    struct GeneratorInput {
        std::string name;
        std::string path;
        GeneratorInputFormat format {};
        auto operator<=>(const GeneratorInput &) const = default;
    };

    struct GeneratorDeclaration {
        std::string module;
        std::string callable;
        std::string lock_path;
        std::vector<GeneratorInput> inputs;
        auto operator<=>(const GeneratorDeclaration &) const = default;
    };

    struct SourcePackManifest {
        std::uint32_t format {1};
        PackId pack;
        PackVersion version;
        PackKind kind {PackKind::rules};
        std::uint32_t engine_api {1};
        std::string python_version;
        std::vector<std::string> entry_modules;
        std::string budget_profile;
        std::string policy_profile;
        std::optional<GeneratorDeclaration> generator;
        std::vector<PackDependency> dependencies;
        std::vector<CapabilityId> required_capabilities;
        std::vector<CapabilityId> optional_capabilities;
        auto operator<=>(const SourcePackManifest &) const = default;
    };

    struct SourceIndexEntry {
        std::string media_type;
        std::string path;
        std::string sha256;
        std::size_t size {};
        auto operator<=>(const SourceIndexEntry &) const = default;
    };

    struct SourceIndex {
        std::uint32_t format {1};
        std::vector<SourceIndexEntry> entries;
        auto operator<=>(const SourceIndex &) const = default;
    };

    struct SignatureEnvelope {
        std::uint32_t version {1};
        std::string algorithm {"Ed25519"};
        std::string key_id;
        std::vector<std::byte> signature;
    };

    struct TrustedSigner {
        std::string key_id;
        std::vector<std::byte> public_key;
        std::vector<std::string> allowed_pack_prefixes;
        bool revoked {};
    };

    enum struct TrustMode { production, development };

    struct TrustPolicy {
        TrustMode mode {TrustMode::production};
        bool allow_unsigned_packs {};
        bool allow_unsigned_generators {};
        std::vector<TrustedSigner> signers;
    };

    struct SignatureVerifier {
        virtual ~SignatureVerifier() = default;

        [[nodiscard]] virtual std::expected<bool, PackagingError>
        verify_ed25519(std::span<const std::byte> public_key, std::span<const std::byte> message,
                       std::span<const std::byte> signature) const = 0;
    };

    // OpenSSL is loaded only from this explicit path. The implementation never
    // searches PATH or the current directory for a cryptographic provider.
    struct OpenSsl3Ed25519Verifier final: SignatureVerifier {
        std::filesystem::path crypto_library;

        [[nodiscard]] std::expected<bool, PackagingError>
        verify_ed25519(std::span<const std::byte> public_key, std::span<const std::byte> message,
                       std::span<const std::byte> signature) const override;
    };

    enum struct PackTrustKind { production_signed, development_unsigned };

    struct PackTrust {
        PackTrustKind kind {PackTrustKind::development_unsigned};
        std::string signer_key_id;
        bool generator_execution_authorized {};
    };

    struct LoadedSourcePack {
        SourcePackManifest manifest;
        SourceIndex index;
        SourceDigest source_digest;
        SourceDigest closure_digest;
        PackTrust trust;
        VerifiedRulePack contract_pack;
    };

    [[nodiscard]] std::string sha256_hex(std::span<const std::byte> bytes);
    [[nodiscard]] std::string canonical_manifest(const SourcePackManifest &manifest);
    [[nodiscard]] std::expected<SourcePackManifest, PackagingError> parse_canonical_manifest(std::string_view text);
    [[nodiscard]] std::string canonical_index(const SourceIndex &index);
    [[nodiscard]] std::expected<SourceIndex, PackagingError> parse_canonical_index(std::string_view text);
    [[nodiscard]] std::string canonical_signature_envelope(const SignatureEnvelope &envelope);
    [[nodiscard]] std::expected<SignatureEnvelope, PackagingError>
    parse_canonical_signature_envelope(std::string_view text);
    [[nodiscard]] std::expected<LoadedSourcePack, PackagingError>
    verify_and_load_source_pack(const SourcePackArchive &archive, const TrustPolicy &policy,
                                const SignatureVerifier &signature_verifier, const SourcePackLimits &limits = {});
    [[nodiscard]] std::expected<std::vector<std::byte>, PackagingError>
    encode_canonical_source_pack(const SourcePackArchive &archive, const SourcePackLimits &limits = {});
    [[nodiscard]] std::expected<SourcePackArchive, PackagingError>
    decode_canonical_source_pack(std::span<const std::byte> bytes, const SourcePackLimits &limits = {});
    [[nodiscard]] std::expected<void, PackagingError> write_canonical_source_pack(const std::filesystem::path &path,
                                                                                  const SourcePackArchive &archive,
                                                                                  const SourcePackLimits &limits = {});
    [[nodiscard]] std::expected<SourcePackArchive, PackagingError>
    read_canonical_source_pack(const std::filesystem::path &path, const SourcePackLimits &limits = {});
    [[nodiscard]] std::expected<LoadedSourcePack, PackagingError>
    read_verify_and_load_source_pack(const std::filesystem::path &path, const TrustPolicy &policy,
                                     const SignatureVerifier &signature_verifier, const SourcePackLimits &limits = {});

} // namespace rule_engine::python::packaging
