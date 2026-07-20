#include "rule_engine/python/packaging/source_pack.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <fstream>
#include <limits>
#include <set>
#include <system_error>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#endif

namespace rule_engine::python::packaging {
    namespace {

        constexpr std::uint32_t local_header_signature = 0x04034b50U;
        constexpr std::uint32_t central_header_signature = 0x02014b50U;
        constexpr std::uint32_t end_header_signature = 0x06054b50U;
        constexpr std::uint16_t zip_version = 20U;
        constexpr std::uint16_t canonical_creator = 0x0314U;
        constexpr std::uint16_t utf8_flag = 0x0800U;
        constexpr std::uint16_t stored_method = 0U;
        constexpr std::uint16_t canonical_dos_time = 0U;
        constexpr std::uint16_t canonical_dos_date = 0x0021U;
        constexpr std::uint32_t canonical_external_attributes = 0100444U << 16U;
        constexpr std::size_t local_header_size = 30U;
        constexpr std::size_t central_header_size = 46U;
        constexpr std::size_t end_header_size = 22U;

        PackagingError archive_error(const PackagingErrorCode code, std::string message,
                                     std::optional<std::string> subject = std::nullopt) {
            return PackagingError {.code = code, .message = std::move(message), .subject = std::move(subject)};
        }

        void append_u16(std::vector<std::byte> &output, const std::uint16_t value) {
            output.push_back(static_cast<std::byte>(value & 0xffU));
            output.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
        }

        void append_u32(std::vector<std::byte> &output, const std::uint32_t value) {
            for (unsigned shift = 0; shift < 32U; shift += 8U) {
                output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
            }
        }

        std::optional<std::uint16_t> read_u16(const std::span<const std::byte> input, const std::size_t offset) {
            if (offset > input.size() || input.size() - offset < 2U) {
                return std::nullopt;
            }
            return static_cast<std::uint16_t>(std::to_integer<std::uint16_t>(input[offset]) |
                                              (std::to_integer<std::uint16_t>(input[offset + 1U]) << 8U));
        }

        std::optional<std::uint32_t> read_u32(const std::span<const std::byte> input, const std::size_t offset) {
            if (offset > input.size() || input.size() - offset < 4U) {
                return std::nullopt;
            }
            return std::to_integer<std::uint32_t>(input[offset]) |
                   (std::to_integer<std::uint32_t>(input[offset + 1U]) << 8U) |
                   (std::to_integer<std::uint32_t>(input[offset + 2U]) << 16U) |
                   (std::to_integer<std::uint32_t>(input[offset + 3U]) << 24U);
        }

        std::uint32_t crc32(const std::span<const std::byte> bytes) noexcept {
            std::uint32_t crc = 0xffffffffU;
            for (const auto byte : bytes) {
                crc ^= std::to_integer<std::uint8_t>(byte);
                for (unsigned bit = 0; bit < 8U; ++bit) {
                    const auto mask = 0U - (crc & 1U);
                    crc = (crc >> 1U) ^ (0xedb88320U & mask);
                }
            }
            return ~crc;
        }

        bool canonical_path(const std::string_view path, const std::size_t maximum_path_bytes) noexcept {
            if (path.empty() || path.size() > maximum_path_bytes || path.front() == '/' || path.back() == '/' ||
                path.front() == ' ' || path.back() == ' ') {
                return false;
            }
            std::size_t segment_begin = 0U;
            for (std::size_t index = 0; index <= path.size(); ++index) {
                if (index != path.size() && path[index] != '/') {
                    const auto character = static_cast<unsigned char>(path[index]);
                    if (character < 0x21U || character > 0x7eU || character == '\\' || character == ':' ||
                        character == 0x7fU) {
                        return false;
                    }
                    continue;
                }
                const auto segment = path.substr(segment_begin, index - segment_begin);
                if (segment.empty() || segment == "." || segment == ".." || segment.front() == ' ' ||
                    segment.back() == ' ') {
                    return false;
                }
                segment_begin = index + 1U;
            }
            return true;
        }

        std::string folded_path(std::string_view path) {
            std::string folded {path};
            std::ranges::transform(folded, folded.begin(), [](const unsigned char character) {
                return static_cast<char>(std::tolower(character));
            });
            return folded;
        }

        struct EncodedEntry {
            const ArchiveEntry *entry {};
            std::uint32_t crc {};
            std::uint32_t size {};
            std::uint32_t local_offset {};
        };

        std::expected<std::vector<EncodedEntry>, PackagingError>
        validate_entries_for_encoding(const SourcePackArchive &archive, const SourcePackLimits &limits) {
            if (archive.entries.size() > limits.maximum_entries ||
                archive.entries.size() > std::numeric_limits<std::uint16_t>::max()) {
                return std::unexpected(
                    archive_error(PackagingErrorCode::size_limit, "ZIP entry count exceeds the configured bound"));
            }

            std::vector<EncodedEntry> encoded;
            encoded.reserve(archive.entries.size());
            std::set<std::string> folded_paths;
            std::string_view previous_path;
            std::uint64_t local_offset = 0U;
            for (const auto &entry : archive.entries) {
                if (!canonical_path(entry.path, limits.maximum_path_bytes)) {
                    return std::unexpected(
                        archive_error(PackagingErrorCode::invalid_path, "ZIP entry path is not canonical", entry.path));
                }
                if (!previous_path.empty() && !(previous_path < entry.path)) {
                    return std::unexpected(archive_error(PackagingErrorCode::noncanonical_archive,
                                                         "ZIP entries are not in ascending UTF-8 byte order",
                                                         entry.path));
                }
                previous_path = entry.path;
                if (!folded_paths.emplace(folded_path(entry.path)).second) {
                    return std::unexpected(archive_error(PackagingErrorCode::path_collision,
                                                         "ZIP entry collides under Windows case folding", entry.path));
                }
                if (entry.kind != ArchiveEntryKind::regular_file || entry.compression != ArchiveCompression::stored ||
                    entry.encrypted || !entry.canonical_metadata) {
                    return std::unexpected(archive_error(PackagingErrorCode::unsupported_entry,
                                                         "ZIP entry is not a canonical stored regular file",
                                                         entry.path));
                }
                if (entry.bytes.size() > limits.maximum_entry_bytes ||
                    entry.bytes.size() > std::numeric_limits<std::uint32_t>::max() ||
                    entry.path.size() > std::numeric_limits<std::uint16_t>::max()) {
                    return std::unexpected(archive_error(PackagingErrorCode::size_limit,
                                                         "ZIP entry exceeds a classic ZIP bound", entry.path));
                }
                if (local_offset > std::numeric_limits<std::uint32_t>::max()) {
                    return std::unexpected(
                        archive_error(PackagingErrorCode::size_limit, "ZIP local header offset exceeds classic ZIP"));
                }
                encoded.push_back(EncodedEntry {
                    .entry = &entry,
                    .crc = crc32(entry.bytes),
                    .size = static_cast<std::uint32_t>(entry.bytes.size()),
                    .local_offset = static_cast<std::uint32_t>(local_offset),
                });
                local_offset += local_header_size + entry.path.size() + entry.bytes.size();
                if (local_offset > limits.maximum_archive_bytes) {
                    return std::unexpected(
                        archive_error(PackagingErrorCode::size_limit, "ZIP archive exceeds the configured bound"));
                }
            }
            return encoded;
        }

        struct CentralEntry {
            std::string path;
            std::uint32_t crc {};
            std::uint32_t size {};
            std::uint32_t local_offset {};
        };

        std::expected<std::vector<std::byte>, PackagingError> read_bounded_file(const std::filesystem::path &path,
                                                                                const std::size_t maximum_bytes) {
            std::error_code filesystem_error;
            const auto file_size = std::filesystem::file_size(path, filesystem_error);
            if (filesystem_error) {
                return std::unexpected(
                    archive_error(PackagingErrorCode::filesystem_error, "cannot stat source-pack file", path.string()));
            }
            if (file_size > maximum_bytes) {
                return std::unexpected(archive_error(PackagingErrorCode::size_limit,
                                                     "source-pack file exceeds the configured bound", path.string()));
            }
            std::ifstream input {path, std::ios::binary};
            if (!input) {
                return std::unexpected(
                    archive_error(PackagingErrorCode::filesystem_error, "cannot open source-pack file", path.string()));
            }
            std::vector<std::byte> bytes(static_cast<std::size_t>(file_size));
            if (!bytes.empty()) {
                input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            }
            if (!input || static_cast<std::size_t>(input.gcount()) != bytes.size()) {
                return std::unexpected(archive_error(PackagingErrorCode::filesystem_error,
                                                     "cannot read complete source-pack file", path.string()));
            }
            return bytes;
        }

    } // namespace

    std::expected<std::vector<std::byte>, PackagingError> encode_canonical_source_pack(const SourcePackArchive &archive,
                                                                                       const SourcePackLimits &limits) {
        const auto entries = validate_entries_for_encoding(archive, limits);
        if (!entries) {
            return std::unexpected(entries.error());
        }

        std::vector<std::byte> output;
        output.reserve(std::min(limits.maximum_archive_bytes, static_cast<std::size_t>(1U * mebibyte)));
        for (const auto &encoded : *entries) {
            append_u32(output, local_header_signature);
            append_u16(output, zip_version);
            append_u16(output, utf8_flag);
            append_u16(output, stored_method);
            append_u16(output, canonical_dos_time);
            append_u16(output, canonical_dos_date);
            append_u32(output, encoded.crc);
            append_u32(output, encoded.size);
            append_u32(output, encoded.size);
            append_u16(output, static_cast<std::uint16_t>(encoded.entry->path.size()));
            append_u16(output, 0U);
            output.insert(output.end(), reinterpret_cast<const std::byte *>(encoded.entry->path.data()),
                          reinterpret_cast<const std::byte *>(encoded.entry->path.data() + encoded.entry->path.size()));
            output.insert(output.end(), encoded.entry->bytes.begin(), encoded.entry->bytes.end());
        }

        if (output.size() > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected(
                archive_error(PackagingErrorCode::size_limit, "ZIP central-directory offset exceeds classic ZIP"));
        }
        const auto central_offset = static_cast<std::uint32_t>(output.size());
        for (const auto &encoded : *entries) {
            append_u32(output, central_header_signature);
            append_u16(output, canonical_creator);
            append_u16(output, zip_version);
            append_u16(output, utf8_flag);
            append_u16(output, stored_method);
            append_u16(output, canonical_dos_time);
            append_u16(output, canonical_dos_date);
            append_u32(output, encoded.crc);
            append_u32(output, encoded.size);
            append_u32(output, encoded.size);
            append_u16(output, static_cast<std::uint16_t>(encoded.entry->path.size()));
            append_u16(output, 0U);
            append_u16(output, 0U);
            append_u16(output, 0U);
            append_u16(output, 0U);
            append_u32(output, canonical_external_attributes);
            append_u32(output, encoded.local_offset);
            output.insert(output.end(), reinterpret_cast<const std::byte *>(encoded.entry->path.data()),
                          reinterpret_cast<const std::byte *>(encoded.entry->path.data() + encoded.entry->path.size()));
        }
        const auto central_size = output.size() - central_offset;
        if (central_size > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected(
                archive_error(PackagingErrorCode::size_limit, "ZIP central directory exceeds classic ZIP"));
        }
        append_u32(output, end_header_signature);
        append_u16(output, 0U);
        append_u16(output, 0U);
        append_u16(output, static_cast<std::uint16_t>(entries->size()));
        append_u16(output, static_cast<std::uint16_t>(entries->size()));
        append_u32(output, static_cast<std::uint32_t>(central_size));
        append_u32(output, central_offset);
        append_u16(output, 0U);

        if (output.size() > limits.maximum_archive_bytes) {
            return std::unexpected(
                archive_error(PackagingErrorCode::size_limit, "ZIP archive exceeds the configured bound"));
        }
        return output;
    }

    std::expected<SourcePackArchive, PackagingError>
    decode_canonical_source_pack(const std::span<const std::byte> bytes, const SourcePackLimits &limits) {
        if (bytes.size() > limits.maximum_archive_bytes) {
            return std::unexpected(
                archive_error(PackagingErrorCode::size_limit, "source-pack archive exceeds the configured bound"));
        }
        if (bytes.size() < end_header_size) {
            return std::unexpected(
                archive_error(PackagingErrorCode::noncanonical_archive, "ZIP end record is missing or truncated"));
        }

        const auto end_offset = bytes.size() - end_header_size;
        const auto end_signature = read_u32(bytes, end_offset);
        const auto disk_number = read_u16(bytes, end_offset + 4U);
        const auto central_disk = read_u16(bytes, end_offset + 6U);
        const auto disk_entries = read_u16(bytes, end_offset + 8U);
        const auto total_entries = read_u16(bytes, end_offset + 10U);
        const auto central_size = read_u32(bytes, end_offset + 12U);
        const auto central_offset = read_u32(bytes, end_offset + 16U);
        const auto comment_size = read_u16(bytes, end_offset + 20U);
        if (!end_signature || *end_signature != end_header_signature || !disk_number || *disk_number != 0U ||
            !central_disk || *central_disk != 0U || !disk_entries || !total_entries ||
            *disk_entries != *total_entries || !central_size || !central_offset || !comment_size ||
            *comment_size != 0U || *total_entries > limits.maximum_entries ||
            static_cast<std::uint64_t>(*central_offset) + *central_size != end_offset) {
            return std::unexpected(archive_error(PackagingErrorCode::noncanonical_archive,
                                                 "ZIP end record is not canonical classic single-disk metadata"));
        }

        std::vector<CentralEntry> central_entries;
        central_entries.reserve(*total_entries);
        std::size_t cursor = *central_offset;
        std::string previous_path;
        std::set<std::string> folded_paths;
        for (std::size_t index = 0; index < *total_entries; ++index) {
            if (cursor > end_offset || end_offset - cursor < central_header_size) {
                return std::unexpected(
                    archive_error(PackagingErrorCode::noncanonical_archive, "ZIP central directory is truncated"));
            }
            const auto signature = read_u32(bytes, cursor);
            const auto creator = read_u16(bytes, cursor + 4U);
            const auto needed = read_u16(bytes, cursor + 6U);
            const auto flags = read_u16(bytes, cursor + 8U);
            const auto method = read_u16(bytes, cursor + 10U);
            const auto time = read_u16(bytes, cursor + 12U);
            const auto date = read_u16(bytes, cursor + 14U);
            const auto crc = read_u32(bytes, cursor + 16U);
            const auto compressed_size = read_u32(bytes, cursor + 20U);
            const auto uncompressed_size = read_u32(bytes, cursor + 24U);
            const auto path_size = read_u16(bytes, cursor + 28U);
            const auto extra_size = read_u16(bytes, cursor + 30U);
            const auto entry_comment_size = read_u16(bytes, cursor + 32U);
            const auto entry_disk = read_u16(bytes, cursor + 34U);
            const auto internal_attributes = read_u16(bytes, cursor + 36U);
            const auto external_attributes = read_u32(bytes, cursor + 38U);
            const auto local_offset = read_u32(bytes, cursor + 42U);
            if (!signature || *signature != central_header_signature || !creator || *creator != canonical_creator ||
                !needed || *needed != zip_version || !flags || *flags != utf8_flag || !method ||
                *method != stored_method || !time || *time != canonical_dos_time || !date ||
                *date != canonical_dos_date || !crc || !compressed_size || !uncompressed_size ||
                *compressed_size != *uncompressed_size || !path_size || *path_size == 0U || !extra_size ||
                *extra_size != 0U || !entry_comment_size || *entry_comment_size != 0U || !entry_disk ||
                *entry_disk != 0U || !internal_attributes || *internal_attributes != 0U || !external_attributes ||
                *external_attributes != canonical_external_attributes || !local_offset) {
                return std::unexpected(archive_error(PackagingErrorCode::noncanonical_archive,
                                                     "ZIP central-directory entry has noncanonical metadata"));
            }
            if (*uncompressed_size > limits.maximum_entry_bytes || *path_size > limits.maximum_path_bytes ||
                cursor + central_header_size > end_offset || *path_size > end_offset - (cursor + central_header_size)) {
                return std::unexpected(archive_error(PackagingErrorCode::size_limit,
                                                     "ZIP central-directory entry exceeds configured bounds"));
            }
            const auto path_offset = cursor + central_header_size;
            std::string path {reinterpret_cast<const char *>(bytes.data() + path_offset), *path_size};
            if (!canonical_path(path, limits.maximum_path_bytes)) {
                return std::unexpected(
                    archive_error(PackagingErrorCode::invalid_path, "ZIP entry path is not canonical", path));
            }
            if (!previous_path.empty() && !(previous_path < path)) {
                return std::unexpected(archive_error(PackagingErrorCode::noncanonical_archive,
                                                     "ZIP entries are not in ascending UTF-8 byte order", path));
            }
            previous_path = path;
            if (!folded_paths.emplace(folded_path(path)).second) {
                return std::unexpected(archive_error(PackagingErrorCode::path_collision,
                                                     "ZIP entry collides under Windows case folding", path));
            }
            central_entries.push_back(CentralEntry {
                .path = std::move(path),
                .crc = *crc,
                .size = *uncompressed_size,
                .local_offset = *local_offset,
            });
            cursor = path_offset + *path_size;
        }
        if (cursor != end_offset) {
            return std::unexpected(archive_error(PackagingErrorCode::noncanonical_archive,
                                                 "ZIP central-directory byte count does not match its entries"));
        }

        SourcePackArchive archive;
        archive.entries.reserve(central_entries.size());
        std::size_t expected_local_offset = 0U;
        for (const auto &central : central_entries) {
            const auto local_offset = static_cast<std::size_t>(central.local_offset);
            if (local_offset != expected_local_offset || local_offset > *central_offset ||
                *central_offset - local_offset < local_header_size) {
                return std::unexpected(archive_error(PackagingErrorCode::noncanonical_archive,
                                                     "ZIP local headers are not contiguous and canonical",
                                                     central.path));
            }
            const auto signature = read_u32(bytes, local_offset);
            const auto needed = read_u16(bytes, local_offset + 4U);
            const auto flags = read_u16(bytes, local_offset + 6U);
            const auto method = read_u16(bytes, local_offset + 8U);
            const auto time = read_u16(bytes, local_offset + 10U);
            const auto date = read_u16(bytes, local_offset + 12U);
            const auto crc = read_u32(bytes, local_offset + 14U);
            const auto compressed_size = read_u32(bytes, local_offset + 18U);
            const auto uncompressed_size = read_u32(bytes, local_offset + 22U);
            const auto path_size = read_u16(bytes, local_offset + 26U);
            const auto extra_size = read_u16(bytes, local_offset + 28U);
            if (!signature || *signature != local_header_signature || !needed || *needed != zip_version || !flags ||
                *flags != utf8_flag || !method || *method != stored_method || !time || *time != canonical_dos_time ||
                !date || *date != canonical_dos_date || !crc || *crc != central.crc || !compressed_size ||
                *compressed_size != central.size || !uncompressed_size || *uncompressed_size != central.size ||
                !path_size || *path_size != central.path.size() || !extra_size || *extra_size != 0U) {
                return std::unexpected(archive_error(PackagingErrorCode::noncanonical_archive,
                                                     "ZIP local header disagrees with canonical central metadata",
                                                     central.path));
            }
            const auto path_offset = local_offset + local_header_size;
            if (path_offset > *central_offset || *path_size > *central_offset - path_offset) {
                return std::unexpected(archive_error(PackagingErrorCode::noncanonical_archive,
                                                     "ZIP local path is truncated", central.path));
            }
            const std::string_view local_path {reinterpret_cast<const char *>(bytes.data() + path_offset), *path_size};
            if (local_path != central.path) {
                return std::unexpected(archive_error(PackagingErrorCode::noncanonical_archive,
                                                     "ZIP local and central paths disagree", central.path));
            }
            const auto payload_offset = path_offset + *path_size;
            if (payload_offset > *central_offset || central.size > *central_offset - payload_offset) {
                return std::unexpected(
                    archive_error(PackagingErrorCode::noncanonical_archive, "ZIP payload is truncated", central.path));
            }
            const auto payload = bytes.subspan(payload_offset, central.size);
            if (crc32(payload) != central.crc) {
                return std::unexpected(archive_error(PackagingErrorCode::archive_crc_mismatch,
                                                     "ZIP payload CRC-32 does not match", central.path));
            }
            archive.entries.push_back(ArchiveEntry {
                .path = central.path,
                .bytes = {payload.begin(), payload.end()},
                .kind = ArchiveEntryKind::regular_file,
                .compression = ArchiveCompression::stored,
                .encrypted = false,
                .canonical_metadata = true,
            });
            expected_local_offset = payload_offset + central.size;
        }
        if (expected_local_offset != *central_offset) {
            return std::unexpected(archive_error(PackagingErrorCode::noncanonical_archive,
                                                 "ZIP local-record extent does not meet the central directory"));
        }
        return archive;
    }

    std::expected<void, PackagingError> write_canonical_source_pack(const std::filesystem::path &path,
                                                                    const SourcePackArchive &archive,
                                                                    const SourcePackLimits &limits) {
        const auto encoded = encode_canonical_source_pack(archive, limits);
        if (!encoded) {
            return std::unexpected(encoded.error());
        }
        auto temporary_path = path;
        temporary_path += L".rule-engine-tmp";
        std::error_code filesystem_error;
        if (std::filesystem::exists(temporary_path, filesystem_error) || filesystem_error) {
            return std::unexpected(archive_error(PackagingErrorCode::filesystem_error,
                                                 "source-pack temporary path already exists or cannot be checked",
                                                 temporary_path.string()));
        }
        std::ofstream output {temporary_path, std::ios::binary | std::ios::trunc};
        if (!output) {
            return std::unexpected(archive_error(PackagingErrorCode::filesystem_error,
                                                 "cannot create source-pack temporary file", temporary_path.string()));
        }
        if (!encoded->empty()) {
            output.write(reinterpret_cast<const char *>(encoded->data()),
                         static_cast<std::streamsize>(encoded->size()));
        }
        output.flush();
        const auto write_succeeded = output.good();
        output.close();
        if (!write_succeeded) {
            std::filesystem::remove(temporary_path, filesystem_error);
            return std::unexpected(archive_error(PackagingErrorCode::filesystem_error,
                                                 "cannot write complete source-pack temporary file",
                                                 temporary_path.string()));
        }
#ifdef _WIN32
        if (MoveFileExW(temporary_path.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ==
            0) {
            std::filesystem::remove(temporary_path, filesystem_error);
            return std::unexpected(archive_error(PackagingErrorCode::filesystem_error,
                                                 "cannot atomically publish source-pack file", path.string()));
        }
#else
        std::filesystem::rename(temporary_path, path, filesystem_error);
        if (filesystem_error) {
            std::filesystem::remove(temporary_path, filesystem_error);
            return std::unexpected(archive_error(PackagingErrorCode::filesystem_error,
                                                 "cannot atomically publish source-pack file", path.string()));
        }
#endif
        return {};
    }

    std::expected<SourcePackArchive, PackagingError> read_canonical_source_pack(const std::filesystem::path &path,
                                                                                const SourcePackLimits &limits) {
        const auto bytes = read_bounded_file(path, limits.maximum_archive_bytes);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        return decode_canonical_source_pack(*bytes, limits);
    }

    std::expected<LoadedSourcePack, PackagingError>
    read_verify_and_load_source_pack(const std::filesystem::path &path, const TrustPolicy &policy,
                                     const SignatureVerifier &signature_verifier, const SourcePackLimits &limits) {
        const auto archive = read_canonical_source_pack(path, limits);
        if (!archive) {
            return std::unexpected(archive.error());
        }
        return verify_and_load_source_pack(*archive, policy, signature_verifier, limits);
    }

} // namespace rule_engine::python::packaging
