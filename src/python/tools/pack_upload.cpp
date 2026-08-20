#include "rule_engine/python/tools/pack_upload.hpp"

#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <ranges>
#include <set>
#include <string_view>
#include <system_error>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace rule_engine::python::tools {
    namespace {

        constexpr std::size_t maximum_upload_sessions = 64U;
        constexpr std::size_t maximum_completion_records = 4'096U;
        constexpr std::size_t maximum_tenant_completion_records = 1'024U;
        constexpr std::uint64_t maximum_upload_bytes = balanced_v1.compile.source_closure_bytes;
        constexpr std::uint64_t maximum_reserved_bytes = 256U * mebibyte;
        constexpr std::size_t maximum_metadata_bytes = 4U * kibibyte;
        constexpr std::size_t maximum_maintenance_journal_bytes = 1U * mebibyte;
        constexpr std::size_t maximum_maintenance_audit_records = 32U;
        constexpr std::size_t maximum_maintenance_targets =
            maximum_completion_records * 2U + maximum_upload_sessions * 2U;
        constexpr std::string_view metadata_header {"rule-engine.pack-upload.v2"};
        constexpr std::string_view completion_header {"rule-engine.pack-upload-complete.v2"};
        constexpr std::string_view maintenance_audit_header {"rule-engine.pack-registry-maintenance.v1"};
        constexpr std::string_view maintenance_journal_header {"rule-engine.pack-registry-maintenance-pending.v1"};

        [[nodiscard]] protocol_v2::ProtocolError upload_error(const protocol_v2::ProtocolErrorCode code,
                                                              std::string message) {
            return {.code = code, .message = std::move(message), .byte_offset = 0U};
        }

        [[nodiscard]] bool safe_atom(const std::string_view value) noexcept {
            return !value.empty() && value.size() <= 1'024U &&
                   std::ranges::all_of(
                       value, [](const unsigned char character) { return character >= 0x20U && character <= 0x7eU; });
        }

        [[nodiscard]] bool canonical_source_digest(const std::string_view value) noexcept {
            return value.size() == 71U && value.starts_with("sha256:") &&
                   std::ranges::all_of(value.substr(7U), [](const char character) {
                       return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
                   });
        }

        [[nodiscard]] std::uint64_t current_unix_ms() noexcept {
            const auto now = std::chrono::system_clock::now().time_since_epoch();
            const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
            return milliseconds < 0 ? 0U : static_cast<std::uint64_t>(milliseconds);
        }

        [[nodiscard]] bool elapsed(const std::uint64_t now, const std::uint64_t since,
                                   const std::chrono::milliseconds duration) noexcept {
            return duration.count() > 0 && now >= since && now - since >= static_cast<std::uint64_t>(duration.count());
        }

        [[nodiscard]] std::string upload_key(const TenantId &tenant, const std::string_view upload_id) {
            std::string material = tenant.value;
            material.push_back('\0');
            material.append(upload_id);
            return packaging::sha256_hex(std::as_bytes(std::span {material}));
        }

        struct UploadPaths {
            std::filesystem::path metadata;
            std::filesystem::path partial;
            std::filesystem::path complete;
        };

        [[nodiscard]] UploadPaths paths_for(const std::filesystem::path &spool, const TenantId &tenant,
                                            const std::string_view upload_id) {
            const auto key = upload_key(tenant, upload_id);
            return {
                .metadata = spool / (key + ".meta"),
                .partial = spool / (key + ".part"),
                .complete = spool / (key + ".done"),
            };
        }

        struct ScopedSpoolLock {
#ifdef _WIN32
            HANDLE handle {INVALID_HANDLE_VALUE};
#else
            int descriptor {-1};
#endif

            ScopedSpoolLock() = default;
            ScopedSpoolLock(const ScopedSpoolLock &) = delete;
            ScopedSpoolLock &operator=(const ScopedSpoolLock &) = delete;

            ScopedSpoolLock(ScopedSpoolLock &&other) noexcept {
#ifdef _WIN32
                handle = std::exchange(other.handle, INVALID_HANDLE_VALUE);
#else
                descriptor = std::exchange(other.descriptor, -1);
#endif
            }

            ~ScopedSpoolLock() {
#ifdef _WIN32
                if (handle == INVALID_HANDLE_VALUE) {
                    return;
                }
                OVERLAPPED overlap {};
                static_cast<void>(UnlockFileEx(handle, 0U, MAXDWORD, MAXDWORD, &overlap));
                static_cast<void>(CloseHandle(handle));
#else
                if (descriptor < 0) {
                    return;
                }
                static_cast<void>(::flock(descriptor, LOCK_UN));
                static_cast<void>(::close(descriptor));
#endif
            }

            [[nodiscard]] static std::expected<ScopedSpoolLock, protocol_v2::ProtocolError>
            acquire(const std::filesystem::path &path) {
                ScopedSpoolLock result;
#ifdef _WIN32
                result.handle =
                    CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (result.handle == INVALID_HANDLE_VALUE) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                        "upload spool lock cannot be opened"));
                }
                OVERLAPPED overlap {};
                if (LockFileEx(result.handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0U, MAXDWORD,
                               MAXDWORD, &overlap) == 0) {
                    static_cast<void>(CloseHandle(result.handle));
                    result.handle = INVALID_HANDLE_VALUE;
                    return std::unexpected(
                        upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable, "upload spool is busy"));
                }
#else
                result.descriptor = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
                if (result.descriptor < 0 || ::flock(result.descriptor, LOCK_EX | LOCK_NB) != 0) {
                    if (result.descriptor >= 0) {
                        static_cast<void>(::close(result.descriptor));
                        result.descriptor = -1;
                    }
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                        "upload spool is busy or unavailable"));
                }
#endif
                return result;
            }
        };

        [[nodiscard]] std::expected<std::string, protocol_v2::ProtocolError>
        read_text(const std::filesystem::path &path) {
            std::error_code filesystem_error;
            const auto status = std::filesystem::symlink_status(path, filesystem_error);
            if (filesystem_error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload metadata is unavailable"));
            }
            const auto size = std::filesystem::file_size(path, filesystem_error);
            if (filesystem_error || size == 0U || size > maximum_metadata_bytes) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload metadata is invalid"));
            }
            std::ifstream input {path, std::ios::binary};
            std::string value(static_cast<std::size_t>(size), '\0');
            input.read(value.data(), static_cast<std::streamsize>(value.size()));
            if (!input || input.gcount() != static_cast<std::streamsize>(value.size())) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload metadata cannot be read"));
            }
            return value;
        }

        [[nodiscard]] std::vector<std::string_view> lines(const std::string_view text) {
            std::vector<std::string_view> result;
            std::size_t begin {};
            while (begin < text.size()) {
                const auto end = text.find('\n', begin);
                if (end == std::string_view::npos) {
                    return {};
                }
                result.push_back(text.substr(begin, end - begin));
                begin = end + 1U;
            }
            return result;
        }

        [[nodiscard]] std::optional<std::uint64_t> parse_unsigned(const std::string_view value) {
            std::uint64_t result {};
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
            if (parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size()) {
                return std::nullopt;
            }
            return result;
        }

        struct UploadMetadata {
            TenantId tenant;
            PackId pack;
            std::uint64_t total_bytes {};
            std::uint64_t created_at_unix_ms {};
        };

        [[nodiscard]] std::expected<UploadMetadata, protocol_v2::ProtocolError>
        read_metadata(const std::filesystem::path &path) {
            auto text = read_text(path);
            if (!text) {
                return std::unexpected(std::move(text.error()));
            }
            const auto fields = lines(*text);
            if (fields.size() != 5U || fields[0] != metadata_header || !safe_atom(fields[1]) || !safe_atom(fields[2])) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload metadata is malformed"));
            }
            const auto total = parse_unsigned(fields[3]);
            const auto created = parse_unsigned(fields[4]);
            if (!total || *total == 0U || *total > maximum_upload_bytes || !created || *created == 0U) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded, "upload size is invalid"));
            }
            return UploadMetadata {
                .tenant = TenantId {std::string {fields[1]}},
                .pack = PackId {std::string {fields[2]}},
                .total_bytes = *total,
                .created_at_unix_ms = *created,
            };
        }

        struct CompletionMetadata {
            TenantId tenant;
            PackId pack;
            SourceDigest source_digest;
            std::uint64_t total_bytes {};
            std::uint64_t published_at_unix_ms {};
        };

        struct MaintenanceAudit {
            ResidentPackRegistryObservation aggregate;
            std::vector<std::pair<std::uint64_t, ResidentPackRegistryMaintenanceReceipt>> records;
        };

        enum struct MaintenanceTargetKind : std::uint8_t { partial, metadata, object, completion };

        struct MaintenanceTarget {
            MaintenanceTargetKind kind {MaintenanceTargetKind::partial};
            std::string filename;
            std::uint64_t expected_bytes {};
        };

        struct MaintenanceJournal {
            std::uint64_t base_successful_runs {};
            std::uint64_t at_unix_ms {};
            ResidentPackRegistryMaintenanceReceipt receipt;
            std::vector<MaintenanceTarget> targets;
        };

        [[nodiscard]] bool canonical_hash_filename(const std::string_view filename,
                                                   const std::string_view extension) noexcept {
            if (!filename.ends_with(extension) || filename.size() != 64U + extension.size()) {
                return false;
            }
            return std::ranges::all_of(filename.substr(0U, 64U), [](const char character) {
                return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
            });
        }

        [[nodiscard]] char target_code(const MaintenanceTargetKind kind) noexcept {
            switch (kind) {
                case MaintenanceTargetKind::partial: return 'P';
                case MaintenanceTargetKind::metadata: return 'M';
                case MaintenanceTargetKind::object: return 'O';
                case MaintenanceTargetKind::completion: return 'C';
                default: return '?';
            }
        }

        [[nodiscard]] std::optional<MaintenanceTargetKind> parse_target_code(const char code) noexcept {
            switch (code) {
                case 'P': return MaintenanceTargetKind::partial;
                case 'M': return MaintenanceTargetKind::metadata;
                case 'O': return MaintenanceTargetKind::object;
                case 'C': return MaintenanceTargetKind::completion;
                default: return std::nullopt;
            }
        }

        [[nodiscard]] std::optional<std::pair<std::uint64_t, ResidentPackRegistryMaintenanceReceipt>>
        parse_maintenance_record(const std::string_view line) {
            std::array<std::uint64_t, 5U> values {};
            std::size_t begin {};
            for (std::size_t index = 0U; index < values.size(); ++index) {
                const auto end = index + 1U == values.size() ? line.size() : line.find(':', begin);
                if (end == std::string_view::npos) {
                    return std::nullopt;
                }
                const auto parsed = parse_unsigned(line.substr(begin, end - begin));
                if (!parsed) {
                    return std::nullopt;
                }
                values[index] = *parsed;
                begin = end + 1U;
            }
            if (begin != line.size() + 1U || values[0] == 0U) {
                return std::nullopt;
            }
            return std::pair {
                values[0],
                ResidentPackRegistryMaintenanceReceipt {.expired_partial_sessions = values[1],
                                                        .removed_completion_records = values[2],
                                                        .removed_objects = values[3],
                                                        .reclaimed_bytes = values[4]},
            };
        }

        [[nodiscard]] std::expected<MaintenanceAudit, protocol_v2::ProtocolError>
        read_maintenance_audit(const std::filesystem::path &path) {
            std::error_code filesystem_error;
            const auto status = std::filesystem::symlink_status(path, filesystem_error);
            if (filesystem_error == std::errc::no_such_file_or_directory) {
                return MaintenanceAudit {};
            }
            if (filesystem_error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "registry maintenance audit is unavailable"));
            }
            auto text = read_text(path);
            if (!text) {
                return std::unexpected(std::move(text.error()));
            }
            const auto fields = lines(*text);
            if (fields.size() < 8U || fields[0] != maintenance_audit_header) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::malformed, "registry maintenance audit is malformed"));
            }
            std::array<std::uint64_t, 7U> values {};
            for (std::size_t index = 0U; index < values.size(); ++index) {
                const auto parsed = parse_unsigned(fields[index + 1U]);
                if (!parsed) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed,
                                                        "registry maintenance audit is malformed"));
                }
                values[index] = *parsed;
            }
            if (values[6] > maximum_maintenance_audit_records || fields.size() != 8U + values[6]) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                    "registry maintenance audit exceeds its record bound"));
            }
            MaintenanceAudit result {
                .aggregate = {.successful_maintenance_runs = values[0],
                              .last_maintenance_unix_ms = values[1],
                              .expired_partial_sessions = values[2],
                              .removed_completion_records = values[3],
                              .removed_objects = values[4],
                              .reclaimed_bytes = values[5]},
                .records = {},
            };
            result.records.reserve(static_cast<std::size_t>(values[6]));
            for (std::size_t index = 0U; index < values[6]; ++index) {
                auto record = parse_maintenance_record(fields[8U + index]);
                if (!record) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed,
                                                        "registry maintenance audit record is malformed"));
                }
                result.records.push_back(std::move(*record));
            }
            if ((result.aggregate.successful_maintenance_runs == 0U) != result.records.empty() ||
                (!result.records.empty() && result.records.back().first != result.aggregate.last_maintenance_unix_ms)) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed,
                                                    "registry maintenance audit aggregate is inconsistent"));
            }
            return result;
        }

        [[nodiscard]] std::string serialize_maintenance_journal(const MaintenanceJournal &journal) {
            std::string text =
                std::string {maintenance_journal_header} + '\n' + std::to_string(journal.base_successful_runs) + '\n' +
                std::to_string(journal.at_unix_ms) + '\n' + std::to_string(journal.receipt.expired_partial_sessions) +
                '\n' + std::to_string(journal.receipt.removed_completion_records) + '\n' +
                std::to_string(journal.receipt.removed_objects) + '\n' +
                std::to_string(journal.receipt.reclaimed_bytes) + '\n' + std::to_string(journal.targets.size()) + '\n';
            for (const auto &target : journal.targets) {
                text.push_back(target_code(target.kind));
                text.push_back(':');
                text += std::to_string(target.expected_bytes);
                text.push_back(':');
                text += target.filename;
                text.push_back('\n');
            }
            return text;
        }

        [[nodiscard]] std::expected<std::optional<MaintenanceJournal>, protocol_v2::ProtocolError>
        read_maintenance_journal(const std::filesystem::path &path) {
            std::error_code filesystem_error;
            const auto status = std::filesystem::symlink_status(path, filesystem_error);
            if (filesystem_error == std::errc::no_such_file_or_directory) {
                return std::optional<MaintenanceJournal> {};
            }
            if (filesystem_error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "registry maintenance journal is unavailable"));
            }
            const auto size = std::filesystem::file_size(path, filesystem_error);
            if (filesystem_error || size == 0U || size > maximum_maintenance_journal_bytes) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                    "registry maintenance journal exceeds its byte bound"));
            }
            auto text = read_text(path);
            if (!text) {
                return std::unexpected(std::move(text.error()));
            }
            const auto fields = lines(*text);
            if (fields.size() < 8U || fields[0] != maintenance_journal_header) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed,
                                                    "registry maintenance journal is malformed"));
            }
            std::array<std::uint64_t, 7U> values {};
            for (std::size_t index = 0U; index < values.size(); ++index) {
                const auto parsed = parse_unsigned(fields[index + 1U]);
                if (!parsed) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed,
                                                        "registry maintenance journal is malformed"));
                }
                values[index] = *parsed;
            }
            if (values[1] == 0U || values[6] > maximum_maintenance_targets || fields.size() != 8U + values[6]) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                    "registry maintenance journal exceeds its target bound"));
            }
            MaintenanceJournal journal {
                .base_successful_runs = values[0],
                .at_unix_ms = values[1],
                .receipt = {.expired_partial_sessions = values[2],
                            .removed_completion_records = values[3],
                            .removed_objects = values[4],
                            .reclaimed_bytes = values[5]},
                .targets = {},
            };
            journal.targets.reserve(static_cast<std::size_t>(values[6]));
            for (std::size_t index = 0U; index < values[6]; ++index) {
                const auto field = fields[8U + index];
                if (field.size() < 4U || field[1] != ':') {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed,
                                                        "registry maintenance journal target is malformed"));
                }
                const auto second = field.find(':', 2U);
                const auto kind = parse_target_code(field[0]);
                const auto bytes = second == std::string_view::npos ? std::optional<std::uint64_t> {} :
                                                                      parse_unsigned(field.substr(2U, second - 2U));
                const auto filename =
                    second == std::string_view::npos ? std::string_view {} : field.substr(second + 1U);
                const auto extension = kind == MaintenanceTargetKind::partial  ? ".part" :
                                       kind == MaintenanceTargetKind::metadata ? ".meta" :
                                       kind == MaintenanceTargetKind::object   ? ".rpack" :
                                                                                 ".done";
                if (!kind || !bytes || !canonical_hash_filename(filename, extension) ||
                    ((*kind == MaintenanceTargetKind::metadata || *kind == MaintenanceTargetKind::completion) &&
                     *bytes != 0U)) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed,
                                                        "registry maintenance journal target is malformed"));
                }
                journal.targets.push_back(
                    MaintenanceTarget {.kind = *kind, .filename = std::string {filename}, .expected_bytes = *bytes});
            }
            return std::optional<MaintenanceJournal> {std::move(journal)};
        }

        [[nodiscard]] std::expected<CompletionMetadata, protocol_v2::ProtocolError>
        read_completion(const std::filesystem::path &path) {
            auto text = read_text(path);
            if (!text) {
                return std::unexpected(std::move(text.error()));
            }
            const auto fields = lines(*text);
            if (fields.size() != 6U || fields[0] != completion_header || !safe_atom(fields[1]) ||
                !safe_atom(fields[2]) || !canonical_source_digest(fields[3])) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload completion is malformed"));
            }
            const auto total = parse_unsigned(fields[4]);
            const auto published = parse_unsigned(fields[5]);
            if (!total || *total == 0U || *total > maximum_upload_bytes || !published || *published == 0U) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload completion size is invalid"));
            }
            return CompletionMetadata {
                .tenant = TenantId {std::string {fields[1]}},
                .pack = PackId {std::string {fields[2]}},
                .source_digest = SourceDigest {std::string {fields[3]}},
                .total_bytes = *total,
                .published_at_unix_ms = *published,
            };
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError> write_text(const std::filesystem::path &path,
                                                                                 const std::string_view content) {
#ifdef _WIN32
            const auto handle = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
            if (handle == INVALID_HANDLE_VALUE) {
                const auto code = GetLastError();
                return std::unexpected(upload_error(code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS ?
                                                        protocol_v2::ProtocolErrorCode::digest_mismatch :
                                                        protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS ?
                                                        "upload metadata already exists" :
                                                        "upload metadata cannot be created"));
            }
            std::size_t offset {};
            bool complete {true};
            while (offset < content.size()) {
                const auto remaining = content.size() - offset;
                const auto chunk = static_cast<DWORD>(
                    (std::min) (remaining, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
                DWORD written {};
                if (WriteFile(handle, content.data() + offset, chunk, &written, nullptr) == 0 || written != chunk) {
                    complete = false;
                    break;
                }
                offset += written;
            }
            if (complete && FlushFileBuffers(handle) == 0) {
                complete = false;
            }
            if (CloseHandle(handle) == 0) {
                complete = false;
            }
            if (!complete) {
                std::error_code ignored;
                std::filesystem::remove(path, ignored);
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload metadata cannot be written durably"));
            }
#else
            const auto descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (descriptor < 0) {
                return std::unexpected(upload_error(
                    errno == EEXIST ? protocol_v2::ProtocolErrorCode::digest_mismatch :
                                      protocol_v2::ProtocolErrorCode::dependency_unavailable,
                    errno == EEXIST ? "upload metadata already exists" : "upload metadata cannot be created"));
            }
            std::size_t offset {};
            bool complete {true};
            while (offset < content.size()) {
                const auto written = ::write(descriptor, content.data() + offset, content.size() - offset);
                if (written < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    complete = false;
                    break;
                }
                if (written == 0) {
                    complete = false;
                    break;
                }
                offset += static_cast<std::size_t>(written);
            }
            if (complete && ::fsync(descriptor) != 0) {
                complete = false;
            }
            if (::close(descriptor) != 0) {
                complete = false;
            }
            if (!complete) {
                std::error_code ignored;
                std::filesystem::remove(path, ignored);
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload metadata cannot be written durably"));
            }
#endif
            return {};
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError> replace_text(const std::filesystem::path &path,
                                                                                   const std::string_view content) {
            auto temporary = path;
            temporary += ".new";
            std::error_code ignored;
            std::filesystem::remove(temporary, ignored);
            if (auto written = write_text(temporary, content); !written) {
                return written;
            }
#ifdef _WIN32
            if (MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
#else
            if (::rename(temporary.c_str(), path.c_str()) != 0) {
#endif
                std::filesystem::remove(temporary, ignored);
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "registry maintenance audit cannot be replaced durably"));
            }
#ifndef _WIN32
            const auto directory = ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            const auto directory_synced = directory >= 0 && ::fsync(directory) == 0;
            const auto directory_closed = directory >= 0 && ::close(directory) == 0;
            if (!directory_synced || !directory_closed) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "registry maintenance audit directory cannot be synced"));
            }
#endif
            return {};
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        remove_maintenance_record(const std::filesystem::path &path) {
            std::error_code filesystem_error;
            if (!std::filesystem::remove(path, filesystem_error) || filesystem_error) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "registry maintenance journal cannot be removed"));
            }
#ifndef _WIN32
            const auto directory = ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            const auto directory_synced = directory >= 0 && ::fsync(directory) == 0;
            const auto directory_closed = directory >= 0 && ::close(directory) == 0;
            if (!directory_synced || !directory_closed) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "registry maintenance journal removal cannot be synced"));
            }
#endif
            return {};
        }

        [[nodiscard]] std::expected<std::uint64_t, protocol_v2::ProtocolError>
        partial_size(const std::filesystem::path &path) {
            std::error_code filesystem_error;
            const auto status = std::filesystem::symlink_status(path, filesystem_error);
            if (filesystem_error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload partial file is unavailable"));
            }
            const auto size = std::filesystem::file_size(path, filesystem_error);
            if (filesystem_error) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload partial size is unavailable"));
            }
            return size;
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        create_empty_partial(const std::filesystem::path &path) {
            return write_text(path, {});
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        append_durable(const std::filesystem::path &path, const std::span<const std::byte> payload) {
#ifdef _WIN32
            const auto handle =
                CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
            if (handle == INVALID_HANDLE_VALUE) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload partial cannot be opened"));
            }
            std::size_t offset {};
            bool complete {true};
            while (offset < payload.size()) {
                const auto remaining = payload.size() - offset;
                const auto chunk = static_cast<DWORD>(
                    (std::min) (remaining, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
                DWORD written {};
                if (WriteFile(handle, payload.data() + offset, chunk, &written, nullptr) == 0 || written != chunk) {
                    complete = false;
                    break;
                }
                offset += written;
            }
            if (complete && FlushFileBuffers(handle) == 0) {
                complete = false;
            }
            if (CloseHandle(handle) == 0) {
                complete = false;
            }
            if (!complete) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload chunk cannot be stored durably"));
            }
#else
            const auto descriptor = ::open(path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
            if (descriptor < 0) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload partial cannot be opened"));
            }
            std::size_t offset {};
            bool complete {true};
            while (offset < payload.size()) {
                const auto written = ::write(descriptor, payload.data() + offset, payload.size() - offset);
                if (written < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    complete = false;
                    break;
                }
                if (written == 0) {
                    complete = false;
                    break;
                }
                offset += static_cast<std::size_t>(written);
            }
            if (complete && ::fsync(descriptor) != 0) {
                complete = false;
            }
            if (::close(descriptor) != 0) {
                complete = false;
            }
            if (!complete) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload chunk cannot be stored durably"));
            }
#endif
            return {};
        }

    } // namespace

    struct FilesystemResidentPackUploadBackend::Impl {
        std::filesystem::path registry;
        std::filesystem::path spool;
        packaging::TrustPolicy trust;
        std::filesystem::path crypto_library;
        PackRegistryLimits limits;
        std::mutex mutex;
        void (*maintenance_lock_hook)(void *) noexcept {};
        void *maintenance_lock_hook_context {};
        bool (*maintenance_audit_hook)(void *) noexcept {};
        void *maintenance_audit_hook_context {};

        [[nodiscard]] std::filesystem::path maintenance_audit_path() const { return spool / ".maintenance.audit"; }
        [[nodiscard]] std::filesystem::path maintenance_journal_path() const { return spool / ".maintenance.pending"; }

        [[nodiscard]] std::expected<ResidentPackRegistryObservation, protocol_v2::ProtocolError>
        observe_maintenance() const {
            auto audit = read_maintenance_audit(maintenance_audit_path());
            if (!audit) {
                return std::unexpected(std::move(audit.error()));
            }
            return audit->aggregate;
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        record_maintenance(const std::uint64_t expected_base_runs, const std::uint64_t at_unix_ms,
                           const ResidentPackRegistryMaintenanceReceipt &receipt) const {
            auto audit = read_maintenance_audit(maintenance_audit_path());
            if (!audit) {
                return std::unexpected(std::move(audit.error()));
            }
            const auto same_receipt = [&] {
                if (audit->records.empty()) {
                    return false;
                }
                const auto &[record_at, record] = audit->records.back();
                return record_at == at_unix_ms && record.expired_partial_sessions == receipt.expired_partial_sessions &&
                       record.removed_completion_records == receipt.removed_completion_records &&
                       record.removed_objects == receipt.removed_objects &&
                       record.reclaimed_bytes == receipt.reclaimed_bytes;
            };
            if (expected_base_runs != (std::numeric_limits<std::uint64_t>::max)() &&
                audit->aggregate.successful_maintenance_runs == expected_base_runs + 1U && same_receipt()) {
                return {};
            }
            if (audit->aggregate.successful_maintenance_runs != expected_base_runs) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "registry maintenance journal conflicts with its audit"));
            }
            const auto add = [](const std::uint64_t left, const std::uint64_t right) -> std::optional<std::uint64_t> {
                if (left > (std::numeric_limits<std::uint64_t>::max)() - right) {
                    return std::nullopt;
                }
                return left + right;
            };
            const auto runs = add(audit->aggregate.successful_maintenance_runs, 1U);
            const auto expired = add(audit->aggregate.expired_partial_sessions, receipt.expired_partial_sessions);
            const auto completions =
                add(audit->aggregate.removed_completion_records, receipt.removed_completion_records);
            const auto objects = add(audit->aggregate.removed_objects, receipt.removed_objects);
            const auto bytes = add(audit->aggregate.reclaimed_bytes, receipt.reclaimed_bytes);
            if (!runs || !expired || !completions || !objects || !bytes) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                    "registry maintenance counters overflowed"));
            }
            audit->aggregate = {.successful_maintenance_runs = *runs,
                                .last_maintenance_unix_ms = at_unix_ms,
                                .expired_partial_sessions = *expired,
                                .removed_completion_records = *completions,
                                .removed_objects = *objects,
                                .reclaimed_bytes = *bytes};
            audit->records.emplace_back(at_unix_ms, receipt);
            if (audit->records.size() > maximum_maintenance_audit_records) {
                audit->records.erase(
                    audit->records.begin(),
                    audit->records.begin() +
                        static_cast<std::ptrdiff_t>(audit->records.size() - maximum_maintenance_audit_records));
            }
            std::string text = std::string {maintenance_audit_header} + '\n' + std::to_string(*runs) + '\n' +
                               std::to_string(at_unix_ms) + '\n' + std::to_string(*expired) + '\n' +
                               std::to_string(*completions) + '\n' + std::to_string(*objects) + '\n' +
                               std::to_string(*bytes) + '\n' + std::to_string(audit->records.size()) + '\n';
            for (const auto &[record_at, record] : audit->records) {
                text += std::to_string(record_at) + ':' + std::to_string(record.expired_partial_sessions) + ':' +
                        std::to_string(record.removed_completion_records) + ':' +
                        std::to_string(record.removed_objects) + ':' + std::to_string(record.reclaimed_bytes) + '\n';
            }
            if (text.size() > maximum_metadata_bytes) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                    "registry maintenance audit exceeds its byte bound"));
            }
            return replace_text(maintenance_audit_path(), text);
        }

        [[nodiscard]] std::filesystem::path maintenance_target_path(const MaintenanceTarget &target) const {
            if (target.kind == MaintenanceTargetKind::object) {
                return registry / "sha256" / target.filename;
            }
            return spool / target.filename;
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError>
        apply_maintenance_journal(const MaintenanceJournal &journal) const {
            std::error_code filesystem_error;
            for (const auto &target : journal.targets) {
                const auto path = maintenance_target_path(target);
                const auto status = std::filesystem::symlink_status(path, filesystem_error);
                if (filesystem_error == std::errc::no_such_file_or_directory) {
                    filesystem_error.clear();
                    continue;
                }
                if (filesystem_error || !std::filesystem::is_regular_file(status) ||
                    std::filesystem::is_symlink(status)) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                        "registry maintenance target is unavailable or unsafe"));
                }
                if (target.kind == MaintenanceTargetKind::partial || target.kind == MaintenanceTargetKind::object) {
                    const auto size = std::filesystem::file_size(path, filesystem_error);
                    if (filesystem_error || size != target.expected_bytes) {
                        return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                            "registry maintenance target changed after planning"));
                    }
                }
                if (!std::filesystem::remove(path, filesystem_error) || filesystem_error) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                        "registry maintenance target cannot be removed"));
                }
            }
            return {};
        }

        [[nodiscard]] std::expected<void, protocol_v2::ProtocolError> recover_maintenance() const {
            auto pending = read_maintenance_journal(maintenance_journal_path());
            if (!pending) {
                return std::unexpected(std::move(pending.error()));
            }
            if (!*pending) {
                return {};
            }
            if (auto applied = apply_maintenance_journal(**pending); !applied) {
                return applied;
            }
            if (auto recorded =
                    record_maintenance((*pending)->base_successful_runs, (*pending)->at_unix_ms, (*pending)->receipt);
                !recorded) {
                return recorded;
            }
            return remove_maintenance_record(maintenance_journal_path());
        }

        [[nodiscard]] std::expected<std::optional<ResidentPackUploadReceipt>, protocol_v2::ProtocolError>
        completed(const UploadPaths &paths, const TenantId &tenant, const PackId &pack) const {
            std::error_code filesystem_error;
            const auto exists = std::filesystem::exists(paths.complete, filesystem_error);
            if (filesystem_error) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload completion cannot be inspected"));
            }
            if (!exists) {
                return std::optional<ResidentPackUploadReceipt> {};
            }
            auto completion = read_completion(paths.complete);
            if (!completion) {
                return std::unexpected(std::move(completion.error()));
            }
            if (completion->tenant != tenant || completion->pack != pack) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::digest_mismatch, "upload identity was reused"));
            }
            auto object_path = packaging::content_addressed_source_pack_path(registry, completion->source_digest);
            if (!object_path) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed,
                                                    "upload completion has an invalid source digest"));
            }
            packaging::OpenSsl3Ed25519Verifier verifier;
            verifier.crypto_library = crypto_library;
            auto loaded = packaging::read_verify_and_load_source_pack(*object_path, trust, verifier);
            if (!loaded || loaded->manifest.pack != pack || loaded->closure_digest != completion->source_digest) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "completed source-pack publication is unavailable"));
            }
            return std::optional<ResidentPackUploadReceipt> {ResidentPackUploadReceipt {
                .received_bytes = completion->total_bytes,
                .total_bytes = completion->total_bytes,
                .source_digest = std::move(completion->source_digest),
            }};
        }

        [[nodiscard]] std::expected<std::uint64_t, protocol_v2::ProtocolError> published_bytes() const {
            const auto objects = registry / "sha256";
            std::error_code filesystem_error;
            if (!std::filesystem::exists(objects, filesystem_error)) {
                return 0U;
            }
            std::uint64_t result {};
            for (const auto &entry : std::filesystem::directory_iterator {objects, filesystem_error}) {
                if (filesystem_error) {
                    break;
                }
                const auto status = entry.symlink_status(filesystem_error);
                if (filesystem_error || !std::filesystem::is_regular_file(status) ||
                    std::filesystem::is_symlink(status) || entry.path().extension() != ".rpack" ||
                    !canonical_source_digest("sha256:" + entry.path().stem().string())) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                        "source-pack object inventory is unsafe"));
                }
                const auto size = entry.file_size(filesystem_error);
                if (filesystem_error || size == 0U || size > limits.maximum_published_bytes ||
                    result > limits.maximum_published_bytes - size) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                        "source-pack object capacity is exhausted"));
                }
                result += size;
            }
            if (filesystem_error) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "source-pack object inventory is unavailable"));
            }
            return result;
        }

        [[nodiscard]] std::expected<MaintenanceJournal, protocol_v2::ProtocolError>
        plan_maintenance(const std::span<const SourceDigest> reachable_source_digests,
                         const std::uint64_t now_unix_ms) const {
            auto audit = read_maintenance_audit(maintenance_audit_path());
            if (!audit || audit->aggregate.successful_maintenance_runs == (std::numeric_limits<std::uint64_t>::max)()) {
                return std::unexpected(audit ? upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                            "registry maintenance counters overflowed") :
                                               std::move(audit.error()));
            }
            MaintenanceJournal journal {.base_successful_runs = audit->aggregate.successful_maintenance_runs,
                                        .at_unix_ms = now_unix_ms,
                                        .receipt = {},
                                        .targets = {}};
            const auto add_bytes = [&](const std::uint64_t size) -> bool {
                if (journal.receipt.reclaimed_bytes > (std::numeric_limits<std::uint64_t>::max)() - size) {
                    return false;
                }
                journal.receipt.reclaimed_bytes += size;
                return true;
            };
            std::error_code filesystem_error;
            for (const auto &entry : std::filesystem::directory_iterator {spool, filesystem_error}) {
                if (filesystem_error) {
                    break;
                }
                if (entry.path().extension() != ".meta") {
                    continue;
                }
                auto metadata = read_metadata(entry.path());
                if (!metadata) {
                    return std::unexpected(std::move(metadata.error()));
                }
                if (elapsed(now_unix_ms, metadata->created_at_unix_ms, limits.partial_session_ttl)) {
                    const auto partial = entry.path().parent_path() / (entry.path().stem().string() + ".part");
                    const auto partial_status = std::filesystem::symlink_status(partial, filesystem_error);
                    if (filesystem_error != std::errc::no_such_file_or_directory) {
                        if (filesystem_error || !std::filesystem::is_regular_file(partial_status) ||
                            std::filesystem::is_symlink(partial_status)) {
                            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                                "expired upload partial is unavailable or unsafe"));
                        }
                        const auto size = std::filesystem::file_size(partial, filesystem_error);
                        if (filesystem_error || !add_bytes(size)) {
                            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                                "registry maintenance counters overflowed"));
                        }
                        journal.targets.push_back({.kind = MaintenanceTargetKind::partial,
                                                   .filename = partial.filename().string(),
                                                   .expected_bytes = size});
                    }
                    filesystem_error.clear();
                    journal.targets.push_back({.kind = MaintenanceTargetKind::metadata,
                                               .filename = entry.path().filename().string(),
                                               .expected_bytes = 0U});
                    ++journal.receipt.expired_partial_sessions;
                }
            }
            if (filesystem_error) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload spool cannot be enumerated"));
            }

            std::set<std::string, std::less<>> reachable;
            for (const auto &digest : reachable_source_digests) { reachable.insert(digest.value); }
            struct CompletionGroup {
                std::uint64_t newest_published_at {};
                std::vector<std::filesystem::path> paths;
            };
            std::map<std::string, CompletionGroup, std::less<>> completions;
            for (const auto &entry : std::filesystem::directory_iterator {spool, filesystem_error}) {
                if (filesystem_error) {
                    break;
                }
                if (entry.path().extension() != ".done") {
                    continue;
                }
                auto completion = read_completion(entry.path());
                if (!completion) {
                    return std::unexpected(std::move(completion.error()));
                }
                auto &group = completions[completion->source_digest.value];
                group.newest_published_at = (std::max) (group.newest_published_at, completion->published_at_unix_ms);
                group.paths.push_back(entry.path());
            }
            if (filesystem_error) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "registry completion inventory is unavailable"));
            }

            for (const auto &[digest_value, group] : completions) {
                if (reachable.contains(digest_value) ||
                    !elapsed(now_unix_ms, group.newest_published_at, limits.unreferenced_retention)) {
                    continue;
                }
                auto object = packaging::content_addressed_source_pack_path(registry, SourceDigest {digest_value});
                if (!object) {
                    return std::unexpected(
                        upload_error(protocol_v2::ProtocolErrorCode::malformed, "registry digest is invalid"));
                }
                const auto status = std::filesystem::symlink_status(*object, filesystem_error);
                const auto missing = filesystem_error == std::errc::no_such_file_or_directory;
                if (!missing && (filesystem_error || !std::filesystem::is_regular_file(status) ||
                                 std::filesystem::is_symlink(status))) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                        "unreferenced registry object is unavailable or unsafe"));
                }
                filesystem_error.clear();
                if (!missing) {
                    const auto size = std::filesystem::file_size(*object, filesystem_error);
                    if (filesystem_error || !add_bytes(size)) {
                        return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                            "registry maintenance counters overflowed"));
                    }
                    journal.targets.push_back({.kind = MaintenanceTargetKind::object,
                                               .filename = object->filename().string(),
                                               .expected_bytes = size});
                    ++journal.receipt.removed_objects;
                }
                for (const auto &completion_path : group.paths) {
                    journal.targets.push_back({.kind = MaintenanceTargetKind::completion,
                                               .filename = completion_path.filename().string(),
                                               .expected_bytes = 0U});
                    ++journal.receipt.removed_completion_records;
                }
            }
            if (journal.targets.size() > maximum_maintenance_targets) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                    "registry maintenance plan exceeds its target bound"));
            }
            const auto text = serialize_maintenance_journal(journal);
            if (text.size() > maximum_maintenance_journal_bytes) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                    "registry maintenance journal exceeds its byte bound"));
            }
            return journal;
        }
    };

    FilesystemResidentPackUploadBackend::FilesystemResidentPackUploadBackend(std::unique_ptr<Impl> impl) noexcept:
        impl_ {std::move(impl)} {}
    FilesystemResidentPackUploadBackend::~FilesystemResidentPackUploadBackend() = default;

    void FilesystemResidentPackUploadBackend::set_maintenance_lock_hook_for_testing(void (*hook)(void *) noexcept,
                                                                                    void *context) noexcept {
        if (impl_ == nullptr) {
            return;
        }
        std::scoped_lock lock {impl_->mutex};
        impl_->maintenance_lock_hook = hook;
        impl_->maintenance_lock_hook_context = context;
    }

    void FilesystemResidentPackUploadBackend::set_maintenance_audit_hook_for_testing(bool (*hook)(void *) noexcept,
                                                                                     void *context) noexcept {
        if (impl_ == nullptr) {
            return;
        }
        std::scoped_lock lock {impl_->mutex};
        impl_->maintenance_audit_hook = hook;
        impl_->maintenance_audit_hook_context = context;
    }

    std::expected<std::unique_ptr<FilesystemResidentPackUploadBackend>, protocol_v2::ProtocolError>
    FilesystemResidentPackUploadBackend::create(std::filesystem::path registry_root,
                                                packaging::TrustPolicy trust_policy,
                                                std::filesystem::path crypto_library,
                                                const PackRegistryLimits limits) noexcept {
        std::error_code registry_error;
        const auto registry_status = std::filesystem::symlink_status(registry_root, registry_error);
        std::error_code crypto_error;
        const auto crypto_status = std::filesystem::symlink_status(crypto_library, crypto_error);
        if (registry_root.empty() || !registry_root.is_absolute() || crypto_library.empty() ||
            !crypto_library.is_absolute() || registry_error || crypto_error ||
            !std::filesystem::is_directory(registry_status) || std::filesystem::is_symlink(registry_status) ||
            !std::filesystem::is_regular_file(crypto_status) || std::filesystem::is_symlink(crypto_status) ||
            limits.maximum_published_bytes < maximum_upload_bytes ||
            limits.maximum_published_bytes > maximum_pack_registry_bytes ||
            limits.maximum_tenant_bytes < maximum_upload_bytes ||
            limits.maximum_tenant_bytes > limits.maximum_published_bytes ||
            limits.partial_session_ttl <= std::chrono::milliseconds::zero() ||
            limits.unreferenced_retention <= std::chrono::milliseconds::zero()) {
            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                "pack upload dependencies are unavailable"));
        }
        auto spool = registry_root / ".uploads";
        std::error_code filesystem_error;
        if (!std::filesystem::exists(spool, filesystem_error)) {
            filesystem_error.clear();
            static_cast<void>(std::filesystem::create_directory(spool, filesystem_error));
        }
        const auto spool_status = std::filesystem::symlink_status(spool, filesystem_error);
        if (filesystem_error || !std::filesystem::is_directory(spool_status) ||
            std::filesystem::is_symlink(spool_status)) {
            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                "pack upload spool is unavailable"));
        }
        auto impl = std::make_unique<Impl>();
        impl->registry = std::move(registry_root);
        impl->spool = std::move(spool);
        impl->trust = std::move(trust_policy);
        impl->crypto_library = std::move(crypto_library);
        impl->limits = limits;
        auto spool_lock = ScopedSpoolLock::acquire(impl->spool / ".spool.lock");
        if (!spool_lock) {
            return std::unexpected(std::move(spool_lock.error()));
        }
        if (auto recovered = impl->recover_maintenance(); !recovered) {
            return std::unexpected(std::move(recovered.error()));
        }
        return std::unique_ptr<FilesystemResidentPackUploadBackend> {
            new FilesystemResidentPackUploadBackend {std::move(impl)}};
    }

    std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
    FilesystemResidentPackUploadBackend::begin(const TenantId &tenant, const PackId &pack,
                                               const std::string_view upload_id,
                                               const std::uint64_t total_bytes) noexcept {
        if (impl_ == nullptr || !safe_atom(tenant.value) || !safe_atom(pack.value) || !safe_atom(upload_id) ||
            total_bytes == 0U || total_bytes > maximum_upload_bytes) {
            return std::unexpected(
                upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded, "upload begin is invalid"));
        }
        std::scoped_lock lock {impl_->mutex};
        auto spool_lock = ScopedSpoolLock::acquire(impl_->spool / ".spool.lock");
        if (!spool_lock) {
            return std::unexpected(std::move(spool_lock.error()));
        }
        if (auto recovered = impl_->recover_maintenance(); !recovered) {
            return std::unexpected(std::move(recovered.error()));
        }
        const auto paths = paths_for(impl_->spool, tenant, upload_id);
        auto completed = impl_->completed(paths, tenant, pack);
        if (!completed) {
            return std::unexpected(std::move(completed.error()));
        }
        if (*completed) {
            return std::move(**completed);
        }
        std::error_code filesystem_error;
        if (std::filesystem::exists(paths.metadata, filesystem_error)) {
            auto metadata = read_metadata(paths.metadata);
            auto size = partial_size(paths.partial);
            if (!metadata || !size || metadata->tenant != tenant || metadata->pack != pack ||
                metadata->total_bytes != total_bytes || *size > total_bytes) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::digest_mismatch, "upload identity was reused"));
            }
            return ResidentPackUploadReceipt {
                .received_bytes = *size, .total_bytes = total_bytes, .source_digest = std::nullopt};
        }
        std::size_t sessions {};
        std::size_t completions {};
        std::size_t tenant_completions {};
        std::uint64_t reserved {};
        std::uint64_t tenant_reserved {};
        std::map<std::string, std::uint64_t, std::less<>> tenant_objects;
        for (const auto &entry : std::filesystem::directory_iterator {impl_->spool, filesystem_error}) {
            if (filesystem_error) {
                break;
            }
            if (entry.path().extension() == ".done") {
                auto completion = read_completion(entry.path());
                if (!completion) {
                    return std::unexpected(std::move(completion.error()));
                }
                ++completions;
                if (completion->tenant == tenant) {
                    ++tenant_completions;
                    tenant_objects.try_emplace(completion->source_digest.value, completion->total_bytes);
                }
                continue;
            }
            if (entry.path().extension() != ".meta") {
                continue;
            }
            auto metadata = read_metadata(entry.path());
            if (!metadata || reserved > maximum_reserved_bytes - metadata->total_bytes) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload reservation state is invalid"));
            }
            ++sessions;
            reserved += metadata->total_bytes;
            if (metadata->tenant == tenant) {
                if (tenant_reserved > impl_->limits.maximum_tenant_bytes - metadata->total_bytes) {
                    return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                        "tenant upload reservation is exhausted"));
                }
                tenant_reserved += metadata->total_bytes;
            }
        }
        std::uint64_t tenant_published {};
        for (const auto &[_, size] : tenant_objects) {
            if (tenant_published > impl_->limits.maximum_tenant_bytes - size) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded,
                                                    "tenant source-pack quota is exhausted"));
            }
            tenant_published += size;
        }
        auto published = impl_->published_bytes();
        if (!published) {
            return std::unexpected(std::move(published.error()));
        }
        if (filesystem_error || sessions >= maximum_upload_sessions || completions >= maximum_completion_records ||
            tenant_completions >= maximum_tenant_completion_records ||
            total_bytes > maximum_reserved_bytes - reserved || reserved > impl_->limits.maximum_published_bytes ||
            *published > impl_->limits.maximum_published_bytes - reserved ||
            total_bytes > impl_->limits.maximum_published_bytes - *published - reserved ||
            tenant_reserved > impl_->limits.maximum_tenant_bytes ||
            tenant_published > impl_->limits.maximum_tenant_bytes - tenant_reserved ||
            total_bytes > impl_->limits.maximum_tenant_bytes - tenant_published - tenant_reserved) {
            return std::unexpected(
                upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded, "pack registry quota is exhausted"));
        }
        const auto metadata_text = std::string {metadata_header} + '\n' + tenant.value + '\n' + pack.value + '\n' +
                                   std::to_string(total_bytes) + '\n' + std::to_string(current_unix_ms()) + '\n';
        if (auto written = write_text(paths.metadata, metadata_text); !written) {
            return std::unexpected(std::move(written.error()));
        }
        if (auto created = create_empty_partial(paths.partial); !created) {
            std::filesystem::remove(paths.metadata, filesystem_error);
            return std::unexpected(std::move(created.error()));
        }
        return ResidentPackUploadReceipt {
            .received_bytes = 0U, .total_bytes = total_bytes, .source_digest = std::nullopt};
    }

    std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
    FilesystemResidentPackUploadBackend::append(const TenantId &tenant, const PackId &pack,
                                                const std::string_view upload_id, const std::uint64_t offset,
                                                const std::span<const std::byte> payload) noexcept {
        if (impl_ == nullptr || !safe_atom(tenant.value) || !safe_atom(pack.value) || !safe_atom(upload_id) ||
            payload.empty()) {
            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload chunk is invalid"));
        }
        std::scoped_lock lock {impl_->mutex};
        auto spool_lock = ScopedSpoolLock::acquire(impl_->spool / ".spool.lock");
        if (!spool_lock) {
            return std::unexpected(std::move(spool_lock.error()));
        }
        if (auto recovered = impl_->recover_maintenance(); !recovered) {
            return std::unexpected(std::move(recovered.error()));
        }
        const auto paths = paths_for(impl_->spool, tenant, upload_id);
        auto completed = impl_->completed(paths, tenant, pack);
        if (!completed) {
            return std::unexpected(std::move(completed.error()));
        }
        if (*completed) {
            return std::move(**completed);
        }
        auto metadata = read_metadata(paths.metadata);
        auto size = partial_size(paths.partial);
        if (!metadata || !size || metadata->tenant != tenant || metadata->pack != pack ||
            *size > metadata->total_bytes || offset > *size || payload.size() > metadata->total_bytes - offset) {
            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::digest_mismatch,
                                                "upload chunk does not match current progress"));
        }
        if (offset < *size) {
            if (payload.size() > *size - offset) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::digest_mismatch,
                                                    "upload retry overlaps unacknowledged progress"));
            }
            std::ifstream input {paths.partial, std::ios::binary};
            input.seekg(static_cast<std::streamoff>(offset));
            std::vector<std::byte> existing(payload.size());
            input.read(reinterpret_cast<char *>(existing.data()), static_cast<std::streamsize>(existing.size()));
            if (!input || existing != std::vector<std::byte> {payload.begin(), payload.end()}) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::digest_mismatch,
                                                    "upload retry changed durable bytes"));
            }
            return ResidentPackUploadReceipt {
                .received_bytes = *size, .total_bytes = metadata->total_bytes, .source_digest = std::nullopt};
        }
        if (auto appended = append_durable(paths.partial, payload); !appended) {
            return std::unexpected(std::move(appended.error()));
        }
        auto new_size = partial_size(paths.partial);
        if (!new_size || *new_size != *size + payload.size()) {
            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                "upload progress could not be confirmed"));
        }
        return ResidentPackUploadReceipt {
            .received_bytes = *new_size, .total_bytes = metadata->total_bytes, .source_digest = std::nullopt};
    }

    std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
    FilesystemResidentPackUploadBackend::finalize(const TenantId &tenant, const PackId &pack,
                                                  const std::string_view upload_id) noexcept {
        if (impl_ == nullptr || !safe_atom(tenant.value) || !safe_atom(pack.value) || !safe_atom(upload_id)) {
            return std::unexpected(
                upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload finalize is invalid"));
        }
        std::scoped_lock lock {impl_->mutex};
        auto spool_lock = ScopedSpoolLock::acquire(impl_->spool / ".spool.lock");
        if (!spool_lock) {
            return std::unexpected(std::move(spool_lock.error()));
        }
        if (auto recovered = impl_->recover_maintenance(); !recovered) {
            return std::unexpected(std::move(recovered.error()));
        }
        const auto paths = paths_for(impl_->spool, tenant, upload_id);
        auto completed = impl_->completed(paths, tenant, pack);
        if (!completed) {
            return std::unexpected(std::move(completed.error()));
        }
        if (*completed) {
            return std::move(**completed);
        }
        auto metadata = read_metadata(paths.metadata);
        auto size = partial_size(paths.partial);
        if (!metadata || !size || metadata->tenant != tenant || metadata->pack != pack ||
            *size != metadata->total_bytes) {
            return std::unexpected(
                upload_error(protocol_v2::ProtocolErrorCode::digest_mismatch, "upload is not complete"));
        }
        auto archive = packaging::read_canonical_source_pack(
            paths.partial, packaging::SourcePackLimits {.maximum_archive_bytes = maximum_upload_bytes});
        if (!archive) {
            return std::unexpected(
                upload_error(protocol_v2::ProtocolErrorCode::malformed, "uploaded source pack is not canonical"));
        }
        packaging::OpenSsl3Ed25519Verifier verifier;
        verifier.crypto_library = impl_->crypto_library;
        auto published = packaging::publish_verified_source_pack(
            impl_->registry, upload_id, pack, *archive, impl_->trust, verifier,
            packaging::SourcePackLimits {.maximum_archive_bytes = maximum_upload_bytes});
        if (!published) {
            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::provider_violation,
                                                "uploaded source pack failed provenance or immutable publication"));
        }
        const auto completion_text = std::string {completion_header} + '\n' + tenant.value + '\n' + pack.value + '\n' +
                                     published->closure_digest.value + '\n' + std::to_string(*size) + '\n' +
                                     std::to_string(current_unix_ms()) + '\n';
        if (auto written = write_text(paths.complete, completion_text); !written) {
            return std::unexpected(std::move(written.error()));
        }
        std::error_code ignored;
        std::filesystem::remove(paths.partial, ignored);
        std::filesystem::remove(paths.metadata, ignored);
        return ResidentPackUploadReceipt {
            .received_bytes = *size,
            .total_bytes = *size,
            .source_digest = std::move(published->closure_digest),
        };
    }

    std::expected<ResidentPackRegistryMaintenanceReceipt, protocol_v2::ProtocolError>
    FilesystemResidentPackUploadBackend::maintain(const std::span<const SourceDigest> reachable_source_digests,
                                                  const std::uint64_t now_unix_ms) noexcept {
        if (impl_ == nullptr || now_unix_ms == 0U ||
            std::ranges::any_of(reachable_source_digests,
                                [](const auto &digest) { return !canonical_source_digest(digest.value); })) {
            return std::unexpected(
                upload_error(protocol_v2::ProtocolErrorCode::malformed, "registry maintenance input is invalid"));
        }
        std::scoped_lock lock {impl_->mutex};
        auto spool_lock = ScopedSpoolLock::acquire(impl_->spool / ".spool.lock");
        if (!spool_lock) {
            return std::unexpected(std::move(spool_lock.error()));
        }
        if (impl_->maintenance_lock_hook != nullptr) {
            impl_->maintenance_lock_hook(impl_->maintenance_lock_hook_context);
        }
        if (auto recovered = impl_->recover_maintenance(); !recovered) {
            return std::unexpected(std::move(recovered.error()));
        }
        auto journal = impl_->plan_maintenance(reachable_source_digests, now_unix_ms);
        if (!journal) {
            return std::unexpected(std::move(journal.error()));
        }
        const auto journal_text = serialize_maintenance_journal(*journal);
        if (auto written = replace_text(impl_->maintenance_journal_path(), journal_text); !written) {
            return std::unexpected(std::move(written.error()));
        }
        if (auto applied = impl_->apply_maintenance_journal(*journal); !applied) {
            return std::unexpected(std::move(applied.error()));
        }
        if (impl_->maintenance_audit_hook != nullptr &&
            !impl_->maintenance_audit_hook(impl_->maintenance_audit_hook_context)) {
            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                "registry maintenance audit is unavailable"));
        }
        if (auto recorded =
                impl_->record_maintenance(journal->base_successful_runs, journal->at_unix_ms, journal->receipt);
            !recorded) {
            return std::unexpected(std::move(recorded.error()));
        }
        if (auto removed = remove_maintenance_record(impl_->maintenance_journal_path()); !removed) {
            return std::unexpected(std::move(removed.error()));
        }
        return journal->receipt;
    }

    std::expected<ResidentPackRegistryObservation, protocol_v2::ProtocolError>
    FilesystemResidentPackUploadBackend::observe_maintenance() noexcept {
        if (impl_ == nullptr) {
            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                "registry maintenance observation is unavailable"));
        }
        std::unique_lock lock {impl_->mutex, std::try_to_lock};
        if (!lock.owns_lock()) {
            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                "registry maintenance observation is busy"));
        }
        auto spool_lock = ScopedSpoolLock::acquire(impl_->spool / ".spool.lock");
        if (!spool_lock) {
            return std::unexpected(std::move(spool_lock.error()));
        }
        auto pending = read_maintenance_journal(impl_->maintenance_journal_path());
        if (!pending || *pending) {
            return std::unexpected(pending ? upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                          "registry maintenance recovery is pending") :
                                             std::move(pending.error()));
        }
        return impl_->observe_maintenance();
    }

} // namespace rule_engine::python::tools
