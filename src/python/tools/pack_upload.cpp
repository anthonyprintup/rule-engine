#include "rule_engine/python/tools/pack_upload.hpp"

#include <cerrno>
#include <charconv>
#include <fstream>
#include <limits>
#include <mutex>
#include <ranges>
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
        constexpr std::uint64_t maximum_upload_bytes = balanced_v1.compile.source_closure_bytes;
        constexpr std::uint64_t maximum_reserved_bytes = 256U * mebibyte;
        constexpr std::size_t maximum_metadata_bytes = 4U * kibibyte;
        constexpr std::string_view metadata_header {"rule-engine.pack-upload.v1"};
        constexpr std::string_view completion_header {"rule-engine.pack-upload-complete.v1"};

        [[nodiscard]] protocol_v2::ProtocolError upload_error(const protocol_v2::ProtocolErrorCode code,
                                                              std::string message) {
            return {.code = code, .message = std::move(message), .byte_offset = 0U};
        }

        [[nodiscard]] bool safe_atom(const std::string_view value) noexcept {
            return !value.empty() && value.size() <= 1'024U &&
                   std::ranges::all_of(
                       value, [](const unsigned char character) { return character >= 0x20U && character <= 0x7eU; });
        }

        [[nodiscard]] std::string upload_key(const std::string_view upload_id) {
            return packaging::sha256_hex(std::as_bytes(std::span {upload_id.data(), upload_id.size()}));
        }

        struct UploadPaths {
            std::filesystem::path metadata;
            std::filesystem::path partial;
            std::filesystem::path complete;
        };

        [[nodiscard]] UploadPaths paths_for(const std::filesystem::path &spool, const std::string_view upload_id) {
            const auto key = upload_key(upload_id);
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
            PackId pack;
            std::uint64_t total_bytes {};
        };

        [[nodiscard]] std::expected<UploadMetadata, protocol_v2::ProtocolError>
        read_metadata(const std::filesystem::path &path) {
            auto text = read_text(path);
            if (!text) {
                return std::unexpected(std::move(text.error()));
            }
            const auto fields = lines(*text);
            if (fields.size() != 3U || fields[0] != metadata_header || !safe_atom(fields[1])) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload metadata is malformed"));
            }
            const auto total = parse_unsigned(fields[2]);
            if (!total || *total == 0U || *total > maximum_upload_bytes) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded, "upload size is invalid"));
            }
            return UploadMetadata {.pack = PackId {std::string {fields[1]}}, .total_bytes = *total};
        }

        [[nodiscard]] std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
        read_completion(const std::filesystem::path &path, const PackId &pack) {
            auto text = read_text(path);
            if (!text) {
                return std::unexpected(std::move(text.error()));
            }
            const auto fields = lines(*text);
            if (fields.size() != 4U || fields[0] != completion_header || fields[1] != pack.value ||
                !fields[2].starts_with("sha256:") || fields[2].size() != 71U) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload completion is malformed"));
            }
            const auto total = parse_unsigned(fields[3]);
            if (!total || *total == 0U || *total > maximum_upload_bytes) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload completion size is invalid"));
            }
            return ResidentPackUploadReceipt {
                .received_bytes = *total,
                .total_bytes = *total,
                .source_digest = SourceDigest {std::string {fields[2]}},
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

    } // namespace

    struct FilesystemResidentPackUploadBackend::Impl {
        std::filesystem::path registry;
        std::filesystem::path spool;
        packaging::TrustPolicy trust;
        std::filesystem::path crypto_library;
        std::mutex mutex;

        [[nodiscard]] std::expected<std::optional<ResidentPackUploadReceipt>, protocol_v2::ProtocolError>
        completed(const UploadPaths &paths, const PackId &pack) const {
            std::error_code filesystem_error;
            const auto exists = std::filesystem::exists(paths.complete, filesystem_error);
            if (filesystem_error) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "upload completion cannot be inspected"));
            }
            if (!exists) {
                return std::optional<ResidentPackUploadReceipt> {};
            }
            auto receipt = read_completion(paths.complete, pack);
            if (!receipt) {
                return std::unexpected(std::move(receipt.error()));
            }
            auto object_path = packaging::content_addressed_source_pack_path(registry, *receipt->source_digest);
            if (!object_path) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed,
                                                    "upload completion has an invalid source digest"));
            }
            packaging::OpenSsl3Ed25519Verifier verifier;
            verifier.crypto_library = crypto_library;
            auto loaded = packaging::read_verify_and_load_source_pack(*object_path, trust, verifier);
            if (!loaded || loaded->manifest.pack != pack || loaded->closure_digest != *receipt->source_digest) {
                return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable,
                                                    "completed source-pack publication is unavailable"));
            }
            return std::optional<ResidentPackUploadReceipt> {std::move(*receipt)};
        }
    };

    FilesystemResidentPackUploadBackend::FilesystemResidentPackUploadBackend(std::unique_ptr<Impl> impl) noexcept:
        impl_ {std::move(impl)} {}
    FilesystemResidentPackUploadBackend::~FilesystemResidentPackUploadBackend() = default;

    std::expected<std::unique_ptr<FilesystemResidentPackUploadBackend>, protocol_v2::ProtocolError>
    FilesystemResidentPackUploadBackend::create(std::filesystem::path registry_root,
                                                packaging::TrustPolicy trust_policy,
                                                std::filesystem::path crypto_library) noexcept {
        std::error_code registry_error;
        const auto registry_status = std::filesystem::symlink_status(registry_root, registry_error);
        std::error_code crypto_error;
        const auto crypto_status = std::filesystem::symlink_status(crypto_library, crypto_error);
        if (registry_root.empty() || !registry_root.is_absolute() || crypto_library.empty() ||
            !crypto_library.is_absolute() || registry_error || crypto_error ||
            !std::filesystem::is_directory(registry_status) || std::filesystem::is_symlink(registry_status) ||
            !std::filesystem::is_regular_file(crypto_status) || std::filesystem::is_symlink(crypto_status)) {
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
        return std::unique_ptr<FilesystemResidentPackUploadBackend> {
            new FilesystemResidentPackUploadBackend {std::move(impl)}};
    }

    std::expected<ResidentPackUploadReceipt, protocol_v2::ProtocolError>
    FilesystemResidentPackUploadBackend::begin(const PackId &pack, const std::string_view upload_id,
                                               const std::uint64_t total_bytes) noexcept {
        if (impl_ == nullptr || !safe_atom(pack.value) || !safe_atom(upload_id) || total_bytes == 0U ||
            total_bytes > maximum_upload_bytes) {
            return std::unexpected(
                upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded, "upload begin is invalid"));
        }
        std::scoped_lock lock {impl_->mutex};
        auto spool_lock = ScopedSpoolLock::acquire(impl_->spool / ".spool.lock");
        if (!spool_lock) {
            return std::unexpected(std::move(spool_lock.error()));
        }
        const auto paths = paths_for(impl_->spool, upload_id);
        auto completed = impl_->completed(paths, pack);
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
            if (!metadata || !size || metadata->pack != pack || metadata->total_bytes != total_bytes ||
                *size > total_bytes) {
                return std::unexpected(
                    upload_error(protocol_v2::ProtocolErrorCode::digest_mismatch, "upload identity was reused"));
            }
            return ResidentPackUploadReceipt {
                .received_bytes = *size, .total_bytes = total_bytes, .source_digest = std::nullopt};
        }
        std::size_t sessions {};
        std::uint64_t reserved {};
        for (const auto &entry : std::filesystem::directory_iterator {impl_->spool, filesystem_error}) {
            if (filesystem_error) {
                break;
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
        }
        if (filesystem_error || sessions >= maximum_upload_sessions ||
            total_bytes > maximum_reserved_bytes - reserved) {
            return std::unexpected(
                upload_error(protocol_v2::ProtocolErrorCode::limit_exceeded, "upload spool capacity is exhausted"));
        }
        const auto metadata_text =
            std::string {metadata_header} + '\n' + pack.value + '\n' + std::to_string(total_bytes) + '\n';
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
    FilesystemResidentPackUploadBackend::append(const PackId &pack, const std::string_view upload_id,
                                                const std::uint64_t offset,
                                                const std::span<const std::byte> payload) noexcept {
        if (impl_ == nullptr || !safe_atom(pack.value) || !safe_atom(upload_id) || payload.empty()) {
            return std::unexpected(upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload chunk is invalid"));
        }
        std::scoped_lock lock {impl_->mutex};
        auto spool_lock = ScopedSpoolLock::acquire(impl_->spool / ".spool.lock");
        if (!spool_lock) {
            return std::unexpected(std::move(spool_lock.error()));
        }
        const auto paths = paths_for(impl_->spool, upload_id);
        auto completed = impl_->completed(paths, pack);
        if (!completed) {
            return std::unexpected(std::move(completed.error()));
        }
        if (*completed) {
            return std::move(**completed);
        }
        auto metadata = read_metadata(paths.metadata);
        auto size = partial_size(paths.partial);
        if (!metadata || !size || metadata->pack != pack || *size > metadata->total_bytes || offset > *size ||
            payload.size() > metadata->total_bytes - offset) {
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
        std::ofstream output {paths.partial, std::ios::binary | std::ios::app};
        output.write(reinterpret_cast<const char *>(payload.data()), static_cast<std::streamsize>(payload.size()));
        output.flush();
        if (!output) {
            return std::unexpected(
                upload_error(protocol_v2::ProtocolErrorCode::dependency_unavailable, "upload chunk cannot be stored"));
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
    FilesystemResidentPackUploadBackend::finalize(const PackId &pack, const std::string_view upload_id) noexcept {
        if (impl_ == nullptr || !safe_atom(pack.value) || !safe_atom(upload_id)) {
            return std::unexpected(
                upload_error(protocol_v2::ProtocolErrorCode::malformed, "upload finalize is invalid"));
        }
        std::scoped_lock lock {impl_->mutex};
        auto spool_lock = ScopedSpoolLock::acquire(impl_->spool / ".spool.lock");
        if (!spool_lock) {
            return std::unexpected(std::move(spool_lock.error()));
        }
        const auto paths = paths_for(impl_->spool, upload_id);
        auto completed = impl_->completed(paths, pack);
        if (!completed) {
            return std::unexpected(std::move(completed.error()));
        }
        if (*completed) {
            return std::move(**completed);
        }
        auto metadata = read_metadata(paths.metadata);
        auto size = partial_size(paths.partial);
        if (!metadata || !size || metadata->pack != pack || *size != metadata->total_bytes) {
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
        const auto completion_text = std::string {completion_header} + '\n' + pack.value + '\n' +
                                     published->closure_digest.value + '\n' + std::to_string(*size) + '\n';
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

} // namespace rule_engine::python::tools
