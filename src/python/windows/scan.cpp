#include "rule_engine/python/windows/provider.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <TlHelp32.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::windows {
    namespace {

        constexpr std::uint64_t maximum_provider_scan_bytes = 64U * 1024U * 1024U;

        struct UniqueHandle {
            HANDLE value {nullptr};
            explicit UniqueHandle(const HANDLE handle) noexcept: value {handle} {}
            ~UniqueHandle() noexcept {
                if (value != nullptr && value != INVALID_HANDLE_VALUE) {
                    CloseHandle(value);
                }
            }
            UniqueHandle(const UniqueHandle &) = delete;
            UniqueHandle &operator=(const UniqueHandle &) = delete;
            UniqueHandle(UniqueHandle &&other) noexcept: value {std::exchange(other.value, nullptr)} {}
            UniqueHandle &operator=(UniqueHandle &&) = delete;
        };

        struct ProcessIdentity {
            std::uint32_t pid {};
            std::uint64_t creation_time {};
        };

        struct ModuleRange {
            std::uint64_t base {};
            std::uint64_t size {};
        };

        [[nodiscard]] ProviderError failure(ProviderErrorCode code, std::string operation, std::string message,
                                            const DWORD platform_code = 0U) {
            return ProviderError {.code = code,
                                  .operation = std::move(operation),
                                  .message = std::move(message),
                                  .platform_code = platform_code};
        }

        [[nodiscard]] ProviderError win32_failure(std::string operation, std::string message) {
            const auto code = GetLastError();
            return failure(code == ERROR_ACCESS_DENIED || code == ERROR_PRIVILEGE_NOT_HELD ?
                               ProviderErrorCode::access_denied :
                               ProviderErrorCode::unavailable,
                           std::move(operation), std::move(message), code);
        }

        [[nodiscard]] bool expired(const std::uint64_t deadline) noexcept {
            return deadline != 0U && unix_time_ms() >= deadline;
        }

        [[nodiscard]] std::optional<std::uint64_t> unsigned_identity(const IdentityScalar &value) noexcept {
            if (const auto *number = std::get_if<std::uint64_t>(&value)) {
                return *number;
            }
            if (const auto *number = std::get_if<std::int64_t>(&value); number != nullptr && *number >= 0) {
                return static_cast<std::uint64_t>(*number);
            }
            return std::nullopt;
        }

        [[nodiscard]] const SubjectKey *process_ancestor(const SubjectKey &subject) noexcept {
            auto current = std::addressof(subject);
            while (current != nullptr) {
                if (current->descriptor.value == process_schema) {
                    return current;
                }
                current = current->parent.get();
            }
            return nullptr;
        }

        [[nodiscard]] std::expected<ProcessIdentity, ProviderError> process_identity(const SubjectKey &subject) {
            const auto *process = process_ancestor(subject);
            if (process == nullptr || !process->valid() || process->identity.size() != 2U ||
                process->identity[0].field_id != 1U || process->identity[1].field_id != 2U) {
                return std::unexpected(failure(ProviderErrorCode::invalid_subject, "scan subject",
                                               "subject has no valid Windows process ancestor"));
            }
            const auto pid = unsigned_identity(process->identity[0].value);
            const auto creation = unsigned_identity(process->identity[1].value);
            if (!pid.has_value() || !creation.has_value() || *pid > (std::numeric_limits<std::uint32_t>::max)()) {
                return std::unexpected(
                    failure(ProviderErrorCode::invalid_subject, "scan subject", "process identity fields are invalid"));
            }
            return ProcessIdentity {.pid = static_cast<std::uint32_t>(*pid), .creation_time = *creation};
        }

        [[nodiscard]] std::expected<UniqueHandle, ProviderError>
        open_process(const SubjectKey &subject, const DWORD access, const std::uint64_t deadline) {
            if (expired(deadline)) {
                return std::unexpected(
                    failure(ProviderErrorCode::timed_out, "scan process", "provider deadline expired"));
            }
            auto identity = process_identity(subject);
            if (!identity) {
                return std::unexpected(std::move(identity.error()));
            }
            UniqueHandle process {OpenProcess(access, FALSE, identity->pid)};
            if (process.value == nullptr) {
                return std::unexpected(win32_failure("OpenProcess", "failed to open scan process"));
            }
            FILETIME creation {};
            FILETIME exit {};
            FILETIME kernel {};
            FILETIME user {};
            if (GetProcessTimes(process.value, &creation, &exit, &kernel, &user) == FALSE) {
                return std::unexpected(win32_failure("GetProcessTimes", "failed to verify scan process"));
            }
            const auto observed = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) | creation.dwLowDateTime;
            if (observed != identity->creation_time) {
                return std::unexpected(failure(ProviderErrorCode::subject_changed, "scan process",
                                               "PID creation time changed before scan"));
            }
            return process;
        }

        [[nodiscard]] std::expected<void, ProviderError>
        reverify_process(const HANDLE process, const SubjectKey &subject, const std::uint64_t deadline) {
            if (expired(deadline)) {
                return std::unexpected(
                    failure(ProviderErrorCode::timed_out, "scan process", "provider deadline expired during scan"));
            }
            auto identity = process_identity(subject);
            if (!identity) {
                return std::unexpected(std::move(identity.error()));
            }
            FILETIME creation {};
            FILETIME exit {};
            FILETIME kernel {};
            FILETIME user {};
            if (GetProcessTimes(process, &creation, &exit, &kernel, &user) == FALSE) {
                return std::unexpected(win32_failure("GetProcessTimes", "failed to revalidate scan process"));
            }
            const auto observed = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) | creation.dwLowDateTime;
            if (observed != identity->creation_time) {
                return std::unexpected(failure(ProviderErrorCode::subject_changed, "scan process",
                                               "PID creation time changed during scan"));
            }
            return {};
        }

        [[nodiscard]] std::expected<std::filesystem::path, ProviderError> image_path(const SubjectKey &subject,
                                                                                     const std::uint64_t deadline) {
            if (subject.descriptor.value == image_schema && !subject.identity.empty()) {
                const auto *encoded = std::get_if<UnicodeValue>(&subject.identity[0].value);
                if (encoded == nullptr || encoded->utf8.empty() ||
                    encoded->utf8.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
                    return std::unexpected(
                        failure(ProviderErrorCode::invalid_subject, "file scan", "image path identity is invalid"));
                }
                const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, encoded->utf8.data(),
                                                       static_cast<int>(encoded->utf8.size()), nullptr, 0);
                if (count <= 0) {
                    return std::unexpected(failure(ProviderErrorCode::invalid_subject, "file scan",
                                                   "image path identity is not valid UTF-8"));
                }
                std::wstring wide(static_cast<std::size_t>(count), L'\0');
                if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, encoded->utf8.data(),
                                        static_cast<int>(encoded->utf8.size()), wide.data(), count) != count) {
                    return std::unexpected(
                        failure(ProviderErrorCode::invalid_subject, "file scan", "image path conversion failed"));
                }
                return std::filesystem::path {wide};
            }
            const auto *process = process_ancestor(subject);
            if (process == nullptr) {
                return std::unexpected(
                    failure(ProviderErrorCode::invalid_subject, "file scan", "subject has no process image"));
            }
            return resolve_process_image_path(*process, deadline);
        }

        [[nodiscard]] std::expected<std::vector<std::byte>, ProviderError>
        read_file_range(const SubjectKey &subject, const std::uint64_t begin, const std::uint64_t size,
                        const std::uint64_t deadline) {
            auto path = image_path(subject, deadline);
            if (!path) {
                return std::unexpected(std::move(path.error()));
            }
            const auto *process = process_ancestor(subject);
            if (process == nullptr) {
                return std::unexpected(
                    failure(ProviderErrorCode::invalid_subject, "file scan", "image has no process parent"));
            }
            auto before = image_subject(*process, *path);
            if (!before) {
                return std::unexpected(std::move(before.error()));
            }
            if (subject.descriptor.value == image_schema &&
                canonical_subject_key(subject) != canonical_subject_key(*before)) {
                return std::unexpected(failure(ProviderErrorCode::subject_changed, "file scan",
                                               "image subject no longer matches the current file identity"));
            }
            UniqueHandle file {CreateFileW(path->c_str(), GENERIC_READ,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
            if (file.value == INVALID_HANDLE_VALUE) {
                return std::unexpected(win32_failure("CreateFileW", "failed to open scan image"));
            }
            LARGE_INTEGER file_size {};
            if (GetFileSizeEx(file.value, &file_size) == FALSE || file_size.QuadPart < 0) {
                return std::unexpected(win32_failure("GetFileSizeEx", "failed to size scan image"));
            }
            const auto extent = static_cast<std::uint64_t>(file_size.QuadPart);
            if (begin > extent || size > extent - begin) {
                return std::unexpected(failure(ProviderErrorCode::invalid_request, "file scan",
                                               "requested range is outside the image file"));
            }
            LARGE_INTEGER position {};
            position.QuadPart = static_cast<LONGLONG>(begin);
            if (SetFilePointerEx(file.value, position, nullptr, FILE_BEGIN) == FALSE) {
                return std::unexpected(win32_failure("SetFilePointerEx", "failed to seek scan image"));
            }
            std::vector<std::byte> bytes(static_cast<std::size_t>(size));
            std::size_t offset {};
            while (offset < bytes.size()) {
                if (expired(deadline)) {
                    return std::unexpected(failure(ProviderErrorCode::timed_out, "file scan",
                                                   "provider deadline expired while reading the image"));
                }
                const auto count = std::min<std::size_t>(bytes.size() - offset, 1U * 1024U * 1024U);
                DWORD received {};
                if (ReadFile(file.value, bytes.data() + offset, static_cast<DWORD>(count), &received, nullptr) ==
                        FALSE ||
                    received == 0U) {
                    return std::unexpected(win32_failure("ReadFile", "failed to read scan image"));
                }
                offset += received;
            }
            auto after = image_subject(*process, *path);
            if (!after) {
                return std::unexpected(std::move(after.error()));
            }
            if (canonical_subject_key(*before) != canonical_subject_key(*after)) {
                return std::unexpected(failure(ProviderErrorCode::subject_changed, "file scan",
                                               "image file identity changed during scan"));
            }
            return bytes;
        }

        [[nodiscard]] std::expected<ModuleRange, ProviderError> main_module_range(const SubjectKey &subject,
                                                                                  const std::uint64_t deadline) {
            auto identity = process_identity(subject);
            if (!identity) {
                return std::unexpected(std::move(identity.error()));
            }
            if (expired(deadline)) {
                return std::unexpected(
                    failure(ProviderErrorCode::timed_out, "module scan", "provider deadline expired"));
            }
            UniqueHandle snapshot {CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, identity->pid)};
            if (snapshot.value == INVALID_HANDLE_VALUE) {
                return std::unexpected(
                    win32_failure("CreateToolhelp32Snapshot", "failed to enumerate the main module"));
            }
            MODULEENTRY32W module {};
            module.dwSize = sizeof(module);
            if (Module32FirstW(snapshot.value, &module) == FALSE) {
                return std::unexpected(win32_failure("Module32FirstW", "failed to query the main module"));
            }
            return ModuleRange {.base =
                                    static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(module.modBaseAddr)),
                                .size = module.modBaseSize};
        }

        [[nodiscard]] bool readable(const DWORD protection) noexcept {
            if ((protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0U) {
                return false;
            }
            const auto base = protection & 0xffU;
            return base == PAGE_READONLY || base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
                   base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
        }

        [[nodiscard]] std::uint32_t permissions(const DWORD protection) noexcept {
            std::uint32_t result {};
            if (readable(protection)) {
                result |= optimizer::scan_permission_read;
            }
            const auto base = protection & 0xffU;
            if (base == PAGE_READWRITE || base == PAGE_WRITECOPY || base == PAGE_EXECUTE_READWRITE ||
                base == PAGE_EXECUTE_WRITECOPY) {
                result |= optimizer::scan_permission_write;
            }
            if (base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE ||
                base == PAGE_EXECUTE_WRITECOPY) {
                result |= optimizer::scan_permission_execute;
            }
            return result;
        }

        [[nodiscard]] std::expected<AcquiredScanSpace, ProviderError>
        read_process_range(const SubjectKey &subject, optimizer::ExplicitScanSpace space,
                           const std::uint64_t authorized_begin, const std::uint64_t authorized_size,
                           const std::uint64_t deadline) {
            if (space.begin < authorized_begin ||
                authorized_size > (std::numeric_limits<std::uint64_t>::max)() - authorized_begin ||
                space.size > authorized_begin + authorized_size - space.begin) {
                return std::unexpected(failure(ProviderErrorCode::invalid_request, "memory scan",
                                               "requested range is outside the authorized scan subject"));
            }
            auto process = open_process(subject, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, deadline);
            if (!process) {
                return std::unexpected(std::move(process.error()));
            }
            MEMORY_BASIC_INFORMATION region {};
            if (VirtualQueryEx(process->value, reinterpret_cast<const void *>(static_cast<std::uintptr_t>(space.begin)),
                               &region, sizeof(region)) == 0U) {
                return std::unexpected(win32_failure("VirtualQueryEx", "failed to validate scan memory"));
            }
            const auto region_begin = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(region.BaseAddress));
            if (region.State != MEM_COMMIT || !readable(region.Protect) || space.begin < region_begin ||
                region.RegionSize > (std::numeric_limits<std::uint64_t>::max)() - region_begin ||
                space.size > region_begin + region.RegionSize - space.begin) {
                return std::unexpected(failure(ProviderErrorCode::access_denied, "memory scan",
                                               "requested memory is not one current readable committed region"));
            }
            std::vector<std::byte> bytes(static_cast<std::size_t>(space.size));
            SIZE_T received {};
            if (!bytes.empty() &&
                (ReadProcessMemory(process->value,
                                   reinterpret_cast<const void *>(static_cast<std::uintptr_t>(space.begin)),
                                   bytes.data(), bytes.size(), &received) == FALSE ||
                 received != bytes.size())) {
                return std::unexpected(win32_failure("ReadProcessMemory", "failed to read the complete scan range"));
            }
            if (auto verified = reverify_process(process->value, subject, deadline); !verified) {
                return std::unexpected(std::move(verified.error()));
            }
            space.permissions = permissions(region.Protect);
            return AcquiredScanSpace {
                .descriptor = std::move(space), .bytes = std::move(bytes), .source_origin = space.begin};
        }

        [[nodiscard]] std::expected<std::uint64_t, ProviderError> region_base(const SubjectKey &subject) {
            if (subject.descriptor.value != memory_region_schema || subject.identity.size() != 2U ||
                subject.identity[1].field_id != 2U || subject.parent == nullptr) {
                return std::unexpected(failure(ProviderErrorCode::invalid_subject, "memory scan",
                                               "readable-memory scan requires a memory-region subject"));
            }
            const auto base = unsigned_identity(subject.identity[1].value);
            if (!base.has_value()) {
                return std::unexpected(failure(ProviderErrorCode::invalid_subject, "memory scan",
                                               "memory-region base identity is invalid"));
            }
            return *base;
        }

        [[nodiscard]] std::expected<std::uint64_t, ProviderError> section_rva(const SubjectKey &subject) {
            if (subject.descriptor.value != pe_section_schema || subject.identity.size() != 2U ||
                subject.identity[0].field_id != 1U || subject.parent == nullptr) {
                return std::unexpected(failure(ProviderErrorCode::invalid_subject, "mapped-section scan",
                                               "mapped-section scan requires a PE-section subject"));
            }
            const auto rva = unsigned_identity(subject.identity[0].value);
            if (!rva.has_value()) {
                return std::unexpected(failure(ProviderErrorCode::invalid_subject, "mapped-section scan",
                                               "PE-section RVA identity is invalid"));
            }
            return *rva;
        }

        [[nodiscard]] std::optional<std::uint64_t> fact_unsigned(const FactValue &value) noexcept {
            if (!value.valid()) {
                return std::nullopt;
            }
            const auto *integer = std::get_if<IntegerValue>(&value.node->data);
            if (integer == nullptr || integer->decimal.empty()) {
                return std::nullopt;
            }
            std::uint64_t output {};
            const auto [end, ec] =
                std::from_chars(integer->decimal.data(), integer->decimal.data() + integer->decimal.size(), output);
            if (ec != std::errc {} || end != integer->decimal.data() + integer->decimal.size()) {
                return std::nullopt;
            }
            return output;
        }

        [[nodiscard]] std::expected<std::uint64_t, ProviderError> section_extent(const SubjectKey &subject,
                                                                                 const std::uint64_t deadline) {
            const auto *process = process_ancestor(subject);
            if (process == nullptr) {
                return std::unexpected(failure(ProviderErrorCode::invalid_subject, "mapped-section scan",
                                               "section subject has no process ancestor"));
            }
            auto path = image_path(subject, deadline);
            if (!path) {
                return std::unexpected(std::move(path.error()));
            }
            auto image = inspect_pe_image(*process, *path, 1U, deadline);
            if (!image) {
                return std::unexpected(std::move(image.error()));
            }
            const auto canonical = canonical_subject_key(subject);
            const auto found = std::ranges::find_if(image->sections.items, [&](const SubjectObservation &item) {
                return canonical_subject_key(item.subject) == canonical;
            });
            if (found == image->sections.items.end()) {
                return std::unexpected(failure(ProviderErrorCode::subject_changed, "mapped-section scan",
                                               "section identity no longer exists in the current image"));
            }
            std::optional<std::uint64_t> virtual_size;
            std::optional<std::uint64_t> raw_size;
            for (const auto &field : found->eager_fields) {
                if (field.field_id == 3U) {
                    virtual_size = fact_unsigned(field.value);
                } else if (field.field_id == 5U) {
                    raw_size = fact_unsigned(field.value);
                }
            }
            if (!virtual_size.has_value() || !raw_size.has_value()) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "mapped-section scan", "section size metadata is malformed"));
            }
            const auto extent = std::max(*virtual_size, *raw_size);
            if (extent == 0U) {
                return std::unexpected(failure(ProviderErrorCode::invalid_subject, "mapped-section scan",
                                               "section has no mappable extent"));
            }
            return extent;
        }

        [[nodiscard]] std::optional<unsigned int> hex_digit(const char value) noexcept {
            if (value >= '0' && value <= '9') {
                return static_cast<unsigned int>(value - '0');
            }
            if (value >= 'a' && value <= 'f') {
                return static_cast<unsigned int>(value - 'a' + 10);
            }
            if (value >= 'A' && value <= 'F') {
                return static_cast<unsigned int>(value - 'A' + 10);
            }
            return std::nullopt;
        }

        [[nodiscard]] std::expected<std::vector<std::byte>, ProviderError>
        decode_hex_bytes(const std::string_view encoded) {
            if (encoded.empty() || (encoded.size() % 2U) != 0U) {
                return std::unexpected(failure(ProviderErrorCode::invalid_request, "scan plan",
                                               "bytes pattern must contain an even nonzero number of hex digits"));
            }
            std::vector<std::byte> output;
            output.reserve(encoded.size() / 2U);
            for (std::size_t index = 0; index < encoded.size(); index += 2U) {
                const auto high = hex_digit(encoded[index]);
                const auto low = hex_digit(encoded[index + 1U]);
                if (!high.has_value() || !low.has_value()) {
                    return std::unexpected(failure(ProviderErrorCode::invalid_request, "scan plan",
                                                   "bytes pattern contains a non-hex digit"));
                }
                output.push_back(static_cast<std::byte>((*high << 4U) | *low));
            }
            return output;
        }

        [[nodiscard]] std::expected<optimizer::StaticScanPattern, ProviderError> decode_pattern(const ScanPlan &plan) {
            const auto encoded = std::string_view {plan.encoded_pattern};
            if (encoded.starts_with("bytes:")) {
                auto bytes = decode_hex_bytes(encoded.substr(6U));
                if (!bytes) {
                    return std::unexpected(std::move(bytes.error()));
                }
                auto pattern = optimizer::make_byte_pattern(plan.plan_id, *bytes);
                if (!pattern) {
                    return std::unexpected(
                        failure(ProviderErrorCode::invalid_request, "scan plan", pattern.error().message));
                }
                return std::move(*pattern);
            }
            if (encoded.starts_with("masked:")) {
                auto pattern = optimizer::make_masked_pattern(plan.plan_id, encoded.substr(7U));
                if (!pattern) {
                    return std::unexpected(
                        failure(ProviderErrorCode::invalid_request, "scan plan", pattern.error().message));
                }
                return std::move(*pattern);
            }
            if (encoded.starts_with("utf8:")) {
                auto pattern =
                    optimizer::make_text_pattern(plan.plan_id, encoded.substr(5U), optimizer::TextEncoding::utf8);
                if (!pattern) {
                    return std::unexpected(
                        failure(ProviderErrorCode::invalid_request, "scan plan", pattern.error().message));
                }
                return std::move(*pattern);
            }
            if (encoded.starts_with("utf16le:")) {
                auto pattern = optimizer::make_text_pattern(plan.plan_id, encoded.substr(8U),
                                                            optimizer::TextEncoding::utf16_little_endian);
                if (!pattern) {
                    return std::unexpected(
                        failure(ProviderErrorCode::invalid_request, "scan plan", pattern.error().message));
                }
                return std::move(*pattern);
            }
            if (encoded.starts_with("re2:")) {
                auto pattern = optimizer::make_re2_pattern(plan.plan_id, encoded.substr(4U));
                if (!pattern) {
                    return std::unexpected(
                        failure(ProviderErrorCode::invalid_request, "scan plan", pattern.error().message));
                }
                return std::move(*pattern);
            }
            return std::unexpected(failure(ProviderErrorCode::invalid_request, "scan plan",
                                           "encoded pattern must use bytes:, masked:, utf8:, utf16le:, or re2:"));
        }

        [[nodiscard]] optimizer::ScanSpaceKind space_kind(const std::string_view kind) {
            if (kind == "process.image.file") {
                return optimizer::ScanSpaceKind::image_file;
            }
            if (kind == "process.image.mapped") {
                return optimizer::ScanSpaceKind::mapped_image;
            }
            if (kind == "process.image.mapped_section") {
                return optimizer::ScanSpaceKind::mapped_section;
            }
            return optimizer::ScanSpaceKind::readable_memory;
        }

        [[nodiscard]] bool known_space_kind(const std::string_view kind) noexcept {
            return kind == "process.image.file" || kind == "process.image.mapped" ||
                   kind == "process.image.mapped_section" || kind == "process.memory";
        }

        template<typename ContractSpace, typename ProviderSpace>
        void copy_space_metadata(const ContractSpace &source, ProviderSpace &target) {
            if constexpr (requires { source.identity; }) {
                if (!source.identity.empty()) {
                    target.identity = source.identity;
                }
            }
            if constexpr (requires {
                              source.label;
                              target.label;
                          }) {
                target.label = source.label;
            }
            if constexpr (requires {
                              source.subject_generation;
                              target.subject_generation;
                          }) {
                target.subject_generation = source.subject_generation;
            }
        }

        template<typename ContractPlan, typename ProviderPlan>
        void copy_plan_metadata(const ContractPlan &source, ProviderPlan &target) {
            if constexpr (requires {
                              source.context_bytes_before;
                              target.context_bytes_before;
                          }) {
                target.context_bytes_before = source.context_bytes_before;
            }
            if constexpr (requires {
                              source.context_bytes_after;
                              target.context_bytes_after;
                          }) {
                target.context_bytes_after = source.context_bytes_after;
            }
            if constexpr (requires {
                              source.result_mode;
                              target.result_mode;
                          }) {
                target.result_mode = source.result_mode;
            }
        }

        template<typename ContractPlan> [[nodiscard]] std::string contract_pattern_id(const ContractPlan &plan) {
            if constexpr (requires { plan.pattern_ids; }) {
                if (!plan.pattern_ids.empty()) {
                    return plan.pattern_ids.front();
                }
            }
            return plan.plan_id;
        }

        template<typename ContractResponse, typename ContractPlan>
        void copy_response_mode(ContractResponse &response, const ContractPlan &plan) {
            if constexpr (requires {
                              response.mode;
                              plan.result_mode;
                          }) {
                response.mode = plan.result_mode;
            }
        }

        template<typename ContractMatch, typename TypedMatch, typename ProviderSpace>
        [[nodiscard]] ContractMatch contract_match(const TypedMatch &match, const ProviderSpace &space) {
            ContractMatch output {};
            output.offset = match.offset;
            output.length = match.length;
            if constexpr (requires {
                              output.pattern_id;
                              match.pattern_id;
                          }) {
                output.pattern_id = match.pattern_id;
            }
            if constexpr (requires {
                              output.scan_space_id;
                              match.scan_space_identity;
                          }) {
                output.scan_space_id = match.scan_space_identity;
            }
            if constexpr (requires {
                              output.absolute_address;
                              match.absolute_address;
                          }) {
                output.absolute_address = match.absolute_address;
            }
            if constexpr (requires {
                              output.permission_snapshot;
                              match.permissions;
                          }) {
                output.permission_snapshot = match.permissions;
            }
            if constexpr (requires {
                              output.matched_bytes;
                              match.matched_bytes;
                          }) {
                output.matched_bytes = match.matched_bytes;
            }
            if constexpr (requires {
                              output.before_bytes;
                              match.context_before;
                          }) {
                output.before_bytes = match.context_before;
            }
            if constexpr (requires {
                              output.after_bytes;
                              match.context_after;
                          }) {
                output.after_bytes = match.context_after;
            }
            if constexpr (requires {
                              output.label;
                              match.label;
                          }) {
                output.label = match.label;
            } else if constexpr (requires {
                                     output.label;
                                     space.label;
                                 }) {
                output.label = space.label;
            }
            if constexpr (requires {
                              output.subject_generation;
                              match.subject_generation;
                          }) {
                output.subject_generation = match.subject_generation;
            } else if constexpr (requires {
                                     output.subject_generation;
                                     space.subject_generation;
                                 }) {
                output.subject_generation = space.subject_generation;
            }
            return output;
        }

    } // namespace

    std::expected<AcquiredScanSpace, ProviderError> acquire_scan_space(const SubjectKey &subject,
                                                                       const optimizer::ExplicitScanSpace &space,
                                                                       const std::uint64_t deadline_unix_ms) {
        if (!subject.valid() || space.identity.empty() || space.size == 0U ||
            space.size > maximum_provider_scan_bytes ||
            space.begin > (std::numeric_limits<std::uint64_t>::max)() - space.size) {
            return std::unexpected(failure(ProviderErrorCode::invalid_request, "scan acquisition",
                                           "scan subject, identity, range, or size is invalid"));
        }
        if (expired(deadline_unix_ms)) {
            return std::unexpected(
                failure(ProviderErrorCode::timed_out, "scan acquisition", "provider deadline expired"));
        }

        if (space.kind == optimizer::ScanSpaceKind::image_file) {
            auto bytes = read_file_range(subject, space.begin, space.size, deadline_unix_ms);
            if (!bytes) {
                return std::unexpected(std::move(bytes.error()));
            }
            auto descriptor = space;
            descriptor.permissions = optimizer::scan_permission_read;
            return AcquiredScanSpace {
                .descriptor = std::move(descriptor), .bytes = std::move(*bytes), .source_origin = space.begin};
        }

        if (space.kind == optimizer::ScanSpaceKind::mapped_image ||
            space.kind == optimizer::ScanSpaceKind::mapped_section) {
            auto module = main_module_range(subject, deadline_unix_ms);
            if (!module) {
                return std::unexpected(std::move(module.error()));
            }
            if (space.kind == optimizer::ScanSpaceKind::mapped_image) {
                return read_process_range(subject, space, module->base, module->size, deadline_unix_ms);
            }
            auto rva = section_rva(subject);
            if (!rva) {
                return std::unexpected(std::move(rva.error()));
            }
            if (*rva > (std::numeric_limits<std::uint64_t>::max)() - module->base || *rva >= module->size) {
                return std::unexpected(failure(ProviderErrorCode::invalid_subject, "mapped-section scan",
                                               "section RVA is outside the mapped image"));
            }
            auto extent = section_extent(subject, deadline_unix_ms);
            if (!extent) {
                return std::unexpected(std::move(extent.error()));
            }
            const auto begin = module->base + *rva;
            return read_process_range(subject, space, begin, std::min(*extent, module->size - *rva), deadline_unix_ms);
        }

        auto base = region_base(subject);
        if (!base) {
            return std::unexpected(std::move(base.error()));
        }
        auto process = open_process(subject, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, deadline_unix_ms);
        if (!process) {
            return std::unexpected(std::move(process.error()));
        }
        MEMORY_BASIC_INFORMATION region {};
        if (VirtualQueryEx(process->value, reinterpret_cast<const void *>(static_cast<std::uintptr_t>(*base)), &region,
                           sizeof(region)) == 0U ||
            reinterpret_cast<std::uintptr_t>(region.BaseAddress) != *base) {
            return std::unexpected(win32_failure("VirtualQueryEx", "memory-region subject is no longer present"));
        }
        return read_process_range(subject, space, *base, static_cast<std::uint64_t>(region.RegionSize),
                                  deadline_unix_ms);
    }

    std::expected<optimizer::MatchSet, ProviderError> execute_scan(const optimizer::ProviderScanRequest &request) {
        if (request.request_id.empty() || !request.subject.valid() || request.plan.plan_id.empty() ||
            request.plan.patterns.empty() || request.plan.maximum_bytes == 0U || request.plan.maximum_matches == 0U ||
            request.plan.maximum_bytes > request.space.size) {
            return std::unexpected(
                failure(ProviderErrorCode::invalid_request, "scan dispatch", "provider scan request is invalid"));
        }
        auto acquired = acquire_scan_space(request.subject, request.space, request.deadline_unix_ms);
        if (!acquired) {
            return std::unexpected(std::move(acquired.error()));
        }
        auto matches =
            optimizer::execute_scan(acquired->descriptor, request.plan, acquired->bytes, acquired->source_origin);
        if (!matches) {
            auto code = ProviderErrorCode::invalid_request;
            if (matches.error().code == optimizer::ScanErrorCode::byte_budget_exceeded ||
                matches.error().code == optimizer::ScanErrorCode::match_budget_exceeded) {
                code = ProviderErrorCode::result_limit;
            } else if (matches.error().code == optimizer::ScanErrorCode::arithmetic_overflow) {
                code = ProviderErrorCode::arithmetic_overflow;
            }
            return std::unexpected(failure(code, "scan execution", matches.error().message));
        }
        if (expired(request.deadline_unix_ms)) {
            return std::unexpected(
                failure(ProviderErrorCode::timed_out, "scan execution", "provider deadline expired during matching"));
        }
        return std::move(*matches);
    }

    ScanResponse dispatch_scan(const ScanRequest &request) {
        ScanResponse response {.request_id = request.request_id,
                               .subject = request.subject,
                               .status = FactTerminalStatus::failed,
                               .matches = {},
                               .truncated = false,
                               .diagnostic = std::nullopt};
        if (request.request_id.empty() || !request.subject.valid() || !known_space_kind(request.space.kind) ||
            request.space.size == 0U || request.plan.plan_id.empty() || request.plan.maximum_bytes == 0U ||
            request.plan.maximum_matches == 0U || request.plan.maximum_bytes > request.space.size) {
            const auto error = failure(ProviderErrorCode::invalid_request, "scan dispatch",
                                       "scan request has an invalid subject, space, bounds, or plan");
            response.status = terminal_status(error.code);
            response.diagnostic = provider_diagnostic(error);
            return response;
        }
        auto provider_plan = request.plan;
        provider_plan.plan_id = contract_pattern_id(request.plan);
        auto pattern = decode_pattern(provider_plan);
        if (!pattern) {
            response.status = terminal_status(pattern.error().code);
            response.diagnostic = provider_diagnostic(pattern.error());
            return response;
        }
        optimizer::ExplicitScanSpace provider_space {};
        provider_space.identity = request.space.kind;
        provider_space.kind = space_kind(request.space.kind);
        provider_space.begin = request.space.begin;
        provider_space.size = request.space.size;
        provider_space.permissions = request.space.permissions;
        provider_space.subject_generation = 0U;
        copy_space_metadata(request.space, provider_space);
        auto typed_plan = optimizer::TypedScanPlan {.plan_id = request.plan.plan_id,
                                                    .patterns = {std::move(*pattern)},
                                                    .maximum_bytes = request.plan.maximum_bytes,
                                                    .maximum_matches = request.plan.maximum_matches,
                                                    .context_bytes_before = 0U,
                                                    .context_bytes_after = 0U};
        copy_plan_metadata(request.plan, typed_plan);
        optimizer::ProviderScanRequest provider {
            .request_id = request.request_id,
            .subject = request.subject,
            .space = std::move(provider_space),
            .plan = std::move(typed_plan),
            .deadline_unix_ms = request.deadline_unix_ms,
        };
        copy_response_mode(response, request.plan);
        auto matches = execute_scan(provider);
        if (!matches) {
            response.status = terminal_status(matches.error().code);
            response.diagnostic = provider_diagnostic(matches.error());
            return response;
        }
        response.matches.reserve(matches->matches.size());
        for (const auto &match : matches->matches) {
            response.matches.push_back(contract_match<ScanMatch>(match, provider.space));
        }
        response.status = FactTerminalStatus::value;
        return response;
    }

} // namespace rule_engine::python::windows
