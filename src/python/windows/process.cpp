#include "rule_engine/python/windows/provider.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <SoftPub.h>
#include <TlHelp32.h>
#include <WinTrust.h>
#include <sddl.h>
#include <wincrypt.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rule_engine::python::windows {
    namespace {

        constexpr LONG status_info_length_mismatch = static_cast<LONG>(0xc0000004UL);
        constexpr ULONG system_process_information = 5U;
        constexpr ULONG process_command_line_information = 60U;
        constexpr std::size_t maximum_native_process_snapshot_bytes = 64U * 1024U * 1024U;
        constexpr std::size_t maximum_process_count = 100'000U;
        constexpr std::size_t maximum_memory_region_count = 100'000U;
        constexpr std::size_t maximum_module_count = 16'384U;

        using NtQuerySystemInformationFn = LONG(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
        using NtQueryInformationProcessFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        using IsWow64Process2Fn = BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *);

        struct NativeSystemProcessInformation {
            ULONG next_entry_offset {};
            ULONG number_of_threads {};
            LARGE_INTEGER working_set_private_size {};
            ULONG hard_fault_count {};
            ULONG number_of_threads_high_watermark {};
            ULONGLONG cycle_time {};
            LARGE_INTEGER create_time {};
            LARGE_INTEGER user_time {};
            LARGE_INTEGER kernel_time {};
            UNICODE_STRING image_name {};
            KPRIORITY base_priority {};
            HANDLE unique_process_id {};
            HANDLE inherited_from_unique_process_id {};
            ULONG handle_count {};
            ULONG session_id {};
        };

        static_assert(offsetof(NativeSystemProcessInformation, image_name) ==
                      offsetof(SYSTEM_PROCESS_INFORMATION, ImageName));
        static_assert(offsetof(NativeSystemProcessInformation, unique_process_id) ==
                      offsetof(SYSTEM_PROCESS_INFORMATION, UniqueProcessId));
        static_assert(offsetof(NativeSystemProcessInformation, handle_count) ==
                      offsetof(SYSTEM_PROCESS_INFORMATION, HandleCount));

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

        struct LocalAllocation {
            HLOCAL value {};
            explicit LocalAllocation(const HLOCAL allocation) noexcept: value {allocation} {}
            ~LocalAllocation() noexcept {
                if (value != nullptr) {
                    LocalFree(value);
                }
            }
            LocalAllocation(const LocalAllocation &) = delete;
            LocalAllocation &operator=(const LocalAllocation &) = delete;
            LocalAllocation(LocalAllocation &&) = delete;
            LocalAllocation &operator=(LocalAllocation &&) = delete;
        };

        struct CertStoreHandle {
            HCERTSTORE value {};
            CertStoreHandle() noexcept = default;
            ~CertStoreHandle() noexcept {
                if (value != nullptr) {
                    CertCloseStore(value, 0);
                }
            }
            CertStoreHandle(const CertStoreHandle &) = delete;
            CertStoreHandle &operator=(const CertStoreHandle &) = delete;
            CertStoreHandle(CertStoreHandle &&) = delete;
            CertStoreHandle &operator=(CertStoreHandle &&) = delete;
        };

        struct CryptMessageHandle {
            HCRYPTMSG value {};
            CryptMessageHandle() noexcept = default;
            ~CryptMessageHandle() noexcept {
                if (value != nullptr) {
                    CryptMsgClose(value);
                }
            }
            CryptMessageHandle(const CryptMessageHandle &) = delete;
            CryptMessageHandle &operator=(const CryptMessageHandle &) = delete;
            CryptMessageHandle(CryptMessageHandle &&) = delete;
            CryptMessageHandle &operator=(CryptMessageHandle &&) = delete;
        };

        struct CertificateContext {
            PCCERT_CONTEXT value {};
            CertificateContext() noexcept = default;
            ~CertificateContext() noexcept {
                if (value != nullptr) {
                    CertFreeCertificateContext(value);
                }
            }
            CertificateContext(const CertificateContext &) = delete;
            CertificateContext &operator=(const CertificateContext &) = delete;
            CertificateContext(CertificateContext &&other) noexcept: value {std::exchange(other.value, nullptr)} {}
            CertificateContext &operator=(CertificateContext &&) = delete;
        };

        struct ProcessEntry {
            std::uint32_t pid {};
            std::uint32_t parent_pid {};
            std::uint32_t thread_count {};
            std::uint32_t handle_count {};
            std::uint32_t session_id {};
            std::uint64_t creation_time {};
            std::string name;
        };

        struct ProcessIdentity {
            std::uint32_t pid {};
            std::uint64_t creation_time {};
        };

        [[nodiscard]] ProviderError error(ProviderErrorCode code, std::string operation, std::string message,
                                          const DWORD platform_code = 0U) {
            return ProviderError {.code = code,
                                  .operation = std::move(operation),
                                  .message = std::move(message),
                                  .platform_code = platform_code};
        }

        [[nodiscard]] ProviderError win32_error(std::string operation, std::string message,
                                                const DWORD code = GetLastError()) {
            auto category = ProviderErrorCode::unavailable;
            if (code == ERROR_ACCESS_DENIED || code == ERROR_PRIVILEGE_NOT_HELD) {
                category = ProviderErrorCode::access_denied;
            } else if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND ||
                       code == ERROR_INVALID_PARAMETER || code == ERROR_NOT_FOUND) {
                category = ProviderErrorCode::not_found;
            } else if (code == ERROR_NOT_SUPPORTED || code == ERROR_CALL_NOT_IMPLEMENTED) {
                category = ProviderErrorCode::unsupported;
            }
            return error(category, std::move(operation), std::move(message), code);
        }

        [[nodiscard]] bool expired(const std::uint64_t deadline_unix_ms) noexcept {
            return deadline_unix_ms != 0U && unix_time_ms() >= deadline_unix_ms;
        }

        [[nodiscard]] std::expected<void, ProviderError> check_deadline(const std::uint64_t deadline_unix_ms,
                                                                        std::string operation) {
            if (!expired(deadline_unix_ms)) {
                return {};
            }
            return std::unexpected(
                error(ProviderErrorCode::timed_out, std::move(operation), "provider deadline expired"));
        }

        [[nodiscard]] std::expected<void, ProviderError>
        check_inventory_bounds(const std::uint64_t deadline_unix_ms, const std::stop_token cancellation) {
            if (cancellation.stop_requested()) {
                return std::unexpected(error(ProviderErrorCode::canceled, "process inventory",
                                             "process inventory enumeration was canceled"));
            }
            return check_deadline(deadline_unix_ms, "process inventory");
        }

        [[nodiscard]] std::optional<std::string> utf8(const std::wstring_view value) {
            if (value.empty()) {
                return std::string {};
            }
            if (value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
                return std::nullopt;
            }
            const auto count = static_cast<int>(value.size());
            const auto required =
                WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), count, nullptr, 0, nullptr, nullptr);
            if (required <= 0) {
                return std::nullopt;
            }
            std::string output(static_cast<std::size_t>(required), '\0');
            if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), count, output.data(), required,
                                    nullptr, nullptr) != required) {
                return std::nullopt;
            }
            return output;
        }

        template<typename Function> [[nodiscard]] Function load_ntdll_function(const char *name) noexcept {
            const auto module = GetModuleHandleW(L"ntdll.dll");
            if (module == nullptr) {
                return nullptr;
            }
            const auto address = GetProcAddress(module, name);
            Function function {};
            static_assert(sizeof(function) == sizeof(address));
            std::memcpy(&function, &address, sizeof(function));
            return function;
        }

        [[nodiscard]] IsWow64Process2Fn is_wow64_process2() noexcept {
            const auto module = GetModuleHandleW(L"kernel32.dll");
            if (module == nullptr) {
                return nullptr;
            }
            const auto address = GetProcAddress(module, "IsWow64Process2");
            IsWow64Process2Fn function {};
            static_assert(sizeof(function) == sizeof(address));
            std::memcpy(&function, &address, sizeof(function));
            return function;
        }

        [[nodiscard]] std::expected<std::vector<ProcessEntry>, ProviderError>
        query_process_entries(const std::uint64_t deadline_unix_ms, const std::stop_token cancellation = {}) {
            if (auto bound = check_inventory_bounds(deadline_unix_ms, cancellation); !bound) {
                return std::unexpected(std::move(bound.error()));
            }

            const auto query = load_ntdll_function<NtQuerySystemInformationFn>("NtQuerySystemInformation");
            if (query == nullptr) {
                return std::unexpected(error(ProviderErrorCode::unsupported, "process inventory",
                                             "NtQuerySystemInformation is unavailable"));
            }

            std::vector<std::byte> buffer(1U * 1024U * 1024U);
            for (;;) {
                ULONG needed {};
                const auto length = static_cast<ULONG>(buffer.size());
                const auto status = query(system_process_information, buffer.data(), length, &needed);
                if (auto bound = check_inventory_bounds(deadline_unix_ms, cancellation); !bound) {
                    return std::unexpected(std::move(bound.error()));
                }
                if (status >= 0) {
                    break;
                }
                if (status != status_info_length_mismatch) {
                    return std::unexpected(error(ProviderErrorCode::unavailable, "process inventory",
                                                 "NtQuerySystemInformation failed", static_cast<DWORD>(status)));
                }
                const auto requested = std::max<std::size_t>(buffer.size() * 2U, needed);
                if (requested > maximum_native_process_snapshot_bytes || requested <= buffer.size()) {
                    return std::unexpected(error(ProviderErrorCode::result_limit, "process inventory",
                                                 "native process snapshot exceeds its byte limit"));
                }
                buffer.resize(requested);
            }

            std::vector<ProcessEntry> entries;
            std::size_t offset {};
            for (;;) {
                if (auto bound = check_inventory_bounds(deadline_unix_ms, cancellation); !bound) {
                    return std::unexpected(std::move(bound.error()));
                }
                if (offset > buffer.size() || buffer.size() - offset < sizeof(NativeSystemProcessInformation)) {
                    return std::unexpected(error(ProviderErrorCode::malformed, "process inventory",
                                                 "native process snapshot is truncated"));
                }
                const auto *entry = reinterpret_cast<const NativeSystemProcessInformation *>(buffer.data() + offset);
                const auto raw_pid = reinterpret_cast<std::uintptr_t>(entry->unique_process_id);
                const auto raw_parent = reinterpret_cast<std::uintptr_t>(entry->inherited_from_unique_process_id);
                if (raw_pid > (std::numeric_limits<std::uint32_t>::max)() ||
                    raw_parent > (std::numeric_limits<std::uint32_t>::max)()) {
                    return std::unexpected(error(ProviderErrorCode::malformed, "process inventory",
                                                 "native process ID exceeds the supported width"));
                }

                std::string name;
                if (entry->image_name.Length != 0U) {
                    if (entry->image_name.Buffer == nullptr || (entry->image_name.Length % sizeof(wchar_t)) != 0U) {
                        return std::unexpected(error(ProviderErrorCode::malformed, "process inventory",
                                                     "native process name is malformed"));
                    }
                    const auto wide_length = entry->image_name.Length / sizeof(wchar_t);
                    auto encoded = utf8(std::wstring_view {entry->image_name.Buffer, wide_length});
                    if (!encoded.has_value()) {
                        return std::unexpected(error(ProviderErrorCode::malformed, "process inventory",
                                                     "native process name is not valid Unicode"));
                    }
                    name = std::move(*encoded);
                } else if (raw_pid == 0U) {
                    name = "System Idle Process";
                } else {
                    name = "System";
                }

                entries.push_back(ProcessEntry {
                    .pid = static_cast<std::uint32_t>(raw_pid),
                    .parent_pid = static_cast<std::uint32_t>(raw_parent),
                    .thread_count = entry->number_of_threads,
                    .handle_count = entry->handle_count,
                    .session_id = entry->session_id,
                    .creation_time = static_cast<std::uint64_t>(entry->create_time.QuadPart),
                    .name = std::move(name),
                });
                if (entries.size() > maximum_process_count) {
                    return std::unexpected(error(ProviderErrorCode::result_limit, "process inventory",
                                                 "process count exceeds the inventory limit"));
                }

                if (entry->next_entry_offset == 0U) {
                    break;
                }
                if (entry->next_entry_offset < sizeof(NativeSystemProcessInformation) ||
                    entry->next_entry_offset > buffer.size() - offset) {
                    return std::unexpected(error(ProviderErrorCode::malformed, "process inventory",
                                                 "native process snapshot has an invalid record offset"));
                }
                offset += entry->next_entry_offset;
            }
            if (auto bound = check_inventory_bounds(deadline_unix_ms, cancellation); !bound) {
                return std::unexpected(std::move(bound.error()));
            }
            return entries;
        }

        [[nodiscard]] const ProcessEntry *find_entry(const std::vector<ProcessEntry> &entries,
                                                     const std::uint32_t pid) noexcept {
            const auto found = std::ranges::find(entries, pid, &ProcessEntry::pid);
            return found == entries.end() ? nullptr : std::addressof(*found);
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

        [[nodiscard]] std::expected<ProcessIdentity, ProviderError> parse_process_subject(const SubjectKey &subject) {
            if (!subject.valid() || subject.descriptor.value != process_schema || subject.parent != nullptr ||
                subject.identity.size() != 2U || subject.identity[0].field_id != 1U ||
                subject.identity[1].field_id != 2U) {
                return std::unexpected(error(ProviderErrorCode::invalid_subject, "process subject",
                                             "expected a root windows.process.v1 key"));
            }
            const auto pid = unsigned_identity(subject.identity[0].value);
            const auto creation = unsigned_identity(subject.identity[1].value);
            if (!pid.has_value() || !creation.has_value() || *pid > (std::numeric_limits<std::uint32_t>::max)()) {
                return std::unexpected(error(ProviderErrorCode::invalid_subject, "process subject",
                                             "process identity fields have invalid types or values"));
            }
            return ProcessIdentity {.pid = static_cast<std::uint32_t>(*pid), .creation_time = *creation};
        }

        [[nodiscard]] std::expected<ProcessEntry, ProviderError> verify_process(const SubjectKey &subject,
                                                                                const std::uint64_t deadline_unix_ms) {
            auto identity = parse_process_subject(subject);
            if (!identity) {
                return std::unexpected(std::move(identity.error()));
            }
            auto entries = query_process_entries(deadline_unix_ms);
            if (!entries) {
                return std::unexpected(std::move(entries.error()));
            }
            const auto *entry = find_entry(*entries, identity->pid);
            if (entry == nullptr) {
                return std::unexpected(
                    error(ProviderErrorCode::not_found, "process subject", "the process no longer exists"));
            }
            if (entry->creation_time != identity->creation_time) {
                return std::unexpected(error(ProviderErrorCode::subject_changed, "process subject",
                                             "the PID now belongs to a different process creation time"));
            }
            return *entry;
        }

        [[nodiscard]] std::expected<UniqueHandle, ProviderError>
        open_verified_process(const SubjectKey &subject, const DWORD access, const std::uint64_t deadline_unix_ms) {
            auto live = verify_process(subject, deadline_unix_ms);
            if (!live) {
                return std::unexpected(std::move(live.error()));
            }
            UniqueHandle process {OpenProcess(access, FALSE, live->pid)};
            if (process.value == nullptr) {
                return std::unexpected(win32_error("OpenProcess", "failed to open the process"));
            }

            FILETIME creation {};
            FILETIME exit {};
            FILETIME kernel {};
            FILETIME user {};
            if (GetProcessTimes(process.value, &creation, &exit, &kernel, &user) == FALSE) {
                return std::unexpected(win32_error("GetProcessTimes", "failed to verify process creation time"));
            }
            const auto observed = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) |
                                  static_cast<std::uint64_t>(creation.dwLowDateTime);
            if (observed != live->creation_time) {
                return std::unexpected(error(ProviderErrorCode::subject_changed, "GetProcessTimes",
                                             "the opened PID has a different creation time"));
            }
            return process;
        }

        [[nodiscard]] FactValue integer(const std::uint64_t value) {
            return make_fact(IntegerValue {.decimal = std::to_string(value)});
        }

        [[nodiscard]] FactValue integer(const std::int64_t value) {
            return make_fact(IntegerValue {.decimal = std::to_string(value)});
        }

        [[nodiscard]] FactValue text(std::string value) { return make_fact(UnicodeValue {.utf8 = std::move(value)}); }

        [[nodiscard]] FactValue list(std::vector<FactValue> values) {
            return make_fact(FactList {.items = std::move(values)});
        }

        [[nodiscard]] FactValue record(std::string_view schema, std::vector<FactRecordField> fields) {
            return make_fact(FactRecord {.schema = SchemaId {std::string {schema}}, .fields = std::move(fields)});
        }

        [[nodiscard]] DataLabel public_label() {
            return DataLabel {.classification = Classification::public_data, .categories = {}};
        }

        [[nodiscard]] DataLabel process_sensitive_label() {
            return DataLabel {.classification = Classification::sensitive, .categories = {"windows.process"}};
        }

        [[nodiscard]] std::string architecture_name(const USHORT machine) {
            switch (machine) {
                case IMAGE_FILE_MACHINE_I386: return "x86";
                case IMAGE_FILE_MACHINE_AMD64: return "x64";
                case IMAGE_FILE_MACHINE_ARMNT: return "arm";
                case IMAGE_FILE_MACHINE_ARM64: return "arm64";
                case IMAGE_FILE_MACHINE_UNKNOWN: return "unknown";
                default: return "other";
            }
        }

        [[nodiscard]] std::expected<FactValue, ProviderError>
        process_architecture(const SubjectKey &subject, const std::uint64_t deadline_unix_ms) {
            auto process = open_verified_process(subject, PROCESS_QUERY_LIMITED_INFORMATION, deadline_unix_ms);
            if (!process) {
                return std::unexpected(std::move(process.error()));
            }
            const auto query = is_wow64_process2();
            if (query == nullptr) {
                BOOL wow64 {};
                if (IsWow64Process(process->value, &wow64) == FALSE) {
                    return std::unexpected(win32_error("IsWow64Process", "failed to query process architecture"));
                }
                return text(wow64 != FALSE ? "x86" : "native");
            }
            USHORT process_machine {};
            USHORT native_machine {};
            if (query(process->value, &process_machine, &native_machine) == FALSE) {
                return std::unexpected(win32_error("IsWow64Process2", "failed to query process architecture"));
            }
            return text(
                architecture_name(process_machine == IMAGE_FILE_MACHINE_UNKNOWN ? native_machine : process_machine));
        }

        [[nodiscard]] std::expected<std::vector<std::byte>, ProviderError>
        token_information(const HANDLE token, const TOKEN_INFORMATION_CLASS information_class) {
            DWORD required {};
            if (GetTokenInformation(token, information_class, nullptr, 0, &required) != FALSE ||
                GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0U) {
                return std::unexpected(win32_error("GetTokenInformation", "failed to size token information"));
            }
            std::vector<std::byte> bytes(required);
            if (GetTokenInformation(token, information_class, bytes.data(), required, &required) == FALSE) {
                return std::unexpected(win32_error("GetTokenInformation", "failed to read token information"));
            }
            return bytes;
        }

        [[nodiscard]] std::expected<std::string, ProviderError> sid_string(const PSID sid) {
            if (sid == nullptr || IsValidSid(sid) == FALSE) {
                return std::unexpected(error(ProviderErrorCode::malformed, "process token", "token SID is invalid"));
            }
            wchar_t *raw {};
            if (ConvertSidToStringSidW(sid, &raw) == FALSE || raw == nullptr) {
                return std::unexpected(win32_error("ConvertSidToStringSidW", "failed to format token SID"));
            }
            LocalAllocation allocation {raw};
            auto encoded = utf8(raw);
            if (!encoded.has_value()) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, "process token", "token SID cannot be encoded as UTF-8"));
            }
            return *encoded;
        }

        [[nodiscard]] std::expected<std::string, ProviderError> account_name(const PSID sid) {
            DWORD name_size {};
            DWORD domain_size {};
            SID_NAME_USE use {};
            if (LookupAccountSidW(nullptr, sid, nullptr, &name_size, nullptr, &domain_size, &use) == FALSE &&
                GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                return std::unexpected(win32_error("LookupAccountSidW", "failed to size the account name"));
            }
            if (name_size == 0U) {
                return std::unexpected(
                    error(ProviderErrorCode::unavailable, "LookupAccountSidW", "the account name is unavailable"));
            }
            std::wstring name(name_size, L'\0');
            std::wstring domain(domain_size, L'\0');
            if (LookupAccountSidW(nullptr, sid, name.data(), &name_size, domain.empty() ? nullptr : domain.data(),
                                  &domain_size, &use) == FALSE) {
                return std::unexpected(win32_error("LookupAccountSidW", "failed to resolve the account name"));
            }
            name.resize(name_size);
            domain.resize(domain_size);
            auto encoded = utf8(domain.empty() ? name : domain + L"\\" + name);
            if (!encoded.has_value()) {
                return std::unexpected(error(ProviderErrorCode::malformed, "process token",
                                             "the account name cannot be encoded as UTF-8"));
            }
            return *encoded;
        }

        [[nodiscard]] std::string integrity_name(const DWORD rid) {
            if (rid < SECURITY_MANDATORY_LOW_RID) {
                return "untrusted";
            }
            if (rid < SECURITY_MANDATORY_MEDIUM_RID) {
                return "low";
            }
            if (rid < SECURITY_MANDATORY_HIGH_RID) {
                return "medium";
            }
            if (rid < SECURITY_MANDATORY_SYSTEM_RID) {
                return "high";
            }
            if (rid < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
                return "system";
            }
            return rid == SECURITY_MANDATORY_PROTECTED_PROCESS_RID ? "protected" : "unknown";
        }

        [[nodiscard]] std::expected<FactValue, ProviderError> process_user(const SubjectKey &subject,
                                                                           const std::uint64_t deadline_unix_ms) {
            auto process = open_verified_process(subject, PROCESS_QUERY_LIMITED_INFORMATION, deadline_unix_ms);
            if (!process) {
                return std::unexpected(std::move(process.error()));
            }
            UniqueHandle token {nullptr};
            if (OpenProcessToken(process->value, TOKEN_QUERY, &token.value) == FALSE) {
                return std::unexpected(win32_error("OpenProcessToken", "failed to open the process token"));
            }
            auto bytes = token_information(token.value, TokenUser);
            if (!bytes) {
                return std::unexpected(std::move(bytes.error()));
            }
            const auto *user = reinterpret_cast<const TOKEN_USER *>(bytes->data());
            auto sid = sid_string(user->User.Sid);
            if (!sid) {
                return std::unexpected(std::move(sid.error()));
            }
            auto name = account_name(user->User.Sid);
            if (!name) {
                return std::unexpected(std::move(name.error()));
            }
            return record(process_user_value_schema, {{.field_id = 1, .value = text(std::move(*sid))},
                                                      {.field_id = 2, .value = text(std::move(*name))}});
        }

        [[nodiscard]] std::expected<FactValue, ProviderError> process_token(const SubjectKey &subject,
                                                                            const std::uint64_t deadline_unix_ms) {
            auto process = open_verified_process(subject, PROCESS_QUERY_LIMITED_INFORMATION, deadline_unix_ms);
            if (!process) {
                return std::unexpected(std::move(process.error()));
            }
            UniqueHandle token {nullptr};
            if (OpenProcessToken(process->value, TOKEN_QUERY, &token.value) == FALSE) {
                return std::unexpected(win32_error("OpenProcessToken", "failed to open the process token"));
            }

            TOKEN_ELEVATION elevation {};
            DWORD received {};
            if (GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &received) == FALSE) {
                return std::unexpected(win32_error("GetTokenInformation", "failed to query token elevation"));
            }
            TOKEN_TYPE type {};
            if (GetTokenInformation(token.value, TokenType, &type, sizeof(type), &received) == FALSE) {
                return std::unexpected(win32_error("GetTokenInformation", "failed to query token type"));
            }
            auto integrity = token_information(token.value, TokenIntegrityLevel);
            if (!integrity) {
                return std::unexpected(std::move(integrity.error()));
            }
            const auto *label = reinterpret_cast<const TOKEN_MANDATORY_LABEL *>(integrity->data());
            const auto count = GetSidSubAuthorityCount(label->Label.Sid);
            if (count == nullptr || *count == 0U) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, "process token", "integrity SID has no subauthority"));
            }
            const auto rid = GetSidSubAuthority(label->Label.Sid, static_cast<DWORD>(*count - 1U));
            if (rid == nullptr) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, "process token", "integrity SID is malformed"));
            }
            return record(process_token_value_schema,
                          {{.field_id = 1, .value = make_fact(elevation.TokenIsElevated != 0U)},
                           {.field_id = 2, .value = text(type == TokenPrimary ? "primary" : "impersonation")},
                           {.field_id = 3, .value = text(integrity_name(*rid))}});
        }

        [[nodiscard]] std::expected<FactValue, ProviderError> process_modules(const SubjectKey &subject,
                                                                              const std::uint64_t deadline_unix_ms) {
            auto identity = parse_process_subject(subject);
            if (!identity) {
                return std::unexpected(std::move(identity.error()));
            }
            if (auto live = verify_process(subject, deadline_unix_ms); !live) {
                return std::unexpected(std::move(live.error()));
            }
            UniqueHandle snapshot {CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, identity->pid)};
            if (snapshot.value == INVALID_HANDLE_VALUE) {
                return std::unexpected(win32_error("CreateToolhelp32Snapshot", "failed to enumerate modules"));
            }
            MODULEENTRY32W module {};
            module.dwSize = sizeof(module);
            if (Module32FirstW(snapshot.value, &module) == FALSE) {
                const auto code = GetLastError();
                if (code == ERROR_NO_MORE_FILES) {
                    return list({});
                }
                return std::unexpected(win32_error("Module32FirstW", "failed to read the first module", code));
            }
            std::vector<FactValue> modules;
            for (;;) {
                auto name = utf8(module.szModule);
                auto path = utf8(module.szExePath);
                if (!name.has_value() || !path.has_value()) {
                    return std::unexpected(error(ProviderErrorCode::malformed, "module inventory",
                                                 "module metadata is not valid Unicode"));
                }
                modules.push_back(record(
                    "windows.process-module-value.v1",
                    {{.field_id = 1, .value = text(std::move(*name))},
                     {.field_id = 2, .value = text(std::move(*path))},
                     {.field_id = 3,
                      .value =
                          integer(static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(module.modBaseAddr)))},
                     {.field_id = 4, .value = integer(static_cast<std::uint64_t>(module.modBaseSize))}}));
                if (modules.size() > maximum_module_count) {
                    return std::unexpected(error(ProviderErrorCode::result_limit, "module inventory",
                                                 "module count exceeds the provider limit"));
                }
                if (Module32NextW(snapshot.value, &module) != FALSE) {
                    continue;
                }
                const auto code = GetLastError();
                if (code != ERROR_NO_MORE_FILES) {
                    return std::unexpected(win32_error("Module32NextW", "module enumeration failed", code));
                }
                break;
            }
            if (auto live = verify_process(subject, deadline_unix_ms); !live) {
                return std::unexpected(std::move(live.error()));
            }
            return list(std::move(modules));
        }

        [[nodiscard]] bool readable_protection(const DWORD protection) noexcept {
            if ((protection & (PAGE_GUARD | PAGE_NOACCESS)) != 0U) {
                return false;
            }
            const auto base = protection & 0xffU;
            return base == PAGE_READONLY || base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
                   base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
        }

        [[nodiscard]] std::uint32_t scan_permissions(const DWORD protection) noexcept {
            std::uint32_t result {};
            if (readable_protection(protection)) {
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

        [[nodiscard]] std::expected<std::vector<MEMORY_BASIC_INFORMATION>, ProviderError>
        query_memory_regions(const SubjectKey &subject, const std::uint64_t deadline_unix_ms) {
            auto process =
                open_verified_process(subject, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, deadline_unix_ms);
            if (!process) {
                return std::unexpected(std::move(process.error()));
            }
            SYSTEM_INFO information {};
            GetNativeSystemInfo(&information);
            auto address = reinterpret_cast<std::uintptr_t>(information.lpMinimumApplicationAddress);
            const auto maximum = reinterpret_cast<std::uintptr_t>(information.lpMaximumApplicationAddress);
            std::vector<MEMORY_BASIC_INFORMATION> regions;
            while (address < maximum) {
                if (auto deadline = check_deadline(deadline_unix_ms, "VirtualQueryEx"); !deadline) {
                    return std::unexpected(std::move(deadline.error()));
                }
                MEMORY_BASIC_INFORMATION region {};
                const auto received =
                    VirtualQueryEx(process->value, reinterpret_cast<const void *>(address), &region, sizeof(region));
                if (received == 0U) {
                    const auto code = GetLastError();
                    if (code == ERROR_INVALID_PARAMETER) {
                        break;
                    }
                    return std::unexpected(win32_error("VirtualQueryEx", "memory enumeration failed", code));
                }
                if (received < sizeof(region) || region.RegionSize == 0U) {
                    return std::unexpected(
                        error(ProviderErrorCode::malformed, "VirtualQueryEx", "memory region has an invalid size"));
                }
                regions.push_back(region);
                if (regions.size() > maximum_memory_region_count) {
                    return std::unexpected(error(ProviderErrorCode::result_limit, "VirtualQueryEx",
                                                 "memory region count exceeds the provider limit"));
                }
                const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
                if (region.RegionSize > maximum - base) {
                    break;
                }
                const auto next = base + region.RegionSize;
                if (next <= address) {
                    return std::unexpected(error(ProviderErrorCode::arithmetic_overflow, "VirtualQueryEx",
                                                 "memory region address did not advance"));
                }
                address = next;
            }
            if (auto live = verify_process(subject, deadline_unix_ms); !live) {
                return std::unexpected(std::move(live.error()));
            }
            return regions;
        }

        [[nodiscard]] std::expected<FactValue, ProviderError> memory_summary(const SubjectKey &subject,
                                                                             const std::uint64_t deadline_unix_ms) {
            auto regions = query_memory_regions(subject, deadline_unix_ms);
            if (!regions) {
                return std::unexpected(std::move(regions.error()));
            }
            std::uint64_t committed {};
            std::uint64_t readable {};
            std::uint64_t readable_bytes {};
            for (const auto &region : *regions) {
                if (region.State == MEM_COMMIT) {
                    ++committed;
                }
                if (region.State == MEM_COMMIT && readable_protection(region.Protect)) {
                    ++readable;
                    if (region.RegionSize <= (std::numeric_limits<std::uint64_t>::max)() - readable_bytes) {
                        readable_bytes += region.RegionSize;
                    } else {
                        return std::unexpected(error(ProviderErrorCode::arithmetic_overflow, "memory summary",
                                                     "readable byte count overflowed"));
                    }
                }
            }
            return record(process_memory_value_schema,
                          {{.field_id = 1, .value = integer(static_cast<std::uint64_t>(regions->size()))},
                           {.field_id = 2, .value = integer(committed)},
                           {.field_id = 3, .value = integer(readable)},
                           {.field_id = 4, .value = integer(readable_bytes)}});
        }

        [[nodiscard]] std::expected<FactValue, ProviderError>
        memory_regions_value(const SubjectKey &subject, const std::uint64_t deadline_unix_ms) {
            auto regions = query_memory_regions(subject, deadline_unix_ms);
            if (!regions) {
                return std::unexpected(std::move(regions.error()));
            }
            std::vector<FactValue> values;
            values.reserve(regions->size());
            for (const auto &region : *regions) {
                values.push_back(record(
                    "windows.memory-region-value.v1",
                    {{.field_id = 1,
                      .value =
                          integer(static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(region.AllocationBase)))},
                     {.field_id = 2,
                      .value =
                          integer(static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(region.BaseAddress)))},
                     {.field_id = 3, .value = integer(static_cast<std::uint64_t>(region.RegionSize))},
                     {.field_id = 4, .value = integer(static_cast<std::uint64_t>(region.State))},
                     {.field_id = 5, .value = integer(static_cast<std::uint64_t>(region.Type))},
                     {.field_id = 6, .value = integer(static_cast<std::uint64_t>(region.Protect))},
                     {.field_id = 7,
                      .value = make_fact(region.State == MEM_COMMIT && readable_protection(region.Protect))},
                     {.field_id = 8, .value = integer(static_cast<std::uint64_t>(scan_permissions(region.Protect)))}}));
            }
            return list(std::move(values));
        }

        [[nodiscard]] std::expected<FactValue, ProviderError>
        record_field(const FactValue &value, const std::uint32_t field_id, std::string operation) {
            if (!value.valid()) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, std::move(operation), "provider record is invalid"));
            }
            const auto *record_value = std::get_if<FactRecord>(&value.node->data);
            if (record_value == nullptr) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, std::move(operation), "provider value is not a record"));
            }
            const auto found = std::ranges::find(record_value->fields, field_id, &FactRecordField::field_id);
            if (found == record_value->fields.end() || !found->value.valid()) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, std::move(operation), "provider record field is missing"));
            }
            return found->value;
        }

        [[nodiscard]] std::expected<FactValue, ProviderError> list_count(const FactValue &value,
                                                                         std::string operation) {
            if (!value.valid()) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, std::move(operation), "provider list is invalid"));
            }
            const auto *list_value = std::get_if<FactList>(&value.node->data);
            if (list_value == nullptr) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, std::move(operation), "provider value is not a list"));
            }
            return integer(static_cast<std::uint64_t>(list_value->items.size()));
        }

        [[nodiscard]] std::expected<FactValue, ProviderError> module_names(const FactValue &value) {
            if (!value.valid()) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, "module inventory", "provider module list is invalid"));
            }
            const auto *list_value = std::get_if<FactList>(&value.node->data);
            if (list_value == nullptr) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, "module inventory", "provider module value is not a list"));
            }
            std::vector<FactValue> names;
            names.reserve(list_value->items.size());
            for (const auto &module : list_value->items) {
                auto name = record_field(module, 1U, "module inventory");
                if (!name) {
                    return std::unexpected(std::move(name.error()));
                }
                names.push_back(std::move(*name));
            }
            return list(std::move(names));
        }

        [[nodiscard]] std::expected<FactValue, ProviderError> command_line(const SubjectKey &subject,
                                                                           const std::uint64_t deadline_unix_ms) {
            auto process =
                open_verified_process(subject, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, deadline_unix_ms);
            if (!process) {
                return std::unexpected(std::move(process.error()));
            }
            const auto query = load_ntdll_function<NtQueryInformationProcessFn>("NtQueryInformationProcess");
            if (query == nullptr) {
                return std::unexpected(error(ProviderErrorCode::unsupported, "process command line",
                                             "NtQueryInformationProcess is unavailable"));
            }
            ULONG required {};
            auto status = query(process->value, process_command_line_information, nullptr, 0, &required);
            if (status != status_info_length_mismatch || required < sizeof(UNICODE_STRING) ||
                required > 1U * 1024U * 1024U) {
                return std::unexpected(error(ProviderErrorCode::unavailable, "process command line",
                                             "failed to size ProcessCommandLineInformation",
                                             static_cast<DWORD>(status)));
            }
            std::vector<std::byte> buffer(required);
            status = query(process->value, process_command_line_information, buffer.data(),
                           static_cast<ULONG>(buffer.size()), &required);
            if (status < 0) {
                return std::unexpected(error(ProviderErrorCode::unavailable, "process command line",
                                             "failed to query ProcessCommandLineInformation",
                                             static_cast<DWORD>(status)));
            }
            const auto *value = reinterpret_cast<const UNICODE_STRING *>(buffer.data());
            if (value->Length == 0U) {
                return text({});
            }
            if (value->Buffer == nullptr || (value->Length % sizeof(wchar_t)) != 0U) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, "process command line", "command line response is malformed"));
            }
            auto encoded = utf8(std::wstring_view {value->Buffer, value->Length / sizeof(wchar_t)});
            if (!encoded.has_value()) {
                return std::unexpected(
                    error(ProviderErrorCode::malformed, "process command line", "command line is not valid Unicode"));
            }
            return text(std::move(*encoded));
        }

        [[nodiscard]] std::string signer_status_name(const LONG status) {
            if (status == ERROR_SUCCESS) {
                return "trusted";
            }
            if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN ||
                status == TRUST_E_PROVIDER_UNKNOWN) {
                return "unsigned";
            }
            if (status == CERT_E_REVOKED) {
                return "revoked";
            }
            if (status == CERT_E_EXPIRED) {
                return "expired";
            }
            if (status == CERT_E_UNTRUSTEDROOT) {
                return "untrusted_root";
            }
            if (status == TRUST_E_BAD_DIGEST) {
                return "bad_digest";
            }
            return "untrusted";
        }

        [[nodiscard]] std::optional<std::string> certificate_name(const PCCERT_CONTEXT certificate, const DWORD type,
                                                                  const DWORD flags = 0U) {
            const auto required = CertGetNameStringW(certificate, type, flags, nullptr, nullptr, 0);
            if (required <= 1U) {
                return std::nullopt;
            }
            std::wstring output(required, L'\0');
            if (CertGetNameStringW(certificate, type, flags, nullptr, output.data(), required) != required) {
                return std::nullopt;
            }
            output.resize(required - 1U);
            return utf8(output);
        }

        [[nodiscard]] std::optional<CertificateContext> signer_certificate(const std::filesystem::path &path) {
            DWORD encoding {};
            DWORD content {};
            DWORD format {};
            CertStoreHandle store;
            CryptMessageHandle message;
            if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                                 CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content, &format, &store.value,
                                 &message.value, nullptr) == FALSE) {
                return std::nullopt;
            }
            DWORD required {};
            if (CryptMsgGetParam(message.value, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &required) == FALSE ||
                required < sizeof(CMSG_SIGNER_INFO)) {
                return std::nullopt;
            }
            std::vector<std::byte> bytes(required);
            if (CryptMsgGetParam(message.value, CMSG_SIGNER_INFO_PARAM, 0, bytes.data(), &required) == FALSE) {
                return std::nullopt;
            }
            const auto *signer = reinterpret_cast<const CMSG_SIGNER_INFO *>(bytes.data());
            CERT_INFO info {};
            info.Issuer = signer->Issuer;
            info.SerialNumber = signer->SerialNumber;
            CertificateContext certificate;
            certificate.value =
                CertFindCertificateInStore(store.value, encoding, 0, CERT_FIND_SUBJECT_CERT, &info, nullptr);
            if (certificate.value == nullptr) {
                return std::nullopt;
            }
            return std::optional<CertificateContext> {std::move(certificate)};
        }

        [[nodiscard]] FactValue optional_text(std::optional<std::string> value) {
            return value.has_value() ? text(std::move(*value)) : make_fact(std::monostate {});
        }

        [[nodiscard]] FactValue optional_bytes(std::optional<BytesValue> value) {
            return value.has_value() ? make_fact(std::move(*value)) : make_fact(std::monostate {});
        }

        [[nodiscard]] std::expected<FrozenValue, ProviderError> signer_for_path(const std::filesystem::path &path,
                                                                                const std::uint64_t deadline_unix_ms) {
            if (auto deadline = check_deadline(deadline_unix_ms, "WinVerifyTrust"); !deadline) {
                return std::unexpected(std::move(deadline.error()));
            }

            WINTRUST_FILE_INFO file {};
            file.cbStruct = sizeof(file);
            file.pcwszFilePath = path.c_str();
            WINTRUST_DATA trust {};
            trust.cbStruct = sizeof(trust);
            trust.dwUIChoice = WTD_UI_NONE;
            trust.fdwRevocationChecks = WTD_REVOKE_NONE;
            trust.dwUnionChoice = WTD_CHOICE_FILE;
            trust.pFile = &file;
            trust.dwStateAction = WTD_STATEACTION_VERIFY;
            trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG;
            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            const auto status = WinVerifyTrust(nullptr, &action, &trust);
            trust.dwStateAction = WTD_STATEACTION_CLOSE;
            static_cast<void>(WinVerifyTrust(nullptr, &action, &trust));

            if (expired(deadline_unix_ms)) {
                return std::unexpected(
                    error(ProviderErrorCode::timed_out, "WinVerifyTrust", "signer verification exceeded its deadline"));
            }
            if (status == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
                return std::unexpected(error(ProviderErrorCode::access_denied, "WinVerifyTrust",
                                             "access to the image was denied", ERROR_ACCESS_DENIED));
            }
            if (status == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
                status == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)) {
                return std::unexpected(error(ProviderErrorCode::not_found, "WinVerifyTrust",
                                             "the image no longer exists", static_cast<DWORD>(status)));
            }

            const auto signed_image = status != TRUST_E_NOSIGNATURE && status != TRUST_E_SUBJECT_FORM_UNKNOWN &&
                                      status != TRUST_E_PROVIDER_UNKNOWN;
            std::optional<std::string> subject;
            std::optional<std::string> issuer;
            std::optional<BytesValue> serial;
            std::optional<BytesValue> thumbprint;
            if (signed_image) {
                auto certificate = signer_certificate(path);
                if (certificate.has_value()) {
                    subject = certificate_name(certificate->value, CERT_NAME_SIMPLE_DISPLAY_TYPE);
                    issuer = certificate_name(certificate->value, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);
                    BytesValue serial_value;
                    serial_value.bytes.reserve(certificate->value->pCertInfo->SerialNumber.cbData);
                    for (DWORD index = 0; index < certificate->value->pCertInfo->SerialNumber.cbData; ++index) {
                        serial_value.bytes.push_back(
                            static_cast<std::byte>(certificate->value->pCertInfo->SerialNumber.pbData[index]));
                    }
                    serial = std::move(serial_value);
                    DWORD thumbprint_size {};
                    if (CertGetCertificateContextProperty(certificate->value, CERT_SHA256_HASH_PROP_ID, nullptr,
                                                          &thumbprint_size) != FALSE &&
                        thumbprint_size > 0U) {
                        BytesValue thumbprint_value;
                        thumbprint_value.bytes.resize(thumbprint_size);
                        if (CertGetCertificateContextProperty(certificate->value, CERT_SHA256_HASH_PROP_ID,
                                                              thumbprint_value.bytes.data(),
                                                              &thumbprint_size) != FALSE) {
                            thumbprint_value.bytes.resize(thumbprint_size);
                            thumbprint = std::move(thumbprint_value);
                        }
                    }
                }
            }

            auto value =
                record(signer_value_schema, {{.field_id = 1, .value = text(signer_status_name(status))},
                                             {.field_id = 2, .value = make_fact(status == ERROR_SUCCESS)},
                                             {.field_id = 3, .value = make_fact(signed_image)},
                                             {.field_id = 4, .value = integer(static_cast<std::int64_t>(status))},
                                             {.field_id = 5, .value = optional_text(std::move(subject))},
                                             {.field_id = 6, .value = optional_text(std::move(issuer))},
                                             {.field_id = 7, .value = optional_bytes(std::move(serial))},
                                             {.field_id = 8, .value = optional_bytes(std::move(thumbprint))}});
            return freeze_provider_value(std::move(value), process_sensitive_label());
        }

        [[nodiscard]] std::expected<std::filesystem::path, ProviderError>
        image_path_from_subject(const SubjectKey &subject) {
            if (!subject.valid() || subject.descriptor.value != image_schema || subject.parent == nullptr ||
                subject.identity.empty() || subject.identity[0].field_id != 1U) {
                return std::unexpected(error(ProviderErrorCode::invalid_subject, "image subject",
                                             "expected a windows.image.v1 subject with a process parent"));
            }
            const auto *path = std::get_if<UnicodeValue>(&subject.identity[0].value);
            if (path == nullptr || path->utf8.empty()) {
                return std::unexpected(
                    error(ProviderErrorCode::invalid_subject, "image subject", "image path identity is missing"));
            }
            const auto wide_size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path->utf8.data(),
                                                       static_cast<int>(path->utf8.size()), nullptr, 0);
            if (wide_size <= 0) {
                return std::unexpected(error(ProviderErrorCode::invalid_subject, "image subject",
                                             "image path identity is not valid UTF-8"));
            }
            std::wstring wide(static_cast<std::size_t>(wide_size), L'\0');
            if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path->utf8.data(),
                                    static_cast<int>(path->utf8.size()), wide.data(), wide_size) != wide_size) {
                return std::unexpected(
                    error(ProviderErrorCode::invalid_subject, "image subject", "image path conversion failed"));
            }
            return std::filesystem::path {wide};
        }

        [[nodiscard]] FactValue identity_fact(const IdentityScalar &identity) {
            return std::visit(
                [](const auto &value) -> FactValue {
                    using ValueType = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::is_same_v<ValueType, bool>) {
                        return make_fact(value);
                    } else if constexpr (std::is_same_v<ValueType, std::int64_t> ||
                                         std::is_same_v<ValueType, std::uint64_t>) {
                        return integer(value);
                    } else {
                        return make_fact(value);
                    }
                },
                identity);
        }

        [[nodiscard]] bool value_matches_schema(const FactValue &value, const SchemaId &schema) noexcept {
            if (!value.valid() || schema.empty()) {
                return false;
            }
            const auto &data = value.node->data;
            const auto id = std::string_view {schema.value};
            if (id == "any") {
                return true;
            }
            if (id == "none" || id == "null") {
                return std::holds_alternative<std::monostate>(data);
            }
            if (id == "bool" || id == "boolean") {
                return std::holds_alternative<bool>(data);
            }
            if (id == "int" || id == "integer") {
                return std::holds_alternative<IntegerValue>(data);
            }
            if (id == "float") {
                return std::holds_alternative<double>(data);
            }
            if (id == "str" || id == "string" || id == "text" || id == "unicode") {
                return std::holds_alternative<UnicodeValue>(data);
            }
            if (id == "bytes") {
                return std::holds_alternative<BytesValue>(data);
            }
            if (id == "list") {
                return std::holds_alternative<FactList>(data);
            }
            if (id == "map" || id == "dict") {
                return std::holds_alternative<FactMap>(data);
            }
            if (const auto *enumeration = std::get_if<EnumValue>(&data); enumeration != nullptr) {
                return enumeration->schema == schema;
            }
            const auto *record = std::get_if<FactRecord>(&data);
            return record != nullptr && record->schema == schema;
        }

        [[nodiscard]] std::expected<FrozenValue, ProviderError> resolve_image_fact(const FactRequest &request) {
            auto path = image_path_from_subject(request.subject);
            if (!path) {
                return std::unexpected(std::move(path.error()));
            }
            auto live_path = resolve_process_image_path(*request.subject.parent, request.deadline_unix_ms);
            if (!live_path) {
                return std::unexpected(std::move(live_path.error()));
            }
            std::error_code equivalent_error;
            if (!std::filesystem::equivalent(*path, *live_path, equivalent_error) || equivalent_error) {
                return std::unexpected(error(ProviderErrorCode::subject_changed, "image fact",
                                             "image subject is not the process's current executable image"));
            }
            auto current = image_subject(*request.subject.parent, *live_path);
            if (!current) {
                return std::unexpected(std::move(current.error()));
            }
            if (canonical_subject_key(*current) != canonical_subject_key(request.subject)) {
                return std::unexpected(error(ProviderErrorCode::subject_changed, "image fact",
                                             "image subject no longer matches the current file identity"));
            }
            path = std::move(live_path);
            const auto route = std::string_view {request.route.fact};
            if (route == "image.signer") {
                return read_image_signer(*path, request.deadline_unix_ms);
            }
            if (route == "image.path" || route == "image.volume_serial" || route == "image.file_id") {
                const auto index = route == "image.path" ? 0U : route == "image.volume_serial" ? 1U : 2U;
                if (request.subject.identity.size() <= index) {
                    return std::unexpected(
                        error(ProviderErrorCode::invalid_subject, "image fact", "image identity field is missing"));
                }
                return freeze_provider_value(identity_fact(request.subject.identity[index].value),
                                             process_sensitive_label());
            }
            if (request.subject.parent == nullptr) {
                return std::unexpected(
                    error(ProviderErrorCode::invalid_subject, "PE fact", "image subject has no process parent"));
            }
            auto pe = inspect_pe_image(*request.subject.parent, *path, 1U, request.deadline_unix_ms);
            if (!pe) {
                return std::unexpected(std::move(pe.error()));
            }
            if (route == "pe.image") {
                return std::move(pe->value);
            }
            const auto field_id = route == "pe.is_valid"            ? 1U :
                                  route == "pe.machine"             ? 2U :
                                  route == "pe.number_of_sections"  ? 3U :
                                  route == "pe.entry_point"         ? 4U :
                                  route == "pe.size_of_image"       ? 5U :
                                  route == "pe.subsystem"           ? 6U :
                                  route == "pe.characteristics"     ? 7U :
                                  route == "pe.dll_characteristics" ? 8U :
                                  route == "pe.timestamp"           ? 9U :
                                  route == "pe.sections"            ? 10U :
                                  route == "pe.imports"             ? 11U :
                                  route == "pe.exports"             ? 12U :
                                  route == "pe.debug_entries"       ? 13U :
                                  route == "pe.resources"           ? 14U :
                                  route == "pe.certificates"        ? 15U :
                                  route == "pe.tls_callbacks"       ? 16U :
                                  route == "image.size"             ? 17U :
                                  route == "image.last_write_time"  ? 18U :
                                                                      0U;
            if (field_id == 0U) {
                return std::unexpected(
                    error(ProviderErrorCode::unsupported, "image fact", "unknown Windows image or PE fact route"));
            }
            auto selected = record_field(pe->value.value, field_id, "PE fact");
            if (!selected) {
                return std::unexpected(std::move(selected.error()));
            }
            return freeze_provider_value(std::move(*selected), pe->value.label);
        }

        [[nodiscard]] std::expected<FrozenValue, ProviderError> resolve_process_fact(const FactRequest &request) {
            auto live = verify_process(request.subject, request.deadline_unix_ms);
            if (!live) {
                return std::unexpected(std::move(live.error()));
            }
            const auto route = std::string_view {request.route.fact};
            if (route == "process.pid") {
                return freeze_provider_value(integer(static_cast<std::uint64_t>(live->pid)), public_label());
            }
            if (route == "process.creation_time") {
                return freeze_provider_value(integer(live->creation_time), public_label());
            }
            if (route == "process.name") {
                return freeze_provider_value(text(live->name), public_label());
            }
            if (route == "process.thread_count") {
                return freeze_provider_value(integer(static_cast<std::uint64_t>(live->thread_count)), public_label());
            }
            if (route == "process.handles.count") {
                return freeze_provider_value(integer(static_cast<std::uint64_t>(live->handle_count)), public_label());
            }
            if (route == "process.session_id") {
                return freeze_provider_value(integer(static_cast<std::uint64_t>(live->session_id)), public_label());
            }
            if (route == "process.parent" || route == "process.parent.pid") {
                auto entries = query_process_entries(request.deadline_unix_ms);
                if (!entries) {
                    return std::unexpected(std::move(entries.error()));
                }
                const auto *parent = find_entry(*entries, live->parent_pid);
                if (route == "process.parent.pid") {
                    return freeze_provider_value(integer(static_cast<std::uint64_t>(live->parent_pid)), public_label());
                }
                return freeze_provider_value(
                    record(
                        process_parent_value_schema,
                        {{.field_id = 1, .value = integer(static_cast<std::uint64_t>(live->parent_pid))},
                         {.field_id = 2,
                          .value = parent == nullptr ? make_fact(std::monostate {}) : integer(parent->creation_time)}}),
                    public_label());
            }
            if (route == "process.path" || route == "process.image.path") {
                auto path = resolve_process_image_path(request.subject, request.deadline_unix_ms);
                if (!path) {
                    return std::unexpected(std::move(path.error()));
                }
                const auto encoded = path->generic_u8string();
                return freeze_provider_value(
                    text(std::string {reinterpret_cast<const char *>(encoded.data()), encoded.size()}),
                    process_sensitive_label());
            }
            if (route == "process.architecture") {
                auto value = process_architecture(request.subject, request.deadline_unix_ms);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                return freeze_provider_value(std::move(*value), public_label());
            }
            if (route == "process.command_line") {
                auto value = command_line(request.subject, request.deadline_unix_ms);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                return freeze_provider_value(std::move(*value), process_sensitive_label());
            }
            if (route == "process.user" || route == "process.user.sid" || route == "process.user.name") {
                auto value = process_user(request.subject, request.deadline_unix_ms);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                if (route != "process.user") {
                    auto selected = record_field(*value, route == "process.user.sid" ? 1U : 2U, "process user");
                    if (!selected) {
                        return std::unexpected(std::move(selected.error()));
                    }
                    return freeze_provider_value(std::move(*selected), process_sensitive_label());
                }
                return freeze_provider_value(std::move(*value), process_sensitive_label());
            }
            if (route == "process.token" || route == "process.token.elevated" || route == "process.token.type" ||
                route == "process.integrity_level") {
                auto value = process_token(request.subject, request.deadline_unix_ms);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                if (route != "process.token") {
                    const auto field_id = route == "process.token.elevated" ? 1U :
                                          route == "process.token.type"     ? 2U :
                                                                              3U;
                    auto selected = record_field(*value, field_id, "process token");
                    if (!selected) {
                        return std::unexpected(std::move(selected.error()));
                    }
                    return freeze_provider_value(std::move(*selected), process_sensitive_label());
                }
                return freeze_provider_value(std::move(*value), process_sensitive_label());
            }
            if (route == "process.modules" || route == "process.modules.count" || route == "process.modules.names") {
                auto value = process_modules(request.subject, request.deadline_unix_ms);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                if (route == "process.modules.count") {
                    auto count = list_count(*value, "module inventory");
                    if (!count) {
                        return std::unexpected(std::move(count.error()));
                    }
                    return freeze_provider_value(std::move(*count), process_sensitive_label());
                }
                if (route == "process.modules.names") {
                    auto names = module_names(*value);
                    if (!names) {
                        return std::unexpected(std::move(names.error()));
                    }
                    return freeze_provider_value(std::move(*names), process_sensitive_label());
                }
                return freeze_provider_value(std::move(*value), process_sensitive_label());
            }
            if (route == "process.memory.summary" || route == "process.memory.regions.count" ||
                route == "process.memory.regions.readable_count") {
                auto value = memory_summary(request.subject, request.deadline_unix_ms);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                if (route != "process.memory.summary") {
                    auto selected =
                        record_field(*value, route == "process.memory.regions.count" ? 1U : 3U, "memory summary");
                    if (!selected) {
                        return std::unexpected(std::move(selected.error()));
                    }
                    return freeze_provider_value(std::move(*selected), process_sensitive_label());
                }
                return freeze_provider_value(std::move(*value), process_sensitive_label());
            }
            if (route == "process.memory.regions") {
                auto value = memory_regions_value(request.subject, request.deadline_unix_ms);
                if (!value) {
                    return std::unexpected(std::move(value.error()));
                }
                return freeze_provider_value(std::move(*value), process_sensitive_label());
            }
            if (route == "process.signer" || route == "process.signer.status" || route == "process.signer.is_signed") {
                auto signer = read_process_signer(request.subject, request.deadline_unix_ms);
                if (!signer || route == "process.signer") {
                    return signer;
                }
                auto selected =
                    record_field(signer->value, route == "process.signer.status" ? 1U : 2U, "process signer");
                if (!selected) {
                    return std::unexpected(std::move(selected.error()));
                }
                return freeze_provider_value(std::move(*selected), signer->label);
            }
            if (route == "process.pe") {
                auto path = resolve_process_image_path(request.subject, request.deadline_unix_ms);
                if (!path) {
                    return std::unexpected(std::move(path.error()));
                }
                auto pe = inspect_pe_image(request.subject, *path, 1U, request.deadline_unix_ms);
                if (!pe) {
                    return std::unexpected(std::move(pe.error()));
                }
                return std::move(pe->value);
            }
            return std::unexpected(
                error(ProviderErrorCode::unsupported, "fact dispatch", "unknown Windows process fact route"));
        }

    } // namespace

    InventorySnapshot enumerate_process_inventory(PeerId peer, const std::uint64_t generation,
                                                  const std::uint64_t deadline_unix_ms,
                                                  const std::stop_token cancellation) {
        auto entries = query_process_entries(deadline_unix_ms, cancellation);
        if (!entries) {
            return invalid_inventory_snapshot(std::move(peer), SchemaId {std::string {process_schema}}, generation,
                                              std::move(entries.error()));
        }

        std::vector<SubjectObservation> observations;
        observations.reserve(entries->size());
        std::unordered_map<std::uint32_t, std::uint64_t> creation_times;
        creation_times.reserve(entries->size());
        for (const auto &entry : *entries) {
            if (auto bound = check_inventory_bounds(deadline_unix_ms, cancellation); !bound) {
                return invalid_inventory_snapshot(std::move(peer), SchemaId {std::string {process_schema}}, generation,
                                                  std::move(bound.error()));
            }
            creation_times.insert_or_assign(entry.pid, entry.creation_time);
        }
        for (const auto &entry : *entries) {
            if (auto bound = check_inventory_bounds(deadline_unix_ms, cancellation); !bound) {
                return invalid_inventory_snapshot(std::move(peer), SchemaId {std::string {process_schema}}, generation,
                                                  std::move(bound.error()));
            }
            const auto parent = creation_times.find(entry.parent_pid);
            observations.push_back(SubjectObservation {
                .subject = process_subject(peer, entry.pid, entry.creation_time),
                .eager_fields = {{.field_id = 1, .value = integer(static_cast<std::uint64_t>(entry.pid))},
                                 {.field_id = 2, .value = integer(entry.creation_time)},
                                 {.field_id = 3, .value = text(entry.name)},
                                 {.field_id = 4, .value = integer(static_cast<std::uint64_t>(entry.parent_pid))},
                                 {.field_id = 5,
                                  .value = parent == creation_times.end() ? make_fact(std::monostate {}) :
                                                                            integer(parent->second)},
                                 {.field_id = 6, .value = integer(static_cast<std::uint64_t>(entry.thread_count))},
                                 {.field_id = 7, .value = integer(static_cast<std::uint64_t>(entry.session_id))}},
            });
        }
        if (auto bound = check_inventory_bounds(deadline_unix_ms, cancellation); !bound) {
            return invalid_inventory_snapshot(std::move(peer), SchemaId {std::string {process_schema}}, generation,
                                              std::move(bound.error()));
        }
        return make_inventory_snapshot(std::move(peer), SchemaId {std::string {process_schema}}, std::nullopt,
                                       generation, std::move(observations), deadline_unix_ms, cancellation);
    }

    InventorySnapshot enumerate_memory_region_inventory(const SubjectKey &process, const std::uint64_t generation,
                                                        const std::uint64_t deadline_unix_ms) {
        auto regions = query_memory_regions(process, deadline_unix_ms);
        if (!regions) {
            return invalid_inventory_snapshot(process.peer, SchemaId {std::string {memory_region_schema}}, generation,
                                              std::move(regions.error()));
        }
        std::vector<SubjectObservation> observations;
        observations.reserve(regions->size());
        for (const auto &region : *regions) {
            const auto allocation = reinterpret_cast<std::uintptr_t>(region.AllocationBase);
            const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            observations.push_back(SubjectObservation {
                .subject = memory_region_subject(process, static_cast<std::uint64_t>(allocation),
                                                 static_cast<std::uint64_t>(base)),
                .eager_fields = {
                    {.field_id = 1, .value = integer(static_cast<std::uint64_t>(region.RegionSize))},
                    {.field_id = 2, .value = integer(static_cast<std::uint64_t>(region.State))},
                    {.field_id = 3, .value = integer(static_cast<std::uint64_t>(region.Type))},
                    {.field_id = 4, .value = integer(static_cast<std::uint64_t>(region.Protect))},
                    {.field_id = 5,
                     .value = make_fact(region.State == MEM_COMMIT && readable_protection(region.Protect))},
                    {.field_id = 6, .value = integer(static_cast<std::uint64_t>(scan_permissions(region.Protect)))}}});
        }
        return make_inventory_snapshot(process.peer, SchemaId {std::string {memory_region_schema}}, process, generation,
                                       std::move(observations));
    }

    std::expected<std::filesystem::path, ProviderError>
    resolve_process_image_path(const SubjectKey &process, const std::uint64_t deadline_unix_ms) {
        auto handle = open_verified_process(process, PROCESS_QUERY_LIMITED_INFORMATION, deadline_unix_ms);
        if (!handle) {
            return std::unexpected(std::move(handle.error()));
        }
        std::wstring path(32'768U, L'\0');
        DWORD size = static_cast<DWORD>(path.size());
        if (QueryFullProcessImageNameW(handle->value, 0, path.data(), &size) == FALSE) {
            return std::unexpected(win32_error("QueryFullProcessImageNameW", "failed to resolve process image path"));
        }
        path.resize(size);
        if (auto deadline = check_deadline(deadline_unix_ms, "process image path"); !deadline) {
            return std::unexpected(std::move(deadline.error()));
        }
        return std::filesystem::path {path};
    }

    std::expected<FrozenValue, ProviderError> read_process_signer(const SubjectKey &process,
                                                                  const std::uint64_t deadline_unix_ms) {
        auto path = resolve_process_image_path(process, deadline_unix_ms);
        if (!path) {
            return std::unexpected(std::move(path.error()));
        }
        return signer_for_path(*path, deadline_unix_ms);
    }

    std::expected<FrozenValue, ProviderError> read_image_signer(const std::filesystem::path &path,
                                                                const std::uint64_t deadline_unix_ms) {
        return signer_for_path(path, deadline_unix_ms);
    }

    FactResponse dispatch_fact(const FactRequest &request) {
        FactResponse response {
            .request_id = request.request_id,
            .subject = request.subject,
            .status = FactTerminalStatus::failed,
            .value = std::nullopt,
            .returned_schema = std::nullopt,
            .diagnostic = std::nullopt,
        };
        if (request.request_id.empty() || request.route.provider != provider_name || request.route.fact.empty() ||
            request.expected_schema.empty() || request.expected_schema_hash.empty() || !request.subject.valid()) {
            const auto failure = error(ProviderErrorCode::invalid_request, "fact dispatch",
                                       "request identity, route, schema, or subject is invalid");
            response.status = terminal_status(failure.code);
            response.diagnostic = provider_diagnostic(failure);
            return response;
        }

        const auto descriptor = find_windows_fact_descriptor(request.subject.descriptor, request.route.fact);
        if (!descriptor.has_value()) {
            const auto failure =
                error(ProviderErrorCode::unsupported, "fact dispatch", "fact route has no provider descriptor");
            response.status = terminal_status(failure.code);
            response.diagnostic = provider_diagnostic(failure);
            return response;
        }
        const SchemaIdentity requested_schema {.id = request.expected_schema,
                                               .canonical_hash = request.expected_schema_hash};
        if (descriptor->value_schema != requested_schema) {
            const auto failure = error(ProviderErrorCode::invalid_request, "fact dispatch",
                                       "requested schema identity does not match the provider descriptor");
            response.status = terminal_status(failure.code);
            response.diagnostic = provider_diagnostic(failure);
            return response;
        }
        if (expired(request.deadline_unix_ms)) {
            const auto failure =
                error(ProviderErrorCode::timed_out, "fact dispatch", "request deadline expired before dispatch");
            response.status = terminal_status(failure.code);
            response.diagnostic = provider_diagnostic(failure);
            return response;
        }

        std::expected<FrozenValue, ProviderError> result =
            std::unexpected(error(ProviderErrorCode::unsupported, "fact dispatch", "subject type is not supported"));
        if (request.subject.descriptor.value == process_schema) {
            result = resolve_process_fact(request);
        } else if (request.subject.descriptor.value == image_schema) {
            result = resolve_image_fact(request);
        }

        if (!result) {
            response.status = terminal_status(result.error().code);
            response.diagnostic = provider_diagnostic(result.error());
            return response;
        }
        if (result->canonical_digest.empty() || !value_matches_schema(result->value, descriptor->value_schema.id)) {
            const auto failure = error(ProviderErrorCode::malformed, "fact dispatch",
                                       "provider value does not match its authoritative descriptor");
            response.status = terminal_status(failure.code);
            response.diagnostic = provider_diagnostic(failure);
            return response;
        }
        response.status = FactTerminalStatus::value;
        response.value = std::move(result->value);
        response.returned_schema = descriptor->value_schema;
        return response;
    }

} // namespace rule_engine::python::windows
