#include <rule_engine/windows/process_provider.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <sddl.h>
#include <SoftPub.h>
#include <TlHelp32.h>
#include <WinTrust.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {
    using namespace std::chrono_literals;

    struct UniqueHandle {
        HANDLE handle {nullptr};
        explicit UniqueHandle(HANDLE value) noexcept: handle {value} {}
        ~UniqueHandle() noexcept {
            if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }
        UniqueHandle(const UniqueHandle &) = delete;
        UniqueHandle &operator=(const UniqueHandle &) = delete;
        UniqueHandle(UniqueHandle &&) = delete;
        UniqueHandle &operator=(UniqueHandle &&) = delete;
    };

    struct LocalMemory {
        HLOCAL handle {nullptr};
        explicit LocalMemory(HLOCAL value) noexcept: handle {value} {}
        ~LocalMemory() noexcept {
            if (handle != nullptr) {
                LocalFree(handle);
            }
        }
        LocalMemory(const LocalMemory &) = delete;
        LocalMemory &operator=(const LocalMemory &) = delete;
        LocalMemory(LocalMemory &&) = delete;
        LocalMemory &operator=(LocalMemory &&) = delete;
    };

    struct ProcessEntry {
        std::uint32_t pid {};
        std::uint32_t parent_pid {};
        std::uint32_t thread_count {};
        std::wstring name;
    };

    struct RemoteUnicodeString {
        USHORT length {};
        USHORT maximum_length {};
        wchar_t *buffer {};
    };

    struct RemoteProcessParametersPrefix {
        std::byte reserved1[16] {};
        void *reserved2[10] {};
        RemoteUnicodeString image_path_name;
        RemoteUnicodeString command_line;
    };

    struct RemotePebPrefix {
        std::byte reserved1[2] {};
        std::byte being_debugged {};
        std::byte reserved2[1] {};
        void *reserved3[2] {};
        void *ldr {};
        RemoteProcessParametersPrefix *process_parameters {};
    };

    struct ProcessBasicInformation {
        void *reserved1 {};
        RemotePebPrefix *peb_base_address {};
        void *reserved2[2] {};
        std::uintptr_t unique_process_id {};
        void *reserved3 {};
    };

    struct MemoryRegionCounts {
        std::uint64_t total {};
        std::uint64_t readable {};
    };

    using NtQueryInformationProcessFn = LONG(WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    using IsWow64Process2Fn = BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *);

    [[nodiscard]] bool nt_success(const LONG status) noexcept { return status >= 0; }

    [[nodiscard]] NtQueryInformationProcessFn nt_query_information_process() noexcept {
        const auto module = GetModuleHandleW(L"ntdll.dll");
        if (module == nullptr) {
            return nullptr;
        }
        const auto address = GetProcAddress(module, "NtQueryInformationProcess");
        NtQueryInformationProcessFn function {};
        std::memcpy(std::addressof(function), std::addressof(address), sizeof(function));
        return function;
    }

    [[nodiscard]] IsWow64Process2Fn is_wow64_process2() noexcept {
        const auto module = GetModuleHandleW(L"kernel32.dll");
        if (module == nullptr) {
            return nullptr;
        }
        const auto address = GetProcAddress(module, "IsWow64Process2");
        if (address == nullptr) {
            return nullptr;
        }
        IsWow64Process2Fn function {};
        std::memcpy(std::addressof(function), std::addressof(address), sizeof(function));
        return function;
    }

    [[nodiscard]] std::string architecture_name_from_machine(const USHORT machine) {
        switch (machine) {
            case IMAGE_FILE_MACHINE_I386: return "x86";
            case IMAGE_FILE_MACHINE_AMD64: return "x64";
            case IMAGE_FILE_MACHINE_ARMNT: return "arm";
            case IMAGE_FILE_MACHINE_ARM64: return "arm64";
            default: return "unknown";
        }
    }

    [[nodiscard]] std::string native_architecture_name() {
        SYSTEM_INFO info {};
        GetNativeSystemInfo(std::addressof(info));
        switch (info.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_INTEL: return "x86";
            case PROCESSOR_ARCHITECTURE_AMD64: return "x64";
            case PROCESSOR_ARCHITECTURE_ARM: return "arm";
            case PROCESSOR_ARCHITECTURE_ARM64: return "arm64";
            default: return "unknown";
        }
    }

    [[nodiscard]] std::string integrity_level_name(const DWORD rid) {
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
        if (rid == SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
            return "protected";
        }
        return "unknown";
    }

    [[nodiscard]] std::optional<std::uint32_t> parse_pid_subject(const std::string_view subject_id) noexcept {
        constexpr std::string_view prefix {"pid:"};
        if (!subject_id.starts_with(prefix)) {
            return std::nullopt;
        }

        std::uint32_t pid {};
        const auto suffix = subject_id.substr(prefix.size());
        const auto *first = suffix.data();
        const auto *last = first + suffix.size();
        const auto [ptr, ec] = std::from_chars(first, last, pid);
        if (ec != std::errc {} || ptr != last) {
            return std::nullopt;
        }
        return pid;
    }

    [[nodiscard]] std::optional<std::string> to_utf8(const std::wstring_view value) {
        if (value.empty()) {
            return std::string {};
        }
        if (value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
            return std::nullopt;
        }

        const auto wide_size = static_cast<int>(value.size());
        const auto size = WideCharToMultiByte(CP_UTF8, 0, value.data(), wide_size, nullptr, 0, nullptr, nullptr);
        if (size <= 0) {
            return std::nullopt;
        }

        std::string out(static_cast<std::size_t>(size), '\0');
        const auto written =
            WideCharToMultiByte(CP_UTF8, 0, value.data(), wide_size, out.data(), size, nullptr, nullptr);
        if (written <= 0) {
            return std::nullopt;
        }
        return out;
    }

    [[nodiscard]] std::expected<std::string, rule_engine::ErrorSet> sid_to_string(PSID sid) {
        if (sid == nullptr || IsValidSid(sid) == FALSE) {
            return std::unexpected(rule_engine::single_error("process", "user SID is invalid"));
        }

        wchar_t *sid_text_raw {};
        if (ConvertSidToStringSidW(sid, std::addressof(sid_text_raw)) == FALSE || sid_text_raw == nullptr) {
            return std::unexpected(rule_engine::single_error("process", "ConvertSidToStringSidW failed"));
        }
        LocalMemory sid_text {static_cast<HLOCAL>(sid_text_raw)};
        auto text = to_utf8(sid_text_raw);
        if (!text.has_value()) {
            return std::unexpected(rule_engine::single_error("process", "failed to encode user SID as UTF-8"));
        }
        return *text;
    }

    [[nodiscard]] std::expected<std::string, rule_engine::ErrorSet> sid_to_account_name(PSID sid) {
        if (sid == nullptr || IsValidSid(sid) == FALSE) {
            return std::unexpected(rule_engine::single_error("process", "user SID is invalid"));
        }

        DWORD name_size {};
        DWORD domain_size {};
        SID_NAME_USE name_use {};
        if (LookupAccountSidW(nullptr,
                              sid,
                              nullptr,
                              std::addressof(name_size),
                              nullptr,
                              std::addressof(domain_size),
                              std::addressof(name_use)) == FALSE &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return std::unexpected(rule_engine::single_error("process", "LookupAccountSidW size failed"));
        }
        if (name_size == 0u) {
            return std::unexpected(rule_engine::single_error("process", "LookupAccountSidW returned empty user name"));
        }

        std::wstring name(name_size, L'\0');
        std::wstring domain(domain_size, L'\0');
        if (LookupAccountSidW(nullptr,
                              sid,
                              name.data(),
                              std::addressof(name_size),
                              domain.empty() ? nullptr : domain.data(),
                              std::addressof(domain_size),
                              std::addressof(name_use)) == FALSE) {
            return std::unexpected(rule_engine::single_error("process", "LookupAccountSidW failed"));
        }

        name.resize(name_size);
        domain.resize(domain_size);
        const auto account = domain.empty() ? name : domain + L"\\" + name;
        auto text = to_utf8(account);
        if (!text.has_value()) {
            return std::unexpected(rule_engine::single_error("process", "failed to encode user name as UTF-8"));
        }
        return *text;
    }

    template <typename T>
    [[nodiscard]] std::expected<T, rule_engine::ErrorSet> read_remote_value(HANDLE process, const void *address) {
        T out {};
        SIZE_T bytes_read {};
        if (address == nullptr ||
            ReadProcessMemory(process, address, std::addressof(out), sizeof(out), std::addressof(bytes_read)) ==
                FALSE ||
            bytes_read != sizeof(out)) {
            return std::unexpected(rule_engine::single_error("process", "ReadProcessMemory failed"));
        }
        return out;
    }

    [[nodiscard]] std::expected<std::wstring, rule_engine::ErrorSet>
    read_remote_command_line(HANDLE process, const std::uint32_t pid) {
        if (pid == GetCurrentProcessId()) {
            const auto *command_line = GetCommandLineW();
            if (command_line == nullptr) {
                return std::unexpected(rule_engine::single_error("process", "GetCommandLineW failed"));
            }
            return std::wstring {command_line};
        }

        const auto query = nt_query_information_process();
        if (query == nullptr) {
            return std::unexpected(rule_engine::single_error("process", "NtQueryInformationProcess unavailable"));
        }

        ProcessBasicInformation basic {};
        ULONG returned {};
        constexpr ULONG process_basic_information = 0u;
        const auto status = query(process,
                                  process_basic_information,
                                  std::addressof(basic),
                                  static_cast<ULONG>(sizeof(basic)),
                                  std::addressof(returned));
        if (!nt_success(status) || basic.peb_base_address == nullptr) {
            return std::unexpected(rule_engine::single_error("process", "NtQueryInformationProcess failed"));
        }

        auto peb = read_remote_value<RemotePebPrefix>(process, basic.peb_base_address);
        if (!peb) {
            return std::unexpected(std::move(peb.error()));
        }
        if (peb->process_parameters == nullptr) {
            return std::unexpected(rule_engine::single_error("process", "process parameters unavailable"));
        }

        auto parameters = read_remote_value<RemoteProcessParametersPrefix>(process, peb->process_parameters);
        if (!parameters) {
            return std::unexpected(std::move(parameters.error()));
        }

        const auto command_line = parameters->command_line;
        if (command_line.length == 0u) {
            return std::wstring {};
        }
        if (command_line.buffer == nullptr || (command_line.length % sizeof(wchar_t)) != 0u) {
            return std::unexpected(rule_engine::single_error("process", "invalid process command line buffer"));
        }

        std::wstring out;
        out.resize(command_line.length / sizeof(wchar_t));
        SIZE_T bytes_read {};
        if (ReadProcessMemory(process,
                              command_line.buffer,
                              out.data(),
                              command_line.length,
                              std::addressof(bytes_read)) == FALSE ||
            bytes_read != command_line.length) {
            return std::unexpected(rule_engine::single_error("process", "ReadProcessMemory command line failed"));
        }
        return out;
    }

    [[nodiscard]] std::expected<std::vector<ProcessEntry>, rule_engine::ErrorSet> enumerate_process_entries() {
        UniqueHandle snapshot {CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
        if (snapshot.handle == INVALID_HANDLE_VALUE) {
            return std::unexpected(rule_engine::single_error("process", "CreateToolhelp32Snapshot failed"));
        }

        PROCESSENTRY32W entry {};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot.handle, &entry) == FALSE) {
            return std::unexpected(rule_engine::single_error("process", "Process32FirstW failed"));
        }

        std::vector<ProcessEntry> out;
        do {
            out.push_back(ProcessEntry {
                .pid = static_cast<std::uint32_t>(entry.th32ProcessID),
                .parent_pid = static_cast<std::uint32_t>(entry.th32ParentProcessID),
                .thread_count = static_cast<std::uint32_t>(entry.cntThreads),
                .name = entry.szExeFile,
            });
        } while (Process32NextW(snapshot.handle, &entry) != FALSE);

        return out;
    }

    [[nodiscard]] const ProcessEntry *find_entry(const std::vector<ProcessEntry> &entries, const std::uint32_t pid) {
        const auto found = std::ranges::find_if(entries, [&](const auto &entry) { return entry.pid == pid; });
        if (found == entries.end()) {
            return nullptr;
        }
        return std::addressof(*found);
    }

    [[nodiscard]] rule_engine::Fact make_fact(std::string subject_id,
                                              std::string key,
                                              rule_engine::Value value,
                                              const rule_engine::FactStatus status,
                                              std::string diagnostic = {}) {
        return rule_engine::Fact {
            .subject_id = std::move(subject_id),
            .key = std::move(key),
            .value = std::move(value),
            .status = status,
            .diagnostic = std::move(diagnostic),
            .ttl = 0s,
        };
    }

    [[nodiscard]] rule_engine::Fact unavailable_fact(const rule_engine::windows::ProcessFactKey &key,
                                                     std::string diagnostic) {
        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::undefined(),
                         rule_engine::FactStatus::unavailable,
                         std::move(diagnostic));
    }

    [[nodiscard]] rule_engine::Fact process_path_fact(const rule_engine::windows::ProcessFactKey &key) {
        auto path = rule_engine::windows::resolve_process_image_path(key.subject_id);
        if (!path) {
            const auto diagnostic = path.error().diagnostics.empty() ? std::string {"failed to resolve process image"}
                                                                     : path.error().diagnostics[0].message;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::access_denied,
                             diagnostic);
        }
        return make_fact(
            key.subject_id, key.key, rule_engine::Value::string(path->string()), rule_engine::FactStatus::available);
    }

    [[nodiscard]] rule_engine::Fact session_id_fact(const rule_engine::windows::ProcessFactKey &key,
                                                    const std::uint32_t pid) {
        DWORD session_id {};
        if (ProcessIdToSessionId(static_cast<DWORD>(pid), &session_id) == FALSE) {
            return unavailable_fact(key, "ProcessIdToSessionId failed");
        }
        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::integer(static_cast<std::int64_t>(session_id)),
                         rule_engine::FactStatus::available);
    }

    [[nodiscard]] std::string win32_diagnostic(std::string_view operation, DWORD error);

    [[nodiscard]] rule_engine::Fact command_line_fact(const rule_engine::windows::ProcessFactKey &key,
                                                      const std::uint32_t pid) {
        UniqueHandle process {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid))};
        if (process.handle == nullptr) {
            const auto status = GetLastError() == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                                      : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id, key.key, rule_engine::Value::undefined(), status, "OpenProcess failed");
        }

        auto command_line = read_remote_command_line(process.handle, pid);
        if (!command_line) {
            const auto diagnostic = command_line.error().diagnostics.empty()
                                        ? std::string {"failed to read process command line"}
                                        : command_line.error().diagnostics[0].message;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             diagnostic);
        }

        auto text = to_utf8(*command_line);
        if (!text.has_value()) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             "failed to encode process command line as UTF-8");
        }
        return make_fact(key.subject_id, key.key, rule_engine::Value::string(*text), rule_engine::FactStatus::available);
    }

    [[nodiscard]] rule_engine::Fact architecture_fact(const rule_engine::windows::ProcessFactKey &key,
                                                      const std::uint32_t pid) {
        UniqueHandle process {OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid))};
        if (process.handle == nullptr) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             win32_diagnostic("OpenProcess for process architecture", error));
        }

        const auto query_wow64_2 = is_wow64_process2();
        if (query_wow64_2 != nullptr) {
            USHORT process_machine {};
            USHORT native_machine {};
            if (query_wow64_2(process.handle, std::addressof(process_machine), std::addressof(native_machine)) ==
                FALSE) {
                return make_fact(key.subject_id,
                                 key.key,
                                 rule_engine::Value::undefined(),
                                 rule_engine::FactStatus::unavailable,
                                 win32_diagnostic("IsWow64Process2", GetLastError()));
            }
            const auto machine = process_machine == IMAGE_FILE_MACHINE_UNKNOWN ? native_machine : process_machine;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::string(architecture_name_from_machine(machine)),
                             rule_engine::FactStatus::available);
        }

        BOOL is_wow64 {};
        if (IsWow64Process(process.handle, std::addressof(is_wow64)) == FALSE) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             win32_diagnostic("IsWow64Process", GetLastError()));
        }
        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::string(is_wow64 != FALSE ? std::string {"x86"}
                                                                       : native_architecture_name()),
                         rule_engine::FactStatus::available);
    }

    [[nodiscard]] rule_engine::Fact integrity_level_fact(const rule_engine::windows::ProcessFactKey &key,
                                                         const std::uint32_t pid) {
        UniqueHandle process {OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid))};
        if (process.handle == nullptr) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             win32_diagnostic("OpenProcess for process integrity level", error));
        }

        HANDLE token_handle {};
        if (OpenProcessToken(process.handle, TOKEN_QUERY, std::addressof(token_handle)) == FALSE) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             win32_diagnostic("OpenProcessToken", error));
        }
        UniqueHandle token {token_handle};

        DWORD required_size {};
        if (GetTokenInformation(token.handle,
                                TokenIntegrityLevel,
                                nullptr,
                                0u,
                                std::addressof(required_size)) == FALSE) {
            const auto error = GetLastError();
            if (error != ERROR_INSUFFICIENT_BUFFER) {
                return make_fact(key.subject_id,
                                 key.key,
                                 rule_engine::Value::undefined(),
                                 rule_engine::FactStatus::unavailable,
                                 win32_diagnostic("GetTokenInformation size", error));
            }
        }
        if (required_size == 0u) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             "GetTokenInformation returned empty integrity label");
        }

        std::vector<std::byte> buffer(required_size);
        if (GetTokenInformation(token.handle,
                                TokenIntegrityLevel,
                                buffer.data(),
                                required_size,
                                std::addressof(required_size)) == FALSE) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             win32_diagnostic("GetTokenInformation integrity label", GetLastError()));
        }

        const auto *label = reinterpret_cast<const TOKEN_MANDATORY_LABEL *>(buffer.data());
        auto *sid = label->Label.Sid;
        if (sid == nullptr || IsValidSid(sid) == FALSE) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             "process integrity label SID is invalid");
        }

        const auto *count = GetSidSubAuthorityCount(sid);
        if (count == nullptr || *count == 0u) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             "process integrity label SID has no sub-authorities");
        }

        const auto sub_authority_index = static_cast<DWORD>(*count) - 1u;
        const auto *rid = GetSidSubAuthority(sid, sub_authority_index);
        if (rid == nullptr) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             "process integrity RID is unavailable");
        }

        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::string(integrity_level_name(*rid)),
                         rule_engine::FactStatus::available);
    }

    [[nodiscard]] rule_engine::Fact user_detail_fact(const rule_engine::windows::ProcessFactKey &key,
                                                     const std::uint32_t pid) {
        UniqueHandle process {OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid))};
        if (process.handle == nullptr) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             win32_diagnostic("OpenProcess for process user details", error));
        }

        HANDLE token_handle {};
        if (OpenProcessToken(process.handle, TOKEN_QUERY, std::addressof(token_handle)) == FALSE) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             win32_diagnostic("OpenProcessToken", error));
        }
        UniqueHandle token {token_handle};

        DWORD required_size {};
        if (GetTokenInformation(token.handle, TokenUser, nullptr, 0u, std::addressof(required_size)) == FALSE) {
            const auto error = GetLastError();
            if (error != ERROR_INSUFFICIENT_BUFFER) {
                return make_fact(key.subject_id,
                                 key.key,
                                 rule_engine::Value::undefined(),
                                 rule_engine::FactStatus::unavailable,
                                 win32_diagnostic("GetTokenInformation user size", error));
            }
        }
        if (required_size == 0u) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             "GetTokenInformation returned empty user token");
        }

        std::vector<std::byte> buffer(required_size);
        if (GetTokenInformation(token.handle,
                                TokenUser,
                                buffer.data(),
                                required_size,
                                std::addressof(required_size)) == FALSE) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             win32_diagnostic("GetTokenInformation user", GetLastError()));
        }

        const auto *user = reinterpret_cast<const TOKEN_USER *>(buffer.data());
        auto *sid = user->User.Sid;
        if (sid == nullptr || IsValidSid(sid) == FALSE) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             "process user SID is invalid");
        }

        std::expected<std::string, rule_engine::ErrorSet> value =
            key.key == "process.user.sid" ? sid_to_string(sid) : sid_to_account_name(sid);
        if (!value) {
            const auto diagnostic = value.error().diagnostics.empty() ? std::string {"failed to resolve user details"}
                                                                      : value.error().diagnostics[0].message;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             diagnostic);
        }

        return make_fact(key.subject_id, key.key, rule_engine::Value::string(*value), rule_engine::FactStatus::available);
    }

    [[nodiscard]] std::string token_type_name(const TOKEN_TYPE type) {
        switch (type) {
            case TokenPrimary: return "primary";
            case TokenImpersonation: return "impersonation";
            default: return "unknown";
        }
    }

    [[nodiscard]] rule_engine::Fact token_metadata_fact(const rule_engine::windows::ProcessFactKey &key,
                                                        const std::uint32_t pid) {
        UniqueHandle process {OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid))};
        if (process.handle == nullptr) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             win32_diagnostic("OpenProcess for process token metadata", error));
        }

        HANDLE token_handle {};
        if (OpenProcessToken(process.handle, TOKEN_QUERY, std::addressof(token_handle)) == FALSE) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             win32_diagnostic("OpenProcessToken", error));
        }
        UniqueHandle token {token_handle};

        DWORD returned_size {};
        if (key.key == "process.token.elevated") {
            TOKEN_ELEVATION elevation {};
            if (GetTokenInformation(token.handle,
                                    TokenElevation,
                                    std::addressof(elevation),
                                    static_cast<DWORD>(sizeof(elevation)),
                                    std::addressof(returned_size)) == FALSE) {
                return make_fact(key.subject_id,
                                 key.key,
                                 rule_engine::Value::undefined(),
                                 rule_engine::FactStatus::unavailable,
                                 win32_diagnostic("GetTokenInformation token elevation", GetLastError()));
            }
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::boolean(elevation.TokenIsElevated != 0u),
                             rule_engine::FactStatus::available);
        }

        TOKEN_TYPE token_type {};
        if (GetTokenInformation(token.handle,
                                TokenType,
                                std::addressof(token_type),
                                static_cast<DWORD>(sizeof(token_type)),
                                std::addressof(returned_size)) == FALSE) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             win32_diagnostic("GetTokenInformation token type", GetLastError()));
        }
        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::string(token_type_name(token_type)),
                         rule_engine::FactStatus::available);
    }

    [[nodiscard]] std::string win32_diagnostic(const std::string_view operation, const DWORD error) {
        return std::string {operation} + " failed: win32=" + std::to_string(error);
    }

    [[nodiscard]] rule_engine::Fact module_snapshot_failure_fact(const rule_engine::windows::ProcessFactKey &key,
                                                                 const std::string_view operation,
                                                                 const DWORD error) {
        const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                         : rule_engine::FactStatus::unavailable;
        auto diagnostic = win32_diagnostic(operation, error);
        if (error == ERROR_PARTIAL_COPY) {
            diagnostic = "partial process module data unavailable: " + diagnostic;
        }
        return make_fact(key.subject_id, key.key, rule_engine::Value::undefined(), status, std::move(diagnostic));
    }

    [[nodiscard]] rule_engine::Fact loaded_modules_fact(const rule_engine::windows::ProcessFactKey &key,
                                                        const std::uint32_t pid) {
        UniqueHandle snapshot {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, static_cast<DWORD>(pid))};
        if (snapshot.handle == INVALID_HANDLE_VALUE) {
            return module_snapshot_failure_fact(key, "CreateToolhelp32Snapshot modules", GetLastError());
        }

        MODULEENTRY32W entry {};
        entry.dwSize = static_cast<DWORD>(sizeof(entry));
        if (Module32FirstW(snapshot.handle, std::addressof(entry)) == FALSE) {
            const auto error = GetLastError();
            if (error == ERROR_NO_MORE_FILES) {
                if (key.key == "process.modules.count") {
                    return make_fact(key.subject_id, key.key, rule_engine::Value::integer(0), rule_engine::FactStatus::available);
                }
                return make_fact(key.subject_id,
                                 key.key,
                                 rule_engine::Value::array({}),
                                 rule_engine::FactStatus::available);
            }
            return module_snapshot_failure_fact(key, "Module32FirstW", error);
        }

        std::vector<rule_engine::Value> names;
        do {
            const auto name = to_utf8(entry.szModule);
            if (!name.has_value()) {
                return make_fact(key.subject_id,
                                 key.key,
                                 rule_engine::Value::undefined(),
                                 rule_engine::FactStatus::unavailable,
                                 "failed to encode module name as UTF-8");
            }
            names.push_back(rule_engine::Value::string(*name));
            entry.dwSize = static_cast<DWORD>(sizeof(entry));
        } while (Module32NextW(snapshot.handle, std::addressof(entry)) != FALSE);

        if (key.key == "process.modules.count") {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::integer(static_cast<std::int64_t>(names.size())),
                             rule_engine::FactStatus::available);
        }
        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::array(std::move(names)),
                         rule_engine::FactStatus::available);
    }

    [[nodiscard]] bool is_readable_protection(const DWORD protect) noexcept {
        if ((protect & PAGE_GUARD) != 0u || (protect & PAGE_NOACCESS) != 0u) {
            return false;
        }

        constexpr DWORD protection_mask = 0xffu;
        switch (protect & protection_mask) {
            case PAGE_READONLY:
            case PAGE_READWRITE:
            case PAGE_WRITECOPY:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY: return true;
            default: return false;
        }
    }

    [[nodiscard]] std::string memory_state_name(const DWORD state) {
        switch (state) {
            case MEM_COMMIT: return "commit";
            case MEM_RESERVE: return "reserve";
            case MEM_FREE: return "free";
            default: return "unknown";
        }
    }

    [[nodiscard]] std::string memory_type_name(const DWORD type) {
        switch (type) {
            case MEM_IMAGE: return "image";
            case MEM_MAPPED: return "mapped";
            case MEM_PRIVATE: return "private";
            default: return "unknown";
        }
    }

    [[nodiscard]] std::string memory_protection_name(const DWORD protect) {
        std::string prefix;
        if ((protect & PAGE_GUARD) != 0u) {
            prefix += "guard|";
        }
        if ((protect & PAGE_NOCACHE) != 0u) {
            prefix += "nocache|";
        }
        if ((protect & PAGE_WRITECOMBINE) != 0u) {
            prefix += "writecombine|";
        }

        constexpr DWORD protection_mask = 0xffu;
        switch (protect & protection_mask) {
            case PAGE_NOACCESS: return prefix + "noaccess";
            case PAGE_READONLY: return prefix + "r";
            case PAGE_READWRITE: return prefix + "rw";
            case PAGE_WRITECOPY: return prefix + "wc";
            case PAGE_EXECUTE: return prefix + "x";
            case PAGE_EXECUTE_READ: return prefix + "rx";
            case PAGE_EXECUTE_READWRITE: return prefix + "rwx";
            case PAGE_EXECUTE_WRITECOPY: return prefix + "xwc";
            default: return prefix + "unknown";
        }
    }

    [[nodiscard]] std::optional<std::int64_t> uintptr_to_i64(const std::uintptr_t value) noexcept {
        if (value > static_cast<std::uintptr_t>((std::numeric_limits<std::int64_t>::max)())) {
            return std::nullopt;
        }
        return static_cast<std::int64_t>(value);
    }

    [[nodiscard]] std::expected<MemoryRegionCounts, rule_engine::ErrorSet>
    query_memory_region_counts(HANDLE process) {
        SYSTEM_INFO info {};
        GetNativeSystemInfo(std::addressof(info));

        auto address = reinterpret_cast<std::uintptr_t>(info.lpMinimumApplicationAddress);
        const auto max_address = reinterpret_cast<std::uintptr_t>(info.lpMaximumApplicationAddress);
        MemoryRegionCounts counts;
        while (address < max_address) {
            MEMORY_BASIC_INFORMATION region {};
            const auto bytes = VirtualQueryEx(process,
                                              reinterpret_cast<LPCVOID>(address),
                                              std::addressof(region),
                                              static_cast<SIZE_T>(sizeof(region)));
            if (bytes == 0u) {
                const auto error = GetLastError();
                if (error == ERROR_INVALID_PARAMETER) {
                    break;
                }
                return std::unexpected(rule_engine::single_error("process", win32_diagnostic("VirtualQueryEx", error)));
            }

            ++counts.total;
            if (region.State == MEM_COMMIT && is_readable_protection(region.Protect)) {
                ++counts.readable;
            }

            const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            const auto size = static_cast<std::uintptr_t>(region.RegionSize);
            if (size == 0u || base > (std::numeric_limits<std::uintptr_t>::max)() - size) {
                break;
            }

            const auto next = base + size;
            if (next <= address) {
                break;
            }
            address = next;
        }

        return counts;
    }

    [[nodiscard]] rule_engine::Fact memory_region_count_fact(const rule_engine::windows::ProcessFactKey &key,
                                                             const std::uint32_t pid) {
        UniqueHandle process {OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(pid))};
        if (process.handle == nullptr) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             win32_diagnostic("OpenProcess for process memory regions", error));
        }

        auto counts = query_memory_region_counts(process.handle);
        if (!counts) {
            const auto diagnostic = counts.error().diagnostics.empty() ? std::string {"failed to query memory regions"}
                                                                       : counts.error().diagnostics[0].message;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             "partial process memory region data unavailable: " + diagnostic);
        }

        const auto value = key.key == "process.memory.regions.count" ? counts->total : counts->readable;
        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::integer(static_cast<std::int64_t>(value)),
                         rule_engine::FactStatus::available);
    }

    [[nodiscard]] std::expected<rule_engine::Value, rule_engine::ErrorSet>
    memory_region_object(const MEMORY_BASIC_INFORMATION &region) {
        const auto base = uintptr_to_i64(reinterpret_cast<std::uintptr_t>(region.BaseAddress));
        const auto size = uintptr_to_i64(static_cast<std::uintptr_t>(region.RegionSize));
        if (!base.has_value() || !size.has_value()) {
            return std::unexpected(rule_engine::single_error("process", "memory region does not fit integer value"));
        }

        return rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
            rule_engine::ObjectEntry {.key = "base", .value = rule_engine::Value::integer(*base)},
            rule_engine::ObjectEntry {.key = "size", .value = rule_engine::Value::integer(*size)},
            rule_engine::ObjectEntry {.key = "state", .value = rule_engine::Value::string(memory_state_name(region.State))},
            rule_engine::ObjectEntry {
                .key = "protection",
                .value = rule_engine::Value::string(memory_protection_name(region.Protect)),
            },
            rule_engine::ObjectEntry {.key = "type", .value = rule_engine::Value::string(memory_type_name(region.Type))},
            rule_engine::ObjectEntry {
                .key = "readable",
                .value = rule_engine::Value::boolean(region.State == MEM_COMMIT && is_readable_protection(region.Protect)),
            },
            rule_engine::ObjectEntry {.key = "scan_space", .value = rule_engine::Value::string("process.memory")},
        });
    }

    [[nodiscard]] std::expected<std::vector<rule_engine::Value>, rule_engine::ErrorSet>
    query_memory_region_values(HANDLE process) {
        SYSTEM_INFO info {};
        GetNativeSystemInfo(std::addressof(info));

        auto address = reinterpret_cast<std::uintptr_t>(info.lpMinimumApplicationAddress);
        const auto max_address = reinterpret_cast<std::uintptr_t>(info.lpMaximumApplicationAddress);
        std::vector<rule_engine::Value> regions;
        while (address < max_address) {
            MEMORY_BASIC_INFORMATION region {};
            const auto bytes = VirtualQueryEx(process,
                                              reinterpret_cast<LPCVOID>(address),
                                              std::addressof(region),
                                              static_cast<SIZE_T>(sizeof(region)));
            if (bytes == 0u) {
                const auto error = GetLastError();
                if (error == ERROR_INVALID_PARAMETER) {
                    break;
                }
                return std::unexpected(rule_engine::single_error("process", win32_diagnostic("VirtualQueryEx", error)));
            }

            auto object = memory_region_object(region);
            if (!object) {
                return std::unexpected(std::move(object.error()));
            }
            regions.push_back(std::move(*object));

            const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
            const auto size = static_cast<std::uintptr_t>(region.RegionSize);
            if (size == 0u || base > (std::numeric_limits<std::uintptr_t>::max)() - size) {
                break;
            }

            const auto next = base + size;
            if (next <= address) {
                break;
            }
            address = next;
        }

        return regions;
    }

    [[nodiscard]] rule_engine::Fact memory_region_array_fact(const rule_engine::windows::ProcessFactKey &key,
                                                             const std::uint32_t pid) {
        UniqueHandle process {OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(pid))};
        if (process.handle == nullptr) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             win32_diagnostic("OpenProcess for process memory regions", error));
        }

        auto regions = query_memory_region_values(process.handle);
        if (!regions) {
            const auto diagnostic = regions.error().diagnostics.empty() ? std::string {"failed to query memory regions"}
                                                                        : regions.error().diagnostics[0].message;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             "partial process memory region data unavailable: " + diagnostic);
        }

        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::array(std::move(*regions)),
                         rule_engine::FactStatus::available);
    }

    [[nodiscard]] std::string wintrust_diagnostic(const std::string_view operation, const LONG status) {
        return std::string {operation} + " failed: status=" + std::to_string(status);
    }

    [[nodiscard]] bool is_wintrust_access_denied(const LONG status) noexcept {
        return static_cast<HRESULT>(status) == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }

    [[nodiscard]] bool is_wintrust_file_unavailable(const LONG status) noexcept {
        const auto result = static_cast<HRESULT>(status);
        return result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
               result == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) ||
               result == HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION);
    }

    [[nodiscard]] std::string signer_status_name(const LONG status) {
        const auto result = static_cast<HRESULT>(status);
        if (result == static_cast<HRESULT>(ERROR_SUCCESS)) {
            return "trusted";
        }
        if (result == TRUST_E_NOSIGNATURE || result == TRUST_E_SUBJECT_FORM_UNKNOWN ||
            result == TRUST_E_PROVIDER_UNKNOWN) {
            return "unsigned";
        }
        if (result == CERT_E_EXPIRED) {
            return "expired";
        }
        if (result == CERT_E_REVOKED || result == CRYPT_E_REVOKED) {
            return "revoked";
        }
        if (result == CERT_E_UNTRUSTEDROOT) {
            return "untrusted_root";
        }
        if (result == TRUST_E_BAD_DIGEST) {
            return "bad_digest";
        }
        if (result == CERT_E_CHAINING) {
            return "chain_error";
        }
        return "untrusted";
    }

    [[nodiscard]] LONG verify_authenticode_status(const std::filesystem::path &path) {
        WINTRUST_FILE_INFO file_info {};
        file_info.cbStruct = static_cast<DWORD>(sizeof(file_info));
        file_info.pcwszFilePath = path.c_str();

        WINTRUST_DATA trust_data {};
        trust_data.cbStruct = static_cast<DWORD>(sizeof(trust_data));
        trust_data.dwUIChoice = WTD_UI_NONE;
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust_data.dwUnionChoice = WTD_CHOICE_FILE;
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        trust_data.pFile = std::addressof(file_info);

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const auto status = WinVerifyTrust(nullptr, std::addressof(action), std::addressof(trust_data));
        if (trust_data.hWVTStateData != nullptr) {
            trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            static_cast<void>(WinVerifyTrust(nullptr, std::addressof(action), std::addressof(trust_data)));
        }
        return status;
    }

    [[nodiscard]] rule_engine::Fact handle_count_fact(const rule_engine::windows::ProcessFactKey &key,
                                                      const std::uint32_t pid) {
        UniqueHandle process {OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid))};
        if (process.handle == nullptr) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             win32_diagnostic("OpenProcess for process handle count", error));
        }

        DWORD handle_count {};
        if (GetProcessHandleCount(process.handle, std::addressof(handle_count)) == FALSE) {
            const auto error = GetLastError();
            const auto status = error == ERROR_ACCESS_DENIED ? rule_engine::FactStatus::access_denied
                                                             : rule_engine::FactStatus::unavailable;
            auto diagnostic = win32_diagnostic("GetProcessHandleCount", error);
            if (status == rule_engine::FactStatus::unavailable) {
                diagnostic = "partial process handle data unavailable: " + diagnostic;
            }
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             status,
                             std::move(diagnostic));
        }

        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::integer(static_cast<std::int64_t>(handle_count)),
                         rule_engine::FactStatus::available);
    }

    [[nodiscard]] rule_engine::Fact signer_status_fact(const rule_engine::windows::ProcessFactKey &key) {
        auto path = rule_engine::windows::resolve_process_image_path(key.subject_id);
        if (!path) {
            const auto diagnostic = path.error().diagnostics.empty() ? std::string {"failed to resolve process image"}
                                                                     : path.error().diagnostics[0].message;
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::access_denied,
                             diagnostic);
        }

        const auto status = verify_authenticode_status(*path);
        if (is_wintrust_access_denied(status)) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::access_denied,
                             wintrust_diagnostic("WinVerifyTrust", status));
        }
        if (is_wintrust_file_unavailable(status)) {
            return make_fact(key.subject_id,
                             key.key,
                             rule_engine::Value::undefined(),
                             rule_engine::FactStatus::unavailable,
                             wintrust_diagnostic("WinVerifyTrust", status));
        }

        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::string(signer_status_name(status)),
                         rule_engine::FactStatus::available);
    }
} // namespace

namespace rule_engine::windows {
    std::expected<std::vector<Subject>, ErrorSet> enumerate_process_subjects() {
        auto entries = enumerate_process_entries();
        if (!entries) {
            return std::unexpected(std::move(entries.error()));
        }

        std::vector<Subject> out;
        out.reserve(entries->size());
        for (const auto &entry : *entries) {
            out.push_back(Subject {
                .kind = "process",
                .id = "pid:" + std::to_string(entry.pid),
            });
        }

        return out;
    }

    std::expected<std::vector<Fact>, ErrorSet> read_process_snapshot_facts(const std::span<const ProcessFactKey> keys) {
        auto entries = enumerate_process_entries();
        if (!entries) {
            return std::unexpected(std::move(entries.error()));
        }

        std::vector<Fact> out;
        out.reserve(keys.size());
        for (const auto &key : keys) {
            const auto pid = parse_pid_subject(key.subject_id);
            if (!pid.has_value()) {
                out.push_back(unavailable_fact(key, "unsupported process subject id"));
                continue;
            }

            const auto *entry = find_entry(*entries, *pid);
            if (entry == nullptr) {
                out.push_back(unavailable_fact(key, "process not found"));
                continue;
            }

            if (key.key == "process.pid") {
                out.push_back(make_fact(key.subject_id,
                                        key.key,
                                        Value::integer(static_cast<std::int64_t>(entry->pid)),
                                        FactStatus::available));
                continue;
            }
            if (key.key == "process.parent.pid") {
                out.push_back(make_fact(key.subject_id,
                                        key.key,
                                        Value::integer(static_cast<std::int64_t>(entry->parent_pid)),
                                        FactStatus::available));
                continue;
            }
            if (key.key == "process.thread_count") {
                out.push_back(make_fact(key.subject_id,
                                        key.key,
                                        Value::integer(static_cast<std::int64_t>(entry->thread_count)),
                                        FactStatus::available));
                continue;
            }
            if (key.key == "process.architecture") {
                out.push_back(architecture_fact(key, entry->pid));
                continue;
            }
            if (key.key == "process.integrity_level") {
                out.push_back(integrity_level_fact(key, entry->pid));
                continue;
            }
            if (key.key == "process.user.sid" || key.key == "process.user.name") {
                out.push_back(user_detail_fact(key, entry->pid));
                continue;
            }
            if (key.key == "process.token.elevated" || key.key == "process.token.type") {
                out.push_back(token_metadata_fact(key, entry->pid));
                continue;
            }
            if (key.key == "process.modules.count" || key.key == "process.modules.names") {
                out.push_back(loaded_modules_fact(key, entry->pid));
                continue;
            }
            if (key.key == "process.memory.regions.count" ||
                key.key == "process.memory.regions.readable_count") {
                out.push_back(memory_region_count_fact(key, entry->pid));
                continue;
            }
            if (key.key == "process.memory.regions") {
                out.push_back(memory_region_array_fact(key, entry->pid));
                continue;
            }
            if (key.key == "process.name") {
                const auto name = to_utf8(entry->name);
                if (!name.has_value()) {
                    out.push_back(unavailable_fact(key, "failed to encode process name as UTF-8"));
                    continue;
                }
                out.push_back(make_fact(key.subject_id, key.key, Value::string(*name), FactStatus::available));
                continue;
            }
            if (key.key == "process.path") {
                out.push_back(process_path_fact(key));
                continue;
            }
            if (key.key == "process.session_id") {
                out.push_back(session_id_fact(key, entry->pid));
                continue;
            }
            if (key.key == "process.command_line") {
                out.push_back(command_line_fact(key, entry->pid));
                continue;
            }

            out.push_back(unavailable_fact(key, "unsupported process snapshot fact"));
        }

        return out;
    }

    std::expected<std::vector<Fact>, ErrorSet> read_process_handle_facts(const std::span<const ProcessFactKey> keys) {
        auto entries = enumerate_process_entries();
        if (!entries) {
            return std::unexpected(std::move(entries.error()));
        }

        std::vector<Fact> out;
        out.reserve(keys.size());
        for (const auto &key : keys) {
            const auto pid = parse_pid_subject(key.subject_id);
            if (!pid.has_value()) {
                out.push_back(unavailable_fact(key, "unsupported process subject id"));
                continue;
            }

            const auto *entry = find_entry(*entries, *pid);
            if (entry == nullptr) {
                out.push_back(unavailable_fact(key, "process not found"));
                continue;
            }

            if (key.key == "process.handles.count") {
                out.push_back(handle_count_fact(key, entry->pid));
                continue;
            }

            out.push_back(unavailable_fact(key, "unsupported process handle fact"));
        }

        return out;
    }

    std::expected<std::vector<Fact>, ErrorSet> read_process_signer_facts(const std::span<const ProcessFactKey> keys) {
        auto entries = enumerate_process_entries();
        if (!entries) {
            return std::unexpected(std::move(entries.error()));
        }

        std::vector<Fact> out;
        out.reserve(keys.size());
        for (const auto &key : keys) {
            const auto pid = parse_pid_subject(key.subject_id);
            if (!pid.has_value()) {
                out.push_back(unavailable_fact(key, "unsupported process subject id"));
                continue;
            }

            const auto *entry = find_entry(*entries, *pid);
            if (entry == nullptr) {
                out.push_back(unavailable_fact(key, "process not found"));
                continue;
            }

            if (key.key == "process.signer.status") {
                out.push_back(signer_status_fact(key));
                continue;
            }

            out.push_back(unavailable_fact(key, "unsupported process signer fact"));
        }

        return out;
    }

    std::expected<std::filesystem::path, ErrorSet> resolve_process_image_path(const std::string_view subject_id) {
        const auto pid = parse_pid_subject(subject_id);
        if (!pid.has_value()) {
            return std::unexpected(single_error("process", "unsupported process subject id"));
        }

        UniqueHandle process {OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(*pid))};
        if (process.handle == nullptr) {
            return std::unexpected(single_error("process", "OpenProcess failed"));
        }

        std::wstring buffer;
        buffer.resize(32768u);
        DWORD size = static_cast<DWORD>(buffer.size());
        if (QueryFullProcessImageNameW(process.handle, 0, buffer.data(), &size) == FALSE || size == 0u) {
            return std::unexpected(single_error("process", "QueryFullProcessImageNameW failed"));
        }
        buffer.resize(size);
        return std::filesystem::path {buffer};
    }
} // namespace rule_engine::windows
