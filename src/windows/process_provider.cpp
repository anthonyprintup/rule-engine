#include <rule_engine/windows/process_provider.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
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

    struct ProcessEntry {
        std::uint32_t pid {};
        std::uint32_t parent_pid {};
        std::wstring name;
    };

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
                out.push_back(unavailable_fact(key, "process command line provider is not implemented in v1"));
                continue;
            }

            out.push_back(unavailable_fact(key, "unsupported process snapshot fact"));
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
