#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <string_view>

namespace {
    struct UniqueHandle {
        HANDLE handle {};

        explicit UniqueHandle(const HANDLE value) noexcept: handle {value} {}
        ~UniqueHandle() noexcept {
            if (handle != nullptr) {
                CloseHandle(handle);
            }
        }

        UniqueHandle(const UniqueHandle &) = delete;
        UniqueHandle &operator=(const UniqueHandle &) = delete;
        UniqueHandle(UniqueHandle &&) = delete;
        UniqueHandle &operator=(UniqueHandle &&) = delete;
    };

    [[nodiscard]] std::wstring current_executable_path() {
        std::array<wchar_t, 32768u> buffer {};
        const auto size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (size == 0u || size >= buffer.size()) {
            return {};
        }
        return std::wstring {buffer.data(), size};
    }

    [[nodiscard]] std::wstring sibling_executable_path(const std::wstring_view executable_name) {
        auto path = current_executable_path();
        if (path.empty()) {
            return {};
        }

        const auto separator = path.find_last_of(L"\\/");
        if (separator == std::wstring::npos) {
            return std::wstring {executable_name};
        }

        path.resize(separator + 1u);
        path += executable_name;
        return path;
    }

    [[nodiscard]] bool file_exists(const std::wstring &path) {
        const auto attributes = GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0u;
    }
} // namespace

TEST_CASE("server client model exposes rule_engine_client executable") {
    const auto client_path = sibling_executable_path(L"rule_engine_client.exe");
    REQUIRE_FALSE(client_path.empty());
    CHECK(file_exists(client_path));
}

TEST_CASE("benchmark model exposes rule_engine_benchmark executable") {
    const auto benchmark_path = sibling_executable_path(L"rule_engine_benchmark.exe");
    REQUIRE_FALSE(benchmark_path.empty());
    CHECK(file_exists(benchmark_path));
}

TEST_CASE("Windows abort probe exits without opening an interactive CRT dialog") {
    const auto probe_path = sibling_executable_path(L"rule_engine_abort_probe.exe");
    REQUIRE_FALSE(probe_path.empty());

    auto command_line = L"\"" + probe_path + L"\"";
    STARTUPINFOW startup {};
    startup.cb = static_cast<DWORD>(sizeof(startup));
    PROCESS_INFORMATION process_info {};

    const auto created = CreateProcessW(nullptr,
                                        command_line.data(),
                                        nullptr,
                                        nullptr,
                                        FALSE,
                                        CREATE_NO_WINDOW,
                                        nullptr,
                                        nullptr,
                                        &startup,
                                        &process_info);
    REQUIRE(created != FALSE);

    const UniqueHandle process {process_info.hProcess};
    const UniqueHandle thread {process_info.hThread};

    constexpr DWORD timeout_ms = 5000u;
    const auto wait_result = WaitForSingleObject(process.handle, timeout_ms);
    if (wait_result == WAIT_TIMEOUT) {
        TerminateProcess(process.handle, 0xC0DEu);
        FAIL("abort probe blocked, likely behind a Windows CRT abort dialog");
    }

    REQUIRE(wait_result == WAIT_OBJECT_0);

    DWORD exit_code {};
    REQUIRE(GetExitCodeProcess(process.handle, &exit_code) != FALSE);
    CHECK(exit_code != STILL_ACTIVE);
    CHECK(exit_code != 0u);
}
