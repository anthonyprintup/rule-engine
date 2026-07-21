#include "rule_engine/python/packaging/worker.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#endif

namespace rule_engine::python::packaging {
    namespace {

        PackagingError launcher_error(const PackagingErrorCode code, std::string message,
                                      std::optional<std::string> subject = std::nullopt) {
            return PackagingError {.code = code, .message = std::move(message), .subject = std::move(subject)};
        }

#ifdef _WIN32
        struct UniqueHandle {
            HANDLE value {INVALID_HANDLE_VALUE};

            UniqueHandle() = default;
            explicit UniqueHandle(const HANDLE handle): value(handle) {}

            ~UniqueHandle() { reset(); }

            UniqueHandle(const UniqueHandle &) = delete;
            UniqueHandle &operator=(const UniqueHandle &) = delete;

            [[nodiscard]] bool valid() const noexcept { return value != nullptr && value != INVALID_HANDLE_VALUE; }

            [[nodiscard]] HANDLE release() noexcept {
                const auto released = value;
                value = INVALID_HANDLE_VALUE;
                return released;
            }

            void reset(const HANDLE replacement = INVALID_HANDLE_VALUE) noexcept {
                if (valid()) {
                    CloseHandle(value);
                }
                value = replacement;
            }
        };

        struct TemporaryDirectory {
            std::filesystem::path path;

            ~TemporaryDirectory() {
                if (!path.empty()) {
                    std::error_code ignored;
                    std::filesystem::remove_all(path, ignored);
                }
            }
        };

        struct AttributeList {
            LPPROC_THREAD_ATTRIBUTE_LIST value {};

            ~AttributeList() {
                if (value != nullptr) {
                    DeleteProcThreadAttributeList(value);
                }
            }
        };

        std::wstring quote_argument(const std::wstring_view argument) {
            if (!argument.empty() && argument.find_first_of(L" \t\"") == std::wstring_view::npos) {
                return std::wstring {argument};
            }
            std::wstring quoted {L'\"'};
            std::size_t slashes = 0U;
            for (const auto character : argument) {
                if (character == L'\\') {
                    ++slashes;
                    continue;
                }
                if (character == L'\"') {
                    quoted.append(slashes * 2U + 1U, L'\\');
                    quoted.push_back(L'\"');
                    slashes = 0U;
                    continue;
                }
                quoted.append(slashes, L'\\');
                slashes = 0U;
                quoted.push_back(character);
            }
            quoted.append(slashes * 2U, L'\\');
            quoted.push_back(L'\"');
            return quoted;
        }

        std::expected<std::filesystem::path, PackagingError>
        create_private_temporary_directory(const std::filesystem::path &configured_root) {
            std::filesystem::path root = configured_root;
            if (root.empty()) {
                std::array<wchar_t, MAX_PATH + 1U> buffer {};
                const auto length = GetTempPathW(static_cast<DWORD>(buffer.size()), buffer.data());
                if (length == 0U || length >= buffer.size()) {
                    return std::unexpected(
                        launcher_error(PackagingErrorCode::filesystem_error, "cannot resolve a worker temporary root"));
                }
                root = std::filesystem::path {std::wstring_view {buffer.data(), length}};
            }
            std::error_code filesystem_error;
            root = std::filesystem::absolute(root, filesystem_error).lexically_normal();
            if (filesystem_error || !std::filesystem::is_directory(root, filesystem_error) || filesystem_error) {
                return std::unexpected(launcher_error(PackagingErrorCode::filesystem_error,
                                                      "worker temporary root is not an existing directory",
                                                      root.string()));
            }
            static std::atomic_uint64_t sequence {};
            for (std::size_t attempt = 0U; attempt < 32U; ++attempt) {
                const auto suffix = std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) +
                                    L"-" + std::to_wstring(sequence.fetch_add(1U, std::memory_order_relaxed));
                auto path = root / (L"rule-engine-python-worker-" + suffix);
                if (CreateDirectoryW(path.c_str(), nullptr) != 0) {
                    return path;
                }
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    return std::unexpected(launcher_error(PackagingErrorCode::filesystem_error,
                                                          "cannot create a private worker directory", path.string()));
                }
            }
            return std::unexpected(launcher_error(PackagingErrorCode::filesystem_error,
                                                  "cannot allocate a unique private worker directory"));
        }

        std::expected<void, PackagingError> make_parent_end_private(const HANDLE handle) {
            if (SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0U) == 0) {
                return std::unexpected(
                    launcher_error(PackagingErrorCode::worker_crashed, "cannot make a worker pipe handle private"));
            }
            return {};
        }

        struct ReaderState {
            HANDLE pipe {INVALID_HANDLE_VALUE};
            std::size_t maximum_bytes {};
            std::vector<std::byte> bytes;
            std::atomic_bool limited {};
            std::atomic_bool failed {};
        };

        DWORD WINAPI read_pipe(LPVOID parameter) {
            auto &state = *static_cast<ReaderState *>(parameter);
            std::array<std::byte, 16U * kibibyte> buffer {};
            while (true) {
                DWORD read {};
                if (ReadFile(state.pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) == 0) {
                    const auto error = GetLastError();
                    if (error != ERROR_BROKEN_PIPE && error != ERROR_HANDLE_EOF && error != ERROR_OPERATION_ABORTED &&
                        error != ERROR_INVALID_HANDLE) {
                        state.failed.store(true, std::memory_order_release);
                    }
                    return 0U;
                }
                if (read == 0U) {
                    return 0U;
                }
                const auto remaining = state.maximum_bytes - std::min(state.maximum_bytes, state.bytes.size());
                const auto accepted = std::min<std::size_t>(read, remaining);
                state.bytes.insert(state.bytes.end(), buffer.begin(),
                                   buffer.begin() + static_cast<std::ptrdiff_t>(accepted));
                if (accepted != read) {
                    state.limited.store(true, std::memory_order_release);
                    return 0U;
                }
            }
        }

        struct WriterState {
            HANDLE pipe {INVALID_HANDLE_VALUE};
            std::span<const std::byte> bytes;
            std::atomic_bool failed {};
        };

        DWORD WINAPI write_pipe(LPVOID parameter) {
            auto &state = *static_cast<WriterState *>(parameter);
            std::size_t offset = 0U;
            while (offset < state.bytes.size()) {
                const auto remaining = state.bytes.size() - offset;
                const auto amount = static_cast<DWORD>(std::min<std::size_t>(remaining, 64U * kibibyte));
                DWORD written {};
                if (WriteFile(state.pipe, state.bytes.data() + offset, amount, &written, nullptr) == 0 ||
                    written == 0U) {
                    state.failed.store(true, std::memory_order_release);
                    break;
                }
                offset += written;
            }
            CloseHandle(state.pipe);
            state.pipe = INVALID_HANDLE_VALUE;
            return 0U;
        }

        std::wstring windows_system_root() {
            std::array<wchar_t, MAX_PATH + 1U> windows_directory {};
            const auto windows_length =
                GetWindowsDirectoryW(windows_directory.data(), static_cast<UINT>(windows_directory.size()));
            return windows_length > 0U && windows_length < windows_directory.size() ?
                       std::wstring {windows_directory.data(), windows_length} :
                       std::wstring {L"C:\\Windows"};
        }

        std::wstring render_command_line(const std::span<const std::wstring> arguments) {
            std::wstring command_line;
            for (const auto &argument : arguments) {
                if (!command_line.empty()) {
                    command_line.push_back(L' ');
                }
                command_line += quote_argument(argument);
            }
            return command_line;
        }

        std::vector<wchar_t> environment_block(const std::span<const std::wstring> variables) {
            std::vector<wchar_t> block;
            for (const auto &variable : variables) {
                block.insert(block.end(), variable.begin(), variable.end());
                block.push_back(L'\0');
            }
            block.push_back(L'\0');
            return block;
        }

        bool wait_for_thread(const UniqueHandle &thread, const DWORD timeout) noexcept {
            return thread.valid() && WaitForSingleObject(thread.value, timeout) == WAIT_OBJECT_0;
        }
#endif

    } // namespace

    WindowsWorkerProcessContract windows_private_worker_process_contract(
        const PrivatePythonRuntime &runtime, const WorkerMode mode, const std::uint32_t hash_seed,
        const std::filesystem::path &temporary_directory, std::wstring system_root) {
        const auto mode_name = mode == WorkerMode::static_parse ? L"parse" : L"generate";
        return WindowsWorkerProcessContract {
            .arguments =
                {
                    runtime.python_executable.wstring(),
                    L"-I",
                    L"-S",
                    L"-s",
                    L"-B",
                    runtime.worker_script.wstring(),
                    std::wstring {L"--mode="} + mode_name,
                    L"--protocol=1",
                },
            .environment =
                {
                    L"PYTHONDONTWRITEBYTECODE=1",
                    std::wstring {L"PYTHONHASHSEED="} + std::to_wstring(hash_seed),
                    L"PYTHONNOUSERSITE=1",
                    std::wstring {L"SYSTEMROOT="} + std::move(system_root),
                    std::wstring {L"TEMP="} + temporary_directory.wstring(),
                    std::wstring {L"TMP="} + temporary_directory.wstring(),
                },
        };
    }

    std::expected<WorkerProcessResult, PackagingError>
    WindowsJobWorkerLauncher::launch(const PrivatePythonRuntime &runtime, const WorkerMode mode,
                                     const std::uint32_t hash_seed, const std::span<const std::byte> framed_request,
                                     const WorkerLimits &limits) {
#ifndef _WIN32
        static_cast<void>(runtime);
        static_cast<void>(mode);
        static_cast<void>(hash_seed);
        static_cast<void>(framed_request);
        static_cast<void>(limits);
        return std::unexpected(launcher_error(PackagingErrorCode::worker_crashed,
                                              "Windows Job Object worker launcher is unavailable on this platform"));
#else
        const auto runtime_valid = validate_exact_private_runtime(runtime);
        if (!runtime_valid) {
            return std::unexpected(runtime_valid.error());
        }
        if (framed_request.size() > limits.maximum_frame_bytes + 4U || limits.maximum_process_memory_bytes == 0U ||
            limits.maximum_job_memory_bytes == 0U || limits.maximum_active_processes == 0U) {
            return std::unexpected(launcher_error(PackagingErrorCode::worker_frame_too_large,
                                                  "worker request or process limits are invalid"));
        }

        const auto temporary = create_private_temporary_directory(temporary_root);
        if (!temporary) {
            return std::unexpected(temporary.error());
        }
        TemporaryDirectory temporary_cleanup {.path = *temporary};

        SECURITY_ATTRIBUTES inheritable_attributes {
            .nLength = sizeof(SECURITY_ATTRIBUTES),
            .lpSecurityDescriptor = nullptr,
            .bInheritHandle = TRUE,
        };
        UniqueHandle child_stdin;
        UniqueHandle parent_stdin;
        UniqueHandle parent_stdout;
        UniqueHandle child_stdout;
        UniqueHandle parent_stderr;
        UniqueHandle child_stderr;
        if (CreatePipe(&child_stdin.value, &parent_stdin.value, &inheritable_attributes, 0U) == 0 ||
            CreatePipe(&parent_stdout.value, &child_stdout.value, &inheritable_attributes, 0U) == 0 ||
            CreatePipe(&parent_stderr.value, &child_stderr.value, &inheritable_attributes, 0U) == 0) {
            return std::unexpected(
                launcher_error(PackagingErrorCode::worker_crashed, "cannot create bounded worker protocol pipes"));
        }
        const auto private_stdin = make_parent_end_private(parent_stdin.value);
        const auto private_stdout = make_parent_end_private(parent_stdout.value);
        const auto private_stderr = make_parent_end_private(parent_stderr.value);
        if (!private_stdin || !private_stdout || !private_stderr) {
            return std::unexpected(!private_stdin  ? private_stdin.error() :
                                   !private_stdout ? private_stdout.error() :
                                                     private_stderr.error());
        }

        UniqueHandle job {CreateJobObjectW(nullptr, nullptr)};
        if (!job.valid()) {
            return std::unexpected(
                launcher_error(PackagingErrorCode::worker_crashed, "cannot create worker Job Object"));
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits {};
        job_limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY |
            JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_JOB_TIME;
        job_limits.BasicLimitInformation.ActiveProcessLimit = limits.maximum_active_processes;
        job_limits.ProcessMemoryLimit = limits.maximum_process_memory_bytes;
        job_limits.JobMemoryLimit = limits.maximum_job_memory_bytes;
        const auto cpu_ticks =
            std::chrono::duration_cast<std::chrono::duration<std::int64_t, std::ratio<1, 10'000'000>>>(
                limits.maximum_cpu_time);
        job_limits.BasicLimitInformation.PerJobUserTimeLimit.QuadPart = std::max<std::int64_t>(1, cpu_ticks.count());
        if (SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &job_limits, sizeof(job_limits)) ==
            0) {
            return std::unexpected(
                launcher_error(PackagingErrorCode::worker_crashed, "cannot configure bounded worker Job Object"));
        }

        SIZE_T attribute_bytes {};
        InitializeProcThreadAttributeList(nullptr, 1U, 0U, &attribute_bytes);
        std::vector<std::byte> attribute_storage(attribute_bytes);
        AttributeList attributes {
            .value = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data()),
        };
        if (attributes.value == nullptr ||
            InitializeProcThreadAttributeList(attributes.value, 1U, 0U, &attribute_bytes) == 0) {
            attributes.value = nullptr;
            return std::unexpected(
                launcher_error(PackagingErrorCode::worker_crashed, "cannot initialize worker handle allowlist"));
        }
        std::array inherited_handles {child_stdin.value, child_stdout.value, child_stderr.value};
        if (UpdateProcThreadAttribute(attributes.value, 0U, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited_handles.data(),
                                      sizeof(inherited_handles), nullptr, nullptr) == 0) {
            return std::unexpected(
                launcher_error(PackagingErrorCode::worker_crashed, "cannot restrict inherited worker handles"));
        }

        const auto process_contract =
            windows_private_worker_process_contract(runtime, mode, hash_seed, *temporary, windows_system_root());
        auto command_line = render_command_line(process_contract.arguments);
        std::vector<wchar_t> mutable_command {command_line.begin(), command_line.end()};
        mutable_command.push_back(L'\0');
        auto environment = environment_block(process_contract.environment);
        STARTUPINFOEXW startup {};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_stdin.value;
        startup.StartupInfo.hStdOutput = child_stdout.value;
        startup.StartupInfo.hStdError = child_stderr.value;
        startup.lpAttributeList = attributes.value;
        PROCESS_INFORMATION process_information {};
        const auto creation_flags =
            CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;
        if (CreateProcessW(runtime.python_executable.c_str(), mutable_command.data(), nullptr, nullptr, TRUE,
                           creation_flags, environment.data(), temporary->c_str(), &startup.StartupInfo,
                           &process_information) == 0) {
            return std::unexpected(launcher_error(PackagingErrorCode::worker_crashed,
                                                  "cannot create exact private CPython worker process"));
        }
        UniqueHandle process {process_information.hProcess};
        UniqueHandle primary_thread {process_information.hThread};
        child_stdin.reset();
        child_stdout.reset();
        child_stderr.reset();
        if (AssignProcessToJobObject(job.value, process.value) == 0) {
            TerminateProcess(process.value, 0xe001U);
            return std::unexpected(launcher_error(PackagingErrorCode::worker_crashed,
                                                  "cannot assign private CPython worker to its Job Object"));
        }

        ReaderState stdout_state {
            .pipe = parent_stdout.value,
            .maximum_bytes = limits.maximum_frame_bytes + 4U,
            .bytes = {},
            .limited = {},
            .failed = {},
        };
        ReaderState stderr_state {
            .pipe = parent_stderr.value,
            .maximum_bytes = limits.maximum_stderr_bytes,
            .bytes = {},
            .limited = {},
            .failed = {},
        };
        WriterState stdin_state {.pipe = parent_stdin.release(), .bytes = framed_request};
        UniqueHandle stdout_thread {CreateThread(nullptr, 0U, read_pipe, &stdout_state, 0U, nullptr)};
        UniqueHandle stderr_thread {CreateThread(nullptr, 0U, read_pipe, &stderr_state, 0U, nullptr)};
        UniqueHandle stdin_thread {CreateThread(nullptr, 0U, write_pipe, &stdin_state, 0U, nullptr)};
        auto finish_protocol_io = [&] {
            if (stdin_thread.valid()) {
                if (!wait_for_thread(stdin_thread, 5'000U)) {
                    CancelSynchronousIo(stdin_thread.value);
                    WaitForSingleObject(stdin_thread.value, INFINITE);
                }
            } else if (stdin_state.pipe != INVALID_HANDLE_VALUE) {
                CloseHandle(stdin_state.pipe);
                stdin_state.pipe = INVALID_HANDLE_VALUE;
            }
            if (stdout_thread.valid() && !wait_for_thread(stdout_thread, 5'000U)) {
                CancelSynchronousIo(stdout_thread.value);
                parent_stdout.reset();
                WaitForSingleObject(stdout_thread.value, INFINITE);
            }
            if (stderr_thread.valid() && !wait_for_thread(stderr_thread, 5'000U)) {
                CancelSynchronousIo(stderr_thread.value);
                parent_stderr.reset();
                WaitForSingleObject(stderr_thread.value, INFINITE);
            }
        };
        if (!stdout_thread.valid() || !stderr_thread.valid() || !stdin_thread.valid()) {
            TerminateJobObject(job.value, 0xe002U);
            finish_protocol_io();
            return std::unexpected(
                launcher_error(PackagingErrorCode::worker_crashed, "cannot create worker protocol I/O threads"));
        }
        if (ResumeThread(primary_thread.value) == static_cast<DWORD>(-1)) {
            TerminateJobObject(job.value, 0xe003U);
            finish_protocol_io();
            return std::unexpected(
                launcher_error(PackagingErrorCode::worker_crashed, "cannot resume contained CPython worker"));
        }

        bool timed_out = false;
        bool output_limited = false;
        bool wait_failed = false;
        const auto started = std::chrono::steady_clock::now();
        while (true) {
            const auto wait = WaitForSingleObject(process.value, 5U);
            if (wait == WAIT_OBJECT_0) {
                break;
            }
            if (wait == WAIT_FAILED) {
                wait_failed = true;
                TerminateJobObject(job.value, 0xe004U);
                break;
            }
            if (stdout_state.limited.load(std::memory_order_acquire) ||
                stderr_state.limited.load(std::memory_order_acquire)) {
                output_limited = true;
                TerminateJobObject(job.value, 0xe005U);
                break;
            }
            if (std::chrono::steady_clock::now() - started >= limits.maximum_elapsed_time) {
                timed_out = true;
                TerminateJobObject(job.value, 0xe006U);
                break;
            }
        }
        // Even after a successful root exit, terminate the job to reap any
        // still-running descendants before accepting protocol output.
        const auto tree_termination_requested = TerminateJobObject(job.value, 0xe007U) != 0;
        WaitForSingleObject(process.value, 5'000U);

        finish_protocol_io();

        DWORD exit_code {};
        if (GetExitCodeProcess(process.value, &exit_code) == 0) {
            exit_code = 0xffffffffU;
        }
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting {};
        bool process_tree_terminated = false;
        if (tree_termination_requested) {
            for (std::size_t attempt = 0U; attempt < 100U; ++attempt) {
                const auto accounting_valid = QueryInformationJobObject(job.value, JobObjectBasicAccountingInformation,
                                                                        &accounting, sizeof(accounting), nullptr) != 0;
                if (accounting_valid && accounting.ActiveProcesses == 0U) {
                    process_tree_terminated = true;
                    break;
                }
                Sleep(1U);
            }
        }
        output_limited = output_limited || stdout_state.limited.load(std::memory_order_acquire) ||
                         stderr_state.limited.load(std::memory_order_acquire);
        const auto io_failed = stdin_state.failed.load(std::memory_order_acquire) ||
                               stdout_state.failed.load(std::memory_order_acquire) ||
                               stderr_state.failed.load(std::memory_order_acquire);
        if (wait_failed) {
            return std::unexpected(
                launcher_error(PackagingErrorCode::worker_crashed, "waiting for private CPython worker failed"));
        }
        return WorkerProcessResult {
            .exit_code = static_cast<std::int32_t>(exit_code),
            .crashed = !timed_out && !output_limited && (exit_code != 0U || io_failed),
            .timed_out = timed_out,
            .output_limited = output_limited,
            .process_tree_terminated = process_tree_terminated,
            .stdout_bytes = std::move(stdout_state.bytes),
            .stderr_excerpt = {reinterpret_cast<const char *>(stderr_state.bytes.data()), stderr_state.bytes.size()},
        };
#endif
    }

} // namespace rule_engine::python::packaging
