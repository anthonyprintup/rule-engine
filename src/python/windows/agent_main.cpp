#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "rule_engine/python/windows/agent.hpp"

#include <atomic>
#include <cstdint>
#include <iostream>
#include <span>
#include <stop_token>
#include <string_view>
#include <vector>

namespace {

    using rule_engine::python::windows::AgentFailure;
    using rule_engine::python::windows::AgentFailureCode;

    std::atomic<std::stop_source *> active_stop_source {};

    BOOL WINAPI stop_handler(const DWORD signal) {
        if (signal != CTRL_C_EVENT && signal != CTRL_BREAK_EVENT && signal != CTRL_CLOSE_EVENT &&
            signal != CTRL_SHUTDOWN_EVENT) {
            return FALSE;
        }
        auto *source = active_stop_source.load(std::memory_order_acquire);
        if (source != nullptr) {
            source->request_stop();
        }
        return TRUE;
    }

    struct ConsoleStopHandler {
        explicit ConsoleStopHandler(std::stop_source &source) noexcept {
            active_stop_source.store(&source, std::memory_order_release);
            installed = SetConsoleCtrlHandler(stop_handler, TRUE) != FALSE;
            if (!installed) {
                active_stop_source.store(nullptr, std::memory_order_release);
            }
        }

        ConsoleStopHandler(const ConsoleStopHandler &) = delete;
        ConsoleStopHandler &operator=(const ConsoleStopHandler &) = delete;

        ~ConsoleStopHandler() {
            active_stop_source.store(nullptr, std::memory_order_release);
            if (installed) {
                SetConsoleCtrlHandler(stop_handler, FALSE);
            }
        }

        bool installed {};
    };

    [[nodiscard]] int exit_code(const AgentFailure &failure) noexcept {
        switch (failure.code) {
            case AgentFailureCode::configuration: return 2;
            case AgentFailureCode::dependency:
            case AgentFailureCode::transport: return 3;
            case AgentFailureCode::authentication: return 4;
            case AgentFailureCode::invariant: return 5;
            case AgentFailureCode::protocol:
            case AgentFailureCode::persistence:
            case AgentFailureCode::provider:
            case AgentFailureCode::canceled: return 1;
            default: return 5;
        }
    }

    int fail(const AgentFailure &failure) {
        std::cerr << "error: " << failure.message;
        if (failure.line != 0U) {
            std::cerr << " (line " << failure.line << ')';
        }
        std::cerr << '\n';
        return exit_code(failure);
    }

} // namespace

int main(const int argc, const char *const *argv) {
    namespace win = rule_engine::python::windows;
    namespace protocol = rule_engine::python::protocol_v2;

    std::vector<std::string_view> arguments;
    arguments.reserve(argc > 1 ? static_cast<std::size_t>(argc - 1) : 0U);
    for (int index = 1; index < argc; ++index) { arguments.emplace_back(argv[index]); }
    auto command = win::parse_windows_agent_command(arguments);
    if (!command) {
        std::cerr << "error: " << command.error().message << "\nTry 'rule_engine_agent --help' for usage.\n";
        return 2;
    }
    if (command->mode == win::AgentCommandMode::help) {
        std::cout << win::windows_agent_help();
        return 0;
    }
    if (command->mode == win::AgentCommandMode::version) {
        std::cout << "rule_engine_agent " << win::agent_version << '\n';
        return 0;
    }

    auto configuration = win::load_windows_agent_config(command->configuration_path);
    if (!configuration) {
        return fail(configuration.error());
    }
    if (auto files = win::validate_windows_agent_config_files(*configuration); !files) {
        return fail(files.error());
    }
    if (auto dependencies = win::validate_windows_agent_dependencies(*configuration); !dependencies) {
        return fail(dependencies.error());
    }
    if (command->mode == win::AgentCommandMode::validate_config) {
        std::cout << "configuration valid\n";
        return 0;
    }

    auto spool = protocol::SqliteAgentSpool::open(configuration->spool_path.string(), configuration->spool_limits,
                                                  configuration->protocol_limits);
    if (!spool) {
        return fail(AgentFailure {.code = spool.error().code == protocol::ProtocolErrorCode::dependency_unavailable ?
                                              AgentFailureCode::dependency :
                                              AgentFailureCode::persistence,
                                  .message = spool.error().message});
    }
    auto session = win::make_tls_windows_agent_session(*configuration);
    if (!session) {
        return fail(session.error());
    }
    auto providers = win::make_windows_agent_provider_factory();
    if (providers == nullptr) {
        return fail(AgentFailure {.code = AgentFailureCode::invariant,
                                  .message = "Windows provider factory could not be created"});
    }

    std::stop_source stop;
    ConsoleStopHandler handler {stop};
    if (!handler.installed) {
        return fail(AgentFailure {.code = AgentFailureCode::dependency,
                                  .message = "Windows console shutdown handler could not be installed"});
    }
    win::WindowsAgentService service {std::move(*configuration), *spool, std::move(*session), std::move(providers)};
    auto result = service.run(stop.get_token());
    if (!result) {
        return fail(result.error());
    }
    return 0;
}
