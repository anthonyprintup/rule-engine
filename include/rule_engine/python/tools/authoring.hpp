#pragma once

#include "rule_engine/python/tools/diagnostics.hpp"

#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

namespace rule_engine::python::tools {

    enum struct PackAction : std::uint8_t { build, verify, inspect, stubs };

    enum struct GeneratorPolicy : std::uint8_t {
        disabled,
        manifest_authorized_only,
    };

    struct PackCommand {
        PackAction action {PackAction::verify};
        std::string input_path;
        std::string output_path;
        std::string signer_reference;
        std::string trust_config_path;
        std::string runtime_root;
        std::string sdk_root;
        std::string temporary_root;
        OutputFormat format {OutputFormat::text};
        GeneratorPolicy generator_policy {GeneratorPolicy::disabled};
        bool development_unsigned {};
    };

    struct PackToolResult {
        bool success {};
        DiagnosticSet diagnostics;
        std::vector<SourceDocument> sources;
        std::vector<DisplayField> fields;
        std::vector<std::string> generated_paths;
    };

    struct PackagingToolBackend {
        virtual ~PackagingToolBackend() = default;
        [[nodiscard]] virtual std::expected<PackToolResult, ToolFailure> execute(const PackCommand &command) = 0;
    };

    struct FactExplanation {
        std::string executable;
        std::string logical_route;
        std::string physical_prefetch;
        bool conditional {};
    };

    enum struct PlanPath : std::uint8_t { exact, optimized };

    struct PlanExplanation {
        std::string executable;
        PlanPath path {PlanPath::exact};
        std::string certificate_reason;
    };

    struct CheckCommand {
        std::string pack_path;
        std::string trust_config_path;
        std::string runtime_root;
        std::string temporary_root;
        OutputFormat format {OutputFormat::text};
        bool development_unsigned {};
        bool watch {};
        bool explain_facts {};
        bool explain_plan {};
    };

    struct CheckToolResult {
        bool success {};
        DiagnosticSet diagnostics;
        std::vector<SourceDocument> sources;
        std::vector<DisplayField> fields;
        std::vector<FactExplanation> facts;
        std::vector<PlanExplanation> plans;
    };

    struct CompilerToolBackend {
        virtual ~CompilerToolBackend() = default;
        [[nodiscard]] virtual std::expected<CheckToolResult, ToolFailure> check(const CheckCommand &command,
                                                                                std::stop_token cancellation) = 0;
    };

    enum struct WatchCompletion : std::uint8_t { published, failed, stale, cancelled };

    struct WatchTicket {
        std::uint64_t generation {};
        std::stop_token cancellation;
    };

    // File-system observation belongs to an outer adapter. This coordinator
    // provides the important semantic boundary: starting a generation cancels
    // its predecessor, and only the latest complete successful result can
    // replace the last published result.
    struct CheckWatchCoordinator {
        [[nodiscard]] WatchTicket begin_generation();
        [[nodiscard]] WatchCompletion complete(const WatchTicket &ticket, CheckToolResult result);
        void cancel_current();
        [[nodiscard]] std::uint64_t current_generation() const;
        [[nodiscard]] std::optional<CheckToolResult> last_published() const;

    private:
        mutable std::mutex mutex_;
        std::uint64_t generation_ {};
        std::stop_source cancellation_;
        std::optional<CheckToolResult> published_;
    };

} // namespace rule_engine::python::tools
