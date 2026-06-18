#pragma once

#include <rule_engine/diagnostic.hpp>
#include <rule_engine/optimizer.hpp>
#include <rule_engine/pattern_fixture_provider.hpp>
#include <rule_engine/protocol.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace rule_engine::client_protocol {
    struct ProviderRequestContext {
        std::stop_token stop_token {};
    };

    using ExtraFactBatchHandler =
        std::function<std::optional<protocol::FactBatchResponseMessage>(const protocol::FactBatchRequestMessage &)>;
    using ExtraCandidateProviderHandler = std::function<std::optional<protocol::CandidateProviderResponseMessage>(
        const protocol::CandidateProviderRequestMessage &)>;
    using ExtraFactBatchHandlerWithContext = std::function<std::optional<protocol::FactBatchResponseMessage>(
        const protocol::FactBatchRequestMessage &, const ProviderRequestContext &)>;
    using ExtraCandidateProviderHandlerWithContext =
        std::function<std::optional<protocol::CandidateProviderResponseMessage>(
            const protocol::CandidateProviderRequestMessage &, const ProviderRequestContext &)>;

    struct ClientListenOptions {
        std::string bind_address {"127.0.0.1"};
        std::uint16_t port {31337};
        std::filesystem::path pattern_fixture_path;
        std::chrono::milliseconds io_timeout {5000};
        std::vector<protocol::Capability> extra_capabilities {};
        ExtraFactBatchHandler extra_fact_handler {};
        ExtraCandidateProviderHandler extra_candidate_provider_handler {};
        ExtraFactBatchHandlerWithContext extra_fact_handler_with_context {};
        ExtraCandidateProviderHandlerWithContext extra_candidate_provider_handler_with_context {};
        std::size_t max_sessions {1};
        std::size_t max_session_workers {1};
        std::stop_token stop_token {};
    };

    struct ClientConnectionOptions {
        std::string host {"127.0.0.1"};
        std::uint16_t port {31337};
        std::chrono::milliseconds io_timeout {5000};
    };

    struct ClientSession {
        protocol::HandshakeMessage handshake;
        protocol::SubjectListMessage subjects;
        std::vector<protocol::FactBatchResponseMessage> responses;
        std::vector<protocol::CandidateProviderResponseMessage> candidate_provider_responses;
    };

    struct ClientEvaluationSession {
        protocol::HandshakeMessage handshake;
        protocol::SubjectListMessage subjects;
        EvaluationStep final_step;
    };

    struct ClientEvaluationInstrumentation {
        std::uint64_t peak_pending_vm_subjects {};
        std::uint64_t vm_backpressure_events {};
        std::uint64_t peak_pending_provider_requests {};
        std::uint64_t provider_backpressure_events {};
        std::uint64_t provider_rounds {};
        std::uint64_t provider_requests {};
        std::uint64_t provider_fact_keys_requested {};
        std::uint64_t provider_facts_returned {};
        std::uint64_t provider_elapsed_us {};
        std::uint64_t candidate_provider_requests {};
        std::uint64_t candidate_provider_filters_requested {};
        std::uint64_t candidate_provider_subjects_returned {};
        std::uint64_t candidate_provider_broad_results {};
        std::uint64_t candidate_provider_filters_not_advertised {};
        std::uint64_t candidate_provider_elapsed_us {};
        std::uint64_t static_fact_cache_lookups {};
        std::uint64_t static_fact_cache_hits {};
        std::uint64_t static_fact_cache_misses {};
        std::uint64_t static_fact_cache_reuses {};
        std::uint64_t static_fact_cache_invalidations {};
        std::uint64_t static_fact_cache_subject_scoped {};
        std::uint64_t static_fact_cache_provider_fact_keys_avoided {};
    };

    struct ClientEvaluationOptions {
        std::size_t max_subject_concurrency {1};
        std::size_t max_provider_rounds {16};
        std::size_t vm_backpressure_subject_threshold {};
        std::size_t provider_backpressure_request_threshold {};
        ClientEvaluationInstrumentation *instrumentation {};
        optimizer::StaticFactCache *static_fact_cache {};
        std::vector<optimizer::StaticFactCacheCandidate> static_fact_cache_candidates {};
        std::string static_fact_identity_route {};
        const FactCache *static_fact_identity_facts {};
        std::optional<optimizer::StaticFactIdentityFactKeys> static_fact_identity_fact_keys {
            optimizer::pe_static_fact_identity_fact_keys()};
        std::stop_token stop_token {};
    };

    struct ClientSubjectEvaluation {
        Subject subject;
        EvaluationStep final_step;
    };

    struct ClientMultiEvaluationSession {
        protocol::HandshakeMessage handshake;
        protocol::SubjectListMessage subjects;
        std::vector<ClientSubjectEvaluation> evaluations;
    };

    struct OptimizedClientEvaluationSession {
        protocol::HandshakeMessage handshake;
        protocol::SubjectListMessage subjects;
        std::vector<Subject> evaluated_subjects;
        std::vector<Fact> facts;
        std::vector<optimizer::CandidateProviderResult> candidate_provider_results;
        std::vector<optimizer::OptimizerTraceEvent> static_fact_cache_trace_events;
        optimizer::OptimizedEvaluationSweep sweep;
    };

    struct OptimizedClientReplayReport {
        optimizer::OptimizedEvaluationSweep sweep;
        std::uint64_t subject_mismatches {};
        std::uint64_t rule_result_mismatches {};
        std::uint64_t trace_event_mismatches {};
        std::uint64_t sweep_metric_mismatches {};
    };

    using ListeningCallback = std::function<void(std::uint16_t)>;

    [[nodiscard]] protocol::HandshakeMessage
    client_handshake(std::span<const protocol::Capability> extra_capabilities = {});
    [[nodiscard]] std::expected<protocol::SubjectListMessage, ErrorSet> enumerate_client_subjects();
    [[nodiscard]] protocol::FactBatchResponseMessage
    handle_client_fact_batch(const protocol::FactBatchRequestMessage &request);
    [[nodiscard]] std::expected<void, ErrorSet> serve_client(const ClientListenOptions &options,
                                                             const ListeningCallback &on_listening = {});
    [[nodiscard]] std::expected<void, ErrorSet> serve_client_once(const ClientListenOptions &options,
                                                                  const ListeningCallback &on_listening = {});
    [[nodiscard]] std::expected<ClientSession, ErrorSet>
    run_client_session(const ClientConnectionOptions &options,
                       const std::vector<protocol::FactBatchRequestMessage> &requests,
                       const std::vector<protocol::CandidateProviderRequestMessage> &candidate_provider_requests = {});
    [[nodiscard]] std::expected<ClientEvaluationSession, ErrorSet>
    evaluate_subject_with_client(const ClientConnectionOptions &options, const VerifiedProgram &program,
                                 const Subject &subject);
    [[nodiscard]] std::expected<ClientMultiEvaluationSession, ErrorSet>
    evaluate_subjects_with_client(const ClientConnectionOptions &options, const VerifiedProgram &program,
                                  const std::vector<Subject> &subjects,
                                  ClientEvaluationOptions evaluation_options = {});
    [[nodiscard]] std::expected<OptimizedClientEvaluationSession, ErrorSet>
    evaluate_subjects_with_optimizer_plan(const ClientConnectionOptions &options, const VerifiedProgram &program,
                                          const optimizer::OptimizerPlan &plan, const std::vector<Subject> &subjects,
                                          ClientEvaluationOptions evaluation_options = {});
    [[nodiscard]] optimizer::OptimizedEvaluationSweep
    replay_optimized_client_evaluation(const VerifiedProgram &program, const optimizer::OptimizerPlan &plan,
                                       const OptimizedClientEvaluationSession &session);
    [[nodiscard]] OptimizedClientReplayReport
    replay_optimized_client_evaluation_with_parity_report(const VerifiedProgram &program,
                                                          const optimizer::OptimizerPlan &plan,
                                                          const OptimizedClientEvaluationSession &session);
} // namespace rule_engine::client_protocol
