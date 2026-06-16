#pragma once

#include <rule_engine/diagnostic.hpp>
#include <rule_engine/pattern_fixture_provider.hpp>
#include <rule_engine/protocol.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace rule_engine::client_protocol {
    using ExtraFactBatchHandler =
        std::function<std::optional<protocol::FactBatchResponseMessage>(const protocol::FactBatchRequestMessage &)>;

    struct ClientListenOptions {
        std::string bind_address {"127.0.0.1"};
        std::uint16_t port {31337};
        std::filesystem::path pattern_fixture_path;
        std::chrono::milliseconds io_timeout {5000};
        ExtraFactBatchHandler extra_fact_handler {};
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
    };

    struct ClientEvaluationSession {
        protocol::HandshakeMessage handshake;
        protocol::SubjectListMessage subjects;
        EvaluationStep final_step;
    };

    struct ClientEvaluationOptions {
        std::size_t max_subject_concurrency {1};
        std::size_t max_provider_rounds {16};
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

    using ListeningCallback = std::function<void(std::uint16_t)>;

    [[nodiscard]] protocol::HandshakeMessage client_handshake();
    [[nodiscard]] std::expected<protocol::SubjectListMessage, ErrorSet> enumerate_client_subjects();
    [[nodiscard]] protocol::FactBatchResponseMessage
    handle_client_fact_batch(const protocol::FactBatchRequestMessage &request);
    [[nodiscard]] std::expected<void, ErrorSet> serve_client_once(const ClientListenOptions &options,
                                                                const ListeningCallback &on_listening = {});
    [[nodiscard]] std::expected<ClientSession, ErrorSet>
    run_client_session(const ClientConnectionOptions &options,
                            const std::vector<protocol::FactBatchRequestMessage> &requests);
    [[nodiscard]] std::expected<ClientEvaluationSession, ErrorSet>
    evaluate_subject_with_client(const ClientConnectionOptions &options, const VerifiedProgram &program, const Subject &subject);
    [[nodiscard]] std::expected<ClientMultiEvaluationSession, ErrorSet>
    evaluate_subjects_with_client(const ClientConnectionOptions &options,
                                const VerifiedProgram &program,
                                const std::vector<Subject> &subjects,
                                ClientEvaluationOptions evaluation_options = {});
} // namespace rule_engine::client_protocol
