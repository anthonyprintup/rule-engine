#pragma once

#include <rule_engine/diagnostic.hpp>
#include <rule_engine/evaluator.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace rule_engine::protocol {
    struct Capability {
        std::string route {};
        std::string filter_key {};
        std::vector<ValueType> argument_types {};
        std::string result_kind {};
    };

    struct HandshakeMessage {
        std::string protocol;
        std::uint32_t version {};
        std::vector<Capability> capabilities;
    };

    struct SubjectListMessage {
        std::vector<Subject> subjects;
    };

    struct FactKey {
        std::string subject_id;
        std::string key;
    };

    struct FactBatchRequestMessage {
        std::string route;
        std::vector<FactKey> keys;
        std::vector<ValueType> expected_types;
        std::vector<PatternScanPlan> scan_plans;
        std::chrono::milliseconds timeout {5000};
    };

    struct FactBatchResponseMessage {
        std::string route;
        std::vector<Fact> values;
    };

    struct CandidateProviderFilterRequest {
        std::string request_id;
        std::string filter_key;
        std::string argument_kind;
        std::string argument_value;
    };

    struct CandidateProviderRequestMessage {
        std::string route;
        std::chrono::milliseconds timeout {5000};
        std::vector<CandidateProviderFilterRequest> filters;
    };

    struct CandidateProviderSubjectSet {
        std::string request_id;
        std::string filter_key;
        FactStatus status {FactStatus::missing};
        std::vector<std::string> subject_ids;
        std::string diagnostic;
        std::chrono::seconds ttl {0};
    };

    struct CandidateProviderResponseMessage {
        std::string route;
        std::vector<CandidateProviderSubjectSet> results;
    };

    struct DecodedFrame {
        std::vector<std::byte> payload;
        std::size_t bytes_consumed {};
    };

    [[nodiscard]] std::expected<std::vector<std::byte>, ErrorSet> encode_handshake(const HandshakeMessage &message);
    [[nodiscard]] std::expected<HandshakeMessage, ErrorSet> decode_handshake(std::span<const std::byte> payload);
    [[nodiscard]] std::expected<std::vector<std::byte>, ErrorSet> encode_subject_list(const SubjectListMessage &message);
    [[nodiscard]] std::expected<SubjectListMessage, ErrorSet> decode_subject_list(std::span<const std::byte> payload);
    [[nodiscard]] std::expected<std::vector<std::byte>, ErrorSet>
    encode_fact_batch_request(const FactBatchRequestMessage &message);
    [[nodiscard]] std::expected<FactBatchRequestMessage, ErrorSet>
    decode_fact_batch_request(std::span<const std::byte> payload);
    [[nodiscard]] std::expected<std::vector<std::byte>, ErrorSet>
    encode_fact_batch_response(const FactBatchResponseMessage &message);
    [[nodiscard]] std::expected<FactBatchResponseMessage, ErrorSet>
    decode_fact_batch_response(std::span<const std::byte> payload);
    [[nodiscard]] std::expected<std::vector<std::byte>, ErrorSet>
    encode_candidate_provider_request(const CandidateProviderRequestMessage &message);
    [[nodiscard]] std::expected<CandidateProviderRequestMessage, ErrorSet>
    decode_candidate_provider_request(std::span<const std::byte> payload);
    [[nodiscard]] std::expected<std::vector<std::byte>, ErrorSet>
    encode_candidate_provider_response(const CandidateProviderResponseMessage &message);
    [[nodiscard]] std::expected<CandidateProviderResponseMessage, ErrorSet>
    decode_candidate_provider_response(std::span<const std::byte> payload);

    [[nodiscard]] std::expected<std::vector<std::byte>, ErrorSet> encode_frame(std::span<const std::byte> payload);
    [[nodiscard]] std::expected<DecodedFrame, ErrorSet> try_decode_frame(std::span<const std::byte> bytes);
} // namespace rule_engine::protocol
