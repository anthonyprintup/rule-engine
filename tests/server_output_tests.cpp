#include <rule_engine/client_protocol.hpp>
#include <rule_engine/server_output.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace {
    [[nodiscard]] bool contains(const std::string_view text, const std::string_view needle) {
        return text.find(needle) != std::string_view::npos;
    }
} // namespace

TEST_CASE("server JSON output serializes evaluation sessions") {
    rule_engine::client_protocol::ClientMultiEvaluationSession session;
    session.handshake.protocol = "rule-engine-client";
    session.handshake.version = 1u;
    session.handshake.capabilities = {
        rule_engine::protocol::Capability {.route = "endpoint.demo.functions"},
    };
    session.subjects.subjects = {
        rule_engine::Subject {.kind = "process", .id = "pid:1"},
        rule_engine::Subject {.kind = "process", .id = "pid:2"},
    };

    rule_engine::EvaluationStep step;
    step.state = rule_engine::EvaluationState::complete;
    step.rule_results = {
        rule_engine::RuleResult {.identifier = "demo.rule", .matched = true, .diagnostics = {}},
        rule_engine::RuleResult {
            .identifier = "quote\"rule",
            .matched = false,
            .diagnostics = {
                rule_engine::Diagnostic {
                    .source = "rules\\demo.yar",
                    .span = rule_engine::SourceSpan {
                        .source_id = 7u,
                        .start = 11u,
                        .end = 17u,
                        .source = "rules\\demo.yar",
                    },
                    .message = "bad\nfact",
                },
            },
        },
    };
    session.evaluations.push_back(rule_engine::client_protocol::ClientSubjectEvaluation {
        .subject = rule_engine::Subject {.kind = "process", .id = "pid:1"},
        .final_step = std::move(step),
    });

    const auto json = rule_engine::server_output::evaluation_session_json("127.0.0.1", 31337u, session);

    CHECK(contains(json, R"("host":"127.0.0.1")"));
    CHECK(contains(json, R"("port":31337)"));
    CHECK(contains(json, R"("protocol":"rule-engine-client")"));
    CHECK(contains(json, R"("subjectsAdvertised":2)"));
    CHECK(contains(json, R"("evaluated":1)"));
    CHECK(contains(json, R"("state":"complete")"));
    CHECK(contains(json, R"("identifier":"demo.rule")"));
    CHECK(contains(json, R"("matched":true)"));
    CHECK(contains(json, R"("identifier":"quote\"rule")"));
    CHECK(contains(json, R"("matched":false)"));
    CHECK(contains(json, R"("source":"rules\\demo.yar")"));
    CHECK(contains(json, R"("spanStart":11)"));
    CHECK(contains(json, R"("spanEnd":17)"));
    CHECK(contains(json, R"("message":"bad\nfact")"));
}

TEST_CASE("server JSON output serializes evaluation instrumentation") {
    rule_engine::client_protocol::ClientMultiEvaluationSession session;
    session.handshake.protocol = "rule-engine-client";
    session.handshake.version = 1u;
    session.subjects.subjects = {
        rule_engine::Subject {.kind = "process", .id = "pid:1"},
    };

    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation {
        .peak_pending_vm_subjects = 4u,
        .vm_backpressure_events = 2u,
        .peak_pending_provider_requests = 3u,
        .provider_backpressure_events = 1u,
        .provider_rounds = 5u,
        .provider_requests = 7u,
        .provider_fact_keys_requested = 11u,
        .provider_facts_returned = 9u,
        .provider_elapsed_us = 1234u,
        .static_fact_cache_lookups = 6u,
        .static_fact_cache_hits = 4u,
        .static_fact_cache_misses = 2u,
        .static_fact_cache_reuses = 4u,
        .static_fact_cache_invalidations = 1u,
        .static_fact_cache_subject_scoped = 3u,
        .static_fact_cache_provider_fact_keys_avoided = 5u,
    };

    const auto json = rule_engine::server_output::evaluation_session_json("127.0.0.1",
                                                                          31337u,
                                                                          session,
                                                                          &instrumentation);

    CHECK(contains(json, R"("instrumentation":{)"));
    CHECK(contains(json, R"("peakPendingVmSubjects":4)"));
    CHECK(contains(json, R"("vmBackpressureEvents":2)"));
    CHECK(contains(json, R"("peakPendingProviderRequests":3)"));
    CHECK(contains(json, R"("providerBackpressureEvents":1)"));
    CHECK(contains(json, R"("providerRounds":5)"));
    CHECK(contains(json, R"("providerRequests":7)"));
    CHECK(contains(json, R"("providerFactKeysRequested":11)"));
    CHECK(contains(json, R"("providerFactsReturned":9)"));
    CHECK(contains(json, R"("providerElapsedUs":1234)"));
    CHECK(contains(json, R"("staticFactCacheLookups":6)"));
    CHECK(contains(json, R"("staticFactCacheHits":4)"));
    CHECK(contains(json, R"("staticFactCacheMisses":2)"));
    CHECK(contains(json, R"("staticFactCacheReuses":4)"));
    CHECK(contains(json, R"("staticFactCacheInvalidations":1)"));
    CHECK(contains(json, R"("staticFactCacheSubjectScoped":3)"));
    CHECK(contains(json, R"("staticFactCacheProviderFactKeysAvoided":5)"));
}

TEST_CASE("server JSON output serializes client smoke facts with typed values") {
    rule_engine::client_protocol::ClientSession session;
    session.handshake.protocol = "rule-engine-client";
    session.handshake.version = 1u;
    session.handshake.capabilities = {
        rule_engine::protocol::Capability {.route = "endpoint.process.snapshot"},
    };
    session.subjects.subjects = {
        rule_engine::Subject {.kind = "process", .id = "pid:42"},
    };
    session.responses = {
        rule_engine::protocol::FactBatchResponseMessage {
            .route = "endpoint.process.snapshot",
            .values = {
                rule_engine::Fact {
                    .subject_id = "pid:42",
                    .key = "process.pid",
                    .value = rule_engine::Value::integer(42),
                    .status = rule_engine::FactStatus::available,
                    .diagnostic = {},
                    .ttl = std::chrono::seconds {0},
                },
                rule_engine::Fact {
                    .subject_id = "pid:42",
                    .key = "process.name",
                    .value = rule_engine::Value::string("proc\"x"),
                    .status = rule_engine::FactStatus::available,
                    .diagnostic = {},
                    .ttl = std::chrono::seconds {30},
                },
                rule_engine::Fact {
                    .subject_id = "pid:42",
                    .key = "process.blob",
                    .value = rule_engine::Value::bytes(std::vector<std::byte> {
                        std::byte {0x0f},
                        std::byte {0xa0},
                    }),
                    .status = rule_engine::FactStatus::available,
                    .diagnostic = {},
                    .ttl = std::chrono::seconds {30},
                },
                rule_engine::Fact {
                    .subject_id = "pid:42",
                    .key = "process.denied",
                    .value = rule_engine::Value::undefined(),
                    .status = rule_engine::FactStatus::access_denied,
                    .diagnostic = "access denied",
                    .ttl = std::chrono::seconds {0},
                },
            },
        },
    };

    const auto json = rule_engine::server_output::client_session_json("localhost", 31338u, session);

    CHECK(contains(json, R"("host":"localhost")"));
    CHECK(contains(json, R"("subjectsAdvertised":1)"));
    CHECK(contains(json, R"("capabilities":[{"route":"endpoint.process.snapshot"}])"));
    CHECK(contains(json, R"("route":"endpoint.process.snapshot")"));
    CHECK(contains(json, R"("key":"process.pid")"));
    CHECK(contains(json, R"("status":"available")"));
    CHECK(contains(json, R"("valueKind":"integer")"));
    CHECK(contains(json, R"("value":42)"));
    CHECK(contains(json, R"("key":"process.name")"));
    CHECK(contains(json, R"("valueKind":"string")"));
    CHECK(contains(json, R"("value":"proc\"x")"));
    CHECK(contains(json, R"("key":"process.blob")"));
    CHECK(contains(json, R"("valueKind":"bytes")"));
    CHECK(contains(json, R"("value":"0fa0")"));
    CHECK(contains(json, R"("key":"process.denied")"));
    CHECK(contains(json, R"("status":"access_denied")"));
    CHECK(contains(json, R"("diagnostic":"access denied")"));
    CHECK(contains(json, R"("ttlSeconds":30)"));
}
