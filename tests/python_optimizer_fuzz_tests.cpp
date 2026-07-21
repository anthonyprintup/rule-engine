#include "rule_engine/python/optimizer/scan_wire.hpp"
#include "rule_engine/python/protocol.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) noexcept;

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::optimizer;
    using namespace rule_engine::python::protocol_v2;

    constexpr std::string_view scan_source_text = "bbb\nMZ alpha\nMZ";

    struct CorpusSeed {
        std::string name;
        std::vector<std::uint8_t> bytes;
    };

    [[nodiscard]] std::vector<std::byte> bytes_of(const std::string_view text) {
        std::vector<std::byte> result;
        result.reserve(text.size());
        for (const char value : text) { result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value))); }
        return result;
    }

    [[nodiscard]] std::vector<std::uint8_t> fuzz_bytes(const std::string_view text) {
        return {reinterpret_cast<const std::uint8_t *>(text.data()),
                reinterpret_cast<const std::uint8_t *>(text.data()) + text.size()};
    }

    [[nodiscard]] std::vector<std::uint8_t> fuzz_bytes(const std::span<const std::byte> input) {
        const auto *begin = reinterpret_cast<const std::uint8_t *>(input.data());
        return {begin, begin + input.size()};
    }

    [[nodiscard]] SubjectKey subject() {
        return SubjectKey {
            .peer = PeerId {"fuzz-peer"},
            .descriptor = SchemaId {"process/v1"},
            .identity = {{.field_id = 1, .value = std::uint64_t {1}}},
            .parent = {},
        };
    }

    [[nodiscard]] ExplicitScanSpace space() {
        return ExplicitScanSpace {
            .identity = "fuzz.space",
            .kind = ScanSpaceKind::image_file,
            .begin = 0x1000,
            .size = scan_source_text.size(),
            .permissions = scan_permission_read,
            .label = DataLabel {},
            .subject_generation = 1,
        };
    }

    [[nodiscard]] TypedScanPlan plan_with(StaticScanPattern pattern) {
        return TypedScanPlan {
            .plan_id = "fuzz.plan",
            .patterns = {std::move(pattern)},
            .maximum_bytes = scan_source_text.size(),
            .maximum_matches = 32,
            .context_bytes_before = 1,
            .context_bytes_after = 1,
            .result_mode = ScanResultMode::exact_complete,
        };
    }

    [[nodiscard]] CorpusSeed encoded_plan_seed(const char selector, StaticScanPattern pattern, std::string name) {
        const auto encoded = serialize_scan_plan(space(), plan_with(std::move(pattern)));
        REQUIRE(encoded.has_value());
        auto result = fuzz_bytes(encoded->encoded_pattern);
        result.insert(result.begin(), static_cast<std::uint8_t>(selector));
        return CorpusSeed {.name = std::move(name), .bytes = std::move(result)};
    }

    [[nodiscard]] CorpusSeed protocol_seed(StaticScanPattern pattern) {
        const ProviderScanRequest request {
            .request_id = RequestId {"fuzz-scan"},
            .subject = subject(),
            .space = space(),
            .plan = plan_with(std::move(pattern)),
            .deadline_unix_ms = 5'000,
        };
        const auto contract_request = to_contract_scan_request(request);
        REQUIRE(contract_request.has_value());
        const PeerEnvelope envelope {
            .protocol_major = major_version,
            .protocol_minor = initial_minor_version,
            .message_id = "fuzz-work",
            .session = SessionId {"fuzz-session"},
            .agent_epoch = "fuzz-epoch",
            .agent_sequence = 0,
            .acknowledged_agent_sequence = 0,
            .body = WorkLeaseMessage {.session = SessionId {"fuzz-session"},
                                      .peer = PeerId {"fuzz-peer"},
                                      .session_fence = 1,
                                      .work_id = "fuzz-work",
                                      .attempt_id = "fuzz-attempt",
                                      .work_fence = 1,
                                      .generation = 1,
                                      .server_sequence = 1,
                                      .route = "fuzz.scan",
                                      .facts = {},
                                      .scans = {*contract_request}},
        };
        const auto encoded = encode_frame(envelope);
        REQUIRE(encoded.has_value());
        return CorpusSeed {.name = "valid-protocol-work-lease", .bytes = fuzz_bytes(*encoded)};
    }

    [[nodiscard]] std::vector<CorpusSeed> deterministic_seeds() {
        const auto literal = make_byte_pattern("literal", bytes_of("MZ"));
        const auto regex = make_re2_pattern("regex", "MZ|alpha");
        REQUIRE(literal.has_value());
        REQUIRE(regex.has_value());

        std::vector<CorpusSeed> result;
        result.push_back(encoded_plan_seed('L', *literal, "valid-literal-plan"));
        result.push_back(encoded_plan_seed('R', *regex, "valid-regex-plan"));
        result.push_back(protocol_seed(*literal));
        result.push_back(CorpusSeed {.name = "valid-zero-length-match", .bytes = fuzz_bytes("ZERO\x03")});
        result.push_back(CorpusSeed {.name = "valid-re2-expression", .bytes = fuzz_bytes("MZ|alpha")});
        result.push_back(CorpusSeed {.name = "count-inflation", .bytes = fuzz_bytes("Lrsp1;18446744073709551615;")});
        result.push_back(CorpusSeed {.name = "length-inflation", .bytes = fuzz_bytes("Lrsp1;1;18446744073709551615;")});
        result.push_back(CorpusSeed {.name = "protocol-length-inflation",
                                     .bytes = {0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU}});
        result.push_back(
            CorpusSeed {.name = "invalid-utf8", .bytes = {0xf0U, 0x28U, 0x8cU, 0x28U, 0xc0U, 0xafU, 0x80U}});
        result.push_back(CorpusSeed {.name = "invalid-base64", .bytes = fuzz_bytes("!!!!====")});
        result.push_back(CorpusSeed {.name = "invalid-regex-unclosed", .bytes = fuzz_bytes("(")});
        result.push_back(CorpusSeed {.name = "invalid-regex-lookbehind", .bytes = fuzz_bytes("(?<=lookbehind)")});
        result.push_back(CorpusSeed {.name = "zero-length-match-at-zero", .bytes = fuzz_bytes("ZERO")});
        result.push_back(CorpusSeed {.name = "zero-length-match-at-end", .bytes = fuzz_bytes("ZERO\xff")});
        return result;
    }

    void run_input(const std::span<const std::uint8_t> input, std::size_t &run_count) {
        REQUIRE(LLVMFuzzerTestOneInput(input.data(), input.size()) == 0);
        ++run_count;
    }

} // namespace

static_assert(noexcept(LLVMFuzzerTestOneInput(nullptr, 0)));

TEST_CASE("optimizer scan fuzz boundary survives deterministic mutation corpus") {
    std::size_t run_count = 0;
    REQUIRE(LLVMFuzzerTestOneInput(nullptr, 0) == 0);
    ++run_count;

    for (const auto &seed : deterministic_seeds()) {
        CAPTURE(seed.name);
        run_input(seed.bytes, run_count);

        for (std::size_t prefix = 0; prefix < seed.bytes.size(); ++prefix) {
            run_input(std::span {seed.bytes}.first(prefix), run_count);
        }
        for (std::size_t index = 0; index < seed.bytes.size(); ++index) {
            auto low_bit = seed.bytes;
            low_bit[index] ^= 0x01U;
            run_input(low_bit, run_count);

            auto high_bit = seed.bytes;
            high_bit[index] ^= 0x80U;
            run_input(high_bit, run_count);
        }
    }

    INFO("deterministic fuzz invocations: " << run_count);
    CHECK(run_count > 1'000);
}
