#include "rule_engine/python/optimizer/scan_wire.hpp"
#include "rule_engine/python/protocol.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

    using namespace rule_engine::python;
    using namespace rule_engine::python::optimizer;
    using namespace rule_engine::python::protocol_v2;

    template<typename Type>
    concept HasPredicate = requires(Type value) { value.predicate; };

    template<typename Type>
    concept HasVerdict = requires(Type value) { value.verdict; };

    static_assert(!HasPredicate<ProviderScanRequest>);
    static_assert(!HasVerdict<ProviderScanRequest>);
    static_assert(!HasPredicate<ScanRequest>);
    static_assert(!HasVerdict<ScanResponse>);

    constexpr std::string_view scan_source_text = "bbb\nMZ alpha\nMZ";
    constexpr std::size_t maximum_result_fuzz_matches = 8;
    constexpr std::size_t maximum_result_fuzz_blob_bytes = 16;

    [[noreturn]] void invariant_failure() noexcept { std::abort(); }

    [[nodiscard]] std::vector<std::byte> bytes_of(const std::string_view text) {
        std::vector<std::byte> result;
        result.reserve(text.size());
        for (const char value : text) { result.push_back(static_cast<std::byte>(static_cast<unsigned char>(value))); }
        return result;
    }

    struct Cursor {
        std::span<const std::byte> input;
        std::size_t offset {};

        [[nodiscard]] std::uint8_t byte() noexcept {
            if (offset >= input.size()) {
                return 0;
            }
            return std::to_integer<std::uint8_t>(input[offset++]);
        }

        [[nodiscard]] std::uint16_t number() noexcept {
            const auto high = static_cast<std::uint16_t>(byte());
            return static_cast<std::uint16_t>((high << 8U) | byte());
        }

        [[nodiscard]] std::span<const std::byte> take(const std::size_t maximum) noexcept {
            const auto requested = static_cast<std::size_t>(byte()) % (maximum + 1U);
            const auto count = std::min(requested, input.size() - offset);
            const auto result = input.subspan(offset, count);
            offset += count;
            return result;
        }

        [[nodiscard]] std::string text(const std::size_t maximum) {
            const auto value = take(maximum);
            if (value.empty()) {
                return {};
            }
            return std::string {reinterpret_cast<const char *>(value.data()), value.size()};
        }

        [[nodiscard]] std::vector<std::byte> blob(const std::size_t maximum) {
            const auto value = take(maximum);
            return {value.begin(), value.end()};
        }
    };

    [[nodiscard]] SubjectKey subject() {
        return SubjectKey {
            .peer = PeerId {"fuzz-peer"},
            .descriptor = SchemaId {"process/v1"},
            .identity = {{.field_id = 1, .value = std::uint64_t {1}}},
            .parent = {},
        };
    }

    [[nodiscard]] ExplicitScanSpace explicit_space(const std::uint64_t size) {
        return ExplicitScanSpace {
            .identity = "fuzz.space",
            .kind = ScanSpaceKind::image_file,
            .begin = 0x1000,
            .size = size,
            .permissions = scan_permission_read,
            .label = DataLabel {},
            .subject_generation = 1,
        };
    }

    [[nodiscard]] ScanSpace contract_space(const std::uint64_t size) {
        return ScanSpace {
            .kind = "file",
            .begin = 0x1000,
            .size = size,
            .permissions = scan_permission_read,
            .identity = "fuzz.space",
            .label = DataLabel {},
            .subject_generation = 1,
        };
    }

    [[nodiscard]] TypedScanPlan typed_plan(std::vector<StaticScanPattern> patterns, const ScanResultMode mode,
                                           const std::uint64_t maximum_bytes) {
        return TypedScanPlan {
            .plan_id = "fuzz.plan",
            .patterns = std::move(patterns),
            .maximum_bytes = maximum_bytes,
            .maximum_matches = 32,
            .context_bytes_before = 1,
            .context_bytes_after = 1,
            .result_mode = mode,
        };
    }

    [[nodiscard]] bool same_plan(const ScanPlan &left, const ScanPlan &right) noexcept {
        return left.plan_id == right.plan_id && left.encoded_pattern == right.encoded_pattern &&
               left.maximum_bytes == right.maximum_bytes && left.maximum_matches == right.maximum_matches &&
               left.context_bytes_before == right.context_bytes_before &&
               left.context_bytes_after == right.context_bytes_after && left.result_mode == right.result_mode &&
               left.pattern_ids == right.pattern_ids;
    }

    void require_protocol_round_trip(const PeerEnvelope &envelope) {
        const auto encoded = encode_frame(envelope);
        if (!encoded) {
            invariant_failure();
        }
        const auto decoded = decode_frame(*encoded);
        if (!decoded || decoded->bytes_consumed != encoded->size()) {
            invariant_failure();
        }
        const auto encoded_again = encode_frame(decoded->envelope);
        if (!encoded_again || *encoded_again != *encoded) {
            invariant_failure();
        }
    }

    void fuzz_protocol_frame(const std::span<const std::byte> input) {
        const ProtocolLimits limits;
        if (input.size() > limits.maximum_frame_bytes) {
            return;
        }
        const auto decoded = decode_frame(input, limits);
        if (!decoded) {
            return;
        }
        const auto canonical = encode_frame(decoded->envelope, limits);
        if (!canonical) {
            invariant_failure();
        }
        const auto decoded_again = decode_frame(*canonical, limits);
        if (!decoded_again || decoded_again->bytes_consumed != canonical->size()) {
            invariant_failure();
        }
        const auto canonical_again = encode_frame(decoded_again->envelope, limits);
        if (!canonical_again || *canonical_again != *canonical) {
            invariant_failure();
        }
    }

    [[nodiscard]] std::string plan_pattern_id(const std::uint8_t selector) {
        switch (selector) {
            case static_cast<std::uint8_t>('R'):
            case static_cast<std::uint8_t>('r'): return "regex";
            case static_cast<std::uint8_t>('M'):
            case static_cast<std::uint8_t>('m'): return "masked";
            default: return "literal";
        }
    }

    [[nodiscard]] bool curated_text_plan(const std::uint8_t selector) noexcept {
        return selector == static_cast<std::uint8_t>('l') || selector == static_cast<std::uint8_t>('r') ||
               selector == static_cast<std::uint8_t>('m');
    }

    void fuzz_scan_plan(const std::span<const std::byte> input) {
        if (input.empty()) {
            return;
        }
        const ScanWireLimits limits;
        const auto selector = std::to_integer<std::uint8_t>(input.front());
        auto payload = input.subspan(1);
        if (curated_text_plan(selector) && !payload.empty() && payload.back() == std::byte {'\n'}) {
            payload = payload.first(payload.size() - 1U);
        }
        if (payload.size() > limits.maximum_encoded_plan_bytes) {
            return;
        }
        const auto source = bytes_of(scan_source_text);
        const auto pattern_id = plan_pattern_id(selector);
        ScanPlan plan {
            .plan_id = "fuzz.plan",
            .encoded_pattern = payload.empty() ?
                                   std::string {} :
                                   std::string {reinterpret_cast<const char *>(payload.data()), payload.size()},
            .maximum_bytes = source.size(),
            .maximum_matches = 32,
            .context_bytes_before = 1,
            .context_bytes_after = 1,
            .result_mode = ScanResultMode::exact_complete,
            .pattern_ids = {pattern_id},
        };
        const auto decoded = deserialize_scan_plan(contract_space(source.size()), plan, limits);
        if (!decoded) {
            return;
        }
        const auto canonical = serialize_scan_plan(decoded->space, decoded->plan, limits);
        if (!canonical || !same_plan(*canonical, plan)) {
            invariant_failure();
        }

        ProviderScanRequest request {
            .request_id = RequestId {"fuzz-scan"},
            .subject = subject(),
            .space = decoded->space,
            .plan = decoded->plan,
            .deadline_unix_ms = 5'000,
        };
        const auto contract_request = to_contract_scan_request(request, limits);
        if (!contract_request) {
            invariant_failure();
        }
        const auto restored_request = from_contract_scan_request(*contract_request, limits);
        if (!restored_request) {
            invariant_failure();
        }
        require_protocol_round_trip(PeerEnvelope {
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
        });

        const auto matches = execute_scan(restored_request->space, restored_request->plan, source, 0x1000);
        if (!matches) {
            return;
        }
        const auto response = to_contract_scan_response(*restored_request, *matches, limits);
        if (!response) {
            invariant_failure();
        }
        const auto restored_matches = from_contract_scan_response(*restored_request, *response, limits);
        if (!restored_matches || restored_matches->count() != matches->count()) {
            invariant_failure();
        }
        require_protocol_round_trip(PeerEnvelope {
            .protocol_major = major_version,
            .protocol_minor = initial_minor_version,
            .message_id = "fuzz-result",
            .session = SessionId {"fuzz-session"},
            .agent_epoch = "fuzz-epoch",
            .agent_sequence = 1,
            .acknowledged_agent_sequence = 0,
            .body = WorkResultMessage {.originating_session = SessionId {"fuzz-session"},
                                       .peer = PeerId {"fuzz-peer"},
                                       .originating_session_fence = 1,
                                       .work_id = "fuzz-work",
                                       .attempt_id = "fuzz-attempt",
                                       .work_fence = 1,
                                       .generation = 1,
                                       .facts = {},
                                       .scans = {*response}},
        });
    }

    [[nodiscard]] std::vector<std::byte> context_before(const std::span<const std::byte> source,
                                                        const std::size_t offset) {
        const auto count = std::min<std::size_t>(1, offset);
        return {source.begin() + static_cast<std::ptrdiff_t>(offset - count),
                source.begin() + static_cast<std::ptrdiff_t>(offset)};
    }

    [[nodiscard]] std::vector<std::byte> context_after(const std::span<const std::byte> source,
                                                       const std::size_t offset) {
        const auto count = std::min<std::size_t>(1, source.size() - offset);
        return {source.begin() + static_cast<std::ptrdiff_t>(offset),
                source.begin() + static_cast<std::ptrdiff_t>(offset + count)};
    }

    [[nodiscard]] bool zero_match_seed(const std::span<const std::byte> input) noexcept {
        constexpr std::array magic {std::byte {'Z'}, std::byte {'E'}, std::byte {'R'}, std::byte {'O'}};
        return input.size() >= magic.size() && std::ranges::equal(input.first(magic.size()), magic);
    }

    void fuzz_scan_result(const std::span<const std::byte> input) {
        const auto source = bytes_of("bbb");
        const std::array literal_bytes {std::byte {'M'}, std::byte {'Z'}};
        const auto literal = make_byte_pattern("literal", literal_bytes);
        const auto empty = make_re2_pattern("empty", "a*");
        if (!literal || !empty) {
            invariant_failure();
        }

        Cursor cursor {input};
        const auto valid_zero = zero_match_seed(input);
        if (valid_zero) {
            cursor.offset = 4;
        }
        const auto mode =
            valid_zero || (cursor.byte() & 1U) != 0U ? ScanResultMode::existential : ScanResultMode::exact_complete;
        ProviderScanRequest request {
            .request_id = RequestId {"fuzz-result"},
            .subject = subject(),
            .space = explicit_space(source.size()),
            .plan = typed_plan({*literal, *empty}, mode, source.size()),
            .deadline_unix_ms = 5'000,
        };
        request.plan.maximum_matches = maximum_result_fuzz_matches;

        ScanResponse response {
            .request_id = request.request_id,
            .subject = request.subject,
            .status = FactTerminalStatus::value,
            .matches = {},
            .truncated = false,
            .diagnostic = std::nullopt,
            .mode = mode,
        };
        if (valid_zero) {
            const auto offset = static_cast<std::size_t>(cursor.byte()) % (source.size() + 1U);
            response.matches.push_back(ScanMatch {
                .offset = offset,
                .length = 0,
                .pattern_id = "empty",
                .scan_space_id = request.space.identity,
                .absolute_address = request.space.begin + offset,
                .permission_snapshot = request.space.permissions,
                .matched_bytes = {},
                .before_bytes = context_before(source, offset),
                .after_bytes = context_after(source, offset),
                .label = request.space.label,
                .subject_generation = request.space.subject_generation,
            });
        } else {
            response.status = static_cast<FactTerminalStatus>(cursor.byte() % 8U);
            response.truncated = (cursor.byte() & 1U) != 0U;
            const auto match_count = static_cast<std::size_t>(cursor.byte()) % (maximum_result_fuzz_matches + 1U);
            response.matches.reserve(match_count);
            for (std::size_t index = 0; index < match_count; ++index) {
                const auto pattern_selector = cursor.byte() % 3U;
                std::string pattern_id;
                if (pattern_selector == 0) {
                    pattern_id = "literal";
                } else if (pattern_selector == 1) {
                    pattern_id = "empty";
                } else {
                    pattern_id = cursor.text(16);
                }
                const auto offset = static_cast<std::uint64_t>(cursor.number());
                const auto length = static_cast<std::uint64_t>(cursor.byte() % 9U);
                const auto address_delta = static_cast<std::uint64_t>(cursor.byte());
                DataLabel label {
                    .classification = static_cast<Classification>(cursor.byte() % 6U),
                    .categories = {},
                };
                if ((cursor.byte() & 1U) != 0U) {
                    label.categories.push_back(cursor.text(16));
                }
                response.matches.push_back(ScanMatch {
                    .offset = offset,
                    .length = length,
                    .pattern_id = std::move(pattern_id),
                    .scan_space_id = (cursor.byte() & 1U) != 0U ? request.space.identity : cursor.text(16),
                    .absolute_address = request.space.begin + offset + address_delta,
                    .permission_snapshot = cursor.byte() % 8U,
                    .matched_bytes = cursor.blob(maximum_result_fuzz_blob_bytes),
                    .before_bytes = cursor.blob(maximum_result_fuzz_blob_bytes),
                    .after_bytes = cursor.blob(maximum_result_fuzz_blob_bytes),
                    .label = std::move(label),
                    .subject_generation = cursor.byte(),
                });
            }
        }

        const auto decoded = from_contract_scan_response(request, response);
        if (!decoded) {
            return;
        }
        const auto canonical = to_contract_scan_response(request, *decoded);
        if (!canonical) {
            invariant_failure();
        }
        const auto decoded_again = from_contract_scan_response(request, *canonical);
        if (!decoded_again || decoded_again->count() != decoded->count()) {
            invariant_failure();
        }
        require_protocol_round_trip(PeerEnvelope {
            .protocol_major = major_version,
            .protocol_minor = initial_minor_version,
            .message_id = "fuzz-result",
            .session = SessionId {"fuzz-session"},
            .agent_epoch = "fuzz-epoch",
            .agent_sequence = 1,
            .acknowledged_agent_sequence = 0,
            .body = WorkResultMessage {.originating_session = SessionId {"fuzz-session"},
                                       .peer = PeerId {"fuzz-peer"},
                                       .originating_session_fence = 1,
                                       .work_id = "fuzz-work",
                                       .attempt_id = "fuzz-attempt",
                                       .work_fence = 1,
                                       .generation = 1,
                                       .facts = {},
                                       .scans = {*canonical}},
        });
    }

    void fuzz_re2(const std::span<const std::byte> input) {
        if (input.empty()) {
            return;
        }
        const ScanWireLimits limits;
        const auto expression_size = std::min(input.size(), limits.maximum_regex_source_bytes);
        const auto expression_bytes = input.first(expression_size);
        const auto expression =
            std::string_view {reinterpret_cast<const char *>(expression_bytes.data()), expression_bytes.size()};
        const auto control = std::to_integer<std::uint8_t>(input.front());
        const RegexOptions options {
            .encoding = (control & 1U) != 0U ? RegexEncoding::latin1 : RegexEncoding::utf8,
            .case_sensitive = (control & 2U) == 0U,
            .dot_matches_newline = (control & 4U) != 0U,
            .multiline = (control & 8U) != 0U,
        };
        const auto pattern = make_re2_pattern("fuzz.regex", expression, options);
        if (!pattern) {
            return;
        }
        const auto source = bytes_of(scan_source_text);
        auto plan = typed_plan({*pattern}, ScanResultMode::existential, source.size());
        plan.maximum_matches = 1;
        static_cast<void>(execute_scan(explicit_space(source.size()), plan, source, 0x1000));
    }

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) noexcept;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, const std::size_t size) noexcept {
    const ScanWireLimits limits;
    if ((data == nullptr && size != 0) || size > limits.maximum_encoded_plan_bytes) {
        return 0;
    }
    const auto input = std::as_bytes(std::span<const std::uint8_t> {data, size});
    fuzz_protocol_frame(input);
    fuzz_scan_plan(input);
    fuzz_scan_result(input);
    fuzz_re2(input);
    return 0;
}
