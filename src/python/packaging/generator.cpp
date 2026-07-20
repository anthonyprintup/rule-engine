#include "rule_engine/python/packaging/generator.hpp"

#include "rule_engine/python/packaging/source_pack.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

namespace rule_engine::python::packaging {
    namespace {

        PackagingError generator_error(const PackagingErrorCode code, std::string message,
                                       std::optional<std::string> subject = std::nullopt) {
            return PackagingError {.code = code, .message = std::move(message), .subject = std::move(subject)};
        }

        bool valid_stable_id(const std::string_view value) noexcept {
            if (value.empty() || value.size() > 128U || value.front() == '.' || value.back() == '.' ||
                value.find("..") != std::string_view::npos) {
                return false;
            }
            return std::ranges::all_of(value, [](const char character) {
                return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
                       character == '.' || character == '_' || character == '-';
            });
        }

        void append_u32(std::vector<std::byte> &output, const std::uint32_t value) {
            for (unsigned shift = 0; shift < 32U; shift += 8U) {
                output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
            }
        }

        void append_string(std::vector<std::byte> &output, const std::string_view value) {
            append_u32(output, static_cast<std::uint32_t>(value.size()));
            output.insert(output.end(), reinterpret_cast<const std::byte *>(value.data()),
                          reinterpret_cast<const std::byte *>(value.data() + value.size()));
        }

        void append_bytes(std::vector<std::byte> &output, const std::span<const std::byte> value) {
            append_u32(output, static_cast<std::uint32_t>(value.size()));
            output.insert(output.end(), value.begin(), value.end());
        }

        bool safe_json_atom(const std::string_view value) noexcept {
            return !value.empty() && std::ranges::all_of(value, [](const char character) {
                return character >= 0x21 && character <= 0x7e && character != '"' && character != '\\';
            });
        }

        std::string base64_encode(const std::span<const std::byte> bytes) {
            constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string output;
            output.reserve((bytes.size() + 2U) / 3U * 4U);
            for (std::size_t index = 0U; index < bytes.size(); index += 3U) {
                const auto remaining = bytes.size() - index;
                const auto first = std::to_integer<std::uint32_t>(bytes[index]);
                const auto second = remaining > 1U ? std::to_integer<std::uint32_t>(bytes[index + 1U]) : 0U;
                const auto third = remaining > 2U ? std::to_integer<std::uint32_t>(bytes[index + 2U]) : 0U;
                const auto value = (first << 16U) | (second << 8U) | third;
                output.push_back(alphabet[(value >> 18U) & 0x3fU]);
                output.push_back(alphabet[(value >> 12U) & 0x3fU]);
                output.push_back(remaining > 1U ? alphabet[(value >> 6U) & 0x3fU] : '=');
                output.push_back(remaining > 2U ? alphabet[value & 0x3fU] : '=');
            }
            return output;
        }

        std::expected<std::vector<std::byte>, PackagingError> base64_decode(const std::string_view text) {
            if (text.size() % 4U != 0U) {
                return std::unexpected(generator_error(PackagingErrorCode::worker_frame_malformed,
                                                       "generated binding base64 length is invalid"));
            }
            auto value_of = [](const char character) noexcept {
                if (character >= 'A' && character <= 'Z') {
                    return static_cast<int>(character - 'A');
                }
                if (character >= 'a' && character <= 'z') {
                    return static_cast<int>(character - 'a' + 26);
                }
                if (character >= '0' && character <= '9') {
                    return static_cast<int>(character - '0' + 52);
                }
                if (character == '+') {
                    return 62;
                }
                if (character == '/') {
                    return 63;
                }
                return -1;
            };
            std::vector<std::byte> bytes;
            bytes.reserve(text.size() / 4U * 3U);
            for (std::size_t index = 0U; index < text.size(); index += 4U) {
                const bool third_padding = text[index + 2U] == '=';
                const bool fourth_padding = text[index + 3U] == '=';
                if ((third_padding && !fourth_padding) ||
                    ((third_padding || fourth_padding) && index + 4U != text.size())) {
                    return std::unexpected(generator_error(PackagingErrorCode::worker_frame_malformed,
                                                           "generated binding base64 padding is invalid"));
                }
                const auto first = value_of(text[index]);
                const auto second = value_of(text[index + 1U]);
                const auto third = third_padding ? 0 : value_of(text[index + 2U]);
                const auto fourth = fourth_padding ? 0 : value_of(text[index + 3U]);
                if (first < 0 || second < 0 || third < 0 || fourth < 0) {
                    return std::unexpected(generator_error(PackagingErrorCode::worker_frame_malformed,
                                                           "generated binding base64 data is invalid"));
                }
                const auto value = (static_cast<std::uint32_t>(first) << 18U) |
                                   (static_cast<std::uint32_t>(second) << 12U) |
                                   (static_cast<std::uint32_t>(third) << 6U) | static_cast<std::uint32_t>(fourth);
                bytes.push_back(static_cast<std::byte>((value >> 16U) & 0xffU));
                if (!third_padding) {
                    bytes.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
                }
                if (!fourth_padding) {
                    bytes.push_back(static_cast<std::byte>(value & 0xffU));
                }
                if ((third_padding && (value & 0xffffU) != 0U) ||
                    (fourth_padding && !third_padding && (value & 0xffU) != 0U)) {
                    return std::unexpected(generator_error(PackagingErrorCode::worker_frame_malformed,
                                                           "generated binding base64 padding bits are not zero"));
                }
            }
            return bytes;
        }

        std::string_view input_format_name(const GeneratorInputFormat format) noexcept {
            switch (format) {
                case GeneratorInputFormat::json: return "json";
                case GeneratorInputFormat::utf8: return "utf8";
                case GeneratorInputFormat::bytes: return "bytes";
                default: return {};
            }
        }

        struct JsonCursor {
            std::string_view text;
            std::size_t offset {};

            bool consume(const std::string_view expected) noexcept {
                if (!text.substr(offset).starts_with(expected)) {
                    return false;
                }
                offset += expected.size();
                return true;
            }

            std::expected<std::string, PackagingError> quoted(const std::string_view field) {
                const auto end = text.find('"', offset);
                if (end == std::string_view::npos) {
                    return std::unexpected(generator_error(PackagingErrorCode::worker_frame_malformed,
                                                           "generated binding JSON string is truncated",
                                                           std::string {field}));
                }
                const auto value = text.substr(offset, end - offset);
                if (!safe_json_atom(value)) {
                    return std::unexpected(generator_error(PackagingErrorCode::worker_frame_malformed,
                                                           "generated binding JSON string is not canonical",
                                                           std::string {field}));
                }
                offset = end;
                return std::string {value};
            }
        };

    } // namespace

    std::expected<CanonicalGeneratorOutput, PackagingError>
    canonicalize_generator_output(const std::span<const GeneratedBinding> bindings, const GeneratorLimits &limits) {
        if (bindings.size() > limits.maximum_bindings || bindings.size() > std::numeric_limits<std::uint32_t>::max()) {
            return std::unexpected(
                generator_error(PackagingErrorCode::generator_limit, "generator emitted too many bindings"));
        }
        std::vector<GeneratedBinding> sorted {bindings.begin(), bindings.end()};
        std::ranges::sort(sorted, {}, [](const GeneratedBinding &binding) { return binding.id.value; });

        std::size_t argument_bytes {};
        std::string previous_id;
        for (const auto &binding : sorted) {
            if (!valid_stable_id(binding.id.value) || !valid_stable_id(binding.template_id.value) ||
                binding.id.value.size() > std::numeric_limits<std::uint32_t>::max() ||
                binding.template_id.value.size() > std::numeric_limits<std::uint32_t>::max() ||
                binding.canonical_arguments.size() > std::numeric_limits<std::uint32_t>::max()) {
                return std::unexpected(generator_error(PackagingErrorCode::invalid_binding,
                                                       "generated binding identity or arguments are invalid",
                                                       binding.id.value));
            }
            if (binding.id.value == previous_id) {
                return std::unexpected(generator_error(PackagingErrorCode::duplicate_binding,
                                                       "generator emitted a duplicate binding ID", binding.id.value));
            }
            previous_id = binding.id.value;
            if (binding.canonical_arguments.size() > limits.maximum_argument_bytes ||
                argument_bytes > limits.maximum_argument_bytes - binding.canonical_arguments.size()) {
                return std::unexpected(generator_error(PackagingErrorCode::generator_limit,
                                                       "generator argument bytes exceed the configured bound",
                                                       binding.id.value));
            }
            argument_bytes += binding.canonical_arguments.size();
        }

        static constexpr char domain_chars[] = "rule-engine-generator-output-v1\0";
        constexpr std::string_view domain {domain_chars, sizeof(domain_chars) - 1U};
        std::vector<std::byte> canonical;
        canonical.reserve(domain.size() + 4U + argument_bytes + sorted.size() * 16U);
        canonical.insert(canonical.end(), reinterpret_cast<const std::byte *>(domain.data()),
                         reinterpret_cast<const std::byte *>(domain.data() + domain.size()));
        append_u32(canonical, static_cast<std::uint32_t>(sorted.size()));
        for (const auto &binding : sorted) {
            append_string(canonical, binding.id.value);
            append_string(canonical, binding.template_id.value);
            append_bytes(canonical, binding.canonical_arguments);
        }
        return CanonicalGeneratorOutput {
            .bindings = std::move(sorted),
            .canonical_bytes = canonical,
            .digest = SourceDigest {"sha256:" + sha256_hex(canonical)},
        };
    }

    std::expected<CanonicalGeneratorOutput, PackagingError>
    compare_generator_runs(const GeneratorRun &first, const GeneratorRun &second, const GeneratorLimits &limits) {
        if (first.hash_seed == 0U || second.hash_seed == 0U || first.hash_seed == second.hash_seed) {
            return std::unexpected(generator_error(PackagingErrorCode::generator_seed_reused,
                                                   "determinism check requires two distinct nonzero hash seeds"));
        }
        auto first_output = canonicalize_generator_output(first.bindings, limits);
        if (!first_output) {
            return std::unexpected(first_output.error());
        }
        auto second_output = canonicalize_generator_output(second.bindings, limits);
        if (!second_output) {
            return std::unexpected(second_output.error());
        }
        if (first_output->canonical_bytes == second_output->canonical_bytes) {
            return first_output;
        }

        std::optional<std::string> first_difference;
        const auto common = std::min(first_output->bindings.size(), second_output->bindings.size());
        for (std::size_t index = 0; index < common; ++index) {
            if (first_output->bindings[index] != second_output->bindings[index]) {
                first_difference = first_output->bindings[index].id.value;
                break;
            }
        }
        if (!first_difference) {
            first_difference = first_output->bindings.size() > common ? first_output->bindings[common].id.value :
                                                                        second_output->bindings[common].id.value;
        }
        return std::unexpected(generator_error(PackagingErrorCode::generator_nondeterministic,
                                               "fresh generator runs produced different canonical bindings",
                                               std::move(first_difference)));
    }

    std::expected<CanonicalGeneratorOutput, PackagingError>
    execute_generator_twice(GeneratorExecutor &executor, const std::uint32_t first_hash_seed,
                            const std::uint32_t second_hash_seed, const GeneratorLimits &limits) {
        if (first_hash_seed == 0U || second_hash_seed == 0U || first_hash_seed == second_hash_seed) {
            return std::unexpected(generator_error(PackagingErrorCode::generator_seed_reused,
                                                   "generator executor requires distinct nonzero hash seeds"));
        }
        auto first = executor.run(first_hash_seed);
        if (!first) {
            return std::unexpected(first.error());
        }
        if (first->hash_seed != first_hash_seed) {
            return std::unexpected(generator_error(PackagingErrorCode::generator_nondeterministic,
                                                   "first generator run did not attest the requested hash seed"));
        }
        auto second = executor.run(second_hash_seed);
        if (!second) {
            return std::unexpected(second.error());
        }
        if (second->hash_seed != second_hash_seed) {
            return std::unexpected(generator_error(PackagingErrorCode::generator_nondeterministic,
                                                   "second generator run did not attest the requested hash seed"));
        }
        return compare_generator_runs(*first, *second, limits);
    }

    std::expected<std::vector<std::byte>, PackagingError>
    encode_trusted_generator_worker_payload(const TrustedGeneratorWorkerPayload &payload, const WorkerLimits &limits) {
        if (!safe_json_atom(payload.callable) || payload.module_source.size() > limits.maximum_payload_bytes) {
            return std::unexpected(
                generator_error(PackagingErrorCode::generator_limit, "generator callable or source bytes are invalid"));
        }
        auto inputs = payload.inputs;
        auto templates = payload.templates;
        std::ranges::sort(inputs, {}, &WorkerGeneratorInput::name);
        std::ranges::sort(templates, {}, &WorkerGeneratorTemplate::factory);
        std::size_t input_bytes {};
        std::string previous;
        for (const auto &input : inputs) {
            if (!safe_json_atom(input.name) || input.name == previous || input_format_name(input.format).empty() ||
                input.bytes.size() > limits.maximum_payload_bytes ||
                input_bytes > limits.maximum_payload_bytes - input.bytes.size()) {
                return std::unexpected(generator_error(PackagingErrorCode::generator_limit,
                                                       "generator input identity or aggregate bytes are invalid",
                                                       input.name));
            }
            previous = input.name;
            input_bytes += input.bytes.size();
        }
        previous.clear();
        for (const auto &item : templates) {
            if (!safe_json_atom(item.factory) || !safe_json_atom(item.template_id.value) || item.factory == previous) {
                return std::unexpected(generator_error(PackagingErrorCode::invalid_binding,
                                                       "generator template descriptor is invalid", item.factory));
            }
            previous = item.factory;
        }

        std::string json = "{\"callable\":\"" + payload.callable + "\",\"inputs\":[";
        for (std::size_t index = 0U; index < inputs.size(); ++index) {
            if (index != 0U) {
                json.push_back(',');
            }
            const auto &input = inputs[index];
            json += "{\"data_b64\":\"" + base64_encode(input.bytes) + "\",\"format\":\"" +
                    std::string {input_format_name(input.format)} + "\",\"name\":\"" + input.name + "\"}";
        }
        json += "],\"module_source_b64\":\"" + base64_encode(payload.module_source) + "\",\"templates\":[";
        for (std::size_t index = 0U; index < templates.size(); ++index) {
            if (index != 0U) {
                json.push_back(',');
            }
            const auto &item = templates[index];
            json += "{\"factory\":\"" + item.factory + "\",\"template_id\":\"" + item.template_id.value + "\"}";
        }
        json += "]}";
        if (json.size() > limits.maximum_payload_bytes) {
            return std::unexpected(generator_error(PackagingErrorCode::generator_limit,
                                                   "canonical generator request exceeds the worker payload bound"));
        }
        return std::vector<std::byte> {reinterpret_cast<const std::byte *>(json.data()),
                                       reinterpret_cast<const std::byte *>(json.data() + json.size())};
    }

    std::expected<std::vector<GeneratedBinding>, PackagingError>
    decode_generated_bindings_worker_payload(const std::span<const std::byte> payload, const GeneratorLimits &limits) {
        const std::string_view json {reinterpret_cast<const char *>(payload.data()), payload.size()};
        JsonCursor cursor {.text = json};
        if (!cursor.consume("{\"bindings\":[")) {
            return std::unexpected(generator_error(PackagingErrorCode::worker_frame_malformed,
                                                   "generated binding payload does not begin canonically"));
        }
        std::vector<GeneratedBinding> bindings;
        if (!cursor.consume("]")) {
            while (true) {
                if (bindings.size() >= limits.maximum_bindings || !cursor.consume("{\"arguments_b64\":\"")) {
                    return std::unexpected(generator_error(PackagingErrorCode::generator_limit,
                                                           "generated binding payload count or shape is invalid"));
                }
                auto arguments_text = cursor.quoted("arguments_b64");
                if (!arguments_text || !cursor.consume("\",\"id\":\"")) {
                    return std::unexpected(arguments_text ? generator_error(PackagingErrorCode::worker_frame_malformed,
                                                                            "generated binding ID field is missing") :
                                                            arguments_text.error());
                }
                auto id = cursor.quoted("id");
                if (!id || !cursor.consume("\",\"template_id\":\"")) {
                    return std::unexpected(id ? generator_error(PackagingErrorCode::worker_frame_malformed,
                                                                "generated binding template field is missing") :
                                                id.error());
                }
                auto template_id = cursor.quoted("template_id");
                if (!template_id || !cursor.consume("\"}")) {
                    return std::unexpected(template_id ? generator_error(PackagingErrorCode::worker_frame_malformed,
                                                                         "generated binding object is malformed") :
                                                         template_id.error());
                }
                auto arguments = base64_decode(*arguments_text);
                if (!arguments) {
                    return std::unexpected(arguments.error());
                }
                bindings.push_back(GeneratedBinding {
                    .id = BindingId {std::move(*id)},
                    .template_id = ExecutableId {std::move(*template_id)},
                    .canonical_arguments = std::move(*arguments),
                });
                if (cursor.consume("]")) {
                    break;
                }
                if (!cursor.consume(",")) {
                    return std::unexpected(generator_error(PackagingErrorCode::worker_frame_malformed,
                                                           "generated binding list separator is malformed"));
                }
            }
        }
        if (!cursor.consume(",\"format\":1,\"schema\":\"rule-engine.bindings/1\"}") || cursor.offset != json.size()) {
            return std::unexpected(generator_error(PackagingErrorCode::worker_frame_malformed,
                                                   "generated binding payload trailer is invalid"));
        }
        auto canonical = canonicalize_generator_output(bindings, limits);
        if (!canonical) {
            return std::unexpected(canonical.error());
        }
        return std::move(canonical->bindings);
    }

    std::expected<GeneratorRun, PackagingError> PythonWorkerGeneratorExecutor::run(const std::uint32_t hash_seed) {
        if (client == nullptr) {
            return std::unexpected(
                generator_error(PackagingErrorCode::worker_crashed, "generator executor has no worker client"));
        }
        WorkerRequest request {
            .protocol = python_worker_protocol_v1,
            .request_id = RequestId {request_id_prefix.value + "-" + std::to_string(hash_seed)},
            .mode = WorkerMode::trusted_generator,
            .runtime = client->runtime.descriptor,
            .payload =
                OpaqueWorkerPayload {
                    .schema = std::string {generator_request_schema_v1},
                    .source = source,
                    .source_digest = SourceDigest {"sha256:" + sha256_hex(canonical_payload)},
                    .bytes = canonical_payload,
                },
            .hash_seed = hash_seed,
            .generator_execution_authorized = generator_execution_authorized,
        };
        auto response = client->invoke(request);
        if (!response) {
            return std::unexpected(response.error());
        }
        auto bindings = decode_generated_bindings_worker_payload(response->payload.bytes, limits);
        if (!bindings) {
            return std::unexpected(bindings.error());
        }
        return GeneratorRun {.hash_seed = hash_seed, .bindings = std::move(*bindings)};
    }

} // namespace rule_engine::python::packaging
