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

} // namespace rule_engine::python::packaging
