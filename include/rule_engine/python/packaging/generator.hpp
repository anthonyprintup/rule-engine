#pragma once

#include "rule_engine/python/contract/budget.hpp"
#include "rule_engine/python/contract/core.hpp"
#include "rule_engine/python/packaging/error.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace rule_engine::python::packaging {

    struct GeneratedBinding {
        BindingId id;
        ExecutableId template_id;
        std::vector<std::byte> canonical_arguments;
        auto operator<=>(const GeneratedBinding &) const = default;
    };

    struct GeneratorRun {
        std::uint32_t hash_seed {};
        std::vector<GeneratedBinding> bindings;
    };

    struct GeneratorLimits {
        std::size_t maximum_bindings {balanced_v1.compile.generated_bindings};
        std::size_t maximum_argument_bytes {balanced_v1.compile.generator_input_bytes};
    };

    struct CanonicalGeneratorOutput {
        std::vector<GeneratedBinding> bindings;
        std::vector<std::byte> canonical_bytes;
        SourceDigest digest;
    };

    struct GeneratorExecutor {
        virtual ~GeneratorExecutor() = default;

        [[nodiscard]] virtual std::expected<GeneratorRun, PackagingError> run(std::uint32_t hash_seed) = 0;
    };

    [[nodiscard]] std::expected<CanonicalGeneratorOutput, PackagingError>
    canonicalize_generator_output(std::span<const GeneratedBinding> bindings, const GeneratorLimits &limits = {});
    [[nodiscard]] std::expected<CanonicalGeneratorOutput, PackagingError>
    compare_generator_runs(const GeneratorRun &first, const GeneratorRun &second, const GeneratorLimits &limits = {});
    [[nodiscard]] std::expected<CanonicalGeneratorOutput, PackagingError>
    execute_generator_twice(GeneratorExecutor &executor, std::uint32_t first_hash_seed, std::uint32_t second_hash_seed,
                            const GeneratorLimits &limits = {});

} // namespace rule_engine::python::packaging
