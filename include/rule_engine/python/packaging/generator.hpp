#pragma once

#include "rule_engine/python/contract/budget.hpp"
#include "rule_engine/python/contract/core.hpp"
#include "rule_engine/python/packaging/error.hpp"
#include "rule_engine/python/packaging/source_pack.hpp"
#include "rule_engine/python/packaging/worker.hpp"

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

    struct WorkerGeneratorInput {
        std::string name;
        GeneratorInputFormat format {GeneratorInputFormat::bytes};
        std::vector<std::byte> bytes;
        auto operator<=>(const WorkerGeneratorInput &) const = default;
    };

    struct WorkerGeneratorTemplate {
        std::string factory;
        ExecutableId template_id;
        auto operator<=>(const WorkerGeneratorTemplate &) const = default;
    };

    struct TrustedGeneratorWorkerPayload {
        std::string callable;
        std::vector<std::byte> module_source;
        std::vector<WorkerGeneratorInput> inputs;
        std::vector<WorkerGeneratorTemplate> templates;
    };

    struct PythonWorkerGeneratorExecutor final: GeneratorExecutor {
        WorkerClient *client {};
        RequestId request_id_prefix;
        SourceId source;
        std::vector<std::byte> canonical_payload;
        bool generator_execution_authorized {};
        GeneratorLimits limits;

        [[nodiscard]] std::expected<GeneratorRun, PackagingError> run(std::uint32_t hash_seed) override;
    };

    [[nodiscard]] std::expected<CanonicalGeneratorOutput, PackagingError>
    canonicalize_generator_output(std::span<const GeneratedBinding> bindings, const GeneratorLimits &limits = {});
    [[nodiscard]] std::expected<CanonicalGeneratorOutput, PackagingError>
    compare_generator_runs(const GeneratorRun &first, const GeneratorRun &second, const GeneratorLimits &limits = {});
    [[nodiscard]] std::expected<CanonicalGeneratorOutput, PackagingError>
    execute_generator_twice(GeneratorExecutor &executor, std::uint32_t first_hash_seed, std::uint32_t second_hash_seed,
                            const GeneratorLimits &limits = {});
    [[nodiscard]] std::expected<std::vector<std::byte>, PackagingError>
    encode_trusted_generator_worker_payload(const TrustedGeneratorWorkerPayload &payload,
                                            const WorkerLimits &limits = {});
    [[nodiscard]] std::expected<std::vector<GeneratedBinding>, PackagingError>
    decode_generated_bindings_worker_payload(std::span<const std::byte> payload, const GeneratorLimits &limits = {});

} // namespace rule_engine::python::packaging
