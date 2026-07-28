#include "rule_engine/python/compiler/source_pack_compiler.hpp"

#include "rule_engine/python/compiler/worker_adapter.hpp"

#include <algorithm>
#include <memory>
#include <ranges>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::compiler {
    namespace {

        using packaging::ArchiveEntry;
        using packaging::CanonicalGeneratorOutput;
        using packaging::LoadedSourcePack;
        using packaging::PackagingError;
        using packaging::SourcePackArchive;

        [[nodiscard]] SourcePackCompileError error(const SourcePackCompileErrorKind kind, std::string code,
                                                   std::string message, DiagnosticSet diagnostics = {}) {
            return {
                .kind = kind,
                .code = std::move(code),
                .message = std::move(message),
                .diagnostics = std::move(diagnostics),
            };
        }

        [[nodiscard]] SourcePackCompileError packaging_error(const SourcePackCompileErrorKind kind, std::string code,
                                                             const PackagingError &failure) {
            auto message = failure.message;
            if (failure.subject) {
                message += " (" + *failure.subject + ')';
            }
            return error(kind, std::move(code), std::move(message));
        }

        [[nodiscard]] const ArchiveEntry *find_entry(const SourcePackArchive &archive, const std::string_view path) {
            const auto found = std::ranges::find(archive.entries, path, &ArchiveEntry::path);
            return found == archive.entries.end() ? nullptr : std::addressof(*found);
        }

        [[nodiscard]] std::string module_path(const std::string_view module) {
            std::string result {"generator/"};
            result.reserve(result.size() + module.size() + 3U);
            for (const char character : module) { result.push_back(character == '.' ? '/' : character); }
            result += ".py";
            return result;
        }

        [[nodiscard]] std::expected<CanonicalGeneratorOutput, SourcePackCompileError>
        execute_generator(const LoadedSourcePack &pack, const SourcePackArchive &archive,
                          const CompilationArtifact &discovery, packaging::WorkerClient &worker) {
            const auto &declaration = *pack.manifest.generator;
            const auto path = module_path(declaration.module);
            const auto *module = find_entry(archive, path);
            if (module == nullptr) {
                return std::unexpected(error(SourcePackCompileErrorKind::source, "PACK-GENERATOR-SOURCE",
                                             "declared generator module is absent"));
            }

            std::vector<packaging::WorkerGeneratorTemplate> templates;
            for (const auto &symbol : discovery.symbols) {
                if (symbol.kind != SymbolKind::rule_template) {
                    continue;
                }
                const auto function =
                    std::ranges::find(discovery.pack.functions, symbol.executable, &BytecodeFunction::id);
                if (function == discovery.pack.functions.end()) {
                    return std::unexpected(error(SourcePackCompileErrorKind::invariant, "PY-GENERATOR-TEMPLATE",
                                                 "compiled rule template has no executable"));
                }
                templates.push_back(packaging::WorkerGeneratorTemplate {
                    .factory = symbol.name,
                    .template_id = symbol.executable,
                });
            }
            std::ranges::sort(templates, {}, &packaging::WorkerGeneratorTemplate::factory);

            std::vector<packaging::WorkerGeneratorInput> inputs;
            inputs.reserve(declaration.inputs.size());
            for (const auto &input : declaration.inputs) {
                const auto *entry = find_entry(archive, input.path);
                if (entry == nullptr) {
                    return std::unexpected(error(SourcePackCompileErrorKind::source, "PACK-GENERATOR-INPUT",
                                                 "declared generator input is absent"));
                }
                inputs.push_back(packaging::WorkerGeneratorInput {
                    .name = input.name,
                    .format = input.format,
                    .bytes = entry->bytes,
                });
            }

            auto payload = packaging::encode_trusted_generator_worker_payload(packaging::TrustedGeneratorWorkerPayload {
                .callable = declaration.callable,
                .module_source = module->bytes,
                .inputs = std::move(inputs),
                .templates = std::move(templates),
            });
            if (!payload) {
                return std::unexpected(
                    packaging_error(SourcePackCompileErrorKind::generator, "PY-GENERATOR-PAYLOAD", payload.error()));
            }

            packaging::PythonWorkerGeneratorExecutor executor;
            executor.client = std::addressof(worker);
            executor.request_id_prefix = RequestId {"source-pack-generator"};
            executor.source = SourceId {path};
            executor.canonical_payload = std::move(*payload);
            executor.generator_execution_authorized = true;
            auto generated = packaging::execute_generator_twice(executor, 0x13579U, 0x24680U);
            if (!generated) {
                return std::unexpected(
                    packaging_error(SourcePackCompileErrorKind::generator, "PY-GENERATOR", generated.error()));
            }
            return std::move(*generated);
        }

    } // namespace

    std::expected<SourcePackCompilation, SourcePackCompileError>
    compile_source_pack(const LoadedSourcePack &pack, const SourcePackArchive &archive, packaging::WorkerClient &worker,
                        const SchemaCatalog &schemas, const std::stop_token cancellation) {
        if (cancellation.stop_requested()) {
            return std::unexpected(
                error(SourcePackCompileErrorKind::canceled, "PY-CANCELLED", "source-pack compilation was canceled"));
        }
        if (pack.manifest.generator && !pack.trust.generator_execution_authorized) {
            return std::unexpected(error(SourcePackCompileErrorKind::authorization, "PACK-GENERATOR-AUTH",
                                         "pack trust policy does not authorize generator execution"));
        }

        WorkerAstEnvelopeProvider provider {worker};
        auto ast_payload = provider.load(pack.contract_pack);
        if (!ast_payload) {
            return std::unexpected(error(SourcePackCompileErrorKind::worker, "PY-WORKER",
                                         "exact private parser worker rejected the pack",
                                         std::move(ast_payload.error())));
        }

        StaticCompiler compiler;
        auto discovery = compiler.compile(pack.contract_pack, *ast_payload, schemas, {});
        if (!discovery) {
            return std::unexpected(error(SourcePackCompileErrorKind::compiler, "PY-COMPILE",
                                         "static discovery compilation failed", std::move(discovery.error())));
        }

        auto bindings = default_rule_bindings(*discovery, pack.manifest.required_capabilities);
        std::optional<CanonicalGeneratorOutput> generated;
        if (pack.manifest.generator) {
            auto output = execute_generator(pack, archive, *discovery, worker);
            if (!output) {
                return std::unexpected(std::move(output.error()));
            }
            bindings.reserve(bindings.size() + output->bindings.size());
            for (const auto &binding : output->bindings) {
                bindings.push_back(OperatorBinding {
                    .id = binding.id,
                    .executable = binding.template_id,
                    .capabilities = pack.manifest.required_capabilities,
                    .budget = balanced_v1,
                });
            }
            generated = std::move(*output);
        }
        if (cancellation.stop_requested()) {
            return std::unexpected(
                error(SourcePackCompileErrorKind::canceled, "PY-CANCELLED", "source-pack compilation was canceled"));
        }
        auto bound = compiler.compile(pack.contract_pack, *ast_payload, schemas, bindings);
        if (!bound) {
            return std::unexpected(error(SourcePackCompileErrorKind::compiler, "PY-COMPILE",
                                         "bound static compilation failed", std::move(bound.error())));
        }
        return SourcePackCompilation {.artifact = std::move(*bound), .generated = std::move(generated)};
    }

} // namespace rule_engine::python::compiler
