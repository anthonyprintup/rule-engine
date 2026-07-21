#include "rule_engine/python/tools/filesystem.hpp"

#include "rule_engine/python/compiler.hpp"
#include "rule_engine/python/optimizer/optimizer.hpp"
#include "rule_engine/python/packaging.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace rule_engine::python::tools {
    namespace {

        using packaging::ArchiveEntry;
        using packaging::ArchiveEntryKind;
        using packaging::CanonicalGeneratorOutput;
        using packaging::GeneratorInputFormat;
        using packaging::LoadedSourcePack;
        using packaging::PackagingError;
        using packaging::PackagingErrorCode;
        using packaging::SourceIndex;
        using packaging::SourceIndexEntry;
        using packaging::SourcePackArchive;
        using packaging::TrustMode;

        constexpr std::size_t maximum_configuration_bytes = 1U * mebibyte;
        constexpr std::string_view sdk_content_digest =
            "sha256:a1917fbe67b4fe7b21667726390620d58b0dab09472b1b18e68c29121337cc0d";
        constexpr std::string_view sdk_manifest_digest =
            "53e7bf64b0bcadeb1989a868ea1e801ffd3612aa6c0863fa7bf46695b24e8d07";

        [[nodiscard]] ToolFailure failure(const ToolFailureKind kind, std::string code, std::string message) {
            return ToolFailure {
                .kind = kind,
                .code = std::move(code),
                .message = std::move(message),
                .diagnostics = {},
            };
        }

        [[nodiscard]] ToolFailure packaging_failure(const PackagingError &error) {
            auto message = error.message;
            if (error.subject.has_value()) {
                message += " (" + *error.subject + ')';
            }
            const auto unavailable = error.code == PackagingErrorCode::crypto_backend_unavailable ||
                                     error.code == PackagingErrorCode::runtime_missing ||
                                     error.code == PackagingErrorCode::runtime_mismatch ||
                                     error.code == PackagingErrorCode::runtime_staging_failed;
            return failure(unavailable ? ToolFailureKind::unavailable_dependency : ToolFailureKind::operation,
                           "PACK-" + std::to_string(static_cast<unsigned>(error.code)), std::move(message));
        }

        [[nodiscard]] std::expected<std::vector<std::byte>, ToolFailure> read_file(const std::filesystem::path &path,
                                                                                   const std::size_t maximum_bytes) {
            std::error_code filesystem_error;
            const auto status = std::filesystem::symlink_status(path, filesystem_error);
            if (filesystem_error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "TOOL-FILE", "required regular file is unavailable"));
            }
            const auto size = std::filesystem::file_size(path, filesystem_error);
            if (filesystem_error || size > maximum_bytes) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "TOOL-FILE-LIMIT", "file exceeds its configured bound"));
            }
            std::ifstream input {path, std::ios::binary};
            if (!input) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "TOOL-FILE", "cannot open required input file"));
            }
            std::vector<std::byte> bytes(static_cast<std::size_t>(size));
            if (!bytes.empty()) {
                input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            }
            if (!input || static_cast<std::size_t>(input.gcount()) != bytes.size()) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "TOOL-FILE", "cannot read complete input file"));
            }
            return bytes;
        }

        [[nodiscard]] std::string text(const std::span<const std::byte> bytes) {
            return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
        }

        [[nodiscard]] std::vector<std::byte> bytes(const std::string_view value) {
            return {reinterpret_cast<const std::byte *>(value.data()),
                    reinterpret_cast<const std::byte *>(value.data() + value.size())};
        }

        [[nodiscard]] std::string media_type(const std::string_view path) {
            if (path.ends_with(".py") || path.ends_with(".pyi")) {
                return "text/x-python";
            }
            if (path.ends_with(".toml")) {
                return "application/toml";
            }
            if (path.ends_with(".json")) {
                return "application/json";
            }
            if (path.ends_with(".rpack")) {
                return "application/vnd.rule-engine.rpack";
            }
            if (path.ends_with(".md") || path.ends_with(".txt") || path.ends_with(".lock")) {
                return "text/plain";
            }
            return "application/octet-stream";
        }

        [[nodiscard]] std::expected<SourcePackArchive, ToolFailure>
        archive_source_tree(const std::filesystem::path &root, const packaging::SourcePackLimits &limits = {}) {
            std::error_code filesystem_error;
            const auto root_status = std::filesystem::symlink_status(root, filesystem_error);
            if (filesystem_error || !std::filesystem::is_directory(root_status) ||
                std::filesystem::is_symlink(root_status)) {
                return std::unexpected(failure(ToolFailureKind::operation, "PACK-SOURCE",
                                               "source root must be a real directory, not a link"));
            }

            SourcePackArchive archive;
            std::uint64_t aggregate_bytes {};
            std::filesystem::recursive_directory_iterator iterator {root, std::filesystem::directory_options::none,
                                                                    filesystem_error};
            const std::filesystem::recursive_directory_iterator end;
            while (!filesystem_error && iterator != end) {
                const auto status = iterator->symlink_status(filesystem_error);
                if (filesystem_error) {
                    break;
                }
                if (std::filesystem::is_symlink(status) || std::filesystem::is_other(status)) {
                    return std::unexpected(failure(ToolFailureKind::operation, "PACK-SOURCE-LINK",
                                                   "source trees cannot contain links or special files"));
                }
                if (std::filesystem::is_directory(status)) {
                    iterator.increment(filesystem_error);
                    continue;
                }
                if (!std::filesystem::is_regular_file(status)) {
                    return std::unexpected(failure(ToolFailureKind::operation, "PACK-SOURCE-FILE",
                                                   "source tree contains a non-regular entry"));
                }
                const auto relative = iterator->path().lexically_relative(root).generic_string();
                if (relative.empty() || relative.starts_with("../") || relative == "META-INF" ||
                    relative.starts_with("META-INF/")) {
                    return std::unexpected(failure(ToolFailureKind::operation, "PACK-SOURCE-PATH",
                                                   "source path is reserved or escapes the source root"));
                }
                if (archive.entries.size() >= limits.maximum_entries) {
                    return std::unexpected(failure(ToolFailureKind::operation, "PACK-SOURCE-LIMIT",
                                                   "source tree exceeds the file-count bound"));
                }
                auto payload = read_file(iterator->path(), limits.maximum_entry_bytes);
                if (!payload.has_value()) {
                    return std::unexpected(payload.error());
                }
                if (payload->size() > limits.maximum_archive_bytes ||
                    aggregate_bytes > limits.maximum_archive_bytes - payload->size()) {
                    return std::unexpected(failure(ToolFailureKind::operation, "PACK-SOURCE-LIMIT",
                                                   "source tree exceeds the aggregate byte bound"));
                }
                aggregate_bytes += payload->size();
                archive.entries.push_back(ArchiveEntry {
                    .path = relative,
                    .bytes = std::move(*payload),
                    .kind = ArchiveEntryKind::regular_file,
                    .compression = packaging::ArchiveCompression::stored,
                    .encrypted = false,
                    .canonical_metadata = true,
                });
                iterator.increment(filesystem_error);
            }
            if (filesystem_error) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "PACK-SOURCE", "cannot enumerate the complete source tree"));
            }
            std::ranges::sort(archive.entries, {}, &ArchiveEntry::path);
            if (std::ranges::find(archive.entries, std::string {"rulepack.toml"}, &ArchiveEntry::path) ==
                archive.entries.end()) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "PACK-MANIFEST", "source tree has no rulepack.toml"));
            }

            SourceIndex index;
            index.entries.reserve(archive.entries.size());
            for (const auto &entry : archive.entries) {
                index.entries.push_back(SourceIndexEntry {
                    .media_type = media_type(entry.path),
                    .path = entry.path,
                    .sha256 = packaging::sha256_hex(entry.bytes),
                    .size = entry.bytes.size(),
                });
            }
            archive.entries.push_back(ArchiveEntry {
                .path = "META-INF/index.json",
                .bytes = bytes(packaging::canonical_index(index)),
                .kind = ArchiveEntryKind::regular_file,
                .compression = packaging::ArchiveCompression::stored,
                .encrypted = false,
                .canonical_metadata = true,
            });
            std::ranges::sort(archive.entries, {}, &ArchiveEntry::path);
            return archive;
        }

        struct RejectingSignatureVerifier final: packaging::SignatureVerifier {
            [[nodiscard]] std::expected<bool, PackagingError>
            verify_ed25519(std::span<const std::byte>, std::span<const std::byte>,
                           std::span<const std::byte>) const override {
                return std::unexpected(PackagingError {
                    .code = PackagingErrorCode::crypto_backend_unavailable,
                    .message = "no explicit production cryptographic provider was configured",
                    .subject = std::nullopt,
                });
            }
        };

        [[nodiscard]] std::expected<LoadedSourcePack, ToolFailure>
        verify_archive(const SourcePackArchive &archive, const bool development_unsigned,
                       const std::string_view trust_config_path) {
            if (development_unsigned) {
                const packaging::TrustPolicy policy {
                    .mode = TrustMode::development,
                    .allow_unsigned_packs = true,
                    .allow_unsigned_generators = true,
                    .signers = {},
                };
                const RejectingSignatureVerifier verifier;
                auto loaded = packaging::verify_and_load_source_pack(archive, policy, verifier);
                if (!loaded.has_value()) {
                    return std::unexpected(packaging_failure(loaded.error()));
                }
                return std::move(*loaded);
            }
            if (trust_config_path.empty()) {
                return std::unexpected(failure(ToolFailureKind::unavailable_dependency, "PACK-TRUST-CONFIG",
                                               "production verification requires --trust-config PATH"));
            }
            auto configuration = load_trust_file(std::filesystem::path {trust_config_path});
            if (!configuration.has_value()) {
                return std::unexpected(configuration.error());
            }
            packaging::OpenSsl3Ed25519Verifier verifier;
            verifier.crypto_library = configuration->crypto_library;
            auto loaded = packaging::verify_and_load_source_pack(archive, configuration->policy, verifier);
            if (!loaded.has_value()) {
                return std::unexpected(packaging_failure(loaded.error()));
            }
            return std::move(*loaded);
        }

        [[nodiscard]] std::expected<packaging::PrivatePythonRuntime, ToolFailure>
        load_runtime(const std::string_view runtime_root) {
            if (runtime_root.empty()) {
                return std::unexpected(failure(ToolFailureKind::unavailable_dependency, "PY-RUNTIME",
                                               "exact-runtime operation requires --runtime-root PATH"));
            }
            auto runtime = packaging::load_exact_private_runtime(std::filesystem::path {runtime_root});
            if (!runtime.has_value()) {
                return std::unexpected(packaging_failure(runtime.error()));
            }
            return std::move(*runtime);
        }

        [[nodiscard]] std::expected<std::filesystem::path, ToolFailure>
        temporary_root(const std::string_view configured) {
            if (!configured.empty()) {
                std::error_code filesystem_error;
                const auto status = std::filesystem::symlink_status(configured, filesystem_error);
                if (filesystem_error || !std::filesystem::is_directory(status) || std::filesystem::is_symlink(status)) {
                    return std::unexpected(failure(ToolFailureKind::unavailable_dependency, "PY-TEMP",
                                                   "configured worker temporary root is unavailable"));
                }
                return std::filesystem::path {configured};
            }
            std::error_code filesystem_error;
            auto value = std::filesystem::temp_directory_path(filesystem_error);
            if (filesystem_error) {
                return std::unexpected(failure(ToolFailureKind::unavailable_dependency, "PY-TEMP",
                                               "cannot resolve the worker temporary directory"));
            }
            return value;
        }

        [[nodiscard]] const ArchiveEntry *find_entry(const SourcePackArchive &archive, const std::string_view path) {
            const auto found = std::ranges::find(archive.entries, path, &ArchiveEntry::path);
            return found == archive.entries.end() ? nullptr : &*found;
        }

        [[nodiscard]] std::string module_path(const std::string_view module) {
            std::string result {"generator/"};
            for (const char character : module) { result.push_back(character == '.' ? '/' : character); }
            result += ".py";
            return result;
        }

        [[nodiscard]] std::expected<CanonicalGeneratorOutput, ToolFailure>
        execute_generator(const LoadedSourcePack &pack, const SourcePackArchive &archive,
                          const compiler::CompilationArtifact &discovery, packaging::WorkerClient &client) {
            if (!pack.manifest.generator.has_value()) {
                return CanonicalGeneratorOutput {};
            }
            if (!pack.trust.generator_execution_authorized) {
                return std::unexpected(failure(ToolFailureKind::authorization, "PACK-GENERATOR-AUTH",
                                               "pack trust policy does not authorize generator execution"));
            }
            const auto &declaration = *pack.manifest.generator;
            const auto path = module_path(declaration.module);
            const auto *module = find_entry(archive, path);
            if (module == nullptr) {
                return std::unexpected(failure(ToolFailureKind::operation, "PACK-GENERATOR-SOURCE",
                                               "declared generator module is absent"));
            }

            std::vector<packaging::WorkerGeneratorTemplate> templates;
            for (const auto &symbol : discovery.symbols) {
                if (symbol.kind != compiler::SymbolKind::rule_template) {
                    continue;
                }
                const auto function = std::ranges::find(discovery.pack.functions, symbol.qualified_name,
                                                        &BytecodeFunction::qualified_name);
                if (function == discovery.pack.functions.end()) {
                    continue;
                }
                templates.push_back(packaging::WorkerGeneratorTemplate {
                    .factory = symbol.name,
                    .template_id = function->id,
                });
            }
            std::ranges::sort(templates, {}, &packaging::WorkerGeneratorTemplate::factory);

            std::vector<packaging::WorkerGeneratorInput> inputs;
            inputs.reserve(declaration.inputs.size());
            for (const auto &input : declaration.inputs) {
                const auto *entry = find_entry(archive, input.path);
                if (entry == nullptr) {
                    return std::unexpected(failure(ToolFailureKind::operation, "PACK-GENERATOR-INPUT",
                                                   "declared generator input is absent"));
                }
                inputs.push_back(packaging::WorkerGeneratorInput {
                    .name = input.name,
                    .format = input.format,
                    .bytes = entry->bytes,
                });
            }
            const auto payload =
                packaging::encode_trusted_generator_worker_payload(packaging::TrustedGeneratorWorkerPayload {
                    .callable = declaration.callable,
                    .module_source = module->bytes,
                    .inputs = std::move(inputs),
                    .templates = std::move(templates),
                });
            if (!payload.has_value()) {
                return std::unexpected(packaging_failure(payload.error()));
            }
            packaging::PythonWorkerGeneratorExecutor executor;
            executor.client = &client;
            executor.request_id_prefix = RequestId {"tool-generator"};
            executor.source = SourceId {path};
            executor.canonical_payload = *payload;
            executor.generator_execution_authorized = true;
            auto generated = packaging::execute_generator_twice(executor, 0x13579U, 0x24680U);
            if (!generated.has_value()) {
                return std::unexpected(packaging_failure(generated.error()));
            }
            return std::move(*generated);
        }

        struct CompiledToolPack {
            compiler::CompilationArtifact artifact;
            std::optional<CanonicalGeneratorOutput> generated;
        };

        struct CapturedAstProvider final: compiler::AstEnvelopeProvider {
            std::vector<std::byte> payload;

            [[nodiscard]] std::expected<std::vector<std::byte>, DiagnosticSet> load(const VerifiedRulePack &) override {
                return std::move(payload);
            }
        };

        [[nodiscard]] std::expected<CompiledToolPack, ToolFailure>
        compile_pack(const LoadedSourcePack &pack, const SourcePackArchive &archive,
                     const packaging::PrivatePythonRuntime &runtime, const std::filesystem::path &worker_temporary_root,
                     const std::stop_token &cancellation) {
            if (cancellation.stop_requested()) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "PY-CANCELLED", "check generation was cancelled"));
            }
            if (pack.manifest.generator.has_value() && !pack.trust.generator_execution_authorized) {
                return std::unexpected(failure(ToolFailureKind::authorization, "PACK-GENERATOR-AUTH",
                                               "pack trust policy does not authorize generator execution"));
            }
            packaging::WindowsJobWorkerLauncher launcher;
            launcher.temporary_root = worker_temporary_root;
            packaging::WorkerClient client {.runtime = runtime, .launcher = launcher, .limits = {}};
            compiler::WorkerAstEnvelopeProvider provider {client};
            auto ast_payload = provider.load(pack.contract_pack);
            if (!ast_payload.has_value()) {
                return std::unexpected(ToolFailure {
                    .kind = ToolFailureKind::operation,
                    .code = "PY-WORKER",
                    .message = "exact private parser worker rejected the pack",
                    .diagnostics = std::move(ast_payload.error()),
                });
            }
            compiler::StaticCompiler static_compiler;
            auto discovery = static_compiler.compile(pack.contract_pack, *ast_payload, {}, {});
            if (!discovery.has_value()) {
                return std::unexpected(ToolFailure {
                    .kind = ToolFailureKind::operation,
                    .code = "PY-COMPILE",
                    .message = "static compilation failed",
                    .diagnostics = std::move(discovery.error()),
                });
            }
            OperatorBindings bindings;
            std::optional<CanonicalGeneratorOutput> generated;
            auto artifact = std::move(*discovery);
            if (pack.manifest.generator.has_value()) {
                auto output = execute_generator(pack, archive, artifact, client);
                if (!output.has_value()) {
                    return std::unexpected(output.error());
                }
                bindings.reserve(output->bindings.size());
                for (const auto &binding : output->bindings) {
                    bindings.push_back(OperatorBinding {
                        .id = binding.id,
                        .executable = binding.template_id,
                        .capabilities = {},
                        .budget = balanced_v1,
                    });
                }
                auto bound = static_compiler.compile(pack.contract_pack, *ast_payload, {}, bindings);
                if (!bound.has_value()) {
                    return std::unexpected(ToolFailure {
                        .kind = ToolFailureKind::operation,
                        .code = "PY-COMPILE",
                        .message = "generated binding compilation failed",
                        .diagnostics = std::move(bound.error()),
                    });
                }
                artifact = std::move(*bound);
                generated = std::move(*output);
            }
            if (cancellation.stop_requested()) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "PY-CANCELLED", "check generation was cancelled"));
            }

            // Exercise the same PackCompiler adapter used by the server as the
            // authoritative final compilation path. The richer StaticCompiler
            // artifact above is retained only for tooling explanations.
            CapturedAstProvider captured_provider;
            captured_provider.payload = std::move(*ast_payload);
            compiler::StaticPackCompiler pack_compiler {captured_provider};
            auto compiled_pack = pack_compiler.compile(pack.contract_pack, {}, bindings);
            if (!compiled_pack.has_value()) {
                return std::unexpected(ToolFailure {
                    .kind = ToolFailureKind::operation,
                    .code = "PY-COMPILE",
                    .message = "static pack compilation failed",
                    .diagnostics = std::move(compiled_pack.error()),
                });
            }
            if (compiled_pack->semantic_hash != artifact.pack.semantic_hash) {
                return std::unexpected(failure(ToolFailureKind::internal_invariant, "PY-COMPILER-DIVERGENCE",
                                               "tooling and server compiler paths produced different semantics"));
            }
            artifact.pack = std::move(*compiled_pack);
            return CompiledToolPack {.artifact = std::move(artifact), .generated = std::move(generated)};
        }

        [[nodiscard]] std::string fallback_reason(const optimizer::ExactFallbackReason reason) {
            using enum optimizer::ExactFallbackReason;
            switch (reason) {
                case none: return "certificate permits an optimized path";
                case certificate_missing: return "certificate missing";
                case duplicate_certificate: return "duplicate certificate";
                case certificate_semantic_hash_mismatch: return "certificate semantic hash mismatch";
                case contradictory_certificate: return "certificate is contradictory";
                case certificate_not_transitively_pure: return "executable is not transitively pure";
                case certificate_may_fault: return "executable may fault";
                case certificate_recorder_observable: return "execution is recorder-observable";
                case recorder_policy_requires_exact: return "recorder policy requires exact execution";
                case certificate_reads_state: return "executable reads state";
                case certificate_reads_history: return "executable reads history";
                case certificate_calls_services: return "executable calls services";
                case certificate_emits_effects: return "executable emits effects";
                case certificate_has_logical_reads: return "executable has logical fact reads";
                case no_transform_requested: return "no transform requested";
                case no_applicable_transform: return "no applicable transform";
                default: return "unknown conservative fallback";
            }
        }

        [[nodiscard]] std::vector<SourceDocument> source_documents(const LoadedSourcePack &pack) {
            std::vector<SourceDocument> sources;
            sources.reserve(pack.contract_pack.sources.size());
            for (const auto &source : pack.contract_pack.sources) {
                sources.push_back(SourceDocument {.id = source.id, .path = source.id.value, .utf8 = source.utf8});
            }
            return sources;
        }

        [[nodiscard]] DisplayField display_field(std::string name, std::string value, DataLabel label = DataLabel {}) {
            return DisplayField {
                .name = std::move(name),
                .value = std::move(value),
                .label = std::move(label),
                .secret_reference = false,
            };
        }

        [[nodiscard]] std::expected<void, ToolFailure> write_bytes(const std::filesystem::path &path,
                                                                   const std::span<const std::byte> payload) {
            std::ofstream output {path, std::ios::binary | std::ios::trunc};
            if (!output) {
                return std::unexpected(failure(ToolFailureKind::operation, "TOOL-WRITE", "cannot create output file"));
            }
            if (!payload.empty()) {
                output.write(reinterpret_cast<const char *>(payload.data()),
                             static_cast<std::streamsize>(payload.size()));
            }
            output.flush();
            if (!output.good()) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "TOOL-WRITE", "cannot write complete output file"));
            }
            return {};
        }

        struct SdkFile {
            std::string path;
            std::string digest;
            std::size_t size {};
            std::vector<std::byte> payload;
        };

        [[nodiscard]] std::optional<std::string> json_string(const std::string_view json, const std::string_view key,
                                                             const std::size_t from = 0U) {
            const auto marker = '"' + std::string {key} + "\": \"";
            const auto begin = json.find(marker, from);
            if (begin == std::string_view::npos) {
                return std::nullopt;
            }
            const auto value_begin = begin + marker.size();
            const auto end = json.find('"', value_begin);
            if (end == std::string_view::npos ||
                json.substr(value_begin, end - value_begin).find('\\') != std::string_view::npos) {
                return std::nullopt;
            }
            return std::string {json.substr(value_begin, end - value_begin)};
        }

        [[nodiscard]] std::expected<std::vector<SdkFile>, ToolFailure> verify_sdk(const std::filesystem::path &root) {
            std::error_code filesystem_error;
            const auto root_status = std::filesystem::symlink_status(root, filesystem_error);
            if (filesystem_error || !std::filesystem::is_directory(root_status) ||
                std::filesystem::is_symlink(root_status)) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "SDK-ROOT", "SDK root must be a real directory"));
            }
            auto manifest_bytes = read_file(root / "manifest.json", maximum_configuration_bytes);
            if (!manifest_bytes.has_value()) {
                return std::unexpected(manifest_bytes.error());
            }
            if (packaging::sha256_hex(*manifest_bytes) != sdk_manifest_digest) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "SDK-MANIFEST", "SDK manifest is not the tracked v1 manifest"));
            }
            const auto manifest = text(*manifest_bytes);
            if (manifest.find("\"format\": 1") == std::string::npos ||
                manifest.find(R"("python": "3.14.6")") == std::string::npos ||
                manifest.find(R"("sdk_id": "rule-engine-python-author-sdk")") == std::string::npos) {
                return std::unexpected(failure(ToolFailureKind::operation, "SDK-MANIFEST",
                                               "SDK manifest identity or exact runtime pin is invalid"));
            }
            const auto content_digest = json_string(manifest, "content_sha256");
            if (!content_digest.has_value() || *content_digest != sdk_content_digest) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "SDK-DIGEST", "SDK manifest is not the tracked v1 SDK"));
            }
            const auto files_begin = manifest.find("\"files\": [");
            const auto files_end = manifest.find("\n  ],", files_begin);
            if (files_begin == std::string::npos || files_end == std::string::npos) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "SDK-MANIFEST", "SDK file list is malformed"));
            }

            std::vector<SdkFile> files;
            std::set<std::string> paths;
            std::size_t cursor = files_begin;
            while (true) {
                const auto path_marker = manifest.find(R"("path": ")", cursor);
                if (path_marker == std::string::npos || path_marker >= files_end) {
                    break;
                }
                const auto path = json_string(manifest, "path", path_marker);
                const auto digest = json_string(manifest, "sha256", path_marker);
                const auto size_marker = manifest.find("\"size\": ", path_marker);
                if (!path.has_value() || !digest.has_value() || size_marker == std::string::npos ||
                    size_marker >= files_end || path->empty() || path->starts_with('/') ||
                    path->find("..") != std::string::npos || path->find('\\') != std::string::npos ||
                    !paths.insert(*path).second) {
                    return std::unexpected(
                        failure(ToolFailureKind::operation, "SDK-MANIFEST", "SDK file entry is invalid"));
                }
                const auto number_begin = size_marker + std::string_view {"\"size\": "}.size();
                const auto number_end = manifest.find_first_not_of("0123456789", number_begin);
                if (number_end == std::string_view::npos || number_end == number_begin) {
                    return std::unexpected(
                        failure(ToolFailureKind::operation, "SDK-MANIFEST", "SDK file size is invalid"));
                }
                std::size_t size {};
                const auto parsed = std::from_chars(manifest.data() + number_begin, manifest.data() + number_end, size);
                if (parsed.ec != std::errc {} || parsed.ptr != manifest.data() + number_end) {
                    return std::unexpected(
                        failure(ToolFailureKind::operation, "SDK-MANIFEST", "SDK file size is invalid"));
                }
                auto payload = read_file(root / std::filesystem::path {*path}, maximum_configuration_bytes);
                if (!payload.has_value() || payload->size() != size || packaging::sha256_hex(*payload) != *digest) {
                    return std::unexpected(
                        failure(ToolFailureKind::operation, "SDK-DIGEST", "SDK file digest or size mismatch"));
                }
                files.push_back(SdkFile {
                    .path = *path,
                    .digest = *digest,
                    .size = size,
                    .payload = std::move(*payload),
                });
                cursor = number_end;
            }
            if (files.empty() || !std::ranges::is_sorted(files, {}, &SdkFile::path)) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "SDK-MANIFEST", "SDK file list is empty or unsorted"));
            }
            std::string aggregate {"rule-engine-python-sdk-files-v1\0", 32U};
            for (const auto &file : files) {
                aggregate += file.path;
                aggregate.push_back('\0');
                aggregate += std::to_string(file.size);
                aggregate.push_back('\0');
                aggregate += file.digest;
                aggregate.push_back('\0');
            }
            if ("sha256:" + packaging::sha256_hex(bytes(aggregate)) != sdk_content_digest) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "SDK-DIGEST", "SDK aggregate digest mismatch"));
            }
            files.push_back(SdkFile {
                .path = "manifest.json",
                .digest = packaging::sha256_hex(*manifest_bytes),
                .size = manifest_bytes->size(),
                .payload = std::move(*manifest_bytes),
            });
            return files;
        }

        [[nodiscard]] std::expected<std::vector<std::string>, ToolFailure>
        split_configuration(const std::string_view text) {
            if (text.find('\r') != std::string::npos) {
                return std::unexpected(failure(ToolFailureKind::operation, "CONFIG-CANONICAL",
                                               "configuration must use canonical LF line endings"));
            }
            std::vector<std::string> lines;
            std::size_t begin {};
            while (begin < text.size()) {
                const auto end = text.find('\n', begin);
                const auto line_end = end == std::string::npos ? text.size() : end;
                if (line_end == begin) {
                    return std::unexpected(failure(ToolFailureKind::operation, "CONFIG-CANONICAL",
                                                   "configuration cannot contain blank lines"));
                }
                lines.emplace_back(text.substr(begin, line_end - begin));
                if (end == std::string::npos) {
                    break;
                }
                begin = end + 1U;
            }
            return lines;
        }

        [[nodiscard]] std::optional<std::string_view> value_after(const std::string_view line,
                                                                  const std::string_view key) {
            const auto prefix = std::string {key} + '=';
            if (!line.starts_with(prefix)) {
                return std::nullopt;
            }
            return line.substr(prefix.size());
        }

        [[nodiscard]] std::optional<std::vector<std::byte>> hex_bytes(const std::string_view value) {
            if (value.empty() || value.size() % 2U != 0U) {
                return std::nullopt;
            }
            auto digit = [](const char character) -> std::optional<unsigned> {
                if (character >= '0' && character <= '9') {
                    return static_cast<unsigned>(character - '0');
                }
                if (character >= 'a' && character <= 'f') {
                    return static_cast<unsigned>(character - 'a' + 10);
                }
                return std::nullopt;
            };
            std::vector<std::byte> output;
            output.reserve(value.size() / 2U);
            for (std::size_t index = 0; index < value.size(); index += 2U) {
                const auto high = digit(value[index]);
                const auto low = digit(value[index + 1U]);
                if (!high.has_value() || !low.has_value()) {
                    return std::nullopt;
                }
                output.push_back(static_cast<std::byte>((*high << 4U) | *low));
            }
            return output;
        }

    } // namespace

    std::expected<TrustFileConfiguration, ToolFailure> load_trust_file(const std::filesystem::path &path) {
        auto content = read_file(path, maximum_configuration_bytes);
        if (!content.has_value()) {
            return std::unexpected(content.error());
        }
        auto lines = split_configuration(text(*content));
        if (!lines.has_value() || lines->size() < 4U || (*lines)[0] != "format=1" || (*lines)[1] != "mode=production") {
            return std::unexpected(lines.has_value() ?
                                       failure(ToolFailureKind::operation, "TRUST-CONFIG",
                                               "trust configuration requires canonical production format 1") :
                                       lines.error());
        }
        const auto crypto = value_after((*lines)[2], "crypto_library");
        if (!crypto.has_value() || crypto->empty()) {
            return std::unexpected(failure(ToolFailureKind::unavailable_dependency, "TRUST-CRYPTO",
                                           "trust configuration has no explicit OpenSSL library"));
        }
        auto crypto_path = std::filesystem::path {*crypto};
        if (crypto_path.is_relative()) {
            crypto_path = path.parent_path() / crypto_path;
        }
        std::error_code filesystem_error;
        const auto crypto_status = std::filesystem::symlink_status(crypto_path, filesystem_error);
        if (filesystem_error || !std::filesystem::is_regular_file(crypto_status) ||
            std::filesystem::is_symlink(crypto_status)) {
            return std::unexpected(failure(ToolFailureKind::unavailable_dependency, "TRUST-CRYPTO",
                                           "configured OpenSSL library is unavailable"));
        }

        packaging::TrustPolicy policy {
            .mode = TrustMode::production,
            .allow_unsigned_packs = false,
            .allow_unsigned_generators = false,
            .signers = {},
        };
        std::string previous_key;
        for (std::size_t index = 3U; index < lines->size(); ++index) {
            const auto signer = value_after((*lines)[index], "signer");
            if (!signer.has_value()) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "TRUST-CONFIG", "trust signer line is invalid"));
            }
            std::array<std::string_view, 4> parts;
            std::size_t begin {};
            for (std::size_t part = 0; part < parts.size(); ++part) {
                const auto separator = signer->find('|', begin);
                if (part + 1U == parts.size()) {
                    if (separator != std::string_view::npos) {
                        return std::unexpected(
                            failure(ToolFailureKind::operation, "TRUST-CONFIG", "trust signer has too many fields"));
                    }
                    parts[part] = signer->substr(begin);
                    continue;
                }
                if (separator == std::string_view::npos) {
                    return std::unexpected(
                        failure(ToolFailureKind::operation, "TRUST-CONFIG", "trust signer is incomplete"));
                }
                parts[part] = signer->substr(begin, separator - begin);
                begin = separator + 1U;
            }
            auto public_key = hex_bytes(parts[1]);
            if (!public_key.has_value() || public_key->size() != 32U ||
                parts[0] != "sha256:" + packaging::sha256_hex(*public_key) || parts[0] <= previous_key ||
                (parts[3] != "active" && parts[3] != "revoked")) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "TRUST-CONFIG", "trust signer fields are invalid"));
            }
            std::vector<std::string> prefixes;
            std::string_view remaining = parts[2];
            while (!remaining.empty()) {
                const auto comma = remaining.find(',');
                const auto prefix = remaining.substr(0, comma);
                if (prefix.empty()) {
                    return std::unexpected(
                        failure(ToolFailureKind::operation, "TRUST-CONFIG", "trust signer scope is empty"));
                }
                prefixes.emplace_back(prefix);
                if (comma == std::string_view::npos) {
                    break;
                }
                remaining.remove_prefix(comma + 1U);
            }
            if (prefixes.empty() || !std::ranges::is_sorted(prefixes) ||
                std::ranges::adjacent_find(prefixes) != prefixes.end()) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "TRUST-CONFIG", "trust signer scopes must be sorted"));
            }
            previous_key = parts[0];
            policy.signers.push_back(packaging::TrustedSigner {
                .key_id = std::string {parts[0]},
                .public_key = std::move(*public_key),
                .allowed_pack_prefixes = std::move(prefixes),
                .revoked = parts[3] == "revoked",
            });
        }
        if (policy.signers.empty()) {
            return std::unexpected(
                failure(ToolFailureKind::operation, "TRUST-CONFIG", "production trust policy has no signers"));
        }
        return TrustFileConfiguration {.policy = std::move(policy), .crypto_library = std::move(crypto_path)};
    }

    std::expected<AdminEndpointConfiguration, ToolFailure> load_admin_endpoint_file(const std::filesystem::path &path) {
        auto content = read_file(path, maximum_configuration_bytes);
        if (!content.has_value()) {
            return std::unexpected(failure(ToolFailureKind::authentication, "ADMIN-CONFIG",
                                           "admin endpoint configuration cannot be read"));
        }
        auto lines = split_configuration(text(*content));
        if (!lines.has_value() || lines->size() != 6U || (*lines)[0] != "format=1") {
            return std::unexpected(failure(ToolFailureKind::authentication, "ADMIN-CONFIG",
                                           "admin endpoint configuration is not canonical format 1"));
        }
        const auto endpoint = value_after((*lines)[1], "endpoint");
        const auto certificate = value_after((*lines)[2], "client_certificate");
        const auto key = value_after((*lines)[3], "client_key");
        const auto trust = value_after((*lines)[4], "trust_bundle");
        const auto actor = value_after((*lines)[5], "actor");
        const auto endpoint_authority = endpoint.has_value() && endpoint->starts_with("https://") ?
                                            endpoint->substr(std::string_view {"https://"}.size()) :
                                            std::string_view {};
        const auto endpoint_host = endpoint_authority.substr(0U, endpoint_authority.find('/'));
        const auto endpoint_has_unsafe_character =
            endpoint_authority.find_first_of("@?#\\\r\n\t ") != std::string_view::npos;
        if (!endpoint.has_value() || endpoint_host.empty() || endpoint_has_unsafe_character ||
            !certificate.has_value() || certificate->empty() || !key.has_value() || key->empty() ||
            !trust.has_value() || trust->empty() || !actor.has_value() || actor->empty() ||
            actor->find_first_of("\r\n\t") != std::string_view::npos) {
            return std::unexpected(failure(ToolFailureKind::authentication, "ADMIN-CONFIG",
                                           "admin endpoint or mTLS identity fields are invalid"));
        }
        std::array material {
            std::filesystem::path {*certificate},
            std::filesystem::path {*key},
            std::filesystem::path {*trust},
        };
        for (auto &material_path : material) {
            if (material_path.is_relative()) {
                material_path = path.parent_path() / material_path;
            }
            std::error_code filesystem_error;
            const auto status = std::filesystem::symlink_status(material_path, filesystem_error);
            if (filesystem_error || !std::filesystem::is_regular_file(status) || std::filesystem::is_symlink(status)) {
                return std::unexpected(
                    failure(ToolFailureKind::authentication, "ADMIN-MTLS", "configured mTLS material is unavailable"));
            }
        }
        return AdminEndpointConfiguration {
            .endpoint = std::string {*endpoint},
            .client_certificate = std::move(material[0]),
            .client_key = std::move(material[1]),
            .trust_bundle = std::move(material[2]),
            .actor = std::string {*actor},
        };
    }

    std::expected<PackToolResult, ToolFailure> FilesystemPackagingBackend::execute(const PackCommand &command) {
        const auto input = std::filesystem::path {command.input_path};
        if (command.action == PackAction::build) {
            if (!command.signer_reference.empty()) {
                return std::unexpected(failure(ToolFailureKind::unavailable_dependency, "PACK-SIGNER",
                                               "external signing adapter is not linked into this executable"));
            }
            if (command.output_path.empty()) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "PACK-OUTPUT", "build requires --output PATH"));
            }
            const auto output = std::filesystem::path {command.output_path};
            std::error_code filesystem_error;
            if (std::filesystem::exists(output, filesystem_error) || filesystem_error) {
                return std::unexpected(failure(ToolFailureKind::operation, "PACK-OUTPUT",
                                               "build output already exists; refusing to overwrite it"));
            }
            auto archive = archive_source_tree(input);
            if (!archive.has_value()) {
                return std::unexpected(archive.error());
            }
            const RejectingSignatureVerifier verifier;
            const packaging::TrustPolicy construction_policy {
                .mode = TrustMode::development,
                .allow_unsigned_packs = true,
                .allow_unsigned_generators = command.development_unsigned,
                .signers = {},
            };
            auto loaded = packaging::verify_and_load_source_pack(*archive, construction_policy, verifier);
            if (!loaded.has_value()) {
                return std::unexpected(packaging_failure(loaded.error()));
            }
            std::optional<CanonicalGeneratorOutput> generated;
            if (loaded->manifest.generator.has_value()) {
                if (command.generator_policy != GeneratorPolicy::manifest_authorized_only) {
                    return std::unexpected(failure(ToolFailureKind::authorization, "PACK-GENERATOR-POLICY",
                                                   "build command disabled generator execution"));
                }
                if (!loaded->trust.generator_execution_authorized) {
                    return std::unexpected(failure(ToolFailureKind::authorization, "PACK-GENERATOR-AUTH",
                                                   "pack trust policy does not authorize generator execution"));
                }
                auto runtime = load_runtime(command.runtime_root);
                auto temp = temporary_root(command.temporary_root);
                if (!runtime.has_value()) {
                    return std::unexpected(runtime.error());
                }
                if (!temp.has_value()) {
                    return std::unexpected(temp.error());
                }
                auto compiled = compile_pack(*loaded, *archive, *runtime, *temp, {});
                if (!compiled.has_value()) {
                    return std::unexpected(compiled.error());
                }
                generated = std::move(compiled->generated);
            }
            const auto written = packaging::write_canonical_source_pack(output, *archive);
            if (!written.has_value()) {
                return std::unexpected(packaging_failure(written.error()));
            }
            PackToolResult result {
                .success = true,
                .diagnostics = {},
                .sources = source_documents(*loaded),
                .fields =
                    {
                        display_field("pack_id", loaded->manifest.pack.value),
                        display_field("version", loaded->manifest.version.value),
                        display_field("source_digest", loaded->source_digest.value),
                        display_field("trust", "development-unsigned"),
                    },
                .generated_paths = {output.string()},
            };
            if (generated.has_value()) {
                result.fields.push_back(
                    display_field("generated_binding_count", std::to_string(generated->bindings.size())));
                result.fields.push_back(display_field("generated_binding_digest", generated->digest.value));
            }
            return result;
        }

        if (command.action == PackAction::stubs) {
            if (command.output_path.empty()) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "SDK-OUTPUT", "stubs requires --output PATH"));
            }
            const auto sdk_root =
                command.sdk_root.empty() ? defaults_.sdk_root : std::filesystem::path {command.sdk_root};
            if (sdk_root.empty()) {
                return std::unexpected(failure(ToolFailureKind::unavailable_dependency, "SDK-ROOT",
                                               "stubs requires --sdk-root PATH or an installed SDK root"));
            }
            auto files = verify_sdk(sdk_root);
            if (!files.has_value()) {
                return std::unexpected(files.error());
            }
            const auto destination = std::filesystem::path {command.output_path};
            std::error_code filesystem_error;
            if (std::filesystem::exists(destination, filesystem_error) || filesystem_error) {
                return std::unexpected(failure(ToolFailureKind::operation, "SDK-OUTPUT",
                                               "stub output already exists; refusing to overwrite it"));
            }
            auto staging = destination;
            staging += ".rule-engine-tmp";
            if (std::filesystem::exists(staging, filesystem_error) || filesystem_error ||
                !std::filesystem::create_directories(staging, filesystem_error) || filesystem_error) {
                return std::unexpected(
                    failure(ToolFailureKind::operation, "SDK-OUTPUT", "cannot create stub staging directory"));
            }
            for (const auto &file : *files) {
                const auto output = staging / std::filesystem::path {file.path};
                if (!std::filesystem::create_directories(output.parent_path(), filesystem_error) || filesystem_error) {
                    if (!std::filesystem::is_directory(output.parent_path(), filesystem_error) || filesystem_error) {
                        std::filesystem::remove_all(staging, filesystem_error);
                        return std::unexpected(failure(ToolFailureKind::operation, "SDK-OUTPUT",
                                                       "cannot create a stub package directory"));
                    }
                }
                auto written = write_bytes(output, file.payload);
                if (!written.has_value()) {
                    std::filesystem::remove_all(staging, filesystem_error);
                    return std::unexpected(written.error());
                }
            }
            std::filesystem::rename(staging, destination, filesystem_error);
            if (filesystem_error) {
                std::filesystem::remove_all(staging, filesystem_error);
                return std::unexpected(
                    failure(ToolFailureKind::operation, "SDK-OUTPUT", "cannot atomically publish stub directory"));
            }
            return PackToolResult {
                .success = true,
                .diagnostics = {},
                .sources = {},
                .fields = {display_field("sdk_digest", std::string {sdk_content_digest}),
                           display_field("python", "3.14.6")},
                .generated_paths = {destination.string()},
            };
        }

        auto archive = packaging::read_canonical_source_pack(input);
        if (!archive.has_value()) {
            return std::unexpected(packaging_failure(archive.error()));
        }
        auto loaded = verify_archive(*archive, command.development_unsigned, command.trust_config_path);
        if (!loaded.has_value()) {
            return std::unexpected(loaded.error());
        }
        PackToolResult result {
            .success = true,
            .diagnostics = {},
            .sources = source_documents(*loaded),
            .fields =
                {
                    display_field("pack_id", loaded->manifest.pack.value),
                    display_field("version", loaded->manifest.version.value),
                    display_field("source_digest", loaded->source_digest.value),
                    display_field("closure_digest", loaded->closure_digest.value),
                    display_field("trust", loaded->trust.kind == packaging::PackTrustKind::production_signed ?
                                               "production-signed" :
                                               "development-unsigned"),
                },
            .generated_paths = {},
        };
        if (command.action == PackAction::inspect) {
            result.fields.push_back(
                display_field("pack_kind", loaded->manifest.kind == packaging::PackKind::rules ? "rules" : "library"));
            result.fields.push_back(display_field("engine_api", std::to_string(loaded->manifest.engine_api)));
            result.fields.push_back(display_field("python", loaded->manifest.python_version));
            result.fields.push_back(display_field("budget_profile", loaded->manifest.budget_profile));
            result.fields.push_back(display_field("policy_profile", loaded->manifest.policy_profile));
            result.fields.push_back(display_field("indexed_file_count", std::to_string(loaded->index.entries.size())));
            result.fields.push_back(
                display_field("entry_module_count", std::to_string(loaded->manifest.entry_modules.size())));
            result.fields.push_back(
                display_field("dependency_count", std::to_string(loaded->manifest.dependencies.size())));
            result.fields.push_back(display_field("required_capability_count",
                                                  std::to_string(loaded->manifest.required_capabilities.size())));
            result.fields.push_back(display_field("optional_capability_count",
                                                  std::to_string(loaded->manifest.optional_capabilities.size())));
            result.fields.push_back(
                display_field("generator", loaded->manifest.generator.has_value() ? "declared-not-executed" : "none"));
        }
        return result;
    }

    std::expected<CheckToolResult, ToolFailure> FilesystemCompilerBackend::check(const CheckCommand &command,
                                                                                 const std::stop_token cancellation) {
        std::error_code filesystem_error;
        const auto input = std::filesystem::path {command.pack_path};
        SourcePackArchive archive;
        if (std::filesystem::is_directory(input, filesystem_error) && !filesystem_error) {
            auto created = archive_source_tree(input);
            if (!created.has_value()) {
                return std::unexpected(created.error());
            }
            archive = std::move(*created);
        } else {
            auto decoded = packaging::read_canonical_source_pack(input);
            if (!decoded.has_value()) {
                return std::unexpected(packaging_failure(decoded.error()));
            }
            archive = std::move(*decoded);
        }
        auto loaded = verify_archive(archive, command.development_unsigned, command.trust_config_path);
        if (!loaded.has_value()) {
            return std::unexpected(loaded.error());
        }
        auto runtime = load_runtime(command.runtime_root);
        auto temp = temporary_root(command.temporary_root);
        if (!runtime.has_value()) {
            return std::unexpected(runtime.error());
        }
        if (!temp.has_value()) {
            return std::unexpected(temp.error());
        }
        auto compiled = compile_pack(*loaded, archive, *runtime, *temp, cancellation);
        if (!compiled.has_value()) {
            if (!compiled.error().diagnostics.empty()) {
                return CheckToolResult {
                    .success = false,
                    .diagnostics = std::move(compiled.error().diagnostics),
                    .sources = source_documents(*loaded),
                    .fields = {},
                    .facts = {},
                    .plans = {},
                };
            }
            return std::unexpected(compiled.error());
        }

        CheckToolResult result {
            .success = true,
            .diagnostics = {},
            .sources = source_documents(*loaded),
            .fields =
                {
                    display_field("pack_id", compiled->artifact.pack.pack.value),
                    display_field("version", compiled->artifact.pack.version.value),
                    display_field("semantic_hash", compiled->artifact.pack.semantic_hash),
                    display_field("function_count", std::to_string(compiled->artifact.pack.functions.size())),
                },
            .facts = {},
            .plans = {},
        };
        for (const auto &requirement : compiled->artifact.fact_requirements) {
            const auto route = requirement.route.provider + '.' + requirement.route.fact;
            result.facts.push_back(FactExplanation {
                .executable = requirement.executable.value,
                .logical_route = route + " via " + requirement.attribute_path,
                .physical_prefetch = route,
                .conditional = requirement.conditional,
            });
        }
        for (const auto &certificate : compiled->artifact.pack.optimization_certificates) {
            const std::array certificates {certificate};
            const auto selected = optimizer::select_optimization(
                certificates, optimizer::OptimizationRequest {
                                  .executable = certificate.executable,
                                  .expected_executable_semantic_hash = certificate.semantic_hash,
                                  .request_specialization = true,
                                  .request_pruning = true,
                                  .full_flight_recorder_armed = false,
                              });
            if (!selected.has_value()) {
                result.plans.push_back(PlanExplanation {
                    .executable = certificate.executable.value,
                    .path = PlanPath::exact,
                    .certificate_reason = "optimizer request rejected; exact path retained",
                });
                continue;
            }
            result.plans.push_back(PlanExplanation {
                .executable = certificate.executable.value,
                .path = selected->use_exact_bytecode ? PlanPath::exact : PlanPath::optimized,
                .certificate_reason = fallback_reason(selected->fallback_reason),
            });
        }
        return result;
    }

    std::expected<AdminToolResult, ToolFailure> FilesystemAdminBackend::execute(const AdminCommand &command) {
        if (command.config_path.empty()) {
            return std::unexpected(failure(ToolFailureKind::unavailable_transport, "ADMIN-CONFIG",
                                           "admin command requires --config PATH for an authenticated endpoint"));
        }
        auto endpoint = load_admin_endpoint_file(std::filesystem::path {command.config_path});
        if (!endpoint.has_value()) {
            return std::unexpected(endpoint.error());
        }
        if (adapter_ == nullptr) {
            return std::unexpected(failure(ToolFailureKind::unavailable_transport, "ADMIN-TRANSPORT",
                                           "authenticated control-plane transport adapter is not linked"));
        }
        return adapter_->execute(*endpoint, command);
    }

} // namespace rule_engine::python::tools
