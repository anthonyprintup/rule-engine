#include "rule_engine/python/packaging.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::packaging {
    namespace {

#ifndef RULE_ENGINE_PACKAGING_WORKER_SCRIPT
#define RULE_ENGINE_PACKAGING_WORKER_SCRIPT ""
#endif

        std::vector<std::byte> bytes(const std::string_view text) {
            return {reinterpret_cast<const std::byte *>(text.data()),
                    reinterpret_cast<const std::byte *>(text.data() + text.size())};
        }

        std::vector<std::byte> repeated_bytes(const std::size_t count, const std::byte value) {
            return std::vector<std::byte>(count, value);
        }

        std::vector<std::byte> hex_bytes(const std::string_view text) {
            if (text.size() % 2U != 0U) {
                return {};
            }
            auto digit = [](const char value) -> unsigned {
                if (value >= '0' && value <= '9') {
                    return static_cast<unsigned>(value - '0');
                }
                return static_cast<unsigned>(value - 'a' + 10);
            };
            std::vector<std::byte> result;
            result.reserve(text.size() / 2U);
            for (std::size_t index = 0U; index < text.size(); index += 2U) {
                result.push_back(static_cast<std::byte>((digit(text[index]) << 4U) | digit(text[index + 1U])));
            }
            return result;
        }

        std::string text(const std::span<const std::byte> value) {
            return {reinterpret_cast<const char *>(value.data()), value.size()};
        }

        std::optional<std::string> environment_value(const char *name) {
#ifdef _WIN32
            char *raw_value {};
            std::size_t length {};
            if (_dupenv_s(&raw_value, &length, name) != 0 || raw_value == nullptr) {
                return std::nullopt;
            }
            std::string value {raw_value};
            std::free(raw_value);
            return value;
#else
            const auto *raw_value = std::getenv(name);
            return raw_value == nullptr ? std::nullopt : std::optional<std::string> {raw_value};
#endif
        }

        SourcePackManifest manifest() {
            return SourcePackManifest {
                .format = 1,
                .pack = PackId {"com.acme.rules"},
                .version = PackVersion {"1.2.3"},
                .kind = PackKind::rules,
                .engine_api = 1,
                .python_version = "3.14.6",
                .entry_modules = {"acme.rules"},
                .budget_profile = "balanced.v1",
                .policy_profile = "production.v1",
                .generator = std::nullopt,
                .dependencies = {},
                .required_capabilities = {CapabilityId {"post.siem.v1"}},
                .optional_capabilities = {CapabilityId {"history.fleet.v1"}},
            };
        }

        std::string media_type_for(const std::string_view path) {
            if (path.ends_with(".py")) {
                return "text/x-python";
            }
            if (path.ends_with(".toml")) {
                return "application/toml";
            }
            if (path.ends_with(".rpack")) {
                return "application/vnd.rule-engine.rpack";
            }
            return "application/octet-stream";
        }

        struct FakeSignatureVerifier final: SignatureVerifier {
            mutable std::size_t calls {};
            bool accepted {true};
            mutable std::vector<std::byte> last_message;

            std::expected<bool, PackagingError>
            verify_ed25519(const std::span<const std::byte> public_key, const std::span<const std::byte> message,
                           const std::span<const std::byte> signature) const override {
                ++calls;
                last_message.assign(message.begin(), message.end());
                REQUIRE(public_key.size() == 32U);
                REQUIRE(signature.size() == 64U);
                return accepted;
            }
        };

        struct SignedArchiveFixture {
            SourcePackArchive archive;
            TrustPolicy policy;
            std::vector<std::byte> public_key;
        };

        SignedArchiveFixture make_signed_archive(const SourcePackManifest &source_manifest = manifest()) {
            std::vector<ArchiveEntry> payloads {
                ArchiveEntry {.path = "rulepack.toml", .bytes = bytes(canonical_manifest(source_manifest))},
                ArchiveEntry {.path = "src/acme/rules.py", .bytes = bytes("def sample() -> bool:\n    return True\n")},
            };
            if (source_manifest.generator) {
                payloads.push_back(ArchiveEntry {.path = "generator.lock", .bytes = bytes("format = 1\n")});
                payloads.push_back(ArchiveEntry {.path = "generator/acme/generate.py",
                                                 .bytes = bytes("def generate(ctx):\n    return None\n")});
                for (const auto &input : source_manifest.generator->inputs) {
                    payloads.push_back(ArchiveEntry {.path = input.path, .bytes = bytes("{}")});
                }
            }
            for (const auto &dependency : source_manifest.dependencies) {
                payloads.push_back(ArchiveEntry {
                    .path = "deps/" + dependency.digest.value.substr(7U) + ".rpack",
                    .bytes = bytes("canonical dependency bytes"),
                });
            }
            std::ranges::sort(payloads, {}, &ArchiveEntry::path);

            SourceIndex source_index;
            for (const auto &payload : payloads) {
                source_index.entries.push_back(SourceIndexEntry {
                    .media_type = media_type_for(payload.path),
                    .path = payload.path,
                    .sha256 = sha256_hex(payload.bytes),
                    .size = payload.bytes.size(),
                });
            }
            const auto index_text = canonical_index(source_index);
            auto public_key = repeated_bytes(32U, std::byte {0x2a});
            const auto key_id = "sha256:" + sha256_hex(public_key);
            const SignatureEnvelope signature {
                .version = 1,
                .algorithm = "Ed25519",
                .key_id = key_id,
                .signature = repeated_bytes(64U, std::byte {0x5c}),
            };

            SourcePackArchive archive;
            archive.entries.push_back(ArchiveEntry {.path = "META-INF/index.json", .bytes = bytes(index_text)});
            archive.entries.push_back(ArchiveEntry {.path = "META-INF/signature.json",
                                                    .bytes = bytes(canonical_signature_envelope(signature))});
            archive.entries.insert(archive.entries.end(), payloads.begin(), payloads.end());
            std::ranges::sort(archive.entries, {}, &ArchiveEntry::path);

            TrustPolicy policy {
                .mode = TrustMode::production,
                .allow_unsigned_packs = false,
                .allow_unsigned_generators = false,
                .signers = {TrustedSigner {
                    .key_id = key_id,
                    .public_key = public_key,
                    .allowed_pack_prefixes = {"com.acme."},
                    .revoked = false,
                }},
            };
            return SignedArchiveFixture {
                .archive = std::move(archive),
                .policy = std::move(policy),
                .public_key = std::move(public_key),
            };
        }

        struct SharedRuntime {
            std::optional<PrivatePythonRuntime> runtime;
            std::filesystem::path temporary_parent;
            std::string unavailable_reason;
            std::string staging_failure;

            SharedRuntime() = default;
            SharedRuntime(const SharedRuntime &) = delete;
            SharedRuntime &operator=(const SharedRuntime &) = delete;
            SharedRuntime(SharedRuntime &&) noexcept = default;

            ~SharedRuntime() {
                if (!temporary_parent.empty()) {
                    std::error_code ignored;
                    std::filesystem::remove_all(temporary_parent, ignored);
                }
            }
        };

        SharedRuntime &shared_runtime() {
            static SharedRuntime state = [] {
                SharedRuntime result;
                const auto root_text = environment_value("RULE_ENGINE_TEST_PYTHON_RUNTIME_ROOT");
                const auto archive_text = environment_value("RULE_ENGINE_TEST_PYTHON_RUNTIME_ARCHIVE");
                if (!root_text || !archive_text || root_text->empty() || archive_text->empty()) {
                    result.unavailable_reason = "exact CPython 3.14.6 test artifact was not configured";
                    return result;
                }
                std::error_code filesystem_error;
                if (!std::filesystem::is_directory(*root_text, filesystem_error) || filesystem_error ||
                    !std::filesystem::is_regular_file(*archive_text, filesystem_error) || filesystem_error) {
                    result.unavailable_reason = "exact CPython 3.14.6 test artifact is absent";
                    return result;
                }
                const auto temporary_root = std::filesystem::temp_directory_path(filesystem_error);
                if (filesystem_error) {
                    result.unavailable_reason = "cannot resolve the test temporary directory";
                    return result;
                }
                const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
                result.temporary_parent = temporary_root / ("rule-engine-python-packaging-" + std::to_string(nonce));
                if (!std::filesystem::create_directory(result.temporary_parent, filesystem_error) || filesystem_error) {
                    result.unavailable_reason = "cannot create the test runtime staging directory";
                    result.temporary_parent.clear();
                    return result;
                }
                const auto staged = stage_exact_private_runtime(PythonRuntimeStageRequest {
                    .artifact_archive = *archive_text,
                    .extracted_distribution = *root_text,
                    .destination = result.temporary_parent / "python-3.14.6",
                    .worker_script = RULE_ENGINE_PACKAGING_WORKER_SCRIPT,
                });
                if (!staged) {
                    result.staging_failure = staged.error().message;
                    return result;
                }
                result.runtime = *staged;
                return result;
            }();
            return state;
        }

        PrivatePythonRuntime exact_runtime() {
            if (shared_runtime().runtime) {
                return *shared_runtime().runtime;
            }
            return PrivatePythonRuntime {
                .descriptor = official_windows_cpython_3146(),
                .origin = RuntimeOrigin::private_bundle,
                .runtime_root = "C:/missing/private/python-3.14.6",
                .python_executable = "C:/missing/private/python-3.14.6/python.exe",
                .worker_script = "C:/missing/private/python-3.14.6/rule_engine_python_worker.py",
                .crypto_library = "C:/missing/private/python-3.14.6/libcrypto-3.dll",
                .installation_manifest = "C:/missing/private/python-3.14.6/rule-engine-python-runtime.manifest",
                .verified_artifact_sha256 = official_windows_cpython_3146().artifact_sha256,
            };
        }

        WorkerRequest parse_request() {
            auto source = bytes("def sample(): pass\n");
            return WorkerRequest {
                .protocol = python_worker_protocol_v1,
                .request_id = RequestId {"request-1"},
                .mode = WorkerMode::static_parse,
                .runtime = official_windows_cpython_3146(),
                .payload =
                    OpaqueWorkerPayload {
                        .schema = std::string {static_source_schema_v1},
                        .source = SourceId {"src/acme/rules.py"},
                        .source_digest = SourceDigest {"sha256:" + sha256_hex(source)},
                        .bytes = std::move(source),
                    },
                .hash_seed = 0,
                .generator_execution_authorized = false,
            };
        }

        WorkerResponse response_for(const WorkerRequest &request) {
            return WorkerResponse {
                .protocol = python_worker_protocol_v1,
                .request_id = request.request_id,
                .mode = request.mode,
                .runtime_version = official_windows_cpython_3146().python_version,
                .runtime_artifact_sha256 = official_windows_cpython_3146().artifact_sha256,
                .status = WorkerResponseStatus::ok,
                .payload =
                    OpaqueWorkerPayload {
                        .schema = request.mode == WorkerMode::static_parse ? std::string {static_ast_schema_v1} :
                                                                             std::string {generated_bindings_schema_v1},
                        .source = request.payload.source,
                        .source_digest = request.payload.source_digest,
                        .bytes = bytes("opaque payload"),
                    },
            };
        }

        struct FakeLauncher final: WorkerLauncher {
            std::size_t calls {};
            WorkerProcessResult result {
                .exit_code = 0,
                .crashed = false,
                .timed_out = false,
                .output_limited = false,
                .process_tree_terminated = true,
                .stdout_bytes = {},
                .stderr_excerpt = {},
            };
            std::optional<PackagingError> failure;

            std::expected<WorkerProcessResult, PackagingError> launch(const PrivatePythonRuntime &, const WorkerMode,
                                                                      const std::uint32_t,
                                                                      const std::span<const std::byte>,
                                                                      const WorkerLimits &) override {
                ++calls;
                if (failure) {
                    return std::unexpected(*failure);
                }
                return result;
            }
        };

        GeneratedBinding binding(std::string id, const std::byte value) {
            return GeneratedBinding {
                .id = BindingId {std::move(id)},
                .template_id = ExecutableId {"com.acme.template"},
                .canonical_arguments = {value},
            };
        }

        struct FakeGenerator final: GeneratorExecutor {
            std::vector<std::uint32_t> seeds;
            bool change_second {};

            std::expected<GeneratorRun, PackagingError> run(const std::uint32_t hash_seed) override {
                seeds.push_back(hash_seed);
                return GeneratorRun {
                    .hash_seed = hash_seed,
                    .bindings = {binding("com.acme.binding",
                                         seeds.size() == 2U && change_second ? std::byte {2} : std::byte {1})},
                };
            }
        };

    } // namespace

    TEST_CASE("canonical source pack validates production trust and stable identities") {
        auto fixture = make_signed_archive();
        FakeSignatureVerifier verifier;

        const auto first = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier);
        const auto second = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier);

        REQUIRE(first.has_value());
        REQUIRE(second.has_value());
        REQUIRE(first->source_digest == second->source_digest);
        REQUIRE(first->closure_digest == second->closure_digest);
        REQUIRE(first->trust.kind == PackTrustKind::production_signed);
        REQUIRE(first->trust.generator_execution_authorized);
        REQUIRE(first->contract_pack.trust.production_authorized);
        REQUIRE(first->contract_pack.sources.size() == 1U);
        REQUIRE(first->contract_pack.sources.front().module == "acme.rules");
        REQUIRE(verifier.calls == 2U);
        REQUIRE_FALSE(verifier.last_message.empty());
    }

    TEST_CASE("SHA-256 and complex canonical manifest use stable public vectors") {
        REQUIRE(sha256_hex(bytes("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        auto complex = manifest();
        complex.generator = GeneratorDeclaration {
            .module = "acme.generate",
            .callable = "generate",
            .lock_path = "generator.lock",
            .inputs = {{.name = "bindings", .path = "inputs/bindings.json", .format = GeneratorInputFormat::json}},
        };
        complex.dependencies = {{.alias = "common",
                                 .pack = PackId {"com.acme.common"},
                                 .digest = SourceDigest {"sha256:" + std::string(64U, '1')}}};

        const auto text = canonical_manifest(complex);
        const auto parsed = parse_canonical_manifest(text);
        REQUIRE(parsed.has_value());
        REQUIRE(*parsed == complex);
    }

    TEST_CASE("pack loader rejects tamper traversal collisions bounds and unsigned production") {
        FakeSignatureVerifier verifier;

        SECTION("payload tamper") {
            auto fixture = make_signed_archive();
            const auto source = std::ranges::find(fixture.archive.entries, "src/acme/rules.py", &ArchiveEntry::path);
            REQUIRE(source != fixture.archive.entries.end());
            source->bytes.push_back(std::byte {'x'});
            const auto result = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::entry_size_mismatch);
        }

        SECTION("path traversal") {
            auto fixture = make_signed_archive();
            const auto source = std::ranges::find(fixture.archive.entries, "src/acme/rules.py", &ArchiveEntry::path);
            source->path = "src/../evil.py";
            std::ranges::sort(fixture.archive.entries, {}, &ArchiveEntry::path);
            const auto result = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::invalid_path);
        }

        SECTION("case-fold collision") {
            auto fixture = make_signed_archive();
            fixture.archive.entries.push_back(ArchiveEntry {.path = "src/ACME/rules.py", .bytes = bytes("pass\n")});
            std::ranges::sort(fixture.archive.entries, {}, &ArchiveEntry::path);
            const auto result = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::path_collision);
        }

        SECTION("aggregate bound") {
            auto fixture = make_signed_archive();
            SourcePackLimits limits;
            limits.maximum_archive_bytes = 16U;
            const auto result = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier, limits);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::size_limit);
        }

        SECTION("unsigned production") {
            auto fixture = make_signed_archive();
            std::erase_if(fixture.archive.entries,
                          [](const ArchiveEntry &entry) { return entry.path == "META-INF/signature.json"; });
            const auto result = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::signature_required);
        }
    }

    TEST_CASE("pack trust policy rejects revoked out-of-scope and cryptographically invalid signatures") {
        FakeSignatureVerifier verifier;

        SECTION("revoked") {
            auto fixture = make_signed_archive();
            fixture.policy.signers.front().revoked = true;
            const auto result = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::signer_revoked);
        }

        SECTION("out of scope") {
            auto fixture = make_signed_archive();
            fixture.policy.signers.front().allowed_pack_prefixes = {"org.example."};
            const auto result = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::signer_out_of_scope);
        }

        SECTION("verifier rejection") {
            auto fixture = make_signed_archive();
            verifier.accepted = false;
            const auto result = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::signature_invalid);
        }
    }

    TEST_CASE("unsigned development trust is explicit and does not authorize generators by default") {
        auto fixture = make_signed_archive();
        std::erase_if(fixture.archive.entries,
                      [](const ArchiveEntry &entry) { return entry.path == "META-INF/signature.json"; });
        fixture.policy.mode = TrustMode::development;
        fixture.policy.allow_unsigned_packs = true;
        fixture.policy.allow_unsigned_generators = false;
        FakeSignatureVerifier verifier;

        const auto result = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier);

        REQUIRE(result.has_value());
        REQUIRE(result->trust.kind == PackTrustKind::development_unsigned);
        REQUIRE_FALSE(result->trust.generator_execution_authorized);
        REQUIRE_FALSE(result->contract_pack.trust.production_authorized);
        REQUIRE(verifier.calls == 0U);
    }

    TEST_CASE("signed generator declarations load only declared bounded inputs") {
        auto generated = manifest();
        generated.generator = GeneratorDeclaration {
            .module = "acme.generate",
            .callable = "generate",
            .lock_path = "generator.lock",
            .inputs = {{.name = "bindings", .path = "inputs/bindings.json", .format = GeneratorInputFormat::json}},
        };
        auto fixture = make_signed_archive(generated);
        FakeSignatureVerifier verifier;

        REQUIRE(verify_and_load_source_pack(fixture.archive, fixture.policy, verifier).has_value());

        SourcePackLimits limits;
        limits.maximum_generator_input_bytes = 1U;
        const auto bounded = verify_and_load_source_pack(fixture.archive, fixture.policy, verifier, limits);
        REQUIRE_FALSE(bounded.has_value());
        REQUIRE(bounded.error().code == PackagingErrorCode::size_limit);
    }

    TEST_CASE("canonical manifest and index parsers reject textual variation") {
        const auto manifest_text = canonical_manifest(manifest());
        REQUIRE(parse_canonical_manifest(manifest_text).has_value());
        REQUIRE_FALSE(parse_canonical_manifest(" " + manifest_text).has_value());

        SourceIndex index {
            .format = 1,
            .entries = {
                {.media_type = "text/x-python", .path = "src/a.py", .sha256 = std::string(64U, '0'), .size = 7}}};
        const auto index_text = canonical_index(index);
        REQUIRE(parse_canonical_index(index_text).has_value());
        REQUIRE_FALSE(parse_canonical_index(index_text + "\n").has_value());
    }

    TEST_CASE("canonical source-pack ZIP codec is deterministic strict and filesystem backed") {
        auto fixture = make_signed_archive();
        const auto first = encode_canonical_source_pack(fixture.archive);
        const auto second = encode_canonical_source_pack(fixture.archive);
        REQUIRE(first.has_value());
        REQUIRE(second.has_value());
        REQUIRE(*second == *first);

        const auto decoded = decode_canonical_source_pack(*first);
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->entries.size() == fixture.archive.entries.size());
        for (std::size_t index = 0U; index < decoded->entries.size(); ++index) {
            REQUIRE(decoded->entries[index].path == fixture.archive.entries[index].path);
            REQUIRE(decoded->entries[index].bytes == fixture.archive.entries[index].bytes);
            REQUIRE(decoded->entries[index].compression == ArchiveCompression::stored);
            REQUIRE(decoded->entries[index].canonical_metadata);
        }

        std::error_code filesystem_error;
        const auto temporary_root = std::filesystem::temp_directory_path(filesystem_error);
        REQUIRE_FALSE(filesystem_error);
        const auto archive_path =
            temporary_root / ("rule-engine-pack-" +
                              std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".rpack");
        REQUIRE(write_canonical_source_pack(archive_path, fixture.archive).has_value());
        const auto from_file = read_canonical_source_pack(archive_path);
        REQUIRE(from_file.has_value());
        REQUIRE(from_file->entries.size() == fixture.archive.entries.size());
        FakeSignatureVerifier verifier;
        const auto verified_file = read_verify_and_load_source_pack(archive_path, fixture.policy, verifier);
        REQUIRE(verified_file.has_value());
        REQUIRE(std::filesystem::remove(archive_path, filesystem_error));
        REQUIRE_FALSE(filesystem_error);

        auto metadata_tamper = *first;
        metadata_tamper[7] = std::byte {0};
        const auto metadata_result = decode_canonical_source_pack(metadata_tamper);
        REQUIRE_FALSE(metadata_result.has_value());
        REQUIRE(metadata_result.error().code == PackagingErrorCode::noncanonical_archive);

        auto payload_tamper = *first;
        const auto needle = bytes("def sample() -> bool:");
        const auto location = std::search(payload_tamper.begin(), payload_tamper.end(), needle.begin(), needle.end());
        REQUIRE(location != payload_tamper.end());
        *location ^= std::byte {1};
        const auto crc_result = decode_canonical_source_pack(payload_tamper);
        REQUIRE_FALSE(crc_result.has_value());
        REQUIRE(crc_result.error().code == PackagingErrorCode::archive_crc_mismatch);

        auto trailing = *first;
        trailing.push_back(std::byte {0});
        REQUIRE_FALSE(decode_canonical_source_pack(trailing).has_value());
    }

    TEST_CASE("OpenSSL 3 backend verifies the RFC 8032 Ed25519 vector from an explicit runtime path") {
        if (!shared_runtime().runtime) {
            if (!shared_runtime().staging_failure.empty()) {
                FAIL_CHECK(shared_runtime().staging_failure);
                return;
            }
            WARN("SKIPPED: " << shared_runtime().unavailable_reason);
            return;
        }
        const auto public_key = hex_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        auto signature = hex_bytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                                   "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        const std::vector<std::byte> message;
        OpenSsl3Ed25519Verifier verifier;
        verifier.crypto_library = shared_runtime().runtime->crypto_library;
        const auto accepted = verifier.verify_ed25519(public_key, message, signature);
        REQUIRE(accepted.has_value());
        REQUIRE(*accepted);
        signature.front() ^= std::byte {1};
        const auto rejected = verifier.verify_ed25519(public_key, message, signature);
        REQUIRE(rejected.has_value());
        REQUIRE_FALSE(*rejected);
    }

    TEST_CASE("runtime descriptor pins official CPython 3.14.6 and never falls back") {
        const auto &descriptor = official_windows_cpython_3146();
        REQUIRE(descriptor.python_version == "3.14.6");
        REQUIRE(descriptor.artifact_url == "https://www.python.org/ftp/python/3.14.6/python-3.14.6-embed-amd64.zip");
        REQUIRE(descriptor.artifact_sha256 == "df901e84a896ff1ee720ad03377e0c8d8c2244fda79808aeeaff6316df1cb75c");
        if (shared_runtime().runtime) {
            REQUIRE(validate_exact_private_runtime(exact_runtime()).has_value());
        }

        auto system = exact_runtime();
        system.origin = RuntimeOrigin::system_installation;
        const auto system_result = validate_exact_private_runtime(system);
        REQUIRE_FALSE(system_result.has_value());
        REQUIRE(system_result.error().code == PackagingErrorCode::runtime_mismatch);

        auto wrong_hash = exact_runtime();
        wrong_hash.verified_artifact_sha256 = std::string(64U, '0');
        REQUIRE_FALSE(validate_exact_private_runtime(wrong_hash).has_value());
    }

    TEST_CASE("worker client preserves opaque AST seam and validates exact response identity") {
        if (!shared_runtime().runtime) {
            if (!shared_runtime().staging_failure.empty()) {
                FAIL_CHECK(shared_runtime().staging_failure);
                return;
            }
            WARN("SKIPPED: " << shared_runtime().unavailable_reason);
            return;
        }
        auto request = parse_request();
        FakeLauncher launcher;
        launcher.result.stdout_bytes = *encode_worker_response_frame(response_for(request));
        WorkerClient client {.runtime = exact_runtime(), .launcher = launcher, .limits = {}};

        const auto response = client.invoke(request);

        REQUIRE(response.has_value());
        REQUIRE(response->payload.schema == static_ast_schema_v1);
        REQUIRE(response->payload.bytes == bytes("opaque payload"));
        REQUIRE(launcher.calls == 1U);
    }

    TEST_CASE("worker client rejects runtime version framing crash timeout and unauthorized generation") {
        if (!shared_runtime().runtime) {
            if (!shared_runtime().staging_failure.empty()) {
                FAIL_CHECK(shared_runtime().staging_failure);
                return;
            }
            WARN("SKIPPED: " << shared_runtime().unavailable_reason);
            return;
        }
        SECTION("wrong installed runtime is rejected before launch") {
            auto request = parse_request();
            FakeLauncher launcher;
            auto runtime = exact_runtime();
            runtime.descriptor.python_version = "3.14.5";
            WorkerClient client {.runtime = runtime, .launcher = launcher, .limits = {}};
            const auto result = client.invoke(request);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::runtime_mismatch);
            REQUIRE(launcher.calls == 0U);
        }

        SECTION("malformed frame") {
            auto request = parse_request();
            FakeLauncher launcher;
            launcher.result.stdout_bytes = {std::byte {1}};
            WorkerClient client {.runtime = exact_runtime(), .launcher = launcher, .limits = {}};
            const auto result = client.invoke(request);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::worker_frame_malformed);
        }

        SECTION("protocol mismatch") {
            auto request = parse_request();
            auto response = response_for(request);
            response.protocol = 2;
            FakeLauncher launcher;
            launcher.result.stdout_bytes = *encode_worker_response_frame(response);
            WorkerClient client {.runtime = exact_runtime(), .launcher = launcher, .limits = {}};
            const auto result = client.invoke(request);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::worker_response_mismatch);
        }

        SECTION("response runtime version mismatch") {
            auto request = parse_request();
            auto response = response_for(request);
            response.runtime_version = "3.14.5";
            FakeLauncher launcher;
            launcher.result.stdout_bytes = *encode_worker_response_frame(response);
            WorkerClient client {.runtime = exact_runtime(), .launcher = launcher, .limits = {}};
            const auto result = client.invoke(request);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::worker_response_mismatch);
        }

        SECTION("crash") {
            auto request = parse_request();
            FakeLauncher launcher;
            launcher.result.crashed = true;
            launcher.result.exit_code = -1;
            WorkerClient client {.runtime = exact_runtime(), .launcher = launcher, .limits = {}};
            const auto result = client.invoke(request);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::worker_crashed);
        }

        SECTION("timeout") {
            auto request = parse_request();
            FakeLauncher launcher;
            launcher.result.timed_out = true;
            WorkerClient client {.runtime = exact_runtime(), .launcher = launcher, .limits = {}};
            const auto result = client.invoke(request);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::worker_timed_out);
        }

        SECTION("output bound") {
            auto request = parse_request();
            FakeLauncher launcher;
            launcher.result.output_limited = true;
            WorkerClient client {.runtime = exact_runtime(), .launcher = launcher, .limits = {}};
            const auto result = client.invoke(request);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::worker_output_limit);
        }

        SECTION("generator requires verified authorization") {
            auto request = parse_request();
            request.mode = WorkerMode::trusted_generator;
            request.payload.schema = generator_request_schema_v1;
            request.hash_seed = 17;
            FakeLauncher launcher;
            WorkerClient client {.runtime = exact_runtime(), .launcher = launcher, .limits = {}};
            const auto result = client.invoke(request);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::worker_unauthorized);
            REQUIRE(launcher.calls == 0U);
        }
    }

    TEST_CASE("worker framing rejects declared and configured size violations") {
        const auto frame = encode_worker_frame("{}", 2U);
        REQUIRE(frame.has_value());
        auto malformed = *frame;
        malformed[0] = std::byte {3};
        const auto malformed_result = decode_worker_frame(malformed, 2U);
        REQUIRE_FALSE(malformed_result.has_value());
        REQUIRE(malformed_result.error().code == PackagingErrorCode::worker_frame_too_large);

        const auto excessive = encode_worker_frame("abc", 2U);
        REQUIRE_FALSE(excessive.has_value());
        REQUIRE(excessive.error().code == PackagingErrorCode::worker_frame_too_large);
    }

    TEST_CASE("exact private CPython process returns opaque AST without executing rule source") {
        if (!shared_runtime().runtime) {
            if (!shared_runtime().staging_failure.empty()) {
                FAIL_CHECK(shared_runtime().staging_failure);
                return;
            }
            WARN("SKIPPED: " << shared_runtime().unavailable_reason);
            return;
        }
        WindowsJobWorkerLauncher launcher;
        launcher.temporary_root = shared_runtime().temporary_parent;
        WorkerClient client {.runtime = *shared_runtime().runtime, .launcher = launcher, .limits = {}};
        auto request = parse_request();
        request.payload.bytes = bytes("raise RuntimeError('must never execute')\n");
        request.payload.source_digest = SourceDigest {"sha256:" + sha256_hex(request.payload.bytes)};

        const auto response = client.invoke(request);

        REQUIRE(response.has_value());
        REQUIRE(response->payload.schema == static_ast_schema_v1);
        const auto ast_payload = text(response->payload.bytes);
        REQUIRE(ast_payload.find("\"schema\":\"rule-engine.ast/1\"") != std::string::npos);
        REQUIRE(ast_payload.find("\"kind\":\"Raise\"") != std::string::npos);
        REQUIRE(ast_payload.find("must never execute") == std::string::npos);
    }

    TEST_CASE("real worker generator is stable across fresh hash seeds") {
        if (!shared_runtime().runtime) {
            if (!shared_runtime().staging_failure.empty()) {
                FAIL_CHECK(shared_runtime().staging_failure);
                return;
            }
            WARN("SKIPPED: " << shared_runtime().unavailable_reason);
            return;
        }
        const auto generator_source =
            bytes("from rule_engine_generator.bindings import demo\n"
                  "def generate(ctx):\n"
                  "    for name in {'gamma', 'alpha', 'beta'}:\n"
                  "        ctx.emit(demo(id='com.acme.' + name, name=name, label=ctx.text('label')))\n");
        const auto payload = encode_trusted_generator_worker_payload(TrustedGeneratorWorkerPayload {
            .callable = "generate",
            .module_source = generator_source,
            .inputs = {{.name = "label", .format = GeneratorInputFormat::utf8, .bytes = bytes("endpoint")}},
            .templates = {{.factory = "demo", .template_id = ExecutableId {"com.acme.template"}}},
        });
        REQUIRE(payload.has_value());
        WindowsJobWorkerLauncher launcher;
        launcher.temporary_root = shared_runtime().temporary_parent;
        WorkerClient client {.runtime = *shared_runtime().runtime, .launcher = launcher, .limits = {}};
        PythonWorkerGeneratorExecutor executor;
        executor.client = &client;
        executor.request_id_prefix = RequestId {"generator"};
        executor.source = SourceId {"generator/acme/generate.py"};
        executor.canonical_payload = *payload;
        executor.generator_execution_authorized = true;

        const auto generated = execute_generator_twice(executor, 101U, 202U);

        REQUIRE(generated.has_value());
        REQUIRE(generated->bindings.size() == 3U);
        REQUIRE(generated->bindings.front().id.value == "com.acme.alpha");
    }

    TEST_CASE("real worker timeout and output limits terminate the contained process tree") {
        if (!shared_runtime().runtime) {
            if (!shared_runtime().staging_failure.empty()) {
                FAIL_CHECK(shared_runtime().staging_failure);
                return;
            }
            WARN("SKIPPED: " << shared_runtime().unavailable_reason);
            return;
        }
        auto request = parse_request();

        SECTION("elapsed deadline") {
            WorkerLimits limits;
            limits.maximum_elapsed_time = std::chrono::milliseconds {0};
            WindowsJobWorkerLauncher launcher;
            launcher.temporary_root = shared_runtime().temporary_parent;
            const auto frame = encode_worker_request_frame(request, limits);
            REQUIRE(frame.has_value());
            const auto result =
                launcher.launch(*shared_runtime().runtime, request.mode, request.hash_seed, *frame, limits);
            REQUIRE(result.has_value());
            REQUIRE(result->timed_out);
            REQUIRE(result->process_tree_terminated);
        }

        SECTION("protocol output") {
            WorkerLimits limits;
            limits.maximum_frame_bytes = 1U * kibibyte;
            WindowsJobWorkerLauncher launcher;
            launcher.temporary_root = shared_runtime().temporary_parent;
            const auto frame = encode_worker_request_frame(request, limits);
            REQUIRE(frame.has_value());
            const auto result =
                launcher.launch(*shared_runtime().runtime, request.mode, request.hash_seed, *frame, limits);
            REQUIRE(result.has_value());
            REQUIRE(result->output_limited);
            REQUIRE(result->process_tree_terminated);
        }

        SECTION("active process limit") {
            const auto module_source =
                bytes("import subprocess, sys\n"
                      "def generate(ctx):\n"
                      "    subprocess.run([sys.executable, '-c', 'import time; time.sleep(30)'], check=True)\n");
            const auto payload = encode_trusted_generator_worker_payload(TrustedGeneratorWorkerPayload {
                .callable = "generate",
                .module_source = module_source,
                .inputs = {},
                .templates = {},
            });
            REQUIRE(payload.has_value());
            WorkerRequest generator_request {
                .protocol = python_worker_protocol_v1,
                .request_id = RequestId {"process-limit"},
                .mode = WorkerMode::trusted_generator,
                .runtime = official_windows_cpython_3146(),
                .payload =
                    OpaqueWorkerPayload {
                        .schema = std::string {generator_request_schema_v1},
                        .source = SourceId {"generator/process_limit.py"},
                        .source_digest = SourceDigest {"sha256:" + sha256_hex(*payload)},
                        .bytes = *payload,
                    },
                .hash_seed = 7U,
                .generator_execution_authorized = true,
            };
            WorkerLimits limits;
            WindowsJobWorkerLauncher launcher;
            launcher.temporary_root = shared_runtime().temporary_parent;
            const auto frame = encode_worker_request_frame(generator_request, limits);
            REQUIRE(frame.has_value());
            const auto result = launcher.launch(*shared_runtime().runtime, generator_request.mode,
                                                generator_request.hash_seed, *frame, limits);
            REQUIRE(result.has_value());
            REQUIRE(result->crashed);
            REQUIRE(result->process_tree_terminated);
        }
    }

    TEST_CASE("generator output is canonical across emission order and detects nondeterminism") {
        const GeneratorRun first {
            .hash_seed = 11,
            .bindings = {binding("com.acme.second", std::byte {2}), binding("com.acme.first", std::byte {1})},
        };
        const GeneratorRun reordered {
            .hash_seed = 29,
            .bindings = {binding("com.acme.first", std::byte {1}), binding("com.acme.second", std::byte {2})},
        };
        const auto stable = compare_generator_runs(first, reordered);
        REQUIRE(stable.has_value());
        REQUIRE(stable->bindings.front().id.value == "com.acme.first");
        REQUIRE(stable->digest.value.starts_with("sha256:"));

        auto changed = reordered;
        changed.bindings.front().canonical_arguments.front() = std::byte {9};
        const auto mismatch = compare_generator_runs(first, changed);
        REQUIRE_FALSE(mismatch.has_value());
        REQUIRE(mismatch.error().code == PackagingErrorCode::generator_nondeterministic);
    }

    TEST_CASE("generator comparison enforces distinct seeds duplicates and output bounds") {
        SECTION("same seed") {
            const GeneratorRun run {.hash_seed = 4, .bindings = {binding("com.acme.one", std::byte {1})}};
            const auto result = compare_generator_runs(run, run);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::generator_seed_reused);
        }

        SECTION("duplicate ID") {
            const std::vector bindings {binding("com.acme.one", std::byte {1}), binding("com.acme.one", std::byte {2})};
            const auto result = canonicalize_generator_output(bindings);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::duplicate_binding);
        }

        SECTION("argument bound") {
            const std::vector bindings {binding("com.acme.one", std::byte {1})};
            const GeneratorLimits limits {.maximum_bindings = 1, .maximum_argument_bytes = 0};
            const auto result = canonicalize_generator_output(bindings, limits);
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error().code == PackagingErrorCode::generator_limit);
        }
    }

    TEST_CASE("generator executor performs exactly two fresh differently-seeded runs") {
        FakeGenerator stable;
        const auto result = execute_generator_twice(stable, 101, 202);
        REQUIRE(result.has_value());
        REQUIRE(stable.seeds == std::vector<std::uint32_t> {101, 202});

        FakeGenerator changing;
        changing.change_second = true;
        const auto mismatch = execute_generator_twice(changing, 303, 404);
        REQUIRE_FALSE(mismatch.has_value());
        REQUIRE(mismatch.error().code == PackagingErrorCode::generator_nondeterministic);
    }

} // namespace rule_engine::python::packaging
