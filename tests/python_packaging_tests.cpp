#include "rule_engine/python/packaging.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::packaging {
    namespace {

        std::vector<std::byte> bytes(const std::string_view text) {
            return {reinterpret_cast<const std::byte *>(text.data()),
                    reinterpret_cast<const std::byte *>(text.data() + text.size())};
        }

        std::vector<std::byte> repeated_bytes(const std::size_t count, const std::byte value) {
            return std::vector<std::byte>(count, value);
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

        PrivatePythonRuntime exact_runtime() {
            return PrivatePythonRuntime {
                .descriptor = official_windows_cpython_3146(),
                .origin = RuntimeOrigin::private_bundle,
                .runtime_root = "C:/private/python-3.14.6",
                .worker_executable = "C:/private/rule_engine_python_worker.exe",
                .verified_artifact_sha256 = official_windows_cpython_3146().artifact_sha256,
                .installation_manifest_verified = true,
            };
        }

        WorkerRequest parse_request() {
            return WorkerRequest {
                .protocol = python_worker_protocol_v1,
                .request_id = RequestId {"request-1"},
                .mode = WorkerMode::static_parse,
                .runtime = official_windows_cpython_3146(),
                .payload =
                    OpaqueWorkerPayload {
                        .schema = std::string {static_source_schema_v1},
                        .source = SourceId {"src/acme/rules.py"},
                        .source_digest = SourceDigest {"sha256:source"},
                        .bytes = bytes("def sample(): pass\n"),
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
            WorkerProcessResult result;
            std::optional<PackagingError> failure;

            std::expected<WorkerProcessResult, PackagingError> launch(const PrivatePythonRuntime &, const WorkerMode,
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

    TEST_CASE("runtime descriptor pins official CPython 3.14.6 and never falls back") {
        const auto &descriptor = official_windows_cpython_3146();
        REQUIRE(descriptor.python_version == "3.14.6");
        REQUIRE(descriptor.artifact_url == "https://www.python.org/ftp/python/3.14.6/python-3.14.6-embed-amd64.zip");
        REQUIRE(descriptor.artifact_sha256 == "df901e84a896ff1ee720ad03377e0c8d8c2244fda79808aeeaff6316df1cb75c");
        REQUIRE(validate_exact_private_runtime(exact_runtime()).has_value());

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
