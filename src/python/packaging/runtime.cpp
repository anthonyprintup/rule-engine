#include "rule_engine/python/packaging/runtime.hpp"

#include "rule_engine/python/packaging/source_pack.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <set>
#include <system_error>
#include <vector>

namespace rule_engine::python::packaging {
    namespace {

        constexpr auto official_version = "3.14.6";
        constexpr auto official_windows_url = "https://www.python.org/ftp/python/3.14.6/python-3.14.6-embed-amd64.zip";
        constexpr auto official_windows_sha256 = "df901e84a896ff1ee720ad03377e0c8d8c2244fda79808aeeaff6316df1cb75c";
        constexpr auto worker_filename = "rule_engine_python_worker.py";
        constexpr auto manifest_filename = "rule-engine-python-runtime.manifest";
        constexpr auto worker_script_sha256 = "985d7710b96532eabf6da89175713d9c484234160beca52157ff4a03c0cb8737";
        constexpr std::size_t maximum_runtime_file_bytes = 32U * mebibyte;
        constexpr std::size_t maximum_artifact_bytes = 32U * mebibyte;

        struct RuntimeFile {
            std::string_view name;
            std::uintmax_t size;
            std::string_view sha256;
        };

        // This is the exact per-file closure extracted from the official pinned
        // artifact. Staging never accepts a merely version-compatible runtime.
        constexpr std::array official_runtime_files {
            RuntimeFile {"LICENSE.txt", 35407U, "935cf13e19f8c31b497d20b05d73623431a226b230c3599bc30fa3348979bc68"},
            RuntimeFile {"_asyncio.pyd", 78048U, "dc6db118862ab3298e55e0f7c44c2c0dae4af9e810d2578271280202d6aa098a"},
            RuntimeFile {"_bz2.pyd", 87776U, "d28c3dd1c22bfb8a6e8a6a9c2359842b797d08e878ecb7805f60e86a45589d11"},
            RuntimeFile {"_ctypes.pyd", 142560U, "25d9b0be550d428fecc697ca20450343a7c3ce77c9f5283e9aecfd188d609250"},
            RuntimeFile {"_decimal.pyd", 290528U, "8d41a84db20a9b985e98c802ad6833cf9625c744ad35478dd346f54f81488706"},
            RuntimeFile {"_elementtree.pyd", 138464U,
                         "16f4d30a50fc25950762a8bbef9dd6c5750729345539c224d489be33e6d6f340"},
            RuntimeFile {"_hashlib.pyd", 69344U, "36ce760b9fac53fe51755f30a68d86f5fde89bf1b66c65c19e04aa3afa404ac2"},
            RuntimeFile {"_lzma.pyd", 160992U, "5f7003f9f0256e36351ca2810b3485db28579b08e4d1d65f6f211fcd1136f395"},
            RuntimeFile {"_multiprocessing.pyd", 38624U,
                         "9e87ce081fbcf0b6596fcba98e121379ad72a33d68e6b2af7a8bcc5b900229ba"},
            RuntimeFile {"_overlapped.pyd", 58080U, "ac877f3da413c1523c07b6a0dd1f7e0d7ceb3e8590a5e9e20a78eb1bcb700793"},
            RuntimeFile {"_queue.pyd", 36576U, "bb53357b4e91ac23ed4061f15ff3e5e91a5b3be1cbb0c6cf294521ae5b4efa1c"},
            RuntimeFile {"_remote_debugging.pyd", 84704U,
                         "38f30e6188450374a993e8fc07e7d41a90842c19290f5c6b46ca10b93c831587"},
            RuntimeFile {"_socket.pyd", 87776U, "25ac83cac32ed0d67b2cc9672ce64cb53f0a29a75b14c276e901023ff43da5f9"},
            RuntimeFile {"_sqlite3.pyd", 132832U, "b0c4edff6d60f300373ec929ab915f95ee601bf167e04d28e4e9e28a8e536fe0"},
            RuntimeFile {"_ssl.pyd", 190688U, "5c07572df2913618cfb851b608cb5f74d740fcce5c3f2e63dc0a2ba39ab35dad"},
            RuntimeFile {"_uuid.pyd", 28384U, "a09308efd309732e3745e70b4456235579c450cac32bed616dfb3913b56f6637"},
            RuntimeFile {"_wmi.pyd", 40160U, "0ab1fbcf18c95d70343012feb1aad61e1ba95aaed5b4a08e57fc5990e8a9a452"},
            RuntimeFile {"_zoneinfo.pyd", 51936U, "c471587b0741aa0b795dcda76667a69e40aeb881b54ea3601a26e050cb27dc8a"},
            RuntimeFile {"_zstd.pyd", 503520U, "262aea62a994920daf152a10bdc0ca83a8b1c0874e71db23734862431de182c6"},
            RuntimeFile {"libcrypto-3.dll", 6242552U,
                         "53c529145339fb042a3dcd3a09c2d7753204f8b4fc79d99e0d31e69a33985958"},
            RuntimeFile {"libffi-8.dll", 39696U, "eff52743773eb550fcc6ce3efc37c85724502233b6b002a35496d828bd7b280a"},
            RuntimeFile {"libssl-3.dll", 1329912U, "b17a87979862d19241edc4318f967e24c3ec356ed6c2368f561179fab2311001"},
            RuntimeFile {"pyexpat.pyd", 222944U, "133942bde91fe43289076a0b50a01b265df4ead078617cca6f6604a4166e1260"},
            RuntimeFile {"python.cat", 595524U, "10da2cf78c77c5bf69469bcb652df2eb0af63d7f9ba08ba3cd4512aed6a42525"},
            RuntimeFile {"python.exe", 106208U, "03168c01b7b7491423350e82c26fee71f35b43694d1319d3c668bda6903a0c38"},
            RuntimeFile {"python3.dll", 73952U, "22c6e46d8bd563cdb072650901461ef68be2ea6cb1e80af859559d9395a27e39"},
            RuntimeFile {"python314._pth", 80U, "2ed7ccda80e9e28ab5877902a9a325586c8a7b7b3e6731d944565bee082e216c"},
            RuntimeFile {"python314.dll", 6778592U, "fde89cdb5c2d08ae65de7ef4abca1876c93ba3796002f5ac0bf7e4d4f5a94da0"},
            RuntimeFile {"python314.zip", 4125572U, "e13e610c2e56173cc933986f38c56c7439e4e1519ddf98829e92c5d348f1c376"},
            RuntimeFile {"pythonw.exe", 104672U, "e3889c5020644b9ecfd9e678f95372b1e127e29e6c02b1129ed88c38381d0972"},
            RuntimeFile {"select.pyd", 33504U, "fab1b4cee101359d82d72061b83cff1855337b3677b9fe01cd69f7548f4c496e"},
            RuntimeFile {"sqlite3.dll", 1584864U, "2940bee51c4a00c7e8f2a8a1be857d4c4ad23b2657fbf7fdf18e3a3fd20066c6"},
            RuntimeFile {"unicodedata.pyd", 759008U,
                         "0d4f124b2d6622d276d777f7106972219f9b310edb5df8149c253da7c013d6d8"},
            RuntimeFile {"vcruntime140_1.dll", 49776U,
                         "6a99bc0128e0c7d6cbbf615fcc26909565e17d4ca3451b97f8987f9c6acbc6c8"},
            RuntimeFile {"vcruntime140.dll", 120400U,
                         "052ad6a20d375957e82aa6a3c441ea548d89be0981516ca7eb306e063d5027f4"},
            RuntimeFile {"winsound.pyd", 32992U, "38eccf01b663abfad0bc40444043410fecc5af895be3a1efbc9bd1cfe787f5a6"},
        };

        PackagingError runtime_error(const PackagingErrorCode code, std::string message,
                                     std::optional<std::string> subject = std::nullopt) {
            return PackagingError {.code = code, .message = std::move(message), .subject = std::move(subject)};
        }

        std::expected<std::vector<std::byte>, PackagingError>
        read_file(const std::filesystem::path &path, const std::size_t maximum_bytes, const PackagingErrorCode code) {
            std::error_code filesystem_error;
            const auto size = std::filesystem::file_size(path, filesystem_error);
            if (filesystem_error) {
                return std::unexpected(runtime_error(code, "cannot stat private-runtime file", path.string()));
            }
            if (size > maximum_bytes) {
                return std::unexpected(runtime_error(code, "private-runtime file exceeds its bound", path.string()));
            }
            std::ifstream input {path, std::ios::binary};
            if (!input) {
                return std::unexpected(runtime_error(code, "cannot open private-runtime file", path.string()));
            }
            std::vector<std::byte> bytes(static_cast<std::size_t>(size));
            if (!bytes.empty()) {
                input.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            }
            if (!input || static_cast<std::size_t>(input.gcount()) != bytes.size()) {
                return std::unexpected(runtime_error(code, "cannot read complete private-runtime file", path.string()));
            }
            return bytes;
        }

        std::expected<std::string, PackagingError>
        hash_file(const std::filesystem::path &path, const std::size_t maximum_bytes, const PackagingErrorCode code) {
            const auto bytes = read_file(path, maximum_bytes, code);
            if (!bytes) {
                return std::unexpected(bytes.error());
            }
            return sha256_hex(*bytes);
        }

        std::string canonical_runtime_manifest() {
            std::string manifest = "format=1\npython_version=3.14.6\nartifact_sha256=";
            manifest += official_windows_sha256;
            manifest += "\nworker_protocol=1\nworker_script=";
            manifest += worker_filename;
            manifest += "\nworker_script_sha256=";
            manifest += worker_script_sha256;
            manifest += '\n';
            for (const auto &file : official_runtime_files) {
                manifest += "file\t";
                manifest += file.name;
                manifest += '\t';
                manifest += std::to_string(file.size);
                manifest += '\t';
                manifest += file.sha256;
                manifest += '\n';
            }
            return manifest;
        }

        std::expected<void, PackagingError> validate_official_distribution(const std::filesystem::path &root,
                                                                           const bool installed) {
            std::error_code filesystem_error;
            if (!std::filesystem::is_directory(root, filesystem_error) || filesystem_error) {
                return std::unexpected(runtime_error(PackagingErrorCode::runtime_missing,
                                                     "private-runtime root is not a directory", root.string()));
            }

            std::set<std::string> expected_names;
            for (const auto &file : official_runtime_files) {
                expected_names.emplace(file.name);
                const auto path = root / file.name;
                const auto status = std::filesystem::symlink_status(path, filesystem_error);
                if (filesystem_error || !std::filesystem::is_regular_file(status) ||
                    std::filesystem::is_symlink(status)) {
                    return std::unexpected(runtime_error(PackagingErrorCode::runtime_missing,
                                                         "private-runtime file is absent or not regular",
                                                         path.string()));
                }
                const auto size = std::filesystem::file_size(path, filesystem_error);
                if (filesystem_error || size != file.size) {
                    return std::unexpected(runtime_error(PackagingErrorCode::runtime_mismatch,
                                                         "private-runtime file size does not match the pinned artifact",
                                                         path.string()));
                }
                const auto digest = hash_file(path, maximum_runtime_file_bytes, PackagingErrorCode::runtime_mismatch);
                if (!digest) {
                    return std::unexpected(digest.error());
                }
                if (*digest != file.sha256) {
                    return std::unexpected(
                        runtime_error(PackagingErrorCode::runtime_mismatch,
                                      "private-runtime file digest does not match the pinned artifact", path.string()));
                }
            }
            if (installed) {
                expected_names.emplace(worker_filename);
                expected_names.emplace(manifest_filename);
            }

            std::size_t observed_entries = 0U;
            std::filesystem::directory_iterator iterator {root, filesystem_error};
            const std::filesystem::directory_iterator end;
            while (!filesystem_error && iterator != end) {
                const auto filename = iterator->path().filename().string();
                if (!expected_names.contains(filename)) {
                    return std::unexpected(runtime_error(PackagingErrorCode::runtime_mismatch,
                                                         "private-runtime root contains an unexpected entry",
                                                         filename));
                }
                ++observed_entries;
                iterator.increment(filesystem_error);
            }
            if (filesystem_error || observed_entries != expected_names.size()) {
                return std::unexpected(
                    runtime_error(PackagingErrorCode::runtime_mismatch,
                                  "private-runtime directory enumeration does not match its manifest", root.string()));
            }
            return {};
        }

        std::expected<void, PackagingError> write_text_file(const std::filesystem::path &path,
                                                            const std::string_view text) {
            std::ofstream output {path, std::ios::binary | std::ios::trunc};
            if (!output) {
                return std::unexpected(runtime_error(PackagingErrorCode::runtime_staging_failed,
                                                     "cannot create private-runtime manifest", path.string()));
            }
            output.write(text.data(), static_cast<std::streamsize>(text.size()));
            output.flush();
            if (!output) {
                return std::unexpected(runtime_error(PackagingErrorCode::runtime_staging_failed,
                                                     "cannot write complete private-runtime manifest", path.string()));
            }
            return {};
        }

        struct StagingCleanup {
            std::filesystem::path path;
            bool armed {true};

            ~StagingCleanup() {
                if (armed) {
                    std::error_code ignored;
                    std::filesystem::remove_all(path, ignored);
                }
            }
        };

        std::expected<std::filesystem::path, PackagingError> absolute_path(const std::filesystem::path &path,
                                                                           const PackagingErrorCode code) {
            std::error_code filesystem_error;
            auto absolute = std::filesystem::absolute(path, filesystem_error).lexically_normal();
            if (filesystem_error || absolute.empty()) {
                return std::unexpected(runtime_error(code, "cannot resolve private-runtime path", path.string()));
            }
            return absolute;
        }

    } // namespace

    PythonRuntimeDescriptor official_windows_cpython_3146() {
        return PythonRuntimeDescriptor {
            .python_version = official_version,
            .platform = RuntimePlatform::windows_x86_64,
            .artifact_url = official_windows_url,
            .artifact_sha256 = official_windows_sha256,
            .worker_protocol = python_worker_protocol_v1,
        };
    }

    std::string_view private_python_worker_script_sha256() noexcept { return worker_script_sha256; }

    std::expected<PrivatePythonRuntime, PackagingError>
    stage_exact_private_runtime(const PythonRuntimeStageRequest &request) {
        const auto artifact = absolute_path(request.artifact_archive, PackagingErrorCode::runtime_staging_failed);
        const auto distribution =
            absolute_path(request.extracted_distribution, PackagingErrorCode::runtime_staging_failed);
        const auto destination = absolute_path(request.destination, PackagingErrorCode::runtime_staging_failed);
        const auto script = absolute_path(request.worker_script, PackagingErrorCode::runtime_staging_failed);
        if (!artifact || !distribution || !destination || !script) {
            if (!artifact) {
                return std::unexpected(artifact.error());
            }
            if (!distribution) {
                return std::unexpected(distribution.error());
            }
            if (!destination) {
                return std::unexpected(destination.error());
            }
            return std::unexpected(script.error());
        }
        if (!destination->has_filename() || destination->parent_path().empty()) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_staging_failed,
                                                 "private-runtime destination must be a scoped child directory",
                                                 destination->string()));
        }

        const auto artifact_digest =
            hash_file(*artifact, maximum_artifact_bytes, PackagingErrorCode::runtime_staging_failed);
        if (!artifact_digest) {
            return std::unexpected(artifact_digest.error());
        }
        if (*artifact_digest != official_windows_sha256) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_mismatch,
                                                 "CPython artifact digest does not match the exact 3.14.6 pin",
                                                 artifact->string()));
        }
        const auto distribution_valid = validate_official_distribution(*distribution, false);
        if (!distribution_valid) {
            return std::unexpected(distribution_valid.error());
        }
        const auto script_digest = hash_file(*script, 1U * mebibyte, PackagingErrorCode::runtime_staging_failed);
        if (!script_digest) {
            return std::unexpected(script_digest.error());
        }
        if (*script_digest != worker_script_sha256) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_mismatch,
                                                 "worker script digest does not match this packaging build",
                                                 script->string()));
        }

        std::error_code filesystem_error;
        if (std::filesystem::exists(*destination, filesystem_error) || filesystem_error) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_staging_failed,
                                                 "private-runtime destination already exists or cannot be checked",
                                                 destination->string()));
        }
        auto staging = *destination;
        staging += L".staging";
        if (std::filesystem::exists(staging, filesystem_error) || filesystem_error) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_staging_failed,
                                                 "private-runtime staging path already exists or cannot be checked",
                                                 staging.string()));
        }
        if (!std::filesystem::is_directory(destination->parent_path(), filesystem_error) || filesystem_error ||
            !std::filesystem::create_directory(staging, filesystem_error) || filesystem_error) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_staging_failed,
                                                 "cannot create private-runtime staging directory", staging.string()));
        }
        StagingCleanup cleanup {.path = staging};

        for (const auto &file : official_runtime_files) {
            std::filesystem::copy_file(*distribution / file.name, staging / file.name,
                                       std::filesystem::copy_options::none, filesystem_error);
            if (filesystem_error) {
                return std::unexpected(runtime_error(PackagingErrorCode::runtime_staging_failed,
                                                     "cannot copy pinned private-runtime file",
                                                     std::string {file.name}));
            }
        }
        std::filesystem::copy_file(*script, staging / worker_filename, std::filesystem::copy_options::none,
                                   filesystem_error);
        if (filesystem_error) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_staging_failed,
                                                 "cannot copy private Python worker script", script->string()));
        }
        const auto manifest_text = canonical_runtime_manifest();
        const auto manifest_written = write_text_file(staging / manifest_filename, manifest_text);
        if (!manifest_written) {
            return std::unexpected(manifest_written.error());
        }
        std::filesystem::rename(staging, *destination, filesystem_error);
        if (filesystem_error) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_staging_failed,
                                                 "cannot atomically publish private-runtime directory",
                                                 destination->string()));
        }
        cleanup.armed = false;
        return load_exact_private_runtime(*destination);
    }

    std::expected<PrivatePythonRuntime, PackagingError>
    load_exact_private_runtime(const std::filesystem::path &runtime_root) {
        const auto root = absolute_path(runtime_root, PackagingErrorCode::runtime_missing);
        if (!root) {
            return std::unexpected(root.error());
        }
        PrivatePythonRuntime runtime {
            .descriptor = official_windows_cpython_3146(),
            .origin = RuntimeOrigin::private_bundle,
            .runtime_root = *root,
            .python_executable = *root / "python.exe",
            .worker_script = *root / worker_filename,
            .crypto_library = *root / "libcrypto-3.dll",
            .installation_manifest = *root / manifest_filename,
            .verified_artifact_sha256 = official_windows_sha256,
        };
        const auto valid = validate_exact_private_runtime(runtime);
        if (!valid) {
            return std::unexpected(valid.error());
        }
        return runtime;
    }

    std::expected<void, PackagingError> validate_exact_private_runtime(const PrivatePythonRuntime &runtime) {
        if (runtime.origin != RuntimeOrigin::private_bundle) {
            return std::unexpected(
                runtime_error(PackagingErrorCode::runtime_mismatch, "system Python fallback is forbidden"));
        }
        const auto &required = official_windows_cpython_3146();
        if (runtime.descriptor != required || runtime.verified_artifact_sha256 != required.artifact_sha256) {
            return std::unexpected(
                runtime_error(PackagingErrorCode::runtime_mismatch,
                              "private Python runtime is not the exact pinned CPython 3.14.6 artifact"));
        }
        if (runtime.runtime_root.empty() || runtime.python_executable.empty() || runtime.worker_script.empty() ||
            runtime.crypto_library.empty() || runtime.installation_manifest.empty()) {
            return std::unexpected(
                runtime_error(PackagingErrorCode::runtime_missing, "private Python installation paths are incomplete"));
        }
        const auto expected_python = runtime.runtime_root / "python.exe";
        const auto expected_script = runtime.runtime_root / worker_filename;
        const auto expected_crypto = runtime.runtime_root / "libcrypto-3.dll";
        const auto expected_manifest = runtime.runtime_root / manifest_filename;
        if (runtime.python_executable.lexically_normal() != expected_python.lexically_normal() ||
            runtime.worker_script.lexically_normal() != expected_script.lexically_normal() ||
            runtime.crypto_library.lexically_normal() != expected_crypto.lexically_normal() ||
            runtime.installation_manifest.lexically_normal() != expected_manifest.lexically_normal()) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_mismatch,
                                                 "private Python runtime paths escape the verified installation root"));
        }
        const auto distribution_valid = validate_official_distribution(runtime.runtime_root, true);
        if (!distribution_valid) {
            return std::unexpected(distribution_valid.error());
        }
        const auto script_digest =
            hash_file(runtime.worker_script, 1U * mebibyte, PackagingErrorCode::runtime_mismatch);
        if (!script_digest) {
            return std::unexpected(script_digest.error());
        }
        if (*script_digest != worker_script_sha256) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_mismatch,
                                                 "private Python worker script digest does not match this build",
                                                 runtime.worker_script.string()));
        }
        const auto manifest_bytes =
            read_file(runtime.installation_manifest, 64U * kibibyte, PackagingErrorCode::runtime_mismatch);
        if (!manifest_bytes) {
            return std::unexpected(manifest_bytes.error());
        }
        const std::string_view manifest_text {reinterpret_cast<const char *>(manifest_bytes->data()),
                                              manifest_bytes->size()};
        if (manifest_text != canonical_runtime_manifest()) {
            return std::unexpected(runtime_error(PackagingErrorCode::runtime_mismatch,
                                                 "private Python installation manifest is not canonical or exact",
                                                 runtime.installation_manifest.string()));
        }
        return {};
    }

} // namespace rule_engine::python::packaging
