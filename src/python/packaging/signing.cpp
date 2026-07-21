#include "rule_engine/python/packaging/signing.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <utility>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <AclAPI.h>
#include <Windows.h>
#endif

namespace rule_engine::python::packaging {
    namespace {

        PackagingError signing_error(const PackagingErrorCode code, std::string message) {
            // Key references and private bytes are intentionally never attached
            // as an error subject or interpolated into diagnostics.
            return PackagingError {.code = code, .message = std::move(message), .subject = std::nullopt};
        }

#ifdef _WIN32
        struct evp_pkey_st;
        struct evp_pkey_ctx_st;
        struct evp_md_ctx_st;
        struct evp_md_st;
        struct engine_st;
        struct ossl_lib_ctx_st;

        using OpenSslVersionMajor = unsigned int(__cdecl *)();
        using NewRawPrivateKey = evp_pkey_st *(__cdecl *) (ossl_lib_ctx_st *, const char *, const char *,
                                                           const unsigned char *, std::size_t);
        using GetRawPublicKey = int(__cdecl *)(const evp_pkey_st *, unsigned char *, std::size_t *);
        using FreeKey = void(__cdecl *)(evp_pkey_st *);
        using NewDigestContext = evp_md_ctx_st *(__cdecl *) ();
        using FreeDigestContext = void(__cdecl *)(evp_md_ctx_st *);
        using DigestSignInit = int(__cdecl *)(evp_md_ctx_st *, evp_pkey_ctx_st **, const evp_md_st *, engine_st *,
                                              evp_pkey_st *);
        using DigestSign = int(__cdecl *)(evp_md_ctx_st *, unsigned char *, std::size_t *, const unsigned char *,
                                          std::size_t);

        struct UniqueHandle {
            HANDLE value {INVALID_HANDLE_VALUE};

            UniqueHandle() = default;
            explicit UniqueHandle(const HANDLE handle): value(handle) {}

            ~UniqueHandle() {
                if (value != nullptr && value != INVALID_HANDLE_VALUE) {
                    CloseHandle(value);
                }
            }

            UniqueHandle(const UniqueHandle &) = delete;
            UniqueHandle &operator=(const UniqueHandle &) = delete;
            UniqueHandle(UniqueHandle &&) = delete;
            UniqueHandle &operator=(UniqueHandle &&) = delete;
        };

        struct LocalSecurityDescriptor {
            PSECURITY_DESCRIPTOR value {};

            LocalSecurityDescriptor() = default;

            ~LocalSecurityDescriptor() {
                if (value != nullptr) {
                    LocalFree(value);
                }
            }

            LocalSecurityDescriptor(const LocalSecurityDescriptor &) = delete;
            LocalSecurityDescriptor &operator=(const LocalSecurityDescriptor &) = delete;
        };

        struct SecretSeed {
            std::array<std::byte, ed25519_seed_bytes> bytes {};

            SecretSeed() = default;

            ~SecretSeed() { SecureZeroMemory(bytes.data(), bytes.size()); }

            SecretSeed(const SecretSeed &) = delete;
            SecretSeed &operator=(const SecretSeed &) = delete;
        };

        struct CryptoLibrary {
            HMODULE value {};

            explicit CryptoLibrary(const HMODULE handle): value(handle) {}

            ~CryptoLibrary() {
                if (value != nullptr) {
                    FreeLibrary(value);
                }
            }

            CryptoLibrary(const CryptoLibrary &) = delete;
            CryptoLibrary &operator=(const CryptoLibrary &) = delete;

            [[nodiscard]] HMODULE release() noexcept {
                const auto released = value;
                value = nullptr;
                return released;
            }
        };

        struct UniqueKey {
            evp_pkey_st *value {};
            FreeKey free {};

            UniqueKey(evp_pkey_st *key, const FreeKey release): value(key), free(release) {}

            ~UniqueKey() {
                if (value != nullptr) {
                    free(value);
                }
            }

            UniqueKey(const UniqueKey &) = delete;
            UniqueKey &operator=(const UniqueKey &) = delete;

            [[nodiscard]] evp_pkey_st *release() noexcept {
                auto *released = value;
                value = nullptr;
                return released;
            }
        };

        struct DigestContext {
            evp_md_ctx_st *value {};
            FreeDigestContext free {};

            DigestContext(evp_md_ctx_st *context, const FreeDigestContext release): value(context), free(release) {}

            ~DigestContext() {
                if (value != nullptr) {
                    free(value);
                }
            }

            DigestContext(const DigestContext &) = delete;
            DigestContext &operator=(const DigestContext &) = delete;
        };

        template<typename Function>
        std::expected<Function, PackagingError> load_function(const HMODULE library, const char *name) {
            const auto procedure = GetProcAddress(library, name);
            if (procedure == nullptr) {
                return std::unexpected(signing_error(PackagingErrorCode::crypto_backend_unavailable,
                                                     "OpenSSL 3 is missing a required Ed25519 signing function"));
            }
            return std::bit_cast<Function>(procedure);
        }

        bool is_normalized_local_drive_path(const std::filesystem::path &path) {
            const auto root_name = path.root_name().wstring();
            const auto native_path = path.native();
            const bool local_drive =
                root_name.size() == 2U &&
                ((root_name[0] >= L'A' && root_name[0] <= L'Z') || (root_name[0] >= L'a' && root_name[0] <= L'z')) &&
                root_name[1] == L':';
            const bool no_alternate_stream = native_path.find(L':', 2U) == std::wstring::npos;
            return path.is_absolute() && local_drive && no_alternate_stream && path.lexically_normal() == path;
        }

        std::expected<std::filesystem::path, PackagingError> parse_file_reference(const std::string_view reference) {
            constexpr std::string_view prefix = "file:";
            constexpr std::size_t maximum_windows_path_code_units = 32'767U;
            constexpr std::size_t maximum_utf8_path_bytes = maximum_windows_path_code_units * 4U;
            if (!reference.starts_with(prefix) || reference.size() == prefix.size() ||
                reference.find('\0') != std::string_view::npos) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_reference_invalid,
                                                     "Ed25519 signing keys require an explicit file: reference"));
            }
            const auto encoded_path = reference.substr(prefix.size());
            if (encoded_path.size() > maximum_utf8_path_bytes) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_reference_invalid,
                                                     "signing-key reference exceeds the platform path bound"));
            }
            const auto wide_size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, encoded_path.data(),
                                                       static_cast<int>(encoded_path.size()), nullptr, 0);
            if (wide_size <= 0 || static_cast<std::size_t>(wide_size) > maximum_windows_path_code_units) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_reference_invalid,
                                                     "signing-key reference is not valid bounded UTF-8"));
            }
            std::wstring wide_path(static_cast<std::size_t>(wide_size), L'\0');
            if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, encoded_path.data(),
                                    static_cast<int>(encoded_path.size()), wide_path.data(), wide_size) != wide_size) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_reference_invalid,
                                                     "signing-key reference cannot be decoded"));
            }
            const std::filesystem::path path {std::move(wide_path)};
            if (!is_normalized_local_drive_path(path)) {
                return std::unexpected(
                    signing_error(PackagingErrorCode::signing_key_reference_invalid,
                                  "signing-key file reference must be a normalized absolute local-drive path"));
            }
            return path;
        }

        std::expected<void, PackagingError> validate_local_file_handle(const HANDLE handle) {
            BY_HANDLE_FILE_INFORMATION information {};
            FILE_STANDARD_INFO standard {};
            if (GetFileType(handle) != FILE_TYPE_DISK || GetFileInformationByHandle(handle, &information) == 0 ||
                GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard)) == 0 ||
                standard.Directory || (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_unavailable,
                                                     "signing-key reference is not a regular local file"));
            }
            if (standard.EndOfFile.QuadPart != static_cast<LONGLONG>(ed25519_seed_bytes)) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_unavailable,
                                                     "Ed25519 seed file must contain exactly 32 bytes"));
            }

            const auto required =
                GetFinalPathNameByHandleW(handle, nullptr, 0U, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if (required == 0U) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_unavailable,
                                                     "cannot resolve the signing-key file target"));
            }
            std::vector<wchar_t> resolved(static_cast<std::size_t>(required) + 1U);
            const auto written = GetFinalPathNameByHandleW(handle, resolved.data(), static_cast<DWORD>(resolved.size()),
                                                           FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if (written == 0U || written >= resolved.size()) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_unavailable,
                                                     "cannot resolve the complete signing-key file target"));
            }
            const std::wstring_view final_path {resolved.data(), written};
            const bool local_drive = written >= 7U && final_path.starts_with(L"\\\\?\\") &&
                                     ((final_path[4] >= L'A' && final_path[4] <= L'Z') ||
                                      (final_path[4] >= L'a' && final_path[4] <= L'z')) &&
                                     final_path[5] == L':' && final_path[6] == L'\\';
            if (!local_drive) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_reference_invalid,
                                                     "signing-key target must remain on a local drive"));
            }
            return {};
        }

        std::expected<std::vector<std::byte>, PackagingError> current_token_user() {
            UniqueHandle token;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value) == 0) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_permissions,
                                                     "cannot inspect the signing process identity"));
            }
            DWORD required {};
            GetTokenInformation(token.value, TokenUser, nullptr, 0U, &required);
            if (required == 0U || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_permissions,
                                                     "cannot size the signing process identity"));
            }
            std::vector<std::byte> token_data(required);
            if (GetTokenInformation(token.value, TokenUser, token_data.data(), required, &required) == 0) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_permissions,
                                                     "cannot read the signing process identity"));
            }
            const auto *token_user = reinterpret_cast<const TOKEN_USER *>(token_data.data());
            const auto sid_bytes = GetLengthSid(token_user->User.Sid);
            std::vector<std::byte> result(sid_bytes);
            if (sid_bytes == 0U || CopySid(sid_bytes, result.data(), token_user->User.Sid) == 0) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_permissions,
                                                     "cannot retain the signing process identity"));
            }
            return result;
        }

        std::expected<void, PackagingError> validate_private_acl(const HANDLE handle) {
            auto caller = current_token_user();
            if (!caller) {
                return std::unexpected(caller.error());
            }
            std::array<std::byte, SECURITY_MAX_SID_SIZE> system_sid {};
            std::array<std::byte, SECURITY_MAX_SID_SIZE> administrators_sid {};
            DWORD system_size = static_cast<DWORD>(system_sid.size());
            DWORD administrators_size = static_cast<DWORD>(administrators_sid.size());
            if (CreateWellKnownSid(WinLocalSystemSid, nullptr, system_sid.data(), &system_size) == 0 ||
                CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators_sid.data(),
                                   &administrators_size) == 0) {
                return std::unexpected(signing_error(PackagingErrorCode::signing_key_permissions,
                                                     "cannot build the signing-key ACL allowlist"));
            }

            PSID owner {};
            PACL dacl {};
            LocalSecurityDescriptor descriptor;
            const auto security_result =
                GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                                nullptr, &dacl, nullptr, &descriptor.value);
            SECURITY_DESCRIPTOR_CONTROL descriptor_control {};
            DWORD descriptor_revision {};
            if (security_result != ERROR_SUCCESS || descriptor.value == nullptr || owner == nullptr ||
                !IsValidSid(owner) || !EqualSid(owner, caller->data()) || dacl == nullptr || !IsValidAcl(dacl) ||
                GetSecurityDescriptorControl(descriptor.value, &descriptor_control, &descriptor_revision) == 0 ||
                (descriptor_control & SE_DACL_PROTECTED) == 0U) {
                return std::unexpected(
                    signing_error(PackagingErrorCode::signing_key_permissions,
                                  "signing-key file must be caller-owned and protected by an explicit valid DACL"));
            }

            for (DWORD index = 0U; index < dacl->AceCount; ++index) {
                void *raw_ace {};
                if (GetAce(dacl, index, &raw_ace) == 0 || raw_ace == nullptr) {
                    return std::unexpected(signing_error(PackagingErrorCode::signing_key_permissions,
                                                         "cannot inspect the complete signing-key DACL"));
                }
                const auto *header = static_cast<const ACE_HEADER *>(raw_ace);
                if ((header->AceFlags & INHERIT_ONLY_ACE) != 0U) {
                    continue;
                }
                if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
                    const bool recognized_deny = header->AceType == ACCESS_DENIED_ACE_TYPE ||
                                                 header->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE ||
                                                 header->AceType == ACCESS_DENIED_CALLBACK_ACE_TYPE ||
                                                 header->AceType == ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE;
                    if (recognized_deny) {
                        continue;
                    }
                    return std::unexpected(
                        signing_error(PackagingErrorCode::signing_key_permissions,
                                      "signing-key DACL contains an unsupported access-control entry"));
                }
                const auto *allow = static_cast<const ACCESS_ALLOWED_ACE *>(raw_ace);
                const auto sid = reinterpret_cast<PSID>(const_cast<DWORD *>(&allow->SidStart));
                if (!IsValidSid(sid)) {
                    return std::unexpected(signing_error(PackagingErrorCode::signing_key_permissions,
                                                         "signing-key DACL contains an invalid principal"));
                }
                const bool permitted = EqualSid(sid, caller->data()) || EqualSid(sid, system_sid.data()) ||
                                       EqualSid(sid, administrators_sid.data());
                if (allow->Mask != 0U && !permitted) {
                    return std::unexpected(
                        signing_error(PackagingErrorCode::signing_key_permissions,
                                      "signing-key file grants access outside caller, SYSTEM, and Administrators"));
                }
            }
            return {};
        }

        struct OpenSslEd25519Signer final: Ed25519Signer {
            HMODULE library {};
            evp_pkey_st *key {};
            FreeKey free_key {};
            NewDigestContext new_context {};
            FreeDigestContext free_context {};
            DigestSignInit sign_init {};
            DigestSign sign_message {};
            std::array<std::byte, ed25519_public_key_bytes> public_bytes {};

            OpenSslEd25519Signer(const HMODULE library_handle, evp_pkey_st *private_key, const FreeKey release_key,
                                 const NewDigestContext allocate_context, const FreeDigestContext release_context,
                                 const DigestSignInit initialize_signing, const DigestSign sign,
                                 const std::array<std::byte, ed25519_public_key_bytes> public_key_bytes):
                library(library_handle),
                key(private_key),
                free_key(release_key),
                new_context(allocate_context),
                free_context(release_context),
                sign_init(initialize_signing),
                sign_message(sign),
                public_bytes(public_key_bytes) {}

            ~OpenSslEd25519Signer() override {
                if (key != nullptr) {
                    free_key(key);
                }
                if (library != nullptr) {
                    FreeLibrary(library);
                }
            }

            OpenSslEd25519Signer(const OpenSslEd25519Signer &) = delete;
            OpenSslEd25519Signer &operator=(const OpenSslEd25519Signer &) = delete;

            [[nodiscard]] std::array<std::byte, ed25519_public_key_bytes> public_key() const noexcept override {
                return public_bytes;
            }

            [[nodiscard]] std::expected<std::array<std::byte, ed25519_signature_bytes>, PackagingError>
            sign(const std::span<const std::byte> message) override {
                DigestContext context {new_context(), free_context};
                if (context.value == nullptr) {
                    return std::unexpected(signing_error(PackagingErrorCode::signing_failed,
                                                         "OpenSSL 3 could not allocate an Ed25519 signing context"));
                }
                if (sign_init(context.value, nullptr, nullptr, nullptr, key) != 1) {
                    return std::unexpected(signing_error(PackagingErrorCode::signing_failed,
                                                         "OpenSSL 3 could not initialize Ed25519 signing"));
                }
                std::array<std::byte, ed25519_signature_bytes> signature {};
                std::size_t signature_size = signature.size();
                if (sign_message(context.value, reinterpret_cast<unsigned char *>(signature.data()), &signature_size,
                                 reinterpret_cast<const unsigned char *>(message.data()), message.size()) != 1 ||
                    signature_size != signature.size()) {
                    return std::unexpected(signing_error(PackagingErrorCode::signing_failed,
                                                         "OpenSSL 3 failed to produce an Ed25519 signature"));
                }
                return signature;
            }
        };
#endif

        std::vector<std::byte> as_vector(const std::span<const std::byte> bytes) {
            return {bytes.begin(), bytes.end()};
        }

    } // namespace

    std::expected<std::unique_ptr<Ed25519Signer>, PackagingError>
    OpenSsl3FileEd25519KeyProvider::open_ed25519(const std::string_view reference) {
#ifndef _WIN32
        static_cast<void>(reference);
        return std::unexpected(signing_error(PackagingErrorCode::crypto_backend_unavailable,
                                             "OpenSSL 3 file signing is currently implemented for Windows"));
#else
        const auto path = parse_file_reference(reference);
        if (!path) {
            return std::unexpected(path.error());
        }
        UniqueHandle file {CreateFileW(path->c_str(), GENERIC_READ | READ_CONTROL, 0U, nullptr, OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
                                       nullptr)};
        if (file.value == INVALID_HANDLE_VALUE) {
            return std::unexpected(signing_error(PackagingErrorCode::signing_key_unavailable,
                                                 "cannot open the referenced Ed25519 seed file"));
        }
        const auto local_file = validate_local_file_handle(file.value);
        if (!local_file) {
            return std::unexpected(local_file.error());
        }
        const auto private_acl = validate_private_acl(file.value);
        if (!private_acl) {
            return std::unexpected(private_acl.error());
        }

        if (crypto_library.empty() || !is_normalized_local_drive_path(crypto_library)) {
            return std::unexpected(signing_error(PackagingErrorCode::crypto_backend_unavailable,
                                                 "OpenSSL 3 must be loaded from an explicit normalized local path"));
        }
        CryptoLibrary library {LoadLibraryExW(crypto_library.c_str(), nullptr,
                                              LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)};
        if (library.value == nullptr) {
            return std::unexpected(signing_error(PackagingErrorCode::crypto_backend_unavailable,
                                                 "cannot load the explicitly selected OpenSSL 3 provider"));
        }

        const auto version_major = load_function<OpenSslVersionMajor>(library.value, "OPENSSL_version_major");
        const auto new_key = load_function<NewRawPrivateKey>(library.value, "EVP_PKEY_new_raw_private_key_ex");
        const auto get_public_key = load_function<GetRawPublicKey>(library.value, "EVP_PKEY_get_raw_public_key");
        const auto free_key = load_function<FreeKey>(library.value, "EVP_PKEY_free");
        const auto new_context = load_function<NewDigestContext>(library.value, "EVP_MD_CTX_new");
        const auto free_context = load_function<FreeDigestContext>(library.value, "EVP_MD_CTX_free");
        const auto sign_init = load_function<DigestSignInit>(library.value, "EVP_DigestSignInit");
        const auto sign_message = load_function<DigestSign>(library.value, "EVP_DigestSign");
        if (!version_major || !new_key || !get_public_key || !free_key || !new_context || !free_context || !sign_init ||
            !sign_message) {
            const auto failure = !version_major  ? version_major.error() :
                                 !new_key        ? new_key.error() :
                                 !get_public_key ? get_public_key.error() :
                                 !free_key       ? free_key.error() :
                                 !new_context    ? new_context.error() :
                                 !free_context   ? free_context.error() :
                                 !sign_init      ? sign_init.error() :
                                                   sign_message.error();
            return std::unexpected(failure);
        }
        if ((*version_major)() != 3U) {
            return std::unexpected(signing_error(PackagingErrorCode::crypto_backend_unavailable,
                                                 "selected crypto provider is not OpenSSL 3"));
        }

        SecretSeed seed;
        DWORD bytes_read {};
        if (ReadFile(file.value, seed.bytes.data(), static_cast<DWORD>(seed.bytes.size()), &bytes_read, nullptr) == 0 ||
            bytes_read != static_cast<DWORD>(seed.bytes.size())) {
            return std::unexpected(signing_error(PackagingErrorCode::signing_key_unavailable,
                                                 "cannot read the complete Ed25519 seed file"));
        }
        UniqueKey private_key {(*new_key)(nullptr, "ED25519", nullptr,
                                          reinterpret_cast<const unsigned char *>(seed.bytes.data()),
                                          seed.bytes.size()),
                               *free_key};
        if (private_key.value == nullptr) {
            return std::unexpected(
                signing_error(PackagingErrorCode::signing_key_unavailable, "OpenSSL 3 rejected the Ed25519 seed"));
        }
        std::array<std::byte, ed25519_public_key_bytes> public_key {};
        std::size_t public_key_size = public_key.size();
        if ((*get_public_key)(private_key.value, reinterpret_cast<unsigned char *>(public_key.data()),
                              &public_key_size) != 1 ||
            public_key_size != public_key.size()) {
            return std::unexpected(signing_error(PackagingErrorCode::signing_key_unavailable,
                                                 "OpenSSL 3 could not derive the Ed25519 public key"));
        }

        auto signer = std::unique_ptr<Ed25519Signer> {
            new OpenSslEd25519Signer {library.release(), private_key.release(), *free_key, *new_context, *free_context,
                                      *sign_init, *sign_message, public_key}};
        return signer;
#endif
    }

    std::expected<SourcePackArchive, PackagingError>
    sign_canonical_source_pack(const SourcePackArchive &unsigned_archive, const SourcePackSigningRequest &request,
                               SigningKeyProvider &key_provider, const SourcePackLimits &limits) {
        const auto message = canonical_source_pack_signature_message(unsigned_archive, limits);
        if (!message) {
            return std::unexpected(message.error());
        }
        auto signer = key_provider.open_ed25519(request.signer_reference);
        if (!signer) {
            return std::unexpected(signer.error());
        }
        if (*signer == nullptr) {
            return std::unexpected(signing_error(PackagingErrorCode::signing_key_unavailable,
                                                 "signing-key provider returned no Ed25519 signer"));
        }
        const auto public_key = (*signer)->public_key();
        const auto key_id = "sha256:" + sha256_hex(public_key);
        if (request.requested_key_id && *request.requested_key_id != key_id) {
            return std::unexpected(signing_error(PackagingErrorCode::signing_key_mismatch,
                                                 "requested signer key ID does not match the derived public key"));
        }
        const auto signature = (*signer)->sign(*message);
        if (!signature) {
            return std::unexpected(signature.error());
        }

        const SignatureEnvelope envelope {
            .version = 1,
            .algorithm = "Ed25519",
            .key_id = key_id,
            .signature = as_vector(*signature),
        };
        const auto envelope_text = canonical_signature_envelope(envelope);
        SourcePackArchive signed_archive = unsigned_archive;
        signed_archive.entries.push_back(ArchiveEntry {
            .path = "META-INF/signature.json",
            .bytes = as_vector(std::as_bytes(std::span {envelope_text})),
        });
        std::ranges::sort(signed_archive.entries, {}, &ArchiveEntry::path);
        const auto canonical_archive = encode_canonical_source_pack(signed_archive, limits);
        if (!canonical_archive) {
            return std::unexpected(canonical_archive.error());
        }
        return signed_archive;
    }

} // namespace rule_engine::python::packaging
