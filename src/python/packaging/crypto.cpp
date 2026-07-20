#include "rule_engine/python/packaging/source_pack.hpp"

#include <bit>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#endif

namespace rule_engine::python::packaging {
    namespace {

        PackagingError crypto_error(std::string message, std::optional<std::string> subject = std::nullopt) {
            return PackagingError {
                .code = PackagingErrorCode::crypto_backend_unavailable,
                .message = std::move(message),
                .subject = std::move(subject),
            };
        }

#ifdef _WIN32
        struct evp_pkey_st;
        struct evp_pkey_ctx_st;
        struct evp_md_ctx_st;
        struct evp_md_st;
        struct engine_st;
        struct ossl_lib_ctx_st;

        using NewRawPublicKey = evp_pkey_st *(__cdecl *) (ossl_lib_ctx_st *, const char *, const char *,
                                                          const unsigned char *, std::size_t);
        using FreePublicKey = void(__cdecl *)(evp_pkey_st *);
        using NewDigestContext = evp_md_ctx_st *(__cdecl *) ();
        using FreeDigestContext = void(__cdecl *)(evp_md_ctx_st *);
        using DigestVerifyInit = int(__cdecl *)(evp_md_ctx_st *, evp_pkey_ctx_st **, const evp_md_st *, engine_st *,
                                                evp_pkey_st *);
        using DigestVerify = int(__cdecl *)(evp_md_ctx_st *, const unsigned char *, std::size_t, const unsigned char *,
                                            std::size_t);

        struct CryptoLibrary {
            HMODULE handle {};

            explicit CryptoLibrary(const HMODULE library): handle(library) {}

            ~CryptoLibrary() {
                if (handle != nullptr) {
                    FreeLibrary(handle);
                }
            }

            CryptoLibrary(const CryptoLibrary &) = delete;
            CryptoLibrary &operator=(const CryptoLibrary &) = delete;
            CryptoLibrary(CryptoLibrary &&) = delete;
            CryptoLibrary &operator=(CryptoLibrary &&) = delete;
        };

        template<typename Function>
        std::expected<Function, PackagingError> load_function(const HMODULE library, const char *name) {
            const auto procedure = GetProcAddress(library, name);
            if (procedure == nullptr) {
                return std::unexpected(crypto_error("OpenSSL 3 provider is missing a required Ed25519 function", name));
            }
            return std::bit_cast<Function>(procedure);
        }

        struct PublicKey {
            evp_pkey_st *value {};
            FreePublicKey free {};

            PublicKey(evp_pkey_st *key, const FreePublicKey release): value(key), free(release) {}

            ~PublicKey() {
                if (value != nullptr) {
                    free(value);
                }
            }

            PublicKey(const PublicKey &) = delete;
            PublicKey &operator=(const PublicKey &) = delete;
            PublicKey(PublicKey &&) = delete;
            PublicKey &operator=(PublicKey &&) = delete;
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
            DigestContext(DigestContext &&) = delete;
            DigestContext &operator=(DigestContext &&) = delete;
        };
#endif

    } // namespace

    std::expected<bool, PackagingError>
    OpenSsl3Ed25519Verifier::verify_ed25519(const std::span<const std::byte> public_key,
                                            const std::span<const std::byte> message,
                                            const std::span<const std::byte> signature) const {
        if (public_key.size() != 32U || signature.size() != 64U) {
            return false;
        }
#ifndef _WIN32
        return std::unexpected(crypto_error("the OpenSSL 3 Ed25519 backend is currently implemented for Windows"));
#else
        if (crypto_library.empty() || !crypto_library.is_absolute()) {
            return std::unexpected(
                crypto_error("OpenSSL 3 must be loaded from an explicit absolute path", crypto_library.string()));
        }
        CryptoLibrary library {LoadLibraryExW(crypto_library.c_str(), nullptr,
                                              LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)};
        if (library.handle == nullptr) {
            return std::unexpected(
                crypto_error("cannot load the explicitly selected OpenSSL 3 provider", crypto_library.string()));
        }

        const auto new_key = load_function<NewRawPublicKey>(library.handle, "EVP_PKEY_new_raw_public_key_ex");
        const auto free_key = load_function<FreePublicKey>(library.handle, "EVP_PKEY_free");
        const auto new_context = load_function<NewDigestContext>(library.handle, "EVP_MD_CTX_new");
        const auto free_context = load_function<FreeDigestContext>(library.handle, "EVP_MD_CTX_free");
        const auto verify_init = load_function<DigestVerifyInit>(library.handle, "EVP_DigestVerifyInit");
        const auto verify = load_function<DigestVerify>(library.handle, "EVP_DigestVerify");
        if (!new_key || !free_key || !new_context || !free_context || !verify_init || !verify) {
            if (!new_key) {
                return std::unexpected(new_key.error());
            }
            if (!free_key) {
                return std::unexpected(free_key.error());
            }
            if (!new_context) {
                return std::unexpected(new_context.error());
            }
            if (!free_context) {
                return std::unexpected(free_context.error());
            }
            if (!verify_init) {
                return std::unexpected(verify_init.error());
            }
            return std::unexpected(verify.error());
        }

        PublicKey key {(*new_key)(nullptr, "ED25519", nullptr,
                                  reinterpret_cast<const unsigned char *>(public_key.data()), public_key.size()),
                       *free_key};
        if (key.value == nullptr) {
            return std::unexpected(crypto_error("OpenSSL 3 rejected the raw Ed25519 public key"));
        }
        DigestContext context {(*new_context)(), *free_context};
        if (context.value == nullptr) {
            return std::unexpected(crypto_error("OpenSSL 3 could not allocate an Ed25519 verification context"));
        }
        if ((*verify_init)(context.value, nullptr, nullptr, nullptr, key.value) != 1) {
            return std::unexpected(crypto_error("OpenSSL 3 could not initialize Ed25519 verification"));
        }
        const auto result =
            (*verify)(context.value, reinterpret_cast<const unsigned char *>(signature.data()), signature.size(),
                      reinterpret_cast<const unsigned char *>(message.data()), message.size());
        if (result < 0) {
            return std::unexpected(crypto_error("OpenSSL 3 failed while verifying an Ed25519 signature"));
        }
        return result == 1;
#endif
    }

} // namespace rule_engine::python::packaging
