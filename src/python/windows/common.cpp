#include "rule_engine/python/windows/provider.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <set>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>

namespace rule_engine::python::windows {
    namespace {

        struct FactDescriptorSpec {
            std::string_view subject_schema;
            std::string_view route;
            std::string_view value_schema;
        };

        struct ValueSchemaSpec {
            std::string_view schema;
            std::string_view canonical_descriptor;
        };

        constexpr std::array value_schema_specs {
            ValueSchemaSpec {process_parent_value_schema,
                             "windows.process-parent-value.v1|1:int|required|2:optional-int|required"},
            ValueSchemaSpec {process_user_value_schema,
                             "windows.process-user-value.v1|1:text|required|2:text|required"},
            ValueSchemaSpec {process_token_value_schema,
                             "windows.process-token-value.v1|1:bool|required|2:text|required|3:text|required"},
            ValueSchemaSpec {
                process_memory_value_schema,
                "windows.process-memory-value.v1|1:int|required|2:int|required|3:int|required|4:int|required"},
            ValueSchemaSpec {signer_value_schema,
                             "windows.signer-value.v1|1:text|required|2:bool|required|3:bool|required|4:int|required|"
                             "5:optional-text|required|6:optional-text|required|7:optional-bytes|required|"
                             "8:optional-bytes|required"},
            ValueSchemaSpec {pe_value_schema,
                             "windows.pe-value.v1|1:bool|required|2-9:optional-int|required|10-16:list|required|"
                             "17:int|required|18:int|required"},
        };

        constexpr std::array fact_descriptor_specs {
            FactDescriptorSpec {process_schema, "process.pid", "int"},
            FactDescriptorSpec {process_schema, "process.creation_time", "int"},
            FactDescriptorSpec {process_schema, "process.name", "text"},
            FactDescriptorSpec {process_schema, "process.thread_count", "int"},
            FactDescriptorSpec {process_schema, "process.handles.count", "int"},
            FactDescriptorSpec {process_schema, "process.session_id", "int"},
            FactDescriptorSpec {process_schema, "process.parent", process_parent_value_schema},
            FactDescriptorSpec {process_schema, "process.parent.pid", "int"},
            FactDescriptorSpec {process_schema, "process.path", "text"},
            FactDescriptorSpec {process_schema, "process.image.path", "text"},
            FactDescriptorSpec {process_schema, "process.architecture", "text"},
            FactDescriptorSpec {process_schema, "process.command_line", "text"},
            FactDescriptorSpec {process_schema, "process.user", process_user_value_schema},
            FactDescriptorSpec {process_schema, "process.user.sid", "text"},
            FactDescriptorSpec {process_schema, "process.user.name", "text"},
            FactDescriptorSpec {process_schema, "process.token", process_token_value_schema},
            FactDescriptorSpec {process_schema, "process.token.elevated", "bool"},
            FactDescriptorSpec {process_schema, "process.token.type", "text"},
            FactDescriptorSpec {process_schema, "process.integrity_level", "text"},
            FactDescriptorSpec {process_schema, "process.modules", "list"},
            FactDescriptorSpec {process_schema, "process.modules.count", "int"},
            FactDescriptorSpec {process_schema, "process.modules.names", "list"},
            FactDescriptorSpec {process_schema, "process.memory.summary", process_memory_value_schema},
            FactDescriptorSpec {process_schema, "process.memory.regions.count", "int"},
            FactDescriptorSpec {process_schema, "process.memory.regions.readable_count", "int"},
            FactDescriptorSpec {process_schema, "process.memory.regions", "list"},
            FactDescriptorSpec {process_schema, "process.signer", signer_value_schema},
            FactDescriptorSpec {process_schema, "process.signer.status", "text"},
            FactDescriptorSpec {process_schema, "process.signer.is_signed", "bool"},
            FactDescriptorSpec {process_schema, "process.pe", pe_value_schema},
            FactDescriptorSpec {image_schema, "image.signer", signer_value_schema},
            FactDescriptorSpec {image_schema, "image.path", "text"},
            FactDescriptorSpec {image_schema, "image.volume_serial", "int"},
            FactDescriptorSpec {image_schema, "image.file_id", "bytes"},
            FactDescriptorSpec {image_schema, "pe.image", pe_value_schema},
            FactDescriptorSpec {image_schema, "pe.is_valid", "bool"},
            FactDescriptorSpec {image_schema, "pe.machine", "int"},
            FactDescriptorSpec {image_schema, "pe.number_of_sections", "int"},
            FactDescriptorSpec {image_schema, "pe.entry_point", "int"},
            FactDescriptorSpec {image_schema, "pe.size_of_image", "int"},
            FactDescriptorSpec {image_schema, "pe.subsystem", "int"},
            FactDescriptorSpec {image_schema, "pe.characteristics", "int"},
            FactDescriptorSpec {image_schema, "pe.dll_characteristics", "int"},
            FactDescriptorSpec {image_schema, "pe.timestamp", "int"},
            FactDescriptorSpec {image_schema, "pe.sections", "list"},
            FactDescriptorSpec {image_schema, "pe.imports", "list"},
            FactDescriptorSpec {image_schema, "pe.exports", "list"},
            FactDescriptorSpec {image_schema, "pe.debug_entries", "list"},
            FactDescriptorSpec {image_schema, "pe.resources", "list"},
            FactDescriptorSpec {image_schema, "pe.certificates", "list"},
            FactDescriptorSpec {image_schema, "pe.tls_callbacks", "list"},
            FactDescriptorSpec {image_schema, "image.size", "int"},
            FactDescriptorSpec {image_schema, "image.last_write_time", "int"},
        };

        [[nodiscard]] SchemaIdentity provider_schema_identity(const std::string_view schema) {
            SchemaId id {std::string {schema}};
            if (auto builtin = resolve_schema_identity(SchemaCatalog {}, id); builtin.has_value()) {
                return std::move(*builtin);
            }
            const auto descriptor = std::ranges::find(value_schema_specs, schema, &ValueSchemaSpec::schema);
            const auto canonical = descriptor == value_schema_specs.end() ? schema : descriptor->canonical_descriptor;
            return SchemaIdentity {
                .id = std::move(id),
                .canonical_hash =
                    canonical_schema_hash("rule-engine.windows.fact-value-schema.v1|" + std::string {canonical}),
            };
        }

        struct UniqueHandle {
            HANDLE value {INVALID_HANDLE_VALUE};

            explicit UniqueHandle(const HANDLE handle) noexcept: value {handle} {}
            ~UniqueHandle() noexcept {
                if (value != nullptr && value != INVALID_HANDLE_VALUE) {
                    CloseHandle(value);
                }
            }
            UniqueHandle(const UniqueHandle &) = delete;
            UniqueHandle &operator=(const UniqueHandle &) = delete;
            UniqueHandle(UniqueHandle &&) = delete;
            UniqueHandle &operator=(UniqueHandle &&) = delete;
        };

        struct AlgorithmHandle {
            BCRYPT_ALG_HANDLE value {};
            AlgorithmHandle() noexcept = default;
            ~AlgorithmHandle() noexcept {
                if (value != nullptr) {
                    BCryptCloseAlgorithmProvider(value, 0);
                }
            }
            AlgorithmHandle(const AlgorithmHandle &) = delete;
            AlgorithmHandle &operator=(const AlgorithmHandle &) = delete;
            AlgorithmHandle(AlgorithmHandle &&) = delete;
            AlgorithmHandle &operator=(AlgorithmHandle &&) = delete;
        };

        struct HashHandle {
            BCRYPT_HASH_HANDLE value {};
            HashHandle() noexcept = default;
            ~HashHandle() noexcept {
                if (value != nullptr) {
                    BCryptDestroyHash(value);
                }
            }
            HashHandle(const HashHandle &) = delete;
            HashHandle &operator=(const HashHandle &) = delete;
            HashHandle(HashHandle &&) = delete;
            HashHandle &operator=(HashHandle &&) = delete;
        };

        void append_token(std::string &output, const std::string_view token) {
            std::array<char, 32> buffer {};
            const auto [end, error] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), token.size());
            if (error != std::errc {}) {
                output.append("0:");
                return;
            }
            output.append(buffer.data(), end);
            output.push_back(':');
            output.append(token);
            output.push_back(';');
        }

        [[nodiscard]] std::string bytes_hex(const std::span<const std::byte> bytes) {
            constexpr std::string_view digits {"0123456789abcdef"};
            std::string output;
            output.reserve(bytes.size() * 2U);
            for (const auto value : bytes) {
                const auto byte = std::to_integer<unsigned int>(value);
                output.push_back(digits[(byte >> 4U) & 0x0fU]);
                output.push_back(digits[byte & 0x0fU]);
            }
            return output;
        }

        void append_fact(std::string &output, const FactValue &fact, std::unordered_set<const FactNode *> &ancestors,
                         const std::size_t depth) {
            if (!fact.valid() || depth > 64U || !ancestors.insert(fact.node.get()).second) {
                append_token(output, "invalid");
                return;
            }

            std::visit(
                [&](const auto &value) {
                    using ValueType = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::is_same_v<ValueType, std::monostate>) {
                        append_token(output, "none");
                    } else if constexpr (std::is_same_v<ValueType, bool>) {
                        append_token(output, value ? "bool:1" : "bool:0");
                    } else if constexpr (std::is_same_v<ValueType, IntegerValue>) {
                        append_token(output, "integer:" + value.decimal);
                    } else if constexpr (std::is_same_v<ValueType, double>) {
                        std::array<char, 64> buffer {};
                        const auto [end, error] =
                            std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, std::chars_format::hex);
                        append_token(output,
                                     error == std::errc {} ? std::string {buffer.data(), end} : "invalid-double");
                    } else if constexpr (std::is_same_v<ValueType, UnicodeValue>) {
                        append_token(output, "unicode:" + value.utf8);
                    } else if constexpr (std::is_same_v<ValueType, BytesValue>) {
                        append_token(output, "bytes:" + bytes_hex(value.bytes));
                    } else if constexpr (std::is_same_v<ValueType, EnumValue>) {
                        append_token(output, "enum:" + value.schema.value);
                        append_token(output, value.member);
                    } else if constexpr (std::is_same_v<ValueType, FactList>) {
                        append_token(output, "list");
                        for (const auto &item : value.items) { append_fact(output, item, ancestors, depth + 1U); }
                        append_token(output, "/list");
                    } else if constexpr (std::is_same_v<ValueType, FactMap>) {
                        append_token(output, "map");
                        for (const auto &entry : value.entries) {
                            append_fact(output, entry.key, ancestors, depth + 1U);
                            append_fact(output, entry.value, ancestors, depth + 1U);
                        }
                        append_token(output, "/map");
                    } else if constexpr (std::is_same_v<ValueType, FactRecord>) {
                        append_token(output, "record:" + value.schema.value);
                        for (const auto &field : value.fields) {
                            append_token(output, std::to_string(field.field_id));
                            append_fact(output, field.value, ancestors, depth + 1U);
                        }
                        append_token(output, "/record");
                    }
                },
                fact.node->data);
            ancestors.erase(fact.node.get());
        }

        [[nodiscard]] std::string utf8_path(const std::filesystem::path &path) {
            const auto encoded = path.generic_u8string();
            return std::string {reinterpret_cast<const char *>(encoded.data()), encoded.size()};
        }

        [[nodiscard]] std::filesystem::path final_path(const HANDLE file, const std::filesystem::path &fallback) {
            const auto required = GetFinalPathNameByHandleW(file, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if (required == 0U) {
                return fallback.lexically_normal();
            }
            std::wstring output(required, L'\0');
            const auto written =
                GetFinalPathNameByHandleW(file, output.data(), required, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if (written == 0U || written >= required) {
                return fallback.lexically_normal();
            }
            output.resize(written);
            constexpr std::wstring_view extended_prefix {LR"(\\?\)"};
            if (output.starts_with(extended_prefix)) {
                output.erase(0, extended_prefix.size());
            }
            return std::filesystem::path {output}.lexically_normal();
        }

        [[nodiscard]] bool parent_matches(const SubjectKey &subject, const std::optional<SubjectKey> &parent) {
            if (!parent.has_value()) {
                return subject.parent == nullptr;
            }
            return subject.parent != nullptr &&
                   canonical_subject_key(*subject.parent) == canonical_subject_key(*parent);
        }

        [[nodiscard]] bool eager_fields_valid(const std::vector<FactRecordField> &fields) noexcept {
            std::uint32_t prior {};
            for (const auto &field : fields) {
                if (field.field_id == 0U || field.field_id <= prior || !field.value.valid()) {
                    return false;
                }
                prior = field.field_id;
            }
            return true;
        }

        [[nodiscard]] ProviderError snapshot_error(std::string message) {
            return ProviderError {
                .code = ProviderErrorCode::malformed,
                .operation = "inventory",
                .message = std::move(message),
                .platform_code = 0,
            };
        }

    } // namespace

    std::optional<WindowsFactDescriptor> find_windows_fact_descriptor(const SchemaId &subject_schema,
                                                                      const std::string_view route) {
        const auto found = std::ranges::find_if(fact_descriptor_specs, [&](const FactDescriptorSpec &descriptor) {
            return descriptor.subject_schema == subject_schema.value && descriptor.route == route;
        });
        if (found == fact_descriptor_specs.end()) {
            return std::nullopt;
        }
        return WindowsFactDescriptor {
            .subject_schema = SchemaId {std::string {found->subject_schema}},
            .route = std::string {found->route},
            .value_schema = provider_schema_identity(found->value_schema),
        };
    }

    FactTerminalStatus terminal_status(const ProviderErrorCode code) noexcept {
        switch (code) {
            case ProviderErrorCode::not_found:
            case ProviderErrorCode::subject_changed:
            case ProviderErrorCode::unavailable: return FactTerminalStatus::unavailable;
            case ProviderErrorCode::unsupported: return FactTerminalStatus::unsupported;
            case ProviderErrorCode::access_denied: return FactTerminalStatus::denied;
            case ProviderErrorCode::timed_out: return FactTerminalStatus::timed_out;
            case ProviderErrorCode::invalid_request:
            case ProviderErrorCode::invalid_subject:
            case ProviderErrorCode::malformed:
            case ProviderErrorCode::result_limit:
            case ProviderErrorCode::arithmetic_overflow: return FactTerminalStatus::failed;
            default: return FactTerminalStatus::failed;
        }
    }

    Diagnostic provider_diagnostic(const ProviderError &error) {
        return Diagnostic {
            .code = "PYWIN-" + std::to_string(static_cast<unsigned int>(error.code)),
            .severity = DiagnosticSeverity::error,
            .message = error.operation + ": " + error.message,
            .span = std::nullopt,
            .related = {},
        };
    }

    SubjectKey process_subject(PeerId peer, const std::uint32_t pid, const std::uint64_t creation_time) {
        return SubjectKey {
            .peer = std::move(peer),
            .descriptor = SchemaId {std::string {process_schema}},
            .identity = {{.field_id = 1, .value = static_cast<std::uint64_t>(pid)},
                         {.field_id = 2, .value = creation_time}},
            .parent = {},
        };
    }

    SubjectKey memory_region_subject(const SubjectKey &process, const std::uint64_t allocation_base,
                                     const std::uint64_t base) {
        return SubjectKey {
            .peer = process.peer,
            .descriptor = SchemaId {std::string {memory_region_schema}},
            .identity = {{.field_id = 1, .value = allocation_base}, {.field_id = 2, .value = base}},
            .parent = std::make_shared<const SubjectKey>(process),
        };
    }

    std::expected<SubjectKey, ProviderError> image_subject(const SubjectKey &process,
                                                           const std::filesystem::path &path) {
        if (!process.valid() || process.descriptor.value != process_schema) {
            return std::unexpected(ProviderError {
                .code = ProviderErrorCode::invalid_subject,
                .operation = "image identity",
                .message = "image parent is not a valid Windows process subject",
                .platform_code = 0,
            });
        }

        UniqueHandle file {CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (file.value == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            return std::unexpected(ProviderError {
                .code =
                    error == ERROR_ACCESS_DENIED ? ProviderErrorCode::access_denied : ProviderErrorCode::unavailable,
                .operation = "image identity",
                .message = "CreateFileW failed",
                .platform_code = error,
            });
        }

        FILE_ID_INFO identity {};
        if (GetFileInformationByHandleEx(file.value, FileIdInfo, &identity, sizeof(identity)) == FALSE) {
            const auto error = GetLastError();
            return std::unexpected(ProviderError {
                .code =
                    error == ERROR_ACCESS_DENIED ? ProviderErrorCode::access_denied : ProviderErrorCode::unavailable,
                .operation = "image identity",
                .message = "GetFileInformationByHandleEx(FileIdInfo) failed",
                .platform_code = error,
            });
        }

        BytesValue file_id;
        file_id.bytes.reserve(sizeof(identity.FileId.Identifier));
        for (const auto byte : identity.FileId.Identifier) { file_id.bytes.push_back(static_cast<std::byte>(byte)); }

        return SubjectKey {
            .peer = process.peer,
            .descriptor = SchemaId {std::string {image_schema}},
            .identity = {{.field_id = 1, .value = UnicodeValue {utf8_path(final_path(file.value, path))}},
                         {.field_id = 2, .value = static_cast<std::uint64_t>(identity.VolumeSerialNumber)},
                         {.field_id = 3, .value = std::move(file_id)}},
            .parent = std::make_shared<const SubjectKey>(process),
        };
    }

    InventorySnapshot make_inventory_snapshot(PeerId peer, SchemaId schema, std::optional<SubjectKey> parent,
                                              const std::uint64_t generation, std::vector<SubjectObservation> items) {
        const auto invalid = [&](ProviderError error) {
            return invalid_inventory_snapshot(std::move(peer), std::move(schema), generation, std::move(error));
        };

        if (peer.empty() || schema.empty() || generation == 0U) {
            return invalid(snapshot_error("peer, schema, and nonzero generation are required"));
        }
        if (parent.has_value() && (!parent->valid() || parent->peer != peer)) {
            return invalid(snapshot_error("snapshot parent is invalid or belongs to another peer"));
        }

        std::set<std::string> canonical_keys;
        std::vector<std::pair<std::string, std::string>> canonical_items;
        canonical_items.reserve(items.size());
        for (const auto &item : items) {
            if (!item.subject.valid() || item.subject.peer != peer || item.subject.descriptor != schema ||
                !parent_matches(item.subject, parent) || !eager_fields_valid(item.eager_fields)) {
                return invalid(snapshot_error("snapshot contains an invalid subject, parent, schema, or eager field"));
            }
            auto key = canonical_subject_key(item.subject);
            if (key.empty() || !canonical_keys.insert(key).second) {
                return invalid(snapshot_error("snapshot contains a duplicate canonical subject identity"));
            }

            FactValue eager = make_fact(FactRecord {.schema = schema, .fields = item.eager_fields});
            canonical_items.emplace_back(std::move(key), canonical_provider_value(eager));
        }

        std::ranges::sort(canonical_items, {}, &std::pair<std::string, std::string>::first);
        std::string canonical;
        append_token(canonical, "windows-inventory-v1");
        append_token(canonical, peer.value);
        append_token(canonical, schema.value);
        append_token(canonical, std::to_string(generation));
        if (parent.has_value()) {
            append_token(canonical, canonical_subject_key(*parent));
        } else {
            append_token(canonical, "root");
        }
        for (const auto &[key, eager] : canonical_items) {
            append_token(canonical, key);
            append_token(canonical, eager);
        }

        const auto bytes = std::as_bytes(std::span {canonical});
        const auto digest = sha256_digest(bytes);
        if (digest.empty()) {
            return invalid(snapshot_error("failed to calculate the snapshot digest"));
        }

        return InventorySnapshot {
            .begin = SnapshotBegin {.peer = peer, .subject_schema = schema, .generation = generation},
            .items = std::move(items),
            .commit = SnapshotCommit {.peer = peer,
                                      .subject_schema = schema,
                                      .generation = generation,
                                      .item_count = canonical_items.size(),
                                      .canonical_digest = digest},
            .status = FactTerminalStatus::value,
            .authoritative = true,
            .diagnostic = std::nullopt,
        };
    }

    InventorySnapshot invalid_inventory_snapshot(PeerId peer, SchemaId schema, const std::uint64_t generation,
                                                 ProviderError error) {
        return InventorySnapshot {
            .begin = SnapshotBegin {.peer = peer, .subject_schema = schema, .generation = generation},
            .items = {},
            .commit = SnapshotCommit {.peer = std::move(peer),
                                      .subject_schema = std::move(schema),
                                      .generation = generation,
                                      .item_count = 0,
                                      .canonical_digest = {}},
            .status = terminal_status(error.code),
            .authoritative = false,
            .diagnostic = provider_diagnostic(error),
        };
    }

    std::string canonical_provider_value(const FactValue &value) {
        std::string output;
        std::unordered_set<const FactNode *> ancestors;
        append_fact(output, value, ancestors, 0U);
        return output;
    }

    std::string sha256_digest(const std::span<const std::byte> bytes) {
        AlgorithmHandle algorithm;
        if (BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
            return {};
        }

        DWORD object_size {};
        DWORD received {};
        if (BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
                              sizeof(object_size), &received, 0) < 0 ||
            received != sizeof(object_size)) {
            return {};
        }

        std::vector<unsigned char> object(object_size);
        HashHandle hash;
        if (BCryptCreateHash(algorithm.value, &hash.value, object.data(), object_size, nullptr, 0, 0) < 0) {
            return {};
        }

        constexpr auto maximum_chunk = static_cast<std::size_t>((std::numeric_limits<ULONG>::max)());
        std::size_t position {};
        while (position < bytes.size()) {
            const auto count = std::min(maximum_chunk, bytes.size() - position);
            if (BCryptHashData(hash.value, reinterpret_cast<PUCHAR>(const_cast<std::byte *>(bytes.data() + position)),
                               static_cast<ULONG>(count), 0) < 0) {
                return {};
            }
            position += count;
        }

        std::array<unsigned char, 32> digest {};
        if (BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
            return {};
        }
        return "sha256:" + bytes_hex(std::as_bytes(std::span {digest}));
    }

    FrozenValue freeze_provider_value(FactValue value, DataLabel label) {
        const auto canonical = canonical_provider_value(value);
        const auto digest = sha256_digest(std::as_bytes(std::span {canonical}));
        return FrozenValue {.value = std::move(value), .label = std::move(label), .canonical_digest = digest};
    }

    std::uint64_t unix_time_ms() noexcept {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
    }

} // namespace rule_engine::python::windows
