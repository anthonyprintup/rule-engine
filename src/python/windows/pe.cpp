#include "rule_engine/python/windows/provider.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <WinTrust.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::windows {
    namespace {

        constexpr std::uint64_t maximum_image_bytes = 256U * 1024U * 1024U;
        constexpr std::size_t maximum_sections = 4'096U;
        constexpr std::size_t maximum_imports = 100'000U;
        constexpr std::size_t maximum_exports = 100'000U;
        constexpr std::size_t maximum_debug_entries = 4'096U;
        constexpr std::size_t maximum_resources = 100'000U;
        constexpr std::size_t maximum_certificates = 4'096U;
        constexpr std::size_t maximum_tls_callbacks = 4'096U;
        constexpr std::size_t maximum_c_string_bytes = 1U * 1024U * 1024U;
        constexpr std::uint32_t resource_name_is_string = 0x80000000U;
        constexpr std::uint32_t resource_offset_mask = 0x7fffffffU;
        constexpr std::uint32_t resource_data_is_directory = 0x80000000U;

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

        struct ImageBytes {
            std::vector<std::byte> bytes;
            std::uint64_t size {};
            std::uint64_t last_write_time {};
        };

        struct SectionEntry {
            IMAGE_SECTION_HEADER header {};
            std::string name;
        };

        struct ParsedImage {
            bool pe64 {};
            IMAGE_FILE_HEADER file_header {};
            std::uint64_t image_base {};
            std::uint32_t entry_point {};
            std::uint32_t size_of_image {};
            std::uint16_t subsystem {};
            std::uint16_t dll_characteristics {};
            std::array<IMAGE_DATA_DIRECTORY, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> directories {};
            std::vector<SectionEntry> sections;
        };

        struct NestedCollection {
            std::vector<SubjectObservation> observations;
            std::vector<FactValue> values;
        };

        struct ResourceTag {
            std::string canonical;
            FactValue value;
        };

        [[nodiscard]] ProviderError failure(ProviderErrorCode code, std::string operation, std::string message,
                                            const DWORD platform_code = 0U) {
            return ProviderError {.code = code,
                                  .operation = std::move(operation),
                                  .message = std::move(message),
                                  .platform_code = platform_code};
        }

        [[nodiscard]] ProviderError last_error(std::string operation, std::string message) {
            const auto code = GetLastError();
            return failure(code == ERROR_ACCESS_DENIED ? ProviderErrorCode::access_denied :
                                                         ProviderErrorCode::unavailable,
                           std::move(operation), std::move(message), code);
        }

        [[nodiscard]] bool expired(const std::uint64_t deadline) noexcept {
            return deadline != 0U && unix_time_ms() >= deadline;
        }

        [[nodiscard]] FactValue integer(const std::uint64_t value) {
            return make_fact(IntegerValue {.decimal = std::to_string(value)});
        }

        [[nodiscard]] FactValue text(std::string value) { return make_fact(UnicodeValue {.utf8 = std::move(value)}); }

        [[nodiscard]] FactValue list(std::vector<FactValue> values) {
            return make_fact(FactList {.items = std::move(values)});
        }

        [[nodiscard]] FactValue record(const std::string_view schema, std::vector<FactRecordField> fields) {
            return make_fact(FactRecord {.schema = SchemaId {std::string {schema}}, .fields = std::move(fields)});
        }

        [[nodiscard]] DataLabel image_label() {
            return DataLabel {.classification = Classification::sensitive, .categories = {"windows.image"}};
        }

        template<typename T>
        [[nodiscard]] std::optional<T> read_value(const std::span<const std::byte> bytes, const std::size_t offset) {
            if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
                return std::nullopt;
            }
            T output {};
            std::memcpy(&output, bytes.data() + offset, sizeof(output));
            return output;
        }

        [[nodiscard]] std::optional<std::span<const std::byte>>
        read_span(const std::span<const std::byte> bytes, const std::size_t offset, const std::size_t size) {
            if (offset > bytes.size() || size > bytes.size() - offset) {
                return std::nullopt;
            }
            return bytes.subspan(offset, size);
        }

        [[nodiscard]] std::expected<ImageBytes, ProviderError> read_image_bytes(const std::filesystem::path &path,
                                                                                const std::uint64_t deadline) {
            if (expired(deadline)) {
                return std::unexpected(
                    failure(ProviderErrorCode::timed_out, "PE image read", "provider deadline expired"));
            }
            UniqueHandle file {CreateFileW(path.c_str(), GENERIC_READ,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
            if (file.value == INVALID_HANDLE_VALUE) {
                return std::unexpected(last_error("PE image read", "CreateFileW failed"));
            }
            LARGE_INTEGER size {};
            if (GetFileSizeEx(file.value, &size) == FALSE) {
                return std::unexpected(last_error("PE image read", "GetFileSizeEx failed"));
            }
            if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > maximum_image_bytes) {
                return std::unexpected(
                    failure(ProviderErrorCode::result_limit, "PE image read", "image size exceeds the provider limit"));
            }
            FILE_BASIC_INFO basic {};
            if (GetFileInformationByHandleEx(file.value, FileBasicInfo, &basic, sizeof(basic)) == FALSE) {
                return std::unexpected(last_error("PE image read", "failed to query file timestamps"));
            }

            ImageBytes output;
            output.size = static_cast<std::uint64_t>(size.QuadPart);
            output.last_write_time = static_cast<std::uint64_t>(basic.LastWriteTime.QuadPart);
            output.bytes.resize(static_cast<std::size_t>(size.QuadPart));
            std::size_t position {};
            while (position < output.bytes.size()) {
                if (expired(deadline)) {
                    return std::unexpected(failure(ProviderErrorCode::timed_out, "PE image read",
                                                   "provider deadline expired while reading the image"));
                }
                const auto count = std::min<std::size_t>(output.bytes.size() - position, 1U * 1024U * 1024U);
                DWORD received {};
                if (ReadFile(file.value, output.bytes.data() + position, static_cast<DWORD>(count), &received,
                             nullptr) == FALSE) {
                    return std::unexpected(last_error("PE image read", "ReadFile failed"));
                }
                if (received == 0U || received > count) {
                    return std::unexpected(failure(ProviderErrorCode::unavailable, "PE image read",
                                                   "image changed or became truncated during the read"));
                }
                position += received;
            }
            return output;
        }

        [[nodiscard]] std::string section_name(const IMAGE_SECTION_HEADER &section) {
            const auto *begin = reinterpret_cast<const char *>(section.Name);
            const auto *end = std::find(begin, begin + IMAGE_SIZEOF_SHORT_NAME, '\0');
            return std::string {begin, end};
        }

        [[nodiscard]] std::expected<ParsedImage, ProviderError> parse_headers(const std::span<const std::byte> bytes) {
            const auto dos = read_value<IMAGE_DOS_HEADER>(bytes, 0U);
            if (!dos.has_value() || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE parse", "image has no valid DOS header"));
            }
            const auto nt_offset = static_cast<std::size_t>(dos->e_lfanew);
            const auto signature = read_value<DWORD>(bytes, nt_offset);
            if (!signature.has_value() || *signature != IMAGE_NT_SIGNATURE) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE parse", "image has no valid PE signature"));
            }
            if (nt_offset > (std::numeric_limits<std::size_t>::max)() - sizeof(DWORD)) {
                return std::unexpected(
                    failure(ProviderErrorCode::arithmetic_overflow, "PE parse", "PE header offset overflowed"));
            }
            const auto file_offset = nt_offset + sizeof(DWORD);
            const auto file_header = read_value<IMAGE_FILE_HEADER>(bytes, file_offset);
            if (!file_header.has_value() || file_header->NumberOfSections > maximum_sections) {
                return std::unexpected(failure(ProviderErrorCode::malformed, "PE parse",
                                               "PE file header is missing or has too many sections"));
            }
            const auto optional_offset = file_offset + sizeof(IMAGE_FILE_HEADER);
            const auto magic = read_value<WORD>(bytes, optional_offset);
            if (!magic.has_value()) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE parse", "PE optional header is missing"));
            }

            ParsedImage image;
            image.file_header = *file_header;
            std::size_t section_offset {};
            if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                const auto optional = read_value<IMAGE_OPTIONAL_HEADER64>(bytes, optional_offset);
                if (!optional.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE parse", "PE32+ optional header is truncated"));
                }
                image.pe64 = true;
                image.image_base = optional->ImageBase;
                image.entry_point = optional->AddressOfEntryPoint;
                image.size_of_image = optional->SizeOfImage;
                image.subsystem = optional->Subsystem;
                image.dll_characteristics = optional->DllCharacteristics;
                std::copy_n(optional->DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES, image.directories.begin());
                section_offset = optional_offset + file_header->SizeOfOptionalHeader;
            } else if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                const auto optional = read_value<IMAGE_OPTIONAL_HEADER32>(bytes, optional_offset);
                if (!optional.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE parse", "PE32 optional header is truncated"));
                }
                image.pe64 = false;
                image.image_base = optional->ImageBase;
                image.entry_point = optional->AddressOfEntryPoint;
                image.size_of_image = optional->SizeOfImage;
                image.subsystem = optional->Subsystem;
                image.dll_characteristics = optional->DllCharacteristics;
                std::copy_n(optional->DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES, image.directories.begin());
                section_offset = optional_offset + file_header->SizeOfOptionalHeader;
            } else {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE parse", "PE optional header kind is unsupported"));
            }

            image.sections.reserve(file_header->NumberOfSections);
            for (std::size_t index = 0; index < file_header->NumberOfSections; ++index) {
                if (index >
                    ((std::numeric_limits<std::size_t>::max)() - section_offset) / sizeof(IMAGE_SECTION_HEADER)) {
                    return std::unexpected(
                        failure(ProviderErrorCode::arithmetic_overflow, "PE parse", "section table offset overflowed"));
                }
                const auto section =
                    read_value<IMAGE_SECTION_HEADER>(bytes, section_offset + index * sizeof(IMAGE_SECTION_HEADER));
                if (!section.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE parse", "section table is truncated"));
                }
                image.sections.push_back(SectionEntry {.header = *section, .name = section_name(*section)});
            }
            return image;
        }

        [[nodiscard]] std::optional<std::size_t> rva_to_offset(const std::span<const std::byte> bytes,
                                                               const std::span<const SectionEntry> sections,
                                                               const std::uint32_t rva,
                                                               const std::size_t requested = 1U) {
            for (const auto &section : sections) {
                const auto begin = static_cast<std::uint64_t>(section.header.VirtualAddress);
                const auto virtual_size = std::max(section.header.Misc.VirtualSize, section.header.SizeOfRawData);
                const auto end = begin + virtual_size;
                if (rva < begin || static_cast<std::uint64_t>(rva) >= end) {
                    continue;
                }
                const auto delta = static_cast<std::uint64_t>(rva) - begin;
                if (delta > section.header.SizeOfRawData) {
                    return std::nullopt;
                }
                const auto offset = static_cast<std::uint64_t>(section.header.PointerToRawData) + delta;
                if (offset > bytes.size() || requested > bytes.size() - static_cast<std::size_t>(offset)) {
                    return std::nullopt;
                }
                return static_cast<std::size_t>(offset);
            }
            if (rva <= bytes.size() && requested <= bytes.size() - rva) {
                return static_cast<std::size_t>(rva);
            }
            return std::nullopt;
        }

        [[nodiscard]] std::expected<std::string, ProviderError> read_c_string(const std::span<const std::byte> bytes,
                                                                              const std::size_t offset) {
            if (offset >= bytes.size()) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE parse", "string offset is outside the image"));
            }
            const auto available = std::min(maximum_c_string_bytes, bytes.size() - offset);
            const auto *begin = reinterpret_cast<const char *>(bytes.data() + offset);
            const auto *end = std::find(begin, begin + available, '\0');
            if (end == begin + available) {
                return std::unexpected(failure(ProviderErrorCode::malformed, "PE parse",
                                               "image string is unterminated or exceeds its limit"));
            }
            return std::string {begin, end};
        }

        [[nodiscard]] std::string normalized_dll(std::string value) {
            std::ranges::transform(value, value.begin(), [](const char character) {
                const auto byte = static_cast<unsigned char>(character);
                return byte < 0x80U ? static_cast<char>(std::tolower(byte)) : character;
            });
            return value;
        }

        [[nodiscard]] SubjectKey nested_subject(const SubjectKey &parent, const std::string_view schema,
                                                std::vector<IdentityField> identity) {
            return SubjectKey {.peer = parent.peer,
                               .descriptor = SchemaId {std::string {schema}},
                               .identity = std::move(identity),
                               .parent = std::make_shared<const SubjectKey>(parent)};
        }

        [[nodiscard]] NestedCollection parse_sections(const SubjectKey &image, const ParsedImage &parsed) {
            NestedCollection output;
            output.observations.reserve(parsed.sections.size());
            output.values.reserve(parsed.sections.size());
            for (const auto &entry : parsed.sections) {
                const auto &section = entry.header;
                auto value =
                    record(pe_section_schema,
                           {{.field_id = 1, .value = text(entry.name)},
                            {.field_id = 2, .value = integer(static_cast<std::uint64_t>(section.VirtualAddress))},
                            {.field_id = 3, .value = integer(static_cast<std::uint64_t>(section.Misc.VirtualSize))},
                            {.field_id = 4, .value = integer(static_cast<std::uint64_t>(section.PointerToRawData))},
                            {.field_id = 5, .value = integer(static_cast<std::uint64_t>(section.SizeOfRawData))},
                            {.field_id = 6, .value = integer(static_cast<std::uint64_t>(section.Characteristics))}});
                output.observations.push_back(SubjectObservation {
                    .subject = nested_subject(
                        image, pe_section_schema,
                        {{.field_id = 1, .value = static_cast<std::uint64_t>(section.VirtualAddress)},
                         {.field_id = 2, .value = static_cast<std::uint64_t>(section.PointerToRawData)}}),
                    .eager_fields = std::get<FactRecord>(value.node->data).fields,
                });
                output.values.push_back(std::move(value));
            }
            return output;
        }

        template<typename Thunk> [[nodiscard]] std::expected<void, ProviderError>
        parse_import_thunks(const std::span<const std::byte> bytes, const ParsedImage &parsed, const SubjectKey &image,
                            const std::string &dll, const std::uint32_t lookup_rva, const std::uint32_t iat_rva,
                            NestedCollection &output) {
            constexpr auto ordinal_flag = sizeof(Thunk) == 8U ? static_cast<Thunk>(IMAGE_ORDINAL_FLAG64) :
                                                                static_cast<Thunk>(IMAGE_ORDINAL_FLAG32);
            for (std::size_t index = 0; index < maximum_imports; ++index) {
                const auto byte_offset = index * sizeof(Thunk);
                if (byte_offset > (std::numeric_limits<std::uint32_t>::max)() - lookup_rva ||
                    byte_offset > (std::numeric_limits<std::uint32_t>::max)() - iat_rva) {
                    return std::unexpected(
                        failure(ProviderErrorCode::arithmetic_overflow, "PE imports", "import thunk RVA overflowed"));
                }
                const auto entry_rva = lookup_rva + static_cast<std::uint32_t>(byte_offset);
                const auto offset = rva_to_offset(bytes, parsed.sections, entry_rva, sizeof(Thunk));
                if (!offset.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE imports", "import thunk is outside the image"));
                }
                const auto thunk = read_value<Thunk>(bytes, *offset);
                if (!thunk.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE imports", "import thunk is truncated"));
                }
                if (*thunk == 0U) {
                    return {};
                }
                const auto slot_rva = iat_rva + static_cast<std::uint32_t>(byte_offset);
                const auto by_ordinal = (*thunk & ordinal_flag) != 0U;
                const auto ordinal = static_cast<std::uint16_t>(*thunk & 0xffffU);
                std::optional<std::uint16_t> hint;
                std::optional<std::string> name;
                if (!by_ordinal) {
                    const auto name_rva = static_cast<std::uint32_t>(*thunk);
                    const auto name_offset = rva_to_offset(bytes, parsed.sections, name_rva, sizeof(WORD));
                    if (!name_offset.has_value()) {
                        return std::unexpected(
                            failure(ProviderErrorCode::malformed, "PE imports", "import name is outside the image"));
                    }
                    hint = read_value<WORD>(bytes, *name_offset);
                    if (!hint.has_value()) {
                        return std::unexpected(
                            failure(ProviderErrorCode::malformed, "PE imports", "import hint is truncated"));
                    }
                    auto imported_name = read_c_string(bytes, *name_offset + sizeof(WORD));
                    if (!imported_name) {
                        return std::unexpected(std::move(imported_name.error()));
                    }
                    name = std::move(*imported_name);
                }

                auto value =
                    record(pe_import_schema,
                           {{.field_id = 1, .value = text(dll)},
                            {.field_id = 2, .value = name.has_value() ? text(*name) : make_fact(std::monostate {})},
                            {.field_id = 3,
                             .value = by_ordinal ? integer(static_cast<std::uint64_t>(ordinal)) :
                                                   make_fact(std::monostate {})},
                            {.field_id = 4,
                             .value = hint.has_value() ? integer(static_cast<std::uint64_t>(*hint)) :
                                                         make_fact(std::monostate {})},
                            {.field_id = 5, .value = integer(static_cast<std::uint64_t>(slot_rva))}});
                output.observations.push_back(SubjectObservation {
                    .subject = nested_subject(image, pe_import_schema,
                                              {{.field_id = 1, .value = UnicodeValue {.utf8 = dll}},
                                               {.field_id = 2, .value = static_cast<std::uint64_t>(slot_rva)}}),
                    .eager_fields = std::get<FactRecord>(value.node->data).fields,
                });
                output.values.push_back(std::move(value));
                if (output.values.size() > maximum_imports) {
                    return std::unexpected(failure(ProviderErrorCode::result_limit, "PE imports",
                                                   "import count exceeds the provider limit"));
                }
            }
            return std::unexpected(failure(ProviderErrorCode::result_limit, "PE imports",
                                           "one import descriptor exceeds the thunk limit"));
        }

        [[nodiscard]] std::expected<NestedCollection, ProviderError>
        parse_imports(const std::span<const std::byte> bytes, const ParsedImage &parsed, const SubjectKey &image) {
            NestedCollection output;
            const auto directory = parsed.directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (directory.VirtualAddress == 0U || directory.Size == 0U) {
                return output;
            }
            const auto maximum_descriptors =
                std::min<std::size_t>(maximum_imports, directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) + 1U);
            for (std::size_t index = 0; index < maximum_descriptors; ++index) {
                const auto delta = index * sizeof(IMAGE_IMPORT_DESCRIPTOR);
                if (delta > (std::numeric_limits<std::uint32_t>::max)() - directory.VirtualAddress) {
                    return std::unexpected(failure(ProviderErrorCode::arithmetic_overflow, "PE imports",
                                                   "import descriptor RVA overflowed"));
                }
                const auto descriptor_rva = directory.VirtualAddress + static_cast<std::uint32_t>(delta);
                const auto offset =
                    rva_to_offset(bytes, parsed.sections, descriptor_rva, sizeof(IMAGE_IMPORT_DESCRIPTOR));
                if (!offset.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE imports", "import descriptor is outside the image"));
                }
                const auto descriptor = read_value<IMAGE_IMPORT_DESCRIPTOR>(bytes, *offset);
                if (!descriptor.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE imports", "import descriptor is truncated"));
                }
                if (descriptor->OriginalFirstThunk == 0U && descriptor->FirstThunk == 0U && descriptor->Name == 0U) {
                    return output;
                }
                const auto dll_offset = rva_to_offset(bytes, parsed.sections, descriptor->Name);
                if (!dll_offset.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE imports", "import DLL name is outside the image"));
                }
                auto dll = read_c_string(bytes, *dll_offset);
                if (!dll) {
                    return std::unexpected(std::move(dll.error()));
                }
                *dll = normalized_dll(std::move(*dll));
                const auto lookup =
                    descriptor->OriginalFirstThunk != 0U ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
                auto parsed_thunks = parsed.pe64 ?
                                         parse_import_thunks<std::uint64_t>(bytes, parsed, image, *dll, lookup,
                                                                            descriptor->FirstThunk, output) :
                                         parse_import_thunks<std::uint32_t>(bytes, parsed, image, *dll, lookup,
                                                                            descriptor->FirstThunk, output);
                if (!parsed_thunks) {
                    return std::unexpected(std::move(parsed_thunks.error()));
                }
            }
            return std::unexpected(
                failure(ProviderErrorCode::result_limit, "PE imports", "import descriptor list is unterminated"));
        }

        [[nodiscard]] std::expected<NestedCollection, ProviderError>
        parse_exports(const std::span<const std::byte> bytes, const ParsedImage &parsed, const SubjectKey &image) {
            NestedCollection output;
            const auto directory = parsed.directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (directory.VirtualAddress == 0U || directory.Size == 0U) {
                return output;
            }
            const auto offset =
                rva_to_offset(bytes, parsed.sections, directory.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));
            if (!offset.has_value()) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE exports", "export directory is outside the image"));
            }
            const auto exports = read_value<IMAGE_EXPORT_DIRECTORY>(bytes, *offset);
            if (!exports.has_value() || exports->NumberOfFunctions > maximum_exports ||
                exports->NumberOfNames > maximum_exports) {
                return std::unexpected(failure(ProviderErrorCode::result_limit, "PE exports",
                                               "export directory exceeds the provider limit"));
            }

            std::vector<std::optional<std::string>> names(exports->NumberOfFunctions);
            for (std::uint32_t index = 0; index < exports->NumberOfNames; ++index) {
                const auto name_rva_offset = rva_to_offset(
                    bytes, parsed.sections, exports->AddressOfNames + index * sizeof(DWORD), sizeof(DWORD));
                const auto ordinal_offset = rva_to_offset(
                    bytes, parsed.sections, exports->AddressOfNameOrdinals + index * sizeof(WORD), sizeof(WORD));
                if (!name_rva_offset.has_value() || !ordinal_offset.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE exports", "export name table is outside the image"));
                }
                const auto name_rva = read_value<DWORD>(bytes, *name_rva_offset);
                const auto ordinal_index = read_value<WORD>(bytes, *ordinal_offset);
                if (!name_rva.has_value() || !ordinal_index.has_value() || *ordinal_index >= names.size()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE exports", "export name ordinal is invalid"));
                }
                const auto name_offset = rva_to_offset(bytes, parsed.sections, *name_rva);
                if (!name_offset.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE exports", "export name is outside the image"));
                }
                auto name = read_c_string(bytes, *name_offset);
                if (!name) {
                    return std::unexpected(std::move(name.error()));
                }
                names[*ordinal_index] = std::move(*name);
            }

            output.observations.reserve(exports->NumberOfFunctions);
            output.values.reserve(exports->NumberOfFunctions);
            for (std::uint32_t index = 0; index < exports->NumberOfFunctions; ++index) {
                const auto function_offset = rva_to_offset(
                    bytes, parsed.sections, exports->AddressOfFunctions + index * sizeof(DWORD), sizeof(DWORD));
                if (!function_offset.has_value()) {
                    return std::unexpected(failure(ProviderErrorCode::malformed, "PE exports",
                                                   "export address table is outside the image"));
                }
                const auto function_rva = read_value<DWORD>(bytes, *function_offset);
                if (!function_rva.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE exports", "export address is truncated"));
                }
                const auto ordinal = static_cast<std::uint64_t>(exports->Base) + index;
                std::optional<std::string> forwarder;
                const auto directory_end = static_cast<std::uint64_t>(directory.VirtualAddress) + directory.Size;
                if (*function_rva >= directory.VirtualAddress && *function_rva < directory_end) {
                    const auto forwarder_offset = rva_to_offset(bytes, parsed.sections, *function_rva);
                    if (!forwarder_offset.has_value()) {
                        return std::unexpected(failure(ProviderErrorCode::malformed, "PE exports",
                                                       "export forwarder is outside the image"));
                    }
                    auto value = read_c_string(bytes, *forwarder_offset);
                    if (!value) {
                        return std::unexpected(std::move(value.error()));
                    }
                    forwarder = std::move(*value);
                }
                auto value =
                    record(pe_export_schema,
                           {{.field_id = 1, .value = integer(ordinal)},
                            {.field_id = 2,
                             .value = names[index].has_value() ? text(*names[index]) : make_fact(std::monostate {})},
                            {.field_id = 3, .value = integer(static_cast<std::uint64_t>(*function_rva))},
                            {.field_id = 4,
                             .value = forwarder.has_value() ? text(*forwarder) : make_fact(std::monostate {})}});
                output.observations.push_back(SubjectObservation {
                    .subject = nested_subject(image, pe_export_schema, {{.field_id = 1, .value = ordinal}}),
                    .eager_fields = std::get<FactRecord>(value.node->data).fields,
                });
                output.values.push_back(std::move(value));
            }
            return output;
        }

        [[nodiscard]] std::expected<NestedCollection, ProviderError>
        parse_debug(const std::span<const std::byte> bytes, const ParsedImage &parsed, const SubjectKey &image) {
            NestedCollection output;
            const auto directory = parsed.directories[IMAGE_DIRECTORY_ENTRY_DEBUG];
            if (directory.VirtualAddress == 0U || directory.Size == 0U) {
                return output;
            }
            if ((directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY)) != 0U ||
                directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY) > maximum_debug_entries) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE debug", "debug directory has an invalid size"));
            }
            const auto count = directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
            for (std::uint32_t index = 0; index < count; ++index) {
                const auto delta = static_cast<std::uint64_t>(index) * sizeof(IMAGE_DEBUG_DIRECTORY);
                if (delta > (std::numeric_limits<std::uint32_t>::max)() - directory.VirtualAddress) {
                    return std::unexpected(
                        failure(ProviderErrorCode::arithmetic_overflow, "PE debug", "debug directory RVA overflowed"));
                }
                const auto entry_rva = directory.VirtualAddress + static_cast<std::uint32_t>(delta);
                const auto offset = rva_to_offset(bytes, parsed.sections, entry_rva, sizeof(IMAGE_DEBUG_DIRECTORY));
                if (!offset.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE debug", "debug entry is outside the image"));
                }
                const auto entry = read_value<IMAGE_DEBUG_DIRECTORY>(bytes, *offset);
                if (!entry.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE debug", "debug entry is truncated"));
                }
                auto value =
                    record(pe_debug_schema,
                           {{.field_id = 1, .value = integer(static_cast<std::uint64_t>(entry->Type))},
                            {.field_id = 2, .value = integer(static_cast<std::uint64_t>(entry->AddressOfRawData))},
                            {.field_id = 3, .value = integer(static_cast<std::uint64_t>(entry->PointerToRawData))},
                            {.field_id = 4, .value = integer(static_cast<std::uint64_t>(entry->SizeOfData))},
                            {.field_id = 5, .value = integer(static_cast<std::uint64_t>(entry->TimeDateStamp))}});
                output.observations.push_back(SubjectObservation {
                    .subject =
                        nested_subject(image, pe_debug_schema,
                                       {{.field_id = 1, .value = static_cast<std::uint64_t>(entry->Type)},
                                        {.field_id = 2, .value = static_cast<std::uint64_t>(entry->AddressOfRawData)},
                                        {.field_id = 3, .value = static_cast<std::uint64_t>(entry->PointerToRawData)}}),
                    .eager_fields = std::get<FactRecord>(value.node->data).fields,
                });
                output.values.push_back(std::move(value));
            }
            return output;
        }

        void append_utf8(std::string &output, const std::uint32_t point) {
            if (point <= 0x7fU) {
                output.push_back(static_cast<char>(point));
            } else if (point <= 0x7ffU) {
                output.push_back(static_cast<char>(0xc0U | (point >> 6U)));
                output.push_back(static_cast<char>(0x80U | (point & 0x3fU)));
            } else {
                output.push_back(static_cast<char>(0xe0U | (point >> 12U)));
                output.push_back(static_cast<char>(0x80U | ((point >> 6U) & 0x3fU)));
                output.push_back(static_cast<char>(0x80U | (point & 0x3fU)));
            }
        }

        [[nodiscard]] std::expected<ResourceTag, ProviderError>
        resource_tag(const std::span<const std::byte> bytes, const std::size_t resource_base, const std::uint32_t raw) {
            if ((raw & resource_name_is_string) == 0U) {
                const auto id = raw & 0xffffU;
                return ResourceTag {.canonical = "id:" + std::to_string(id),
                                    .value = integer(static_cast<std::uint64_t>(id))};
            }
            const auto relative = raw & resource_offset_mask;
            if (relative > (std::numeric_limits<std::size_t>::max)() - resource_base) {
                return std::unexpected(failure(ProviderErrorCode::arithmetic_overflow, "PE resources",
                                               "resource string offset overflowed"));
            }
            const auto offset = resource_base + relative;
            const auto length = read_value<WORD>(bytes, offset);
            if (!length.has_value() || *length > 32'768U) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE resources", "resource string length is invalid"));
            }
            const auto raw_chars = read_span(bytes, offset + sizeof(WORD), *length * sizeof(char16_t));
            if (!raw_chars.has_value()) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE resources", "resource string is truncated"));
            }
            std::string encoded;
            for (std::size_t index = 0; index < *length; ++index) {
                const auto unit = read_value<char16_t>(*raw_chars, index * sizeof(char16_t));
                if (!unit.has_value() || (*unit >= 0xd800U && *unit <= 0xdfffU)) {
                    return std::unexpected(failure(ProviderErrorCode::malformed, "PE resources",
                                                   "resource name contains an unsupported surrogate"));
                }
                append_utf8(encoded, *unit);
            }
            return ResourceTag {.canonical = "text:" + encoded, .value = text(std::move(encoded))};
        }

        [[nodiscard]] std::expected<void, ProviderError>
        walk_resources(const std::span<const std::byte> bytes, const ParsedImage &parsed, const SubjectKey &image,
                       const std::size_t resource_base, const std::size_t directory_offset, const std::size_t depth,
                       std::vector<ResourceTag> path, NestedCollection &output) {
            if (depth > 3U) {
                return std::unexpected(failure(ProviderErrorCode::malformed, "PE resources",
                                               "resource directory nesting exceeds three identity levels"));
            }
            const auto directory = read_value<IMAGE_RESOURCE_DIRECTORY>(bytes, directory_offset);
            if (!directory.has_value()) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE resources", "resource directory is truncated"));
            }
            const auto count = static_cast<std::size_t>(directory->NumberOfNamedEntries) + directory->NumberOfIdEntries;
            if (count > maximum_resources || output.values.size() + count > maximum_resources) {
                return std::unexpected(failure(ProviderErrorCode::result_limit, "PE resources",
                                               "resource entry count exceeds the provider limit"));
            }
            const auto table = directory_offset + sizeof(IMAGE_RESOURCE_DIRECTORY);
            for (std::size_t index = 0; index < count; ++index) {
                const auto entry = read_value<IMAGE_RESOURCE_DIRECTORY_ENTRY>(
                    bytes, table + index * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
                if (!entry.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE resources", "resource directory entry is truncated"));
                }
                auto tag = resource_tag(bytes, resource_base, entry->Name);
                if (!tag) {
                    return std::unexpected(std::move(tag.error()));
                }
                auto next_path = path;
                next_path.push_back(std::move(*tag));
                const auto relative = entry->OffsetToData & resource_offset_mask;
                if (relative > (std::numeric_limits<std::size_t>::max)() - resource_base) {
                    return std::unexpected(failure(ProviderErrorCode::arithmetic_overflow, "PE resources",
                                                   "resource child offset overflowed"));
                }
                const auto child = resource_base + relative;
                if ((entry->OffsetToData & resource_data_is_directory) != 0U) {
                    auto walked = walk_resources(bytes, parsed, image, resource_base, child, depth + 1U,
                                                 std::move(next_path), output);
                    if (!walked) {
                        return std::unexpected(std::move(walked.error()));
                    }
                    continue;
                }
                if (next_path.size() != 3U) {
                    return std::unexpected(failure(ProviderErrorCode::malformed, "PE resources",
                                                   "resource leaf does not have type/name/language identity"));
                }
                const auto data = read_value<IMAGE_RESOURCE_DATA_ENTRY>(bytes, child);
                if (!data.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE resources", "resource data entry is truncated"));
                }
                std::uint64_t language {};
                if (const auto *id = std::get_if<IntegerValue>(&next_path[2].value.node->data)) {
                    const auto [end, ec] =
                        std::from_chars(id->decimal.data(), id->decimal.data() + id->decimal.size(), language);
                    if (ec != std::errc {} || end != id->decimal.data() + id->decimal.size()) {
                        return std::unexpected(failure(ProviderErrorCode::malformed, "PE resources",
                                                       "resource language identity is invalid"));
                    }
                } else {
                    return std::unexpected(failure(ProviderErrorCode::malformed, "PE resources",
                                                   "resource language identity must be numeric"));
                }
                auto value = record(pe_resource_schema,
                                    {{.field_id = 1, .value = next_path[0].value},
                                     {.field_id = 2, .value = next_path[1].value},
                                     {.field_id = 3, .value = integer(language)},
                                     {.field_id = 4, .value = integer(static_cast<std::uint64_t>(data->OffsetToData))},
                                     {.field_id = 5, .value = integer(static_cast<std::uint64_t>(data->Size))},
                                     {.field_id = 6, .value = integer(static_cast<std::uint64_t>(data->CodePage))}});
                output.observations.push_back(SubjectObservation {
                    .subject =
                        nested_subject(image, pe_resource_schema,
                                       {{.field_id = 1, .value = UnicodeValue {.utf8 = next_path[0].canonical}},
                                        {.field_id = 2, .value = UnicodeValue {.utf8 = next_path[1].canonical}},
                                        {.field_id = 3, .value = language},
                                        {.field_id = 4, .value = static_cast<std::uint64_t>(data->OffsetToData)}}),
                    .eager_fields = std::get<FactRecord>(value.node->data).fields,
                });
                output.values.push_back(std::move(value));
            }
            return {};
        }

        [[nodiscard]] std::expected<NestedCollection, ProviderError>
        parse_resources(const std::span<const std::byte> bytes, const ParsedImage &parsed, const SubjectKey &image) {
            NestedCollection output;
            const auto directory = parsed.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE];
            if (directory.VirtualAddress == 0U || directory.Size == 0U) {
                return output;
            }
            const auto base =
                rva_to_offset(bytes, parsed.sections, directory.VirtualAddress, sizeof(IMAGE_RESOURCE_DIRECTORY));
            if (!base.has_value()) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE resources", "resource directory is outside the image"));
            }
            auto walked = walk_resources(bytes, parsed, image, *base, *base, 0U, {}, output);
            if (!walked) {
                return std::unexpected(std::move(walked.error()));
            }
            return output;
        }

        [[nodiscard]] std::expected<NestedCollection, ProviderError>
        parse_certificates(const std::span<const std::byte> bytes, const ParsedImage &parsed, const SubjectKey &image) {
            NestedCollection output;
            const auto directory = parsed.directories[IMAGE_DIRECTORY_ENTRY_SECURITY];
            if (directory.VirtualAddress == 0U || directory.Size == 0U) {
                return output;
            }
            const auto begin = static_cast<std::size_t>(directory.VirtualAddress);
            if (begin > bytes.size() || directory.Size > bytes.size() - begin) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE certificates", "certificate table is outside the image"));
            }
            const auto end = begin + directory.Size;
            auto offset = begin;
            while (offset < end) {
                if (output.values.size() >= maximum_certificates) {
                    return std::unexpected(failure(ProviderErrorCode::result_limit, "PE certificates",
                                                   "certificate count exceeds the provider limit"));
                }
                const auto certificate = read_value<WIN_CERTIFICATE>(bytes, offset);
                if (!certificate.has_value() || certificate->dwLength < offsetof(WIN_CERTIFICATE, bCertificate) ||
                    certificate->dwLength > end - offset) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE certificates", "certificate entry is malformed"));
                }
                auto value = record(
                    pe_certificate_schema,
                    {{.field_id = 1, .value = integer(static_cast<std::uint64_t>(offset))},
                     {.field_id = 2, .value = integer(static_cast<std::uint64_t>(certificate->dwLength))},
                     {.field_id = 3, .value = integer(static_cast<std::uint64_t>(certificate->wRevision))},
                     {.field_id = 4, .value = integer(static_cast<std::uint64_t>(certificate->wCertificateType))}});
                output.observations.push_back(SubjectObservation {
                    .subject = nested_subject(image, pe_certificate_schema,
                                              {{.field_id = 1, .value = static_cast<std::uint64_t>(offset)}}),
                    .eager_fields = std::get<FactRecord>(value.node->data).fields,
                });
                output.values.push_back(std::move(value));
                const auto aligned = (static_cast<std::size_t>(certificate->dwLength) + 7U) & ~std::size_t {7U};
                if (aligned == 0U || aligned > end - offset) {
                    if (offset + certificate->dwLength == end) {
                        offset = end;
                        break;
                    }
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE certificates", "certificate alignment is invalid"));
                }
                offset += aligned;
            }
            return output;
        }

        template<typename Directory, typename Pointer> [[nodiscard]] std::expected<NestedCollection, ProviderError>
        parse_tls(const std::span<const std::byte> bytes, const ParsedImage &parsed, const SubjectKey &image) {
            NestedCollection output;
            const auto data_directory = parsed.directories[IMAGE_DIRECTORY_ENTRY_TLS];
            if (data_directory.VirtualAddress == 0U || data_directory.Size == 0U) {
                return output;
            }
            const auto directory_offset =
                rva_to_offset(bytes, parsed.sections, data_directory.VirtualAddress, sizeof(Directory));
            if (!directory_offset.has_value()) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE TLS", "TLS directory is outside the image"));
            }
            const auto directory = read_value<Directory>(bytes, *directory_offset);
            if (!directory.has_value() || directory->AddressOfCallBacks == 0U) {
                return output;
            }
            if (directory->AddressOfCallBacks < parsed.image_base ||
                directory->AddressOfCallBacks - parsed.image_base > (std::numeric_limits<std::uint32_t>::max)()) {
                return std::unexpected(
                    failure(ProviderErrorCode::malformed, "PE TLS", "TLS callback table address is invalid"));
            }
            const auto callbacks_rva = static_cast<std::uint32_t>(directory->AddressOfCallBacks - parsed.image_base);
            for (std::size_t index = 0; index < maximum_tls_callbacks; ++index) {
                const auto delta = index * sizeof(Pointer);
                if (delta > (std::numeric_limits<std::uint32_t>::max)() - callbacks_rva) {
                    return std::unexpected(
                        failure(ProviderErrorCode::arithmetic_overflow, "PE TLS", "TLS callback offset overflowed"));
                }
                const auto callback_offset = rva_to_offset(
                    bytes, parsed.sections, callbacks_rva + static_cast<std::uint32_t>(delta), sizeof(Pointer));
                if (!callback_offset.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE TLS", "TLS callback table is outside the image"));
                }
                const auto address = read_value<Pointer>(bytes, *callback_offset);
                if (!address.has_value()) {
                    return std::unexpected(
                        failure(ProviderErrorCode::malformed, "PE TLS", "TLS callback pointer is truncated"));
                }
                if (*address == 0U) {
                    return output;
                }
                if (*address < parsed.image_base || static_cast<std::uint64_t>(*address) - parsed.image_base >
                                                        (std::numeric_limits<std::uint32_t>::max)()) {
                    return std::unexpected(failure(ProviderErrorCode::malformed, "PE TLS",
                                                   "TLS callback address is outside the image base range"));
                }
                const auto rva = static_cast<std::uint32_t>(static_cast<std::uint64_t>(*address) - parsed.image_base);
                auto value = record(pe_tls_callback_schema,
                                    {{.field_id = 1, .value = integer(static_cast<std::uint64_t>(rva))},
                                     {.field_id = 2, .value = integer(static_cast<std::uint64_t>(index))}});
                output.observations.push_back(SubjectObservation {
                    .subject = nested_subject(image, pe_tls_callback_schema,
                                              {{.field_id = 1, .value = static_cast<std::uint64_t>(rva)}}),
                    .eager_fields = std::get<FactRecord>(value.node->data).fields,
                });
                output.values.push_back(std::move(value));
            }
            return std::unexpected(
                failure(ProviderErrorCode::result_limit, "PE TLS", "TLS callback table is unterminated"));
        }

        [[nodiscard]] std::vector<FactRecordField> image_eager_fields(const std::filesystem::path &path,
                                                                      const ImageBytes &file, const bool valid,
                                                                      const ParsedImage *parsed = nullptr) {
            const auto encoded = path.generic_u8string();
            std::vector<FactRecordField> fields {
                {.field_id = 1, .value = make_fact(valid)},
                {.field_id = 2,
                 .value = text(std::string {reinterpret_cast<const char *>(encoded.data()), encoded.size()})},
                {.field_id = 3, .value = integer(file.size)},
                {.field_id = 4, .value = integer(file.last_write_time)},
            };
            if (parsed != nullptr) {
                fields.push_back(
                    {.field_id = 5, .value = integer(static_cast<std::uint64_t>(parsed->file_header.Machine))});
                fields.push_back({.field_id = 6,
                                  .value = integer(static_cast<std::uint64_t>(parsed->file_header.NumberOfSections))});
            }
            return fields;
        }

        [[nodiscard]] InventorySnapshot snapshot(const SubjectKey &image, const std::string_view schema,
                                                 const std::uint64_t generation,
                                                 std::vector<SubjectObservation> observations) {
            return make_inventory_snapshot(image.peer, SchemaId {std::string {schema}}, image, generation,
                                           std::move(observations));
        }

        [[nodiscard]] PeInventorySet invalid_pe_value(const SubjectObservation &image, const ImageBytes &file,
                                                      const std::filesystem::path &path,
                                                      const std::uint64_t generation) {
            auto invalid_image = image;
            if (!invalid_image.eager_fields.empty()) {
                invalid_image.eager_fields.front().value = make_fact(false);
            }
            auto value = record(pe_value_schema, {{.field_id = 1, .value = make_fact(false)},
                                                  {.field_id = 2, .value = make_fact(std::monostate {})},
                                                  {.field_id = 3, .value = make_fact(std::monostate {})},
                                                  {.field_id = 4, .value = make_fact(std::monostate {})},
                                                  {.field_id = 5, .value = make_fact(std::monostate {})},
                                                  {.field_id = 6, .value = make_fact(std::monostate {})},
                                                  {.field_id = 7, .value = make_fact(std::monostate {})},
                                                  {.field_id = 8, .value = make_fact(std::monostate {})},
                                                  {.field_id = 9, .value = make_fact(std::monostate {})},
                                                  {.field_id = 10, .value = list({})},
                                                  {.field_id = 11, .value = list({})},
                                                  {.field_id = 12, .value = list({})},
                                                  {.field_id = 13, .value = list({})},
                                                  {.field_id = 14, .value = list({})},
                                                  {.field_id = 15, .value = list({})},
                                                  {.field_id = 16, .value = list({})},
                                                  {.field_id = 17, .value = integer(file.size)},
                                                  {.field_id = 18, .value = integer(file.last_write_time)}});
            const auto empty = [&](const std::string_view schema) {
                return snapshot(image.subject, schema, generation, {});
            };
            static_cast<void>(path);
            return PeInventorySet {.image = std::move(invalid_image),
                                   .value = freeze_provider_value(std::move(value), image_label()),
                                   .sections = empty(pe_section_schema),
                                   .imports = empty(pe_import_schema),
                                   .exports = empty(pe_export_schema),
                                   .debug_entries = empty(pe_debug_schema),
                                   .resources = empty(pe_resource_schema),
                                   .certificates = empty(pe_certificate_schema),
                                   .tls_callbacks = empty(pe_tls_callback_schema)};
        }

    } // namespace

    std::expected<PeInventorySet, ProviderError> inspect_pe_image(const SubjectKey &process,
                                                                  const std::filesystem::path &path,
                                                                  const std::uint64_t generation,
                                                                  const std::uint64_t deadline_unix_ms) {
        if (generation == 0U) {
            return std::unexpected(
                failure(ProviderErrorCode::invalid_request, "PE inspection", "inventory generation must be nonzero"));
        }
        auto live_path = resolve_process_image_path(process, deadline_unix_ms);
        if (!live_path) {
            return std::unexpected(std::move(live_path.error()));
        }
        std::error_code equivalent_error;
        const auto same_file = std::filesystem::equivalent(*live_path, path, equivalent_error);
        if (equivalent_error || !same_file) {
            return std::unexpected(failure(ProviderErrorCode::subject_changed, "PE inspection",
                                           "requested image is not the process's current executable image"));
        }
        auto file = read_image_bytes(*live_path, deadline_unix_ms);
        if (!file) {
            return std::unexpected(std::move(file.error()));
        }
        auto subject = image_subject(process, *live_path);
        if (!subject) {
            return std::unexpected(std::move(subject.error()));
        }
        SubjectObservation image {
            .subject = *subject,
            .eager_fields = image_eager_fields(*live_path, *file, true),
        };

        auto parsed = parse_headers(file->bytes);
        if (!parsed) {
            return invalid_pe_value(image, *file, *live_path, generation);
        }
        image.eager_fields = image_eager_fields(*live_path, *file, true, std::addressof(*parsed));

        auto sections = parse_sections(*subject, *parsed);
        auto imports = parse_imports(file->bytes, *parsed, *subject);
        if (!imports) {
            return std::unexpected(std::move(imports.error()));
        }
        auto exports = parse_exports(file->bytes, *parsed, *subject);
        if (!exports) {
            return std::unexpected(std::move(exports.error()));
        }
        auto debug = parse_debug(file->bytes, *parsed, *subject);
        if (!debug) {
            return std::unexpected(std::move(debug.error()));
        }
        auto resources = parse_resources(file->bytes, *parsed, *subject);
        if (!resources) {
            return std::unexpected(std::move(resources.error()));
        }
        auto certificates = parse_certificates(file->bytes, *parsed, *subject);
        if (!certificates) {
            return std::unexpected(std::move(certificates.error()));
        }
        auto callbacks = parsed->pe64 ?
                             parse_tls<IMAGE_TLS_DIRECTORY64, std::uint64_t>(file->bytes, *parsed, *subject) :
                             parse_tls<IMAGE_TLS_DIRECTORY32, std::uint32_t>(file->bytes, *parsed, *subject);
        if (!callbacks) {
            return std::unexpected(std::move(callbacks.error()));
        }
        if (expired(deadline_unix_ms)) {
            return std::unexpected(
                failure(ProviderErrorCode::timed_out, "PE inspection", "provider deadline expired during parsing"));
        }

        auto value =
            record(pe_value_schema,
                   {{.field_id = 1, .value = make_fact(true)},
                    {.field_id = 2, .value = integer(static_cast<std::uint64_t>(parsed->file_header.Machine))},
                    {.field_id = 3, .value = integer(static_cast<std::uint64_t>(parsed->file_header.NumberOfSections))},
                    {.field_id = 4, .value = integer(static_cast<std::uint64_t>(parsed->entry_point))},
                    {.field_id = 5, .value = integer(static_cast<std::uint64_t>(parsed->size_of_image))},
                    {.field_id = 6, .value = integer(static_cast<std::uint64_t>(parsed->subsystem))},
                    {.field_id = 7, .value = integer(static_cast<std::uint64_t>(parsed->file_header.Characteristics))},
                    {.field_id = 8, .value = integer(static_cast<std::uint64_t>(parsed->dll_characteristics))},
                    {.field_id = 9, .value = integer(static_cast<std::uint64_t>(parsed->file_header.TimeDateStamp))},
                    {.field_id = 10, .value = list(sections.values)},
                    {.field_id = 11, .value = list(imports->values)},
                    {.field_id = 12, .value = list(exports->values)},
                    {.field_id = 13, .value = list(debug->values)},
                    {.field_id = 14, .value = list(resources->values)},
                    {.field_id = 15, .value = list(certificates->values)},
                    {.field_id = 16, .value = list(callbacks->values)},
                    {.field_id = 17, .value = integer(file->size)},
                    {.field_id = 18, .value = integer(file->last_write_time)}});

        auto result = PeInventorySet {
            .image = std::move(image),
            .value = freeze_provider_value(std::move(value), image_label()),
            .sections = snapshot(*subject, pe_section_schema, generation, std::move(sections.observations)),
            .imports = snapshot(*subject, pe_import_schema, generation, std::move(imports->observations)),
            .exports = snapshot(*subject, pe_export_schema, generation, std::move(exports->observations)),
            .debug_entries = snapshot(*subject, pe_debug_schema, generation, std::move(debug->observations)),
            .resources = snapshot(*subject, pe_resource_schema, generation, std::move(resources->observations)),
            .certificates =
                snapshot(*subject, pe_certificate_schema, generation, std::move(certificates->observations)),
            .tls_callbacks = snapshot(*subject, pe_tls_callback_schema, generation, std::move(callbacks->observations)),
        };
        if (!result.sections.authoritative || !result.imports.authoritative || !result.exports.authoritative ||
            !result.debug_entries.authoritative || !result.resources.authoritative ||
            !result.certificates.authoritative || !result.tls_callbacks.authoritative) {
            return std::unexpected(failure(ProviderErrorCode::malformed, "PE inspection",
                                           "parsed PE produced a duplicate or invalid nested identity"));
        }
        return result;
    }

} // namespace rule_engine::python::windows
