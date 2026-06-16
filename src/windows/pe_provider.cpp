#include <rule_engine/windows/pe_provider.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {
    using namespace std::chrono_literals;

    constexpr auto pe_fact_ttl = 30s;
    constexpr auto max_import_descriptors = 4096u;
    constexpr auto max_imports = 65536u;
    constexpr auto max_import_name_bytes = 4096u;
    constexpr auto max_exports = 65536u;
    constexpr auto max_debug_entries = 1024u;
    constexpr auto max_resource_entries = 65536u;
    constexpr auto max_resource_name_chars = 4096u;
    constexpr auto max_resource_depth = 8u;
    constexpr auto max_certificates = 1024u;
    constexpr auto certificate_alignment = 8u;
    constexpr auto max_tls_callbacks = 4096u;
    constexpr std::uint32_t resource_directory_flag = 0x80000000u;
    constexpr std::uint32_t resource_offset_mask = 0x7fffffffu;

    struct ParsedSections {
        std::vector<IMAGE_SECTION_HEADER> headers;
        std::vector<rule_engine::Value> values;
    };

    struct ResourceName {
        rule_engine::Value id;
        rule_engine::Value name;
    };

    struct CertificateHeader {
        std::uint32_t length;
        std::uint16_t revision;
        std::uint16_t type;
    };

    [[nodiscard]] rule_engine::Fact make_fact(std::string subject_id,
                                              std::string key,
                                              rule_engine::Value value,
                                              const rule_engine::FactStatus status,
                                              std::string diagnostic = {}) {
        return rule_engine::Fact {
            .subject_id = std::move(subject_id),
            .key = std::move(key),
            .value = std::move(value),
            .status = status,
            .diagnostic = std::move(diagnostic),
            .ttl = pe_fact_ttl,
        };
    }

    [[nodiscard]] std::vector<rule_engine::Fact> diagnostic_facts(const std::string &subject_id,
                                                                  const rule_engine::FactStatus status,
                                                                  std::string diagnostic) {
        std::vector<rule_engine::Fact> out;
        out.push_back(make_fact(subject_id, "pe.is_valid", rule_engine::Value::boolean(false), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.machine", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(
            make_fact(subject_id, "pe.number_of_sections", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.entry_point", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.size_of_image", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.subsystem", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.characteristics", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(
            make_fact(subject_id, "pe.dll_characteristics", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.timestamp", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.sections", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.imports", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.exports", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.debug_entries", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.resources", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.certificates", rule_engine::Value::undefined(), status, diagnostic));
        out.push_back(make_fact(subject_id, "pe.tls_callbacks", rule_engine::Value::undefined(), status, diagnostic));
        return out;
    }

    [[nodiscard]] std::expected<std::vector<std::uint8_t>, rule_engine::ErrorSet>
    read_file_bytes(const std::filesystem::path &path) {
        std::ifstream file {path, std::ios::binary | std::ios::ate};
        if (!file) {
            return std::unexpected(rule_engine::single_error(path.string(), "failed to open PE image"));
        }

        const auto end = file.tellg();
        if (end <= 0) {
            return std::unexpected(rule_engine::single_error(path.string(), "empty PE image"));
        }
        const auto size = static_cast<std::size_t>(end);
        if (size > static_cast<std::size_t>((std::numeric_limits<std::streamsize>::max)())) {
            return std::unexpected(rule_engine::single_error(path.string(), "PE image is too large"));
        }
        std::vector<std::uint8_t> bytes(size);
        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!file) {
            return std::unexpected(rule_engine::single_error(path.string(), "failed to read PE image"));
        }
        return bytes;
    }

    template <typename T>
    [[nodiscard]] std::optional<T> read_struct(const std::vector<std::uint8_t> &bytes, const std::size_t offset) {
        if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
            return std::nullopt;
        }
        T out {};
        std::memcpy(&out, bytes.data() + offset, sizeof(T));
        return out;
    }

    [[nodiscard]] std::string section_name(const IMAGE_SECTION_HEADER &section) {
        std::string name;
        name.reserve(IMAGE_SIZEOF_SHORT_NAME);
        for (const auto ch : section.Name) {
            if (ch == 0u) {
                break;
            }
            name.push_back(static_cast<char>(ch));
        }
        return name;
    }

    [[nodiscard]] rule_engine::Value section_value(const IMAGE_SECTION_HEADER &section) {
        const auto characteristics = section.Characteristics;
        return rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
            rule_engine::ObjectEntry {.key = "name", .value = rule_engine::Value::string(section_name(section))},
            rule_engine::ObjectEntry {
                .key = "virtual_address",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(section.VirtualAddress)),
            },
            rule_engine::ObjectEntry {
                .key = "virtual_size",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(section.Misc.VirtualSize)),
            },
            rule_engine::ObjectEntry {
                .key = "raw_data_offset",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(section.PointerToRawData)),
            },
            rule_engine::ObjectEntry {
                .key = "raw_data_size",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(section.SizeOfRawData)),
            },
            rule_engine::ObjectEntry {
                .key = "characteristics",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(characteristics)),
            },
            rule_engine::ObjectEntry {
                .key = "readable",
                .value = rule_engine::Value::boolean((characteristics & IMAGE_SCN_MEM_READ) != 0u),
            },
            rule_engine::ObjectEntry {
                .key = "writable",
                .value = rule_engine::Value::boolean((characteristics & IMAGE_SCN_MEM_WRITE) != 0u),
            },
            rule_engine::ObjectEntry {
                .key = "executable",
                .value = rule_engine::Value::boolean((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0u),
            },
        });
    }

    [[nodiscard]] std::expected<ParsedSections, rule_engine::ErrorSet>
    read_sections(const std::vector<std::uint8_t> &bytes,
                  const IMAGE_FILE_HEADER &file_header,
                  const std::size_t optional_offset) {
        if (optional_offset > bytes.size() ||
            static_cast<std::size_t>(file_header.SizeOfOptionalHeader) > bytes.size() - optional_offset) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE optional header"));
        }

        const auto section_offset = optional_offset + static_cast<std::size_t>(file_header.SizeOfOptionalHeader);
        ParsedSections sections;
        sections.headers.reserve(file_header.NumberOfSections);
        sections.values.reserve(file_header.NumberOfSections);
        for (std::size_t index = 0u; index < static_cast<std::size_t>(file_header.NumberOfSections); ++index) {
            const auto offset = section_offset + (index * sizeof(IMAGE_SECTION_HEADER));
            const auto section = read_struct<IMAGE_SECTION_HEADER>(bytes, offset);
            if (!section.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE section table"));
            }
            sections.headers.push_back(*section);
            sections.values.push_back(section_value(*section));
        }
        return sections;
    }

    [[nodiscard]] std::optional<std::size_t> rva_to_file_offset(const std::vector<std::uint8_t> &bytes,
                                                                const std::vector<IMAGE_SECTION_HEADER> &sections,
                                                                const std::uint64_t rva,
                                                                const std::uint64_t size) {
        if (size == 0u) {
            return std::nullopt;
        }

        for (const auto &section : sections) {
            const auto start = static_cast<std::uint64_t>(section.VirtualAddress);
            const auto virtual_size = static_cast<std::uint64_t>(section.Misc.VirtualSize);
            const auto raw_size = static_cast<std::uint64_t>(section.SizeOfRawData);
            const auto mapped_size = (std::max)(virtual_size, raw_size);
            if (mapped_size == 0u || rva < start || rva - start >= mapped_size) {
                continue;
            }

            const auto delta = rva - start;
            const auto raw_offset = static_cast<std::uint64_t>(section.PointerToRawData) + delta;
            const auto file_offset = static_cast<std::size_t>(raw_offset);
            if (file_offset > bytes.size() || size > static_cast<std::uint64_t>(bytes.size() - file_offset)) {
                return std::nullopt;
            }
            return file_offset;
        }

        const auto file_offset = static_cast<std::size_t>(rva);
        if (file_offset > bytes.size() || size > static_cast<std::uint64_t>(bytes.size() - file_offset)) {
            return std::nullopt;
        }
        return file_offset;
    }

    [[nodiscard]] std::expected<std::string, rule_engine::ErrorSet>
    read_c_string(const std::vector<std::uint8_t> &bytes, const std::size_t offset) {
        std::string out;
        out.reserve(32u);
        for (std::size_t index = offset; index < bytes.size() && out.size() < max_import_name_bytes; ++index) {
            const auto ch = bytes[index];
            if (ch == 0u) {
                return out;
            }
            out.push_back(static_cast<char>(ch));
        }
        return std::unexpected(rule_engine::single_error("pe", "image has an unterminated PE import string"));
    }

    [[nodiscard]] rule_engine::Value import_value(const std::string &dll,
                                                  rule_engine::Value name,
                                                  rule_engine::Value ordinal,
                                                  rule_engine::Value hint,
                                                  const std::uint64_t lookup_rva,
                                                  const std::uint64_t iat_rva) {
        return rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
            rule_engine::ObjectEntry {.key = "dll", .value = rule_engine::Value::string(dll)},
            rule_engine::ObjectEntry {.key = "name", .value = std::move(name)},
            rule_engine::ObjectEntry {.key = "ordinal", .value = std::move(ordinal)},
            rule_engine::ObjectEntry {.key = "hint", .value = std::move(hint)},
            rule_engine::ObjectEntry {
                .key = "lookup_rva",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(lookup_rva)),
            },
            rule_engine::ObjectEntry {
                .key = "iat_rva",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(iat_rva)),
            },
        });
    }

    [[nodiscard]] bool is_null_import_descriptor(const IMAGE_IMPORT_DESCRIPTOR &descriptor) noexcept {
        return descriptor.OriginalFirstThunk == 0u && descriptor.TimeDateStamp == 0u &&
               descriptor.ForwarderChain == 0u && descriptor.Name == 0u && descriptor.FirstThunk == 0u;
    }

    template <typename Thunk>
    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    read_import_thunks(const std::vector<std::uint8_t> &bytes,
                       const std::vector<IMAGE_SECTION_HEADER> &sections,
                       const std::string &dll,
                       const std::uint32_t lookup_table_rva,
                       const std::uint32_t iat_table_rva,
                       const Thunk ordinal_flag,
                       std::vector<rule_engine::Value> &imports) {
        for (std::uint32_t index = 0u; index < max_imports; ++index) {
            const auto entry_rva = static_cast<std::uint64_t>(lookup_table_rva) +
                                   (static_cast<std::uint64_t>(index) * sizeof(Thunk));
            const auto entry_offset = rva_to_file_offset(bytes, sections, entry_rva, sizeof(Thunk));
            if (!entry_offset.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE import thunk table"));
            }

            const auto thunk = read_struct<Thunk>(bytes, *entry_offset);
            if (!thunk.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE import thunk"));
            }
            if (*thunk == 0u) {
                return {};
            }

            const auto iat_rva = static_cast<std::uint64_t>(iat_table_rva) +
                                 (static_cast<std::uint64_t>(index) * sizeof(Thunk));
            if ((*thunk & ordinal_flag) != 0u) {
                const auto ordinal = static_cast<std::int64_t>(*thunk & static_cast<Thunk>(0xffffu));
                imports.push_back(import_value(dll,
                                               rule_engine::Value::undefined(),
                                               rule_engine::Value::integer(ordinal),
                                               rule_engine::Value::undefined(),
                                               entry_rva,
                                               iat_rva));
                continue;
            }

            const auto name_rva = static_cast<std::uint64_t>(*thunk & ~ordinal_flag);
            const auto hint_name_offset = rva_to_file_offset(bytes, sections, name_rva, sizeof(WORD));
            if (!hint_name_offset.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE import name"));
            }
            const auto hint = read_struct<WORD>(bytes, *hint_name_offset);
            if (!hint.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE import hint"));
            }
            auto name = read_c_string(bytes, *hint_name_offset + sizeof(WORD));
            if (!name) {
                return std::unexpected(std::move(name.error()));
            }
            imports.push_back(import_value(dll,
                                           rule_engine::Value::string(std::move(*name)),
                                           rule_engine::Value::undefined(),
                                           rule_engine::Value::integer(static_cast<std::int64_t>(*hint)),
                                           entry_rva,
                                           iat_rva));
        }

        return std::unexpected(rule_engine::single_error("pe", "image import table exceeds safety limit"));
    }

    [[nodiscard]] std::expected<std::vector<rule_engine::Value>, rule_engine::ErrorSet>
    read_imports(const std::vector<std::uint8_t> &bytes,
                 const std::vector<IMAGE_SECTION_HEADER> &sections,
                 const std::uint32_t import_directory_rva,
                 const bool is_pe64) {
        std::vector<rule_engine::Value> imports;
        if (import_directory_rva == 0u) {
            return imports;
        }

        const auto descriptor_offset =
            rva_to_file_offset(bytes, sections, import_directory_rva, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!descriptor_offset.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE import directory"));
        }

        for (std::uint32_t index = 0u; index < max_import_descriptors; ++index) {
            const auto offset = *descriptor_offset + (static_cast<std::size_t>(index) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            const auto descriptor = read_struct<IMAGE_IMPORT_DESCRIPTOR>(bytes, offset);
            if (!descriptor.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE import descriptor"));
            }
            if (is_null_import_descriptor(*descriptor)) {
                return imports;
            }

            const auto dll_name_offset = rva_to_file_offset(bytes, sections, descriptor->Name, 1u);
            if (!dll_name_offset.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE import DLL name"));
            }
            auto dll = read_c_string(bytes, *dll_name_offset);
            if (!dll) {
                return std::unexpected(std::move(dll.error()));
            }

            const auto lookup_table_rva =
                descriptor->OriginalFirstThunk == 0u ? descriptor->FirstThunk : descriptor->OriginalFirstThunk;
            if (lookup_table_rva == 0u) {
                continue;
            }

            if (is_pe64) {
                auto result = read_import_thunks<std::uint64_t>(
                    bytes,
                    sections,
                    *dll,
                    lookup_table_rva,
                    descriptor->FirstThunk,
                    IMAGE_ORDINAL_FLAG64,
                    imports);
                if (!result) {
                    return std::unexpected(std::move(result.error()));
                }
                continue;
            }

            auto result = read_import_thunks<std::uint32_t>(
                bytes,
                sections,
                *dll,
                lookup_table_rva,
                descriptor->FirstThunk,
                IMAGE_ORDINAL_FLAG32,
                imports);
            if (!result) {
                return std::unexpected(std::move(result.error()));
            }
        }

        return std::unexpected(rule_engine::single_error("pe", "image import descriptor table exceeds safety limit"));
    }

    [[nodiscard]] rule_engine::Value export_value(const std::string &module,
                                                  rule_engine::Value name,
                                                  const std::uint32_t ordinal,
                                                  const std::uint32_t rva,
                                                  const bool forwarded,
                                                  rule_engine::Value forwarder) {
        return rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
            rule_engine::ObjectEntry {.key = "module", .value = rule_engine::Value::string(module)},
            rule_engine::ObjectEntry {.key = "name", .value = std::move(name)},
            rule_engine::ObjectEntry {
                .key = "ordinal",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(ordinal)),
            },
            rule_engine::ObjectEntry {
                .key = "rva",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(rva)),
            },
            rule_engine::ObjectEntry {.key = "forwarded", .value = rule_engine::Value::boolean(forwarded)},
            rule_engine::ObjectEntry {.key = "forwarder", .value = std::move(forwarder)},
        });
    }

    [[nodiscard]] bool is_forwarder_rva(const std::uint32_t export_rva,
                                        const std::uint32_t directory_rva,
                                        const std::uint32_t directory_size) noexcept {
        if (directory_rva == 0u || directory_size == 0u || export_rva < directory_rva) {
            return false;
        }
        return static_cast<std::uint64_t>(export_rva - directory_rva) < static_cast<std::uint64_t>(directory_size);
    }

    [[nodiscard]] std::expected<std::vector<rule_engine::Value>, rule_engine::ErrorSet>
    read_exports(const std::vector<std::uint8_t> &bytes,
                 const std::vector<IMAGE_SECTION_HEADER> &sections,
                 const std::uint32_t export_directory_rva,
                 const std::uint32_t export_directory_size) {
        std::vector<rule_engine::Value> exports;
        if (export_directory_rva == 0u || export_directory_size == 0u) {
            return exports;
        }

        const auto directory_offset =
            rva_to_file_offset(bytes, sections, export_directory_rva, sizeof(IMAGE_EXPORT_DIRECTORY));
        if (!directory_offset.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE export directory"));
        }
        const auto directory = read_struct<IMAGE_EXPORT_DIRECTORY>(bytes, *directory_offset);
        if (!directory.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE export header"));
        }
        if (directory->NumberOfFunctions > max_exports || directory->NumberOfNames > max_exports) {
            return std::unexpected(rule_engine::single_error("pe", "image export table exceeds safety limit"));
        }

        std::string module;
        if (directory->Name != 0u) {
            const auto module_offset = rva_to_file_offset(bytes, sections, directory->Name, 1u);
            if (!module_offset.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE export module name"));
            }
            auto module_name = read_c_string(bytes, *module_offset);
            if (!module_name) {
                return std::unexpected(std::move(module_name.error()));
            }
            module = std::move(*module_name);
        }

        const auto function_count = static_cast<std::size_t>(directory->NumberOfFunctions);
        const auto name_count = static_cast<std::size_t>(directory->NumberOfNames);
        std::vector<std::optional<std::string>> names_by_index(function_count);

        if (name_count > 0u) {
            const auto name_table_offset = rva_to_file_offset(
                bytes,
                sections,
                directory->AddressOfNames,
                static_cast<std::uint64_t>(name_count) * sizeof(DWORD));
            const auto ordinal_table_offset = rva_to_file_offset(
                bytes,
                sections,
                directory->AddressOfNameOrdinals,
                static_cast<std::uint64_t>(name_count) * sizeof(WORD));
            if (!name_table_offset.has_value() || !ordinal_table_offset.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE export name table"));
            }

            for (std::size_t index = 0u; index < name_count; ++index) {
                const auto name_rva = read_struct<DWORD>(bytes, *name_table_offset + (index * sizeof(DWORD)));
                const auto ordinal_index = read_struct<WORD>(bytes, *ordinal_table_offset + (index * sizeof(WORD)));
                if (!name_rva.has_value() || !ordinal_index.has_value()) {
                    return std::unexpected(
                        rule_engine::single_error("pe", "image has a truncated PE export name entry"));
                }
                if (static_cast<std::size_t>(*ordinal_index) >= function_count) {
                    return std::unexpected(
                        rule_engine::single_error("pe", "image export name ordinal is out of range"));
                }
                const auto name_offset = rva_to_file_offset(bytes, sections, *name_rva, 1u);
                if (!name_offset.has_value()) {
                    return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE export name"));
                }
                auto export_name = read_c_string(bytes, *name_offset);
                if (!export_name) {
                    return std::unexpected(std::move(export_name.error()));
                }
                names_by_index[static_cast<std::size_t>(*ordinal_index)] = std::move(*export_name);
            }
        }

        if (function_count == 0u) {
            return exports;
        }

        const auto function_table_offset = rva_to_file_offset(
            bytes,
            sections,
            directory->AddressOfFunctions,
            static_cast<std::uint64_t>(function_count) * sizeof(DWORD));
        if (!function_table_offset.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE export function table"));
        }

        exports.reserve(function_count);
        for (std::size_t index = 0u; index < function_count; ++index) {
            const auto function_rva = read_struct<DWORD>(bytes, *function_table_offset + (index * sizeof(DWORD)));
            if (!function_rva.has_value()) {
                return std::unexpected(
                    rule_engine::single_error("pe", "image has a truncated PE export function entry"));
            }
            if (*function_rva == 0u) {
                continue;
            }

            const auto ordinal = directory->Base + static_cast<std::uint32_t>(index);
            auto name = names_by_index[index].has_value() ? rule_engine::Value::string(*names_by_index[index])
                                                          : rule_engine::Value::undefined();
            const auto forwarded = is_forwarder_rva(*function_rva, export_directory_rva, export_directory_size);
            auto forwarder = rule_engine::Value::undefined();
            if (forwarded) {
                const auto forwarder_offset = rva_to_file_offset(bytes, sections, *function_rva, 1u);
                if (!forwarder_offset.has_value()) {
                    return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE export forwarder"));
                }
                auto forwarder_name = read_c_string(bytes, *forwarder_offset);
                if (!forwarder_name) {
                    return std::unexpected(std::move(forwarder_name.error()));
                }
                forwarder = rule_engine::Value::string(std::move(*forwarder_name));
            }

            exports.push_back(export_value(module, std::move(name), ordinal, *function_rva, forwarded, std::move(forwarder)));
        }

        return exports;
    }

    [[nodiscard]] rule_engine::Value debug_entry_value(const IMAGE_DEBUG_DIRECTORY &entry) {
        return rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
            rule_engine::ObjectEntry {
                .key = "type",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(entry.Type)),
            },
            rule_engine::ObjectEntry {
                .key = "timestamp",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(entry.TimeDateStamp)),
            },
            rule_engine::ObjectEntry {
                .key = "major_version",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(entry.MajorVersion)),
            },
            rule_engine::ObjectEntry {
                .key = "minor_version",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(entry.MinorVersion)),
            },
            rule_engine::ObjectEntry {
                .key = "size",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(entry.SizeOfData)),
            },
            rule_engine::ObjectEntry {
                .key = "address_of_raw_data",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(entry.AddressOfRawData)),
            },
            rule_engine::ObjectEntry {
                .key = "pointer_to_raw_data",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(entry.PointerToRawData)),
            },
        });
    }

    [[nodiscard]] std::expected<std::vector<rule_engine::Value>, rule_engine::ErrorSet>
    read_debug_entries(const std::vector<std::uint8_t> &bytes,
                       const std::vector<IMAGE_SECTION_HEADER> &sections,
                       const std::uint32_t debug_directory_rva,
                       const std::uint32_t debug_directory_size) {
        std::vector<rule_engine::Value> entries;
        if (debug_directory_rva == 0u || debug_directory_size == 0u) {
            return entries;
        }
        if ((debug_directory_size % sizeof(IMAGE_DEBUG_DIRECTORY)) != 0u) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE debug directory"));
        }

        const auto count = static_cast<std::size_t>(debug_directory_size / sizeof(IMAGE_DEBUG_DIRECTORY));
        if (count > max_debug_entries) {
            return std::unexpected(rule_engine::single_error("pe", "image debug directory exceeds safety limit"));
        }

        const auto directory_offset = rva_to_file_offset(bytes, sections, debug_directory_rva, debug_directory_size);
        if (!directory_offset.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE debug directory"));
        }

        entries.reserve(count);
        for (std::size_t index = 0u; index < count; ++index) {
            const auto offset = *directory_offset + (index * sizeof(IMAGE_DEBUG_DIRECTORY));
            const auto entry = read_struct<IMAGE_DEBUG_DIRECTORY>(bytes, offset);
            if (!entry.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE debug entry"));
            }
            entries.push_back(debug_entry_value(*entry));
        }
        return entries;
    }

    void append_utf8(std::string &out, const std::uint32_t code_point) {
        if (code_point <= 0x7fu) {
            out.push_back(static_cast<char>(code_point));
            return;
        }
        if (code_point <= 0x7ffu) {
            out.push_back(static_cast<char>(0xc0u | ((code_point >> 6u) & 0x1fu)));
            out.push_back(static_cast<char>(0x80u | (code_point & 0x3fu)));
            return;
        }
        out.push_back(static_cast<char>(0xe0u | ((code_point >> 12u) & 0x0fu)));
        out.push_back(static_cast<char>(0x80u | ((code_point >> 6u) & 0x3fu)));
        out.push_back(static_cast<char>(0x80u | (code_point & 0x3fu)));
    }

    [[nodiscard]] std::expected<std::string, rule_engine::ErrorSet>
    read_resource_string(const std::vector<std::uint8_t> &bytes,
                         const std::size_t resource_base_offset,
                         const std::uint32_t relative_offset) {
        const auto offset = resource_base_offset + static_cast<std::size_t>(relative_offset);
        const auto length = read_struct<WORD>(bytes, offset);
        if (!length.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE resource name"));
        }
        if (*length > max_resource_name_chars) {
            return std::unexpected(rule_engine::single_error("pe", "image PE resource name exceeds safety limit"));
        }

        const auto chars_offset = offset + sizeof(WORD);
        const auto byte_count = static_cast<std::size_t>(*length) * sizeof(WCHAR);
        if (chars_offset > bytes.size() || byte_count > bytes.size() - chars_offset) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE resource name string"));
        }

        std::string out;
        out.reserve(*length);
        for (std::size_t index = 0u; index < static_cast<std::size_t>(*length); ++index) {
            const auto code_unit = read_struct<WORD>(bytes, chars_offset + (index * sizeof(WORD)));
            if (!code_unit.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE resource name code unit"));
            }
            append_utf8(out, static_cast<std::uint32_t>(*code_unit));
        }
        return out;
    }

    [[nodiscard]] std::expected<ResourceName, rule_engine::ErrorSet>
    read_resource_name(const std::vector<std::uint8_t> &bytes,
                       const std::size_t resource_base_offset,
                       const std::uint32_t raw_name) {
        if ((raw_name & resource_directory_flag) == 0u) {
            return ResourceName {
                .id = rule_engine::Value::integer(static_cast<std::int64_t>(raw_name & resource_offset_mask)),
                .name = rule_engine::Value::undefined(),
            };
        }

        auto name = read_resource_string(bytes, resource_base_offset, raw_name & resource_offset_mask);
        if (!name) {
            return std::unexpected(std::move(name.error()));
        }
        return ResourceName {
            .id = rule_engine::Value::undefined(),
            .name = rule_engine::Value::string(std::move(*name)),
        };
    }

    [[nodiscard]] rule_engine::Value resource_value(const std::vector<ResourceName> &path,
                                                    const IMAGE_RESOURCE_DATA_ENTRY &entry) {
        const auto undefined_name = [] { return ResourceName {.id = rule_engine::Value::undefined(), .name = rule_engine::Value::undefined()}; };
        const auto type = path.size() > 0u ? path[0] : undefined_name();
        const auto name = path.size() > 1u ? path[1] : undefined_name();
        const auto language = path.size() > 2u ? path[2] : undefined_name();

        return rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
            rule_engine::ObjectEntry {.key = "type_id", .value = type.id},
            rule_engine::ObjectEntry {.key = "type_name", .value = type.name},
            rule_engine::ObjectEntry {.key = "name_id", .value = name.id},
            rule_engine::ObjectEntry {.key = "name", .value = name.name},
            rule_engine::ObjectEntry {.key = "language_id", .value = language.id},
            rule_engine::ObjectEntry {
                .key = "rva",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(entry.OffsetToData)),
            },
            rule_engine::ObjectEntry {
                .key = "size",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(entry.Size)),
            },
            rule_engine::ObjectEntry {
                .key = "code_page",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(entry.CodePage)),
            },
        });
    }

    [[nodiscard]] std::expected<void, rule_engine::ErrorSet>
    walk_resource_directory(const std::vector<std::uint8_t> &bytes,
                            const std::size_t resource_base_offset,
                            const std::uint32_t relative_offset,
                            const std::uint32_t depth,
                            std::vector<ResourceName> path,
                            std::vector<rule_engine::Value> &resources) {
        if (depth > max_resource_depth) {
            return std::unexpected(rule_engine::single_error("pe", "image PE resource tree exceeds safety limit"));
        }
        if (resources.size() > max_resource_entries) {
            return std::unexpected(rule_engine::single_error("pe", "image PE resource count exceeds safety limit"));
        }

        const auto directory_offset = resource_base_offset + static_cast<std::size_t>(relative_offset);
        const auto directory = read_struct<IMAGE_RESOURCE_DIRECTORY>(bytes, directory_offset);
        if (!directory.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE resource directory"));
        }

        const auto total_entries = static_cast<std::size_t>(directory->NumberOfNamedEntries) +
                                   static_cast<std::size_t>(directory->NumberOfIdEntries);
        if (total_entries > max_resource_entries || resources.size() + total_entries > max_resource_entries) {
            return std::unexpected(rule_engine::single_error("pe", "image PE resource directory exceeds safety limit"));
        }

        const auto entries_offset = directory_offset + sizeof(IMAGE_RESOURCE_DIRECTORY);
        if (entries_offset > bytes.size() ||
            (total_entries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) > bytes.size() - entries_offset) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE resource entry table"));
        }

        for (std::size_t index = 0u; index < total_entries; ++index) {
            const auto entry_offset = entries_offset + (index * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
            const auto entry = read_struct<IMAGE_RESOURCE_DIRECTORY_ENTRY>(bytes, entry_offset);
            if (!entry.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE resource entry"));
            }

            auto child_path = path;
            auto name = read_resource_name(bytes, resource_base_offset, entry->Name);
            if (!name) {
                return std::unexpected(std::move(name.error()));
            }
            child_path.push_back(std::move(*name));

            const auto child_offset = entry->OffsetToData & resource_offset_mask;
            if ((entry->OffsetToData & resource_directory_flag) != 0u) {
                auto result =
                    walk_resource_directory(bytes, resource_base_offset, child_offset, depth + 1u, std::move(child_path), resources);
                if (!result) {
                    return std::unexpected(std::move(result.error()));
                }
                continue;
            }

            const auto data_entry_offset = resource_base_offset + static_cast<std::size_t>(child_offset);
            const auto data_entry = read_struct<IMAGE_RESOURCE_DATA_ENTRY>(bytes, data_entry_offset);
            if (!data_entry.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE resource data entry"));
            }
            resources.push_back(resource_value(child_path, *data_entry));
        }

        return {};
    }

    [[nodiscard]] std::expected<std::vector<rule_engine::Value>, rule_engine::ErrorSet>
    read_resources(const std::vector<std::uint8_t> &bytes,
                   const std::vector<IMAGE_SECTION_HEADER> &sections,
                   const std::uint32_t resource_directory_rva,
                   const std::uint32_t resource_directory_size) {
        std::vector<rule_engine::Value> resources;
        if (resource_directory_rva == 0u || resource_directory_size == 0u) {
            return resources;
        }

        const auto resource_base_offset = rva_to_file_offset(bytes, sections, resource_directory_rva, resource_directory_size);
        if (!resource_base_offset.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE resource directory"));
        }

        auto result = walk_resource_directory(bytes, *resource_base_offset, 0u, 0u, {}, resources);
        if (!result) {
            return std::unexpected(std::move(result.error()));
        }
        return resources;
    }

    [[nodiscard]] std::size_t aligned_certificate_length(const std::size_t length) noexcept {
        const auto remainder = length % certificate_alignment;
        if (remainder == 0u) {
            return length;
        }
        return length + (certificate_alignment - remainder);
    }

    [[nodiscard]] rule_engine::Value certificate_value(const std::size_t file_offset,
                                                       const CertificateHeader &certificate) {
        return rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
            rule_engine::ObjectEntry {
                .key = "file_offset",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(file_offset)),
            },
            rule_engine::ObjectEntry {
                .key = "size",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(certificate.length)),
            },
            rule_engine::ObjectEntry {
                .key = "revision",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(certificate.revision)),
            },
            rule_engine::ObjectEntry {
                .key = "type",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(certificate.type)),
            },
            rule_engine::ObjectEntry {
                .key = "payload_size",
                .value = rule_engine::Value::integer(
                    static_cast<std::int64_t>(certificate.length - sizeof(CertificateHeader))),
            },
        });
    }

    [[nodiscard]] bool is_zero_padding(const std::vector<std::uint8_t> &bytes,
                                       const std::size_t offset,
                                       const std::size_t size) {
        if (offset > bytes.size() || size > bytes.size() - offset) {
            return false;
        }
        return std::ranges::all_of(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                   bytes.begin() + static_cast<std::ptrdiff_t>(offset + size),
                                   [](const auto value) { return value == 0u; });
    }

    [[nodiscard]] std::expected<std::vector<rule_engine::Value>, rule_engine::ErrorSet>
    read_certificates(const std::vector<std::uint8_t> &bytes,
                      const std::uint32_t certificate_table_offset,
                      const std::uint32_t certificate_table_size) {
        std::vector<rule_engine::Value> certificates;
        if (certificate_table_offset == 0u || certificate_table_size == 0u) {
            return certificates;
        }

        const auto table_offset = static_cast<std::size_t>(certificate_table_offset);
        const auto table_size = static_cast<std::size_t>(certificate_table_size);
        if (table_offset > bytes.size() || table_size > bytes.size() - table_offset) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE certificate table"));
        }

        const auto table_end = table_offset + table_size;
        auto cursor = table_offset;
        while (cursor < table_end) {
            const auto remaining = table_end - cursor;
            if (remaining < sizeof(CertificateHeader)) {
                if (is_zero_padding(bytes, cursor, remaining)) {
                    return certificates;
                }
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE certificate entry"));
            }

            if (certificates.size() >= max_certificates) {
                return std::unexpected(rule_engine::single_error("pe", "image PE certificate count exceeds safety limit"));
            }

            const auto header = read_struct<CertificateHeader>(bytes, cursor);
            if (!header.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE certificate entry"));
            }
            if (header->length < sizeof(CertificateHeader)) {
                return std::unexpected(rule_engine::single_error("pe", "image has an invalid PE certificate length"));
            }
            if (static_cast<std::size_t>(header->length) > remaining) {
                return std::unexpected(rule_engine::single_error("pe", "image has truncated PE certificate data"));
            }

            certificates.push_back(certificate_value(cursor, *header));

            const auto aligned_length = aligned_certificate_length(static_cast<std::size_t>(header->length));
            if (aligned_length > remaining) {
                cursor = table_end;
                continue;
            }
            cursor += aligned_length;
        }

        return certificates;
    }

    [[nodiscard]] rule_engine::Value tls_callback_value(const std::size_t index,
                                                        const std::uint64_t callback_va,
                                                        const std::uint64_t image_base) {
        return rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
            rule_engine::ObjectEntry {
                .key = "index",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(index)),
            },
            rule_engine::ObjectEntry {
                .key = "va",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(callback_va)),
            },
            rule_engine::ObjectEntry {
                .key = "rva",
                .value = rule_engine::Value::integer(static_cast<std::int64_t>(callback_va - image_base)),
            },
        });
    }

    template <typename TlsDirectory, typename CallbackAddress>
    [[nodiscard]] std::expected<std::vector<rule_engine::Value>, rule_engine::ErrorSet>
    read_tls_callbacks(const std::vector<std::uint8_t> &bytes,
                       const std::vector<IMAGE_SECTION_HEADER> &sections,
                       const std::uint64_t image_base,
                       const std::uint32_t tls_directory_rva,
                       const std::uint32_t tls_directory_size) {
        std::vector<rule_engine::Value> callbacks;
        if (tls_directory_rva == 0u || tls_directory_size == 0u) {
            return callbacks;
        }
        if (tls_directory_size < sizeof(TlsDirectory)) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE TLS directory"));
        }

        const auto tls_offset = rva_to_file_offset(bytes, sections, tls_directory_rva, sizeof(TlsDirectory));
        if (!tls_offset.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE TLS directory"));
        }
        const auto directory = read_struct<TlsDirectory>(bytes, *tls_offset);
        if (!directory.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE TLS directory"));
        }

        const auto callback_table_va = static_cast<std::uint64_t>(directory->AddressOfCallBacks);
        if (callback_table_va == 0u) {
            return callbacks;
        }
        if (callback_table_va < image_base) {
            return std::unexpected(rule_engine::single_error("pe", "image has an invalid PE TLS callback table VA"));
        }

        const auto callback_table_rva = callback_table_va - image_base;
        const auto callback_table_offset =
            rva_to_file_offset(bytes, sections, callback_table_rva, sizeof(CallbackAddress));
        if (!callback_table_offset.has_value()) {
            return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE TLS callback table"));
        }

        callbacks.reserve(1u);
        for (std::size_t index = 0u; index < max_tls_callbacks; ++index) {
            const auto offset = *callback_table_offset + (index * sizeof(CallbackAddress));
            const auto callback = read_struct<CallbackAddress>(bytes, offset);
            if (!callback.has_value()) {
                return std::unexpected(rule_engine::single_error("pe", "image has a truncated PE TLS callback entry"));
            }

            const auto callback_va = static_cast<std::uint64_t>(*callback);
            if (callback_va == 0u) {
                return callbacks;
            }
            if (callback_va < image_base) {
                return std::unexpected(rule_engine::single_error("pe", "image has an invalid PE TLS callback VA"));
            }

            callbacks.push_back(tls_callback_value(index, callback_va, image_base));
        }

        return std::unexpected(rule_engine::single_error("pe", "image PE TLS callback table exceeds safety limit"));
    }

    [[nodiscard]] std::vector<rule_engine::Fact> valid_pe_facts(const std::string &subject_id,
                                                                const IMAGE_FILE_HEADER &file_header,
                                                                const std::uint32_t entry_point,
                                                                const std::uint32_t size_of_image,
                                                                const std::uint16_t subsystem,
                                                                const std::uint16_t dll_characteristics,
                                                                std::vector<rule_engine::Value> sections,
                                                                std::vector<rule_engine::Value> imports,
                                                                std::vector<rule_engine::Value> exports,
                                                                std::vector<rule_engine::Value> debug_entries,
                                                                std::vector<rule_engine::Value> resources,
                                                                std::vector<rule_engine::Value> certificates,
                                                                std::vector<rule_engine::Value> tls_callbacks) {
        std::vector<rule_engine::Fact> out;
        out.push_back(make_fact(subject_id,
                                "pe.is_valid",
                                rule_engine::Value::boolean(true),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.machine",
                                rule_engine::Value::integer(static_cast<std::int64_t>(file_header.Machine)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.number_of_sections",
                                rule_engine::Value::integer(static_cast<std::int64_t>(file_header.NumberOfSections)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.entry_point",
                                rule_engine::Value::integer(static_cast<std::int64_t>(entry_point)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.size_of_image",
                                rule_engine::Value::integer(static_cast<std::int64_t>(size_of_image)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.subsystem",
                                rule_engine::Value::integer(static_cast<std::int64_t>(subsystem)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.characteristics",
                                rule_engine::Value::integer(static_cast<std::int64_t>(file_header.Characteristics)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.dll_characteristics",
                                rule_engine::Value::integer(static_cast<std::int64_t>(dll_characteristics)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.timestamp",
                                rule_engine::Value::integer(static_cast<std::int64_t>(file_header.TimeDateStamp)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.sections",
                                rule_engine::Value::array(std::move(sections)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.imports",
                                rule_engine::Value::array(std::move(imports)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.exports",
                                rule_engine::Value::array(std::move(exports)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.debug_entries",
                                rule_engine::Value::array(std::move(debug_entries)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.resources",
                                rule_engine::Value::array(std::move(resources)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.certificates",
                                rule_engine::Value::array(std::move(certificates)),
                                rule_engine::FactStatus::available));
        out.push_back(make_fact(subject_id,
                                "pe.tls_callbacks",
                                rule_engine::Value::array(std::move(tls_callbacks)),
                                rule_engine::FactStatus::available));
        return out;
    }
} // namespace

namespace rule_engine::windows {
    std::expected<std::vector<Fact>, ErrorSet> read_pe_image_facts(std::string subject_id,
                                                                   const std::filesystem::path &image_path) {
        auto bytes = read_file_bytes(image_path);
        if (!bytes) {
            const auto diagnostic = bytes.error().diagnostics.empty() ? std::string {"failed to read PE image"}
                                                                      : bytes.error().diagnostics[0].message;
            return diagnostic_facts(subject_id, FactStatus::unavailable, diagnostic);
        }

        const auto dos = read_struct<IMAGE_DOS_HEADER>(*bytes, 0u);
        if (!dos.has_value() || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) {
            return diagnostic_facts(subject_id, FactStatus::available, "image is not a PE file");
        }

        const auto nt_offset = static_cast<std::size_t>(dos->e_lfanew);
        const auto signature = read_struct<DWORD>(*bytes, nt_offset);
        if (!signature.has_value() || *signature != IMAGE_NT_SIGNATURE) {
            return diagnostic_facts(subject_id, FactStatus::available, "image has no PE signature");
        }

        constexpr auto signature_size = sizeof(DWORD);
        const auto file_header_offset = nt_offset + signature_size;
        const auto file_header = read_struct<IMAGE_FILE_HEADER>(*bytes, file_header_offset);
        if (!file_header.has_value()) {
            return diagnostic_facts(subject_id, FactStatus::available, "image has no PE file header");
        }

        const auto optional_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
        const auto optional_magic = read_struct<WORD>(*bytes, optional_offset);
        if (!optional_magic.has_value()) {
            return diagnostic_facts(subject_id, FactStatus::available, "image has no PE optional header");
        }

        if (*optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            const auto optional_header = read_struct<IMAGE_OPTIONAL_HEADER64>(*bytes, optional_offset);
            if (!optional_header.has_value()) {
                return diagnostic_facts(subject_id, FactStatus::available, "image has a truncated PE32+ optional header");
            }
            auto sections = read_sections(*bytes, *file_header, optional_offset);
            if (!sections) {
                const auto diagnostic = sections.error().diagnostics.empty() ? std::string {"failed to read PE sections"}
                                                                             : sections.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto imports = read_imports(
                *bytes,
                sections->headers,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
                true);
            if (!imports) {
                const auto diagnostic = imports.error().diagnostics.empty() ? std::string {"failed to read PE imports"}
                                                                            : imports.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto exports = read_exports(
                *bytes,
                sections->headers,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
            if (!exports) {
                const auto diagnostic = exports.error().diagnostics.empty() ? std::string {"failed to read PE exports"}
                                                                            : exports.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto debug_entries = read_debug_entries(
                *bytes,
                sections->headers,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
            if (!debug_entries) {
                const auto diagnostic = debug_entries.error().diagnostics.empty()
                                            ? std::string {"failed to read PE debug directory"}
                                            : debug_entries.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto resources = read_resources(
                *bytes,
                sections->headers,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
            if (!resources) {
                const auto diagnostic = resources.error().diagnostics.empty()
                                            ? std::string {"failed to read PE resources"}
                                            : resources.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto certificates = read_certificates(
                *bytes,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
            if (!certificates) {
                const auto diagnostic = certificates.error().diagnostics.empty()
                                            ? std::string {"failed to read PE certificates"}
                                            : certificates.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto tls_callbacks = read_tls_callbacks<IMAGE_TLS_DIRECTORY64, std::uint64_t>(
                *bytes,
                sections->headers,
                optional_header->ImageBase,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
            if (!tls_callbacks) {
                const auto diagnostic = tls_callbacks.error().diagnostics.empty()
                                            ? std::string {"failed to read PE TLS callbacks"}
                                            : tls_callbacks.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            return valid_pe_facts(
                subject_id,
                *file_header,
                optional_header->AddressOfEntryPoint,
                optional_header->SizeOfImage,
                optional_header->Subsystem,
                optional_header->DllCharacteristics,
                std::move(sections->values),
                std::move(*imports),
                std::move(*exports),
                std::move(*debug_entries),
                std::move(*resources),
                std::move(*certificates),
                std::move(*tls_callbacks));
        }

        if (*optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            const auto optional_header = read_struct<IMAGE_OPTIONAL_HEADER32>(*bytes, optional_offset);
            if (!optional_header.has_value()) {
                return diagnostic_facts(subject_id, FactStatus::available, "image has a truncated PE32 optional header");
            }
            auto sections = read_sections(*bytes, *file_header, optional_offset);
            if (!sections) {
                const auto diagnostic = sections.error().diagnostics.empty() ? std::string {"failed to read PE sections"}
                                                                             : sections.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto imports = read_imports(
                *bytes,
                sections->headers,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
                false);
            if (!imports) {
                const auto diagnostic = imports.error().diagnostics.empty() ? std::string {"failed to read PE imports"}
                                                                            : imports.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto exports = read_exports(
                *bytes,
                sections->headers,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
            if (!exports) {
                const auto diagnostic = exports.error().diagnostics.empty() ? std::string {"failed to read PE exports"}
                                                                            : exports.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto debug_entries = read_debug_entries(
                *bytes,
                sections->headers,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
            if (!debug_entries) {
                const auto diagnostic = debug_entries.error().diagnostics.empty()
                                            ? std::string {"failed to read PE debug directory"}
                                            : debug_entries.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto resources = read_resources(
                *bytes,
                sections->headers,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
            if (!resources) {
                const auto diagnostic = resources.error().diagnostics.empty()
                                            ? std::string {"failed to read PE resources"}
                                            : resources.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto certificates = read_certificates(
                *bytes,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
            if (!certificates) {
                const auto diagnostic = certificates.error().diagnostics.empty()
                                            ? std::string {"failed to read PE certificates"}
                                            : certificates.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            auto tls_callbacks = read_tls_callbacks<IMAGE_TLS_DIRECTORY32, std::uint32_t>(
                *bytes,
                sections->headers,
                optional_header->ImageBase,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
                optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
            if (!tls_callbacks) {
                const auto diagnostic = tls_callbacks.error().diagnostics.empty()
                                            ? std::string {"failed to read PE TLS callbacks"}
                                            : tls_callbacks.error().diagnostics[0].message;
                return diagnostic_facts(subject_id, FactStatus::available, diagnostic);
            }
            return valid_pe_facts(
                subject_id,
                *file_header,
                optional_header->AddressOfEntryPoint,
                optional_header->SizeOfImage,
                optional_header->Subsystem,
                optional_header->DllCharacteristics,
                std::move(sections->values),
                std::move(*imports),
                std::move(*exports),
                std::move(*debug_entries),
                std::move(*resources),
                std::move(*certificates),
                std::move(*tls_callbacks));
        }

        return diagnostic_facts(subject_id, FactStatus::available, "image has an unsupported PE optional header");
    }
} // namespace rule_engine::windows
