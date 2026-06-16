#include <rule_engine/windows/pe_provider.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace {
    using namespace std::chrono_literals;

    constexpr auto pe_fact_ttl = 30s;

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

    [[nodiscard]] std::vector<rule_engine::Fact> valid_pe_facts(const std::string &subject_id,
                                                                const IMAGE_FILE_HEADER &file_header,
                                                                const std::uint32_t entry_point,
                                                                const std::uint32_t size_of_image) {
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
            return valid_pe_facts(
                subject_id, *file_header, optional_header->AddressOfEntryPoint, optional_header->SizeOfImage);
        }

        if (*optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            const auto optional_header = read_struct<IMAGE_OPTIONAL_HEADER32>(*bytes, optional_offset);
            if (!optional_header.has_value()) {
                return diagnostic_facts(subject_id, FactStatus::available, "image has a truncated PE32 optional header");
            }
            return valid_pe_facts(
                subject_id, *file_header, optional_header->AddressOfEntryPoint, optional_header->SizeOfImage);
        }

        return diagnostic_facts(subject_id, FactStatus::available, "image has an unsupported PE optional header");
    }
} // namespace rule_engine::windows
