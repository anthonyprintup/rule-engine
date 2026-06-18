#include <rule_engine/client_protocol.hpp>
#include <rule_engine/custom_fact_fixture.hpp>
#include <rule_engine/module_config.hpp>
#include <rule_engine/modules.hpp>
#include <rule_engine/optimizer.hpp>
#include <rule_engine/protocol.hpp>
#include <rule_engine/windows/pe_provider.hpp>
#include <rule_engine/windows/process_provider.hpp>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <expected>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {
    [[nodiscard]] std::filesystem::path fixture_path(const std::string_view relative_path) {
        return std::filesystem::path {RULE_ENGINE_SOURCE_DIR} / std::filesystem::path {relative_path};
    }

    [[nodiscard]] std::optional<rule_engine::Fact> find_fact(const std::vector<rule_engine::Fact> &facts,
                                                             const std::string_view key) {
        const auto found = std::ranges::find_if(facts, [&](const auto &fact) { return fact.key == key; });
        if (found == facts.end()) {
            return std::nullopt;
        }
        return *found;
    }

    [[nodiscard]] const rule_engine::Fact *find_fact(const std::vector<rule_engine::Fact> &facts,
                                                     const std::string_view subject_id,
                                                     const std::string_view key) {
        const auto found = std::ranges::find_if(facts, [&](const auto &fact) {
            return fact.subject_id == subject_id && fact.key == key;
        });
        if (found == facts.end()) {
            return nullptr;
        }
        return std::addressof(*found);
    }

    [[nodiscard]] const rule_engine::Value *find_object_entry(const rule_engine::ObjectValue &object,
                                                              const std::string_view key) {
        const auto found = std::ranges::find_if(object.entries, [&](const auto &entry) { return entry.key == key; });
        if (found == object.entries.end()) {
            return nullptr;
        }
        return std::addressof(found->value);
    }

    [[nodiscard]] std::vector<std::byte> ascii_bytes(const std::string_view text) {
        std::vector<std::byte> out;
        out.reserve(text.size());
        for (const auto ch : text) { out.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch))); }
        return out;
    }

    struct TemporaryFile {
        std::filesystem::path path;

        explicit TemporaryFile(std::filesystem::path value): path {std::move(value)} {}
        ~TemporaryFile() noexcept {
            if (!path.empty()) {
                DeleteFileW(path.c_str());
            }
        }

        TemporaryFile(const TemporaryFile &) = delete;
        TemporaryFile &operator=(const TemporaryFile &) = delete;
    };

    struct TemporaryProcess {
        PROCESS_INFORMATION info {};

        explicit TemporaryProcess(PROCESS_INFORMATION value) noexcept: info {value} {}
        ~TemporaryProcess() noexcept { close(); }

        void close() noexcept {
            if (info.hProcess != nullptr) {
                TerminateProcess(info.hProcess, 0u);
                WaitForSingleObject(info.hProcess, 5000u);
                CloseHandle(info.hProcess);
                info.hProcess = nullptr;
            }
            if (info.hThread != nullptr) {
                CloseHandle(info.hThread);
                info.hThread = nullptr;
            }
        }

        TemporaryProcess(const TemporaryProcess &) = delete;
        TemporaryProcess &operator=(const TemporaryProcess &) = delete;
    };

    [[nodiscard]] TemporaryProcess start_hidden_ping_process() {
        std::wstring system_dir;
        system_dir.resize(MAX_PATH);
        const auto system_dir_size = GetSystemDirectoryW(system_dir.data(), static_cast<UINT>(system_dir.size()));
        REQUIRE(system_dir_size > 0u);
        REQUIRE(system_dir_size < system_dir.size());
        system_dir.resize(system_dir_size);

        const auto image_path = std::filesystem::path {system_dir} / L"ping.exe";
        auto command_line = L"\"" + image_path.wstring() + L"\" -n 30 127.0.0.1";
        STARTUPINFOW startup {};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION info {};
        REQUIRE(CreateProcessW(image_path.c_str(),
                               command_line.data(),
                               nullptr,
                               nullptr,
                               FALSE,
                               CREATE_NO_WINDOW,
                               nullptr,
                               nullptr,
                               &startup,
                               &info) != FALSE);
        return TemporaryProcess {info};
    }

    template<typename T>
    void write_struct_at(std::vector<std::uint8_t> &bytes, const std::size_t offset, const T &value) {
        REQUIRE(offset <= bytes.size());
        REQUIRE(sizeof(T) <= bytes.size() - offset);
        std::memcpy(bytes.data() + offset, &value, sizeof(T));
    }

    void write_u32_at(std::vector<std::uint8_t> &bytes, const std::size_t offset, const std::uint32_t value) {
        REQUIRE(offset <= bytes.size());
        REQUIRE(sizeof(value) <= bytes.size() - offset);
        bytes[offset] = static_cast<std::uint8_t>(value & 0xffu);
        bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 8u) & 0xffu);
        bytes[offset + 2u] = static_cast<std::uint8_t>((value >> 16u) & 0xffu);
        bytes[offset + 3u] = static_cast<std::uint8_t>((value >> 24u) & 0xffu);
    }

    void write_u16_at(std::vector<std::uint8_t> &bytes, const std::size_t offset, const std::uint16_t value) {
        REQUIRE(offset <= bytes.size());
        REQUIRE(sizeof(value) <= bytes.size() - offset);
        bytes[offset] = static_cast<std::uint8_t>(value & 0xffu);
        bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 8u) & 0xffu);
    }

    [[nodiscard]] TemporaryFile write_temp_binary_with_extension(const std::wstring_view prefix,
                                                                 const std::vector<std::uint8_t> &bytes,
                                                                 const std::wstring_view extension) {
        std::wstring temp_dir;
        temp_dir.resize(MAX_PATH);
        const auto temp_dir_size = GetTempPathW(static_cast<DWORD>(temp_dir.size()), temp_dir.data());
        REQUIRE(temp_dir_size > 0u);
        REQUIRE(temp_dir_size < temp_dir.size());
        temp_dir.resize(temp_dir_size);

        const auto name = std::wstring {prefix} + L"_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
                          std::to_wstring(GetCurrentThreadId()) + std::wstring {extension};
        auto path = std::filesystem::path {temp_dir} / name;
        DeleteFileW(path.c_str());

        std::ofstream file {path, std::ios::binary};
        REQUIRE(file);
        file.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        REQUIRE(file);

        return TemporaryFile {std::move(path)};
    }

    [[nodiscard]] TemporaryFile write_temp_binary(const std::wstring_view prefix,
                                                  const std::vector<std::uint8_t> &bytes) {
        return write_temp_binary_with_extension(prefix, bytes, L".bin");
    }

    [[nodiscard]] std::filesystem::path windows_directory() {
        std::wstring buffer;
        buffer.resize(MAX_PATH);
        const auto size = GetWindowsDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
        REQUIRE(size > 0u);
        REQUIRE(size < buffer.size());
        buffer.resize(size);
        return std::filesystem::path {buffer};
    }

    [[nodiscard]] std::optional<std::filesystem::path>
    first_existing_path(const std::span<const std::filesystem::path> candidates) {
        for (const auto &candidate : candidates) {
            if (std::filesystem::exists(candidate)) {
                return candidate;
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<std::uint8_t> minimal_pe32_bytes() {
        constexpr auto nt_offset = 0x80u;
        constexpr auto optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

        std::vector<std::uint8_t> bytes(optional_offset + sizeof(IMAGE_OPTIONAL_HEADER32), 0u);

        IMAGE_DOS_HEADER dos {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = static_cast<LONG>(nt_offset);
        write_struct_at(bytes, 0u, dos);

        write_u32_at(bytes, nt_offset, IMAGE_NT_SIGNATURE);

        IMAGE_FILE_HEADER file_header {};
        file_header.Machine = IMAGE_FILE_MACHINE_I386;
        file_header.NumberOfSections = 0u;
        file_header.TimeDateStamp = 0x65a5'1111u;
        file_header.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
        file_header.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
        write_struct_at(bytes, nt_offset + sizeof(DWORD), file_header);

        IMAGE_OPTIONAL_HEADER32 optional_header {};
        optional_header.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        optional_header.ImageBase = 0x0040'0000u;
        optional_header.SectionAlignment = 0x1000u;
        optional_header.FileAlignment = 0x200u;
        optional_header.SizeOfImage = 0x1000u;
        optional_header.SizeOfHeaders = 0x200u;
        optional_header.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        optional_header.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        write_struct_at(bytes, optional_offset, optional_header);

        return bytes;
    }

    [[nodiscard]] std::vector<std::uint8_t> minimal_pe64_bytes() {
        constexpr auto nt_offset = 0x80u;
        constexpr auto optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

        std::vector<std::uint8_t> bytes(optional_offset + sizeof(IMAGE_OPTIONAL_HEADER64), 0u);

        IMAGE_DOS_HEADER dos {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = static_cast<LONG>(nt_offset);
        write_struct_at(bytes, 0u, dos);

        write_u32_at(bytes, nt_offset, IMAGE_NT_SIGNATURE);

        IMAGE_FILE_HEADER file_header {};
        file_header.Machine = IMAGE_FILE_MACHINE_AMD64;
        file_header.NumberOfSections = 0u;
        file_header.TimeDateStamp = 0x65a5'2222u;
        file_header.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        file_header.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
        write_struct_at(bytes, nt_offset + sizeof(DWORD), file_header);

        IMAGE_OPTIONAL_HEADER64 optional_header {};
        optional_header.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optional_header.ImageBase = 0x0000'0001'4000'0000u;
        optional_header.SectionAlignment = 0x1000u;
        optional_header.FileAlignment = 0x200u;
        optional_header.SizeOfImage = 0x1000u;
        optional_header.SizeOfHeaders = 0x200u;
        optional_header.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        optional_header.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        write_struct_at(bytes, optional_offset, optional_header);

        return bytes;
    }

    [[nodiscard]] std::vector<std::uint8_t> truncated_pe32_optional_header_bytes() {
        constexpr auto nt_offset = 0x80u;
        constexpr auto optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

        std::vector<std::uint8_t> bytes(optional_offset + sizeof(WORD), 0u);

        IMAGE_DOS_HEADER dos {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = static_cast<LONG>(nt_offset);
        write_struct_at(bytes, 0u, dos);

        write_u32_at(bytes, nt_offset, IMAGE_NT_SIGNATURE);

        IMAGE_FILE_HEADER file_header {};
        file_header.Machine = IMAGE_FILE_MACHINE_I386;
        file_header.NumberOfSections = 0u;
        file_header.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
        file_header.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
        write_struct_at(bytes, nt_offset + sizeof(DWORD), file_header);
        write_u16_at(bytes, optional_offset, IMAGE_NT_OPTIONAL_HDR32_MAGIC);

        return bytes;
    }

    [[nodiscard]] std::vector<std::uint8_t> unsupported_optional_header_bytes() {
        auto bytes = minimal_pe32_bytes();
        constexpr auto nt_offset = 0x80u;
        constexpr auto optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        write_u16_at(bytes, optional_offset, 0x9999u);
        return bytes;
    }

    [[nodiscard]] TemporaryFile write_pe32_certificate_fixture() {
        constexpr auto dos_offset = 0u;
        constexpr auto nt_offset = 0x80u;
        constexpr auto optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        constexpr auto section_offset = optional_offset + sizeof(IMAGE_OPTIONAL_HEADER32);
        constexpr auto certificate_offset = 0x400u;
        constexpr auto certificate_size = 0x20u;

        std::vector<std::uint8_t> bytes(certificate_offset + certificate_size, 0u);

        IMAGE_DOS_HEADER dos {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = static_cast<LONG>(nt_offset);
        write_struct_at(bytes, dos_offset, dos);

        write_u32_at(bytes, nt_offset, IMAGE_NT_SIGNATURE);

        IMAGE_FILE_HEADER file_header {};
        file_header.Machine = IMAGE_FILE_MACHINE_I386;
        file_header.NumberOfSections = 1u;
        file_header.TimeDateStamp = 0x65a5'1234u;
        file_header.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
        file_header.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
        write_struct_at(bytes, nt_offset + sizeof(DWORD), file_header);

        IMAGE_OPTIONAL_HEADER32 optional_header {};
        optional_header.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        optional_header.AddressOfEntryPoint = 0x1000u;
        optional_header.BaseOfCode = 0x1000u;
        optional_header.ImageBase = 0x400000u;
        optional_header.SectionAlignment = 0x1000u;
        optional_header.FileAlignment = 0x200u;
        optional_header.SizeOfImage = 0x2000u;
        optional_header.SizeOfHeaders = 0x200u;
        optional_header.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        optional_header.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = certificate_offset;
        optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = certificate_size;
        write_struct_at(bytes, optional_offset, optional_header);

        IMAGE_SECTION_HEADER section {};
        std::memcpy(section.Name, ".text", 5u);
        section.Misc.VirtualSize = 0x100u;
        section.VirtualAddress = 0x1000u;
        section.SizeOfRawData = 0x200u;
        section.PointerToRawData = 0x200u;
        section.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        write_struct_at(bytes, section_offset, section);

        write_u32_at(bytes, certificate_offset, certificate_size);
        write_u16_at(bytes, certificate_offset + sizeof(DWORD), 0x0200u);
        write_u16_at(bytes, certificate_offset + sizeof(DWORD) + sizeof(WORD), 0x0002u);
        std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(certificate_offset + 8u), bytes.end(), 0xa5u);

        std::wstring temp_dir;
        temp_dir.resize(MAX_PATH);
        const auto temp_dir_size = GetTempPathW(static_cast<DWORD>(temp_dir.size()), temp_dir.data());
        REQUIRE(temp_dir_size > 0u);
        REQUIRE(temp_dir_size < temp_dir.size());
        temp_dir.resize(temp_dir_size);

        auto path = std::filesystem::path {temp_dir} /
                    (L"rule_engine_certificate_fixture_" + std::to_wstring(GetCurrentProcessId()) + L".exe");
        DeleteFileW(path.c_str());

        std::ofstream file {path, std::ios::binary};
        REQUIRE(file);
        file.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        REQUIRE(file);

        return TemporaryFile {std::move(path)};
    }

    [[nodiscard]] TemporaryFile write_pe32_tls_fixture() {
        constexpr auto dos_offset = 0u;
        constexpr auto nt_offset = 0x80u;
        constexpr auto optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        constexpr auto section_offset = optional_offset + sizeof(IMAGE_OPTIONAL_HEADER32);
        constexpr auto image_base = 0x0040'0000u;
        constexpr auto section_rva = 0x1000u;
        constexpr auto section_offset_raw = 0x200u;
        constexpr auto tls_rva = 0x1100u;
        constexpr auto callback_table_rva = 0x1120u;
        constexpr auto callback_rva = 0x1234u;
        constexpr auto tls_offset = section_offset_raw + (tls_rva - section_rva);
        constexpr auto callback_table_offset = section_offset_raw + (callback_table_rva - section_rva);

        std::vector<std::uint8_t> bytes(0x600u, 0u);

        IMAGE_DOS_HEADER dos {};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = static_cast<LONG>(nt_offset);
        write_struct_at(bytes, dos_offset, dos);

        write_u32_at(bytes, nt_offset, IMAGE_NT_SIGNATURE);

        IMAGE_FILE_HEADER file_header {};
        file_header.Machine = IMAGE_FILE_MACHINE_I386;
        file_header.NumberOfSections = 1u;
        file_header.TimeDateStamp = 0x65a5'5678u;
        file_header.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
        file_header.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
        write_struct_at(bytes, nt_offset + sizeof(DWORD), file_header);

        IMAGE_OPTIONAL_HEADER32 optional_header {};
        optional_header.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        optional_header.AddressOfEntryPoint = callback_rva;
        optional_header.BaseOfCode = section_rva;
        optional_header.ImageBase = image_base;
        optional_header.SectionAlignment = 0x1000u;
        optional_header.FileAlignment = 0x200u;
        optional_header.SizeOfImage = 0x2000u;
        optional_header.SizeOfHeaders = 0x200u;
        optional_header.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        optional_header.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = tls_rva;
        optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY32);
        write_struct_at(bytes, optional_offset, optional_header);

        IMAGE_SECTION_HEADER section {};
        std::memcpy(section.Name, ".rdata", 6u);
        section.Misc.VirtualSize = 0x500u;
        section.VirtualAddress = section_rva;
        section.SizeOfRawData = 0x400u;
        section.PointerToRawData = section_offset_raw;
        section.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        write_struct_at(bytes, section_offset, section);

        IMAGE_TLS_DIRECTORY32 tls {};
        tls.StartAddressOfRawData = image_base + 0x1300u;
        tls.EndAddressOfRawData = image_base + 0x1300u;
        tls.AddressOfIndex = image_base + 0x1310u;
        tls.AddressOfCallBacks = image_base + callback_table_rva;
        write_struct_at(bytes, tls_offset, tls);
        write_u32_at(bytes, callback_table_offset, image_base + callback_rva);
        write_u32_at(bytes, callback_table_offset + sizeof(DWORD), 0u);

        std::wstring temp_dir;
        temp_dir.resize(MAX_PATH);
        const auto temp_dir_size = GetTempPathW(static_cast<DWORD>(temp_dir.size()), temp_dir.data());
        REQUIRE(temp_dir_size > 0u);
        REQUIRE(temp_dir_size < temp_dir.size());
        temp_dir.resize(temp_dir_size);

        auto path = std::filesystem::path {temp_dir} /
                    (L"rule_engine_tls_fixture_" + std::to_wstring(GetCurrentProcessId()) + L".exe");
        DeleteFileW(path.c_str());

        std::ofstream file {path, std::ios::binary};
        REQUIRE(file);
        file.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        REQUIRE(file);

        return TemporaryFile {std::move(path)};
    }

    [[nodiscard]] std::optional<std::string> write_protocol_frame(asio::ip::tcp::socket &socket,
                                                                  const std::vector<std::byte> &payload) {
        auto frame = rule_engine::protocol::encode_frame(payload);
        if (!frame) {
            return frame.error().diagnostics.empty() ? std::string {"frame encode failed"} :
                                                       frame.error().diagnostics[0].message;
        }
        asio::error_code ec;
        asio::write(socket, asio::buffer(frame->data(), frame->size()), ec);
        if (ec) {
            return ec.message();
        }
        return std::nullopt;
    }

    [[nodiscard]] std::expected<std::vector<std::byte>, std::string>
    read_protocol_frame(asio::ip::tcp::socket &socket) {
        std::array<std::byte, 4u> header {};
        asio::error_code ec;
        asio::read(socket, asio::buffer(header.data(), header.size()), ec);
        if (ec) {
            return std::unexpected(ec.message());
        }
        const auto size = (static_cast<std::uint32_t>(header[0]) << 24u) |
                          (static_cast<std::uint32_t>(header[1]) << 16u) |
                          (static_cast<std::uint32_t>(header[2]) << 8u) | static_cast<std::uint32_t>(header[3]);
        std::vector<std::byte> payload(size);
        if (!payload.empty()) {
            asio::read(socket, asio::buffer(payload.data(), payload.size()), ec);
            if (ec) {
                return std::unexpected(ec.message());
            }
        }
        return payload;
    }

    void append_u8(std::vector<std::byte> &out, const std::uint8_t value) {
        out.push_back(static_cast<std::byte>(value));
    }

    void append_u32(std::vector<std::byte> &out, const std::uint32_t value) {
        out.push_back(static_cast<std::byte>(value & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 8u) & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 16u) & 0xffu));
        out.push_back(static_cast<std::byte>((value >> 24u) & 0xffu));
    }

    void append_string(std::vector<std::byte> &out, const std::string_view value) {
        append_u32(out, static_cast<std::uint32_t>(value.size()));
        for (const auto ch : value) { out.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch))); }
    }

    void append_protocol_header(std::vector<std::byte> &out, const std::uint8_t kind) {
        out.push_back(static_cast<std::byte>('R'));
        out.push_back(static_cast<std::byte>('E'));
        out.push_back(static_cast<std::byte>('P'));
        out.push_back(static_cast<std::byte>('V'));
        append_u8(out, kind);
        append_u32(out, 1u);
    }

    struct TestHandle {
        HANDLE value {nullptr};

        explicit TestHandle(HANDLE handle) noexcept: value {handle} {}
        ~TestHandle() noexcept {
            if (value != nullptr && value != INVALID_HANDLE_VALUE) {
                CloseHandle(value);
            }
        }
        TestHandle(const TestHandle &) = delete;
        TestHandle &operator=(const TestHandle &) = delete;
        TestHandle(TestHandle &&) = delete;
        TestHandle &operator=(TestHandle &&) = delete;
    };

    struct VirtualMemory {
        void *value {};

        explicit VirtualMemory(const std::size_t size) noexcept {
            value = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        ~VirtualMemory() noexcept {
            if (value != nullptr) {
                VirtualFree(value, 0u, MEM_RELEASE);
            }
        }
        VirtualMemory(const VirtualMemory &) = delete;
        VirtualMemory &operator=(const VirtualMemory &) = delete;
        VirtualMemory(VirtualMemory &&) = delete;
        VirtualMemory &operator=(VirtualMemory &&) = delete;
    };

    [[nodiscard]] std::uint32_t start_and_wait_for_exited_process() {
        std::wstring system_dir;
        system_dir.resize(MAX_PATH);
        const auto system_dir_size = GetSystemDirectoryW(system_dir.data(), static_cast<UINT>(system_dir.size()));
        REQUIRE(system_dir_size > 0u);
        REQUIRE(system_dir_size < system_dir.size());
        system_dir.resize(system_dir_size);

        const auto cmd_path = system_dir + L"\\cmd.exe";
        auto command_line = L"\"" + cmd_path + L"\" /c exit 0";

        STARTUPINFOW startup {};
        startup.cb = static_cast<DWORD>(sizeof(startup));
        PROCESS_INFORMATION process_info {};
        const auto created =
            CreateProcessW(cmd_path.c_str(), command_line.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                           nullptr, std::addressof(startup), std::addressof(process_info));
        REQUIRE(created != FALSE);

        TestHandle process {process_info.hProcess};
        TestHandle thread {process_info.hThread};
        const auto pid = static_cast<std::uint32_t>(process_info.dwProcessId);
        REQUIRE(WaitForSingleObject(process.value, 10000u) == WAIT_OBJECT_0);
        return pid;
    }
} // namespace

TEST_CASE("protocol frame codec round-trips binary payloads") {
    const std::vector<std::byte> payload {
        std::byte {0x00},
        std::byte {0x7f},
        std::byte {0xff},
    };

    const auto encoded = rule_engine::protocol::encode_frame(payload);
    REQUIRE(encoded.has_value());

    auto decoded = rule_engine::protocol::try_decode_frame(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(decoded->payload == payload);
    CHECK(decoded->bytes_consumed == encoded->size());
}

TEST_CASE("protocol typed messages round-trip handshake subjects and fact batches") {
    rule_engine::protocol::HandshakeMessage handshake;
    handshake.protocol = "rule-engine-client";
    handshake.version = 1u;
    handshake.capabilities.push_back(rule_engine::protocol::Capability {.route = "endpoint.process.snapshot"});
    handshake.capabilities.push_back(rule_engine::protocol::Capability {.route = "endpoint.scan.patterns"});

    const auto handshake_payload = rule_engine::protocol::encode_handshake(handshake);
    REQUIRE(handshake_payload.has_value());
    const auto decoded_handshake = rule_engine::protocol::decode_handshake(*handshake_payload);
    REQUIRE(decoded_handshake.has_value());
    CHECK(decoded_handshake->protocol == "rule-engine-client");
    CHECK(decoded_handshake->version == 1u);
    REQUIRE(decoded_handshake->capabilities.size() == 2u);
    CHECK(decoded_handshake->capabilities[0].route == "endpoint.process.snapshot");
    CHECK(decoded_handshake->capabilities[1].route == "endpoint.scan.patterns");

    rule_engine::protocol::SubjectListMessage subjects;
    subjects.subjects.push_back(rule_engine::Subject {.kind = "process", .id = "pid:1"});
    subjects.subjects.push_back(rule_engine::Subject {.kind = "process", .id = "pid:2"});
    const auto subject_payload = rule_engine::protocol::encode_subject_list(subjects);
    REQUIRE(subject_payload.has_value());
    const auto decoded_subjects = rule_engine::protocol::decode_subject_list(*subject_payload);
    REQUIRE(decoded_subjects.has_value());
    REQUIRE(decoded_subjects->subjects.size() == 2u);
    CHECK(decoded_subjects->subjects[0].id == "pid:1");
    CHECK(decoded_subjects->subjects[1].id == "pid:2");

    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.process.snapshot";
    request.timeout = std::chrono::milliseconds {2500};
    request.keys.push_back(rule_engine::protocol::FactKey {.subject_id = "pid:1", .key = "process.name"});
    request.keys.push_back(rule_engine::protocol::FactKey {.subject_id = "pid:1", .key = "process.pid"});
    request.expected_types.push_back(rule_engine::ValueType::string);
    request.expected_types.push_back(rule_engine::ValueType::integer);
    request.scan_plans.push_back(rule_engine::PatternScanPlan {
        .pattern_key = "$needle",
        .literal =
            {
                std::byte {'n'},
                std::byte {'e'},
                std::byte {'e'},
                std::byte {'d'},
                std::byte {'l'},
                std::byte {'e'},
            },
    });
    const auto request_payload = rule_engine::protocol::encode_fact_batch_request(request);
    REQUIRE(request_payload.has_value());
    const auto decoded_request = rule_engine::protocol::decode_fact_batch_request(*request_payload);
    REQUIRE(decoded_request.has_value());
    CHECK(decoded_request->route == "endpoint.process.snapshot");
    CHECK(decoded_request->timeout == std::chrono::milliseconds {2500});
    REQUIRE(decoded_request->keys.size() == 2u);
    CHECK(decoded_request->keys[0].subject_id == "pid:1");
    CHECK(decoded_request->keys[1].key == "process.pid");
    CHECK(decoded_request->expected_types == std::vector<rule_engine::ValueType> {
                                                 rule_engine::ValueType::string,
                                                 rule_engine::ValueType::integer,
                                             });
    REQUIRE(decoded_request->scan_plans.size() == 1u);
    CHECK(decoded_request->scan_plans[0].pattern_key == "$needle");
    CHECK(decoded_request->scan_plans[0].literal == std::vector<std::byte> {
                                                        std::byte {'n'},
                                                        std::byte {'e'},
                                                        std::byte {'e'},
                                                        std::byte {'d'},
                                                        std::byte {'l'},
                                                        std::byte {'e'},
                                                    });

    rule_engine::protocol::FactBatchResponseMessage response;
    response.route = "endpoint.process.snapshot";
    response.values.push_back(rule_engine::Fact {
        .subject_id = "pid:1",
        .key = "process.name",
        .value = rule_engine::Value::string("cmd.exe"),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    response.values.push_back(rule_engine::Fact {
        .subject_id = "pid:1",
        .key = "process.pid",
        .value = rule_engine::Value::integer(1),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });
    const auto response_payload = rule_engine::protocol::encode_fact_batch_response(response);
    REQUIRE(response_payload.has_value());
    const auto decoded_response = rule_engine::protocol::decode_fact_batch_response(*response_payload);
    REQUIRE(decoded_response.has_value());
    CHECK(decoded_response->route == "endpoint.process.snapshot");
    REQUIRE(decoded_response->values.size() == 2u);
    CHECK(decoded_response->values[0].value.as_string() != nullptr);
    CHECK(*decoded_response->values[0].value.as_string() == "cmd.exe");
    CHECK(decoded_response->values[1].value.as_i64() == 1);
}

TEST_CASE("protocol typed messages round-trip array and object fact values") {
    rule_engine::protocol::FactBatchResponseMessage response;
    response.route = "endpoint.process.image.pe";
    response.values.push_back(rule_engine::Fact {
        .subject_id = "pid:1",
        .key = "pe.imports",
        .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "dll", .value = rule_engine::Value::string("KERNEL32.dll")},
                rule_engine::ObjectEntry {.key = "name", .value = rule_engine::Value::string("CreateFileW")},
                rule_engine::ObjectEntry {.key = "ordinal", .value = rule_engine::Value::undefined()},
                rule_engine::ObjectEntry {.key = "hint", .value = rule_engine::Value::integer(128)},
                rule_engine::ObjectEntry {.key = "lookup_rva", .value = rule_engine::Value::integer(8192)},
                rule_engine::ObjectEntry {.key = "iat_rva", .value = rule_engine::Value::integer(12288)},
                rule_engine::ObjectEntry {
                    .key = "signature",
                    .value = rule_engine::Value::bytes(std::vector<std::byte> {
                        std::byte {0xde},
                        std::byte {0xad},
                        std::byte {0xbe},
                        std::byte {0xef},
                    }),
                },
                rule_engine::ObjectEntry {
                    .key = "metadata",
                    .value = rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                        rule_engine::ObjectEntry {
                            .key = "delay_load",
                            .value = rule_engine::Value::boolean(false),
                        },
                        rule_engine::ObjectEntry {
                            .key = "aliases",
                            .value = rule_engine::Value::array(std::vector<rule_engine::Value> {
                                rule_engine::Value::string("KERNELBASE.dll"),
                            }),
                        },
                    }),
                },
            }),
            rule_engine::Value::object(std::vector<rule_engine::ObjectEntry> {
                rule_engine::ObjectEntry {.key = "dll", .value = rule_engine::Value::string("USER32.dll")},
                rule_engine::ObjectEntry {.key = "name", .value = rule_engine::Value::undefined()},
                rule_engine::ObjectEntry {.key = "ordinal", .value = rule_engine::Value::integer(12)},
                rule_engine::ObjectEntry {.key = "hint", .value = rule_engine::Value::undefined()},
                rule_engine::ObjectEntry {.key = "lookup_rva", .value = rule_engine::Value::integer(16384)},
                rule_engine::ObjectEntry {.key = "iat_rva", .value = rule_engine::Value::integer(20480)},
            }),
        }),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });

    const auto encoded = rule_engine::protocol::encode_fact_batch_response(response);
    REQUIRE(encoded.has_value());
    const auto decoded = rule_engine::protocol::decode_fact_batch_response(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(decoded->route == "endpoint.process.image.pe");
    REQUIRE(decoded->values.size() == 1u);
    CHECK(decoded->values[0].subject_id == "pid:1");
    CHECK(decoded->values[0].key == "pe.imports");
    CHECK(decoded->values[0].status == rule_engine::FactStatus::available);
    CHECK(decoded->values[0].ttl == std::chrono::seconds {30});

    const auto *imports = decoded->values[0].value.as_array();
    REQUIRE(imports != nullptr);
    REQUIRE(imports->values.size() == 2u);

    const auto *first_import = imports->values[0].as_object();
    REQUIRE(first_import != nullptr);
    const auto *dll = find_object_entry(*first_import, "dll");
    REQUIRE(dll != nullptr);
    REQUIRE(dll->as_string() != nullptr);
    CHECK(*dll->as_string() == "KERNEL32.dll");
    const auto *ordinal = find_object_entry(*first_import, "ordinal");
    REQUIRE(ordinal != nullptr);
    CHECK(ordinal->is_undefined());
    const auto *hint = find_object_entry(*first_import, "hint");
    REQUIRE(hint != nullptr);
    CHECK(hint->as_i64() == 128);
    const auto *signature = find_object_entry(*first_import, "signature");
    REQUIRE(signature != nullptr);
    REQUIRE(signature->as_bytes() != nullptr);
    CHECK(*signature->as_bytes() == std::vector<std::byte> {
                                      std::byte {0xde},
                                      std::byte {0xad},
                                      std::byte {0xbe},
                                      std::byte {0xef},
                                  });

    const auto *metadata = find_object_entry(*first_import, "metadata");
    REQUIRE(metadata != nullptr);
    const auto *metadata_object = metadata->as_object();
    REQUIRE(metadata_object != nullptr);
    const auto *delay_load = find_object_entry(*metadata_object, "delay_load");
    REQUIRE(delay_load != nullptr);
    CHECK(delay_load->as_bool() == false);
    const auto *aliases = find_object_entry(*metadata_object, "aliases");
    REQUIRE(aliases != nullptr);
    const auto *alias_array = aliases->as_array();
    REQUIRE(alias_array != nullptr);
    REQUIRE(alias_array->values.size() == 1u);
    REQUIRE(alias_array->values[0].as_string() != nullptr);
    CHECK(*alias_array->values[0].as_string() == "KERNELBASE.dll");

    const auto *second_import = imports->values[1].as_object();
    REQUIRE(second_import != nullptr);
    const auto *second_dll = find_object_entry(*second_import, "dll");
    REQUIRE(second_dll != nullptr);
    REQUIRE(second_dll->as_string() != nullptr);
    CHECK(*second_dll->as_string() == "USER32.dll");
    const auto *second_ordinal = find_object_entry(*second_import, "ordinal");
    REQUIRE(second_ordinal != nullptr);
    CHECK(second_ordinal->as_i64() == 12);
}

TEST_CASE("client handshake advertises configured custom provider capabilities") {
    const auto handshake =
        rule_engine::client_protocol::client_handshake(std::vector<rule_engine::protocol::Capability> {
            rule_engine::protocol::Capability {.route = "endpoint.demo.functions"},
        });

    CHECK(std::ranges::any_of(handshake.capabilities,
                              [](const auto &capability) { return capability.route == "endpoint.process.snapshot"; }));
    CHECK(std::ranges::any_of(handshake.capabilities,
                              [](const auto &capability) { return capability.route == "endpoint.demo.functions"; }));
}

TEST_CASE("client handshake preserves distinct candidate provider filters on one route") {
    const auto handshake =
        rule_engine::client_protocol::client_handshake(std::vector<rule_engine::protocol::Capability> {
            rule_engine::protocol::Capability {
                .route = "endpoint.process.inventory",
                .filter_key = "process.inventory.by_image_name",
                .argument_types = {rule_engine::ValueType::string},
                .result_kind = "subject_set",
            },
            rule_engine::protocol::Capability {
                .route = "endpoint.process.inventory",
                .filter_key = "process.inventory.valid_base_pe_subjects",
                .argument_types = {},
                .result_kind = "subject_set",
            },
        });

    const auto candidate_capabilities = std::ranges::count_if(handshake.capabilities, [](const auto &capability) {
        return capability.route == "endpoint.process.inventory" && capability.result_kind == "subject_set";
    });

    CHECK(candidate_capabilities == 2);
    CHECK(std::ranges::any_of(handshake.capabilities, [](const auto &capability) {
        return capability.route == "endpoint.process.inventory" &&
               capability.filter_key == "process.inventory.by_image_name";
    }));
    CHECK(std::ranges::any_of(handshake.capabilities, [](const auto &capability) {
        return capability.route == "endpoint.process.inventory" &&
               capability.filter_key == "process.inventory.valid_base_pe_subjects";
    }));
}

TEST_CASE("protocol typed messages round-trip generic candidate provider subject sets") {
    rule_engine::protocol::HandshakeMessage handshake;
    handshake.protocol = "rule-engine-client";
    handshake.version = 1u;
    handshake.capabilities.push_back(rule_engine::protocol::Capability {
        .route = "endpoint.process.inventory",
        .filter_key = "process.inventory.by_image_name",
        .argument_types = {rule_engine::ValueType::string},
        .result_kind = "subject_set",
    });

    const auto handshake_payload = rule_engine::protocol::encode_handshake(handshake);
    REQUIRE(handshake_payload.has_value());
    const auto decoded_handshake = rule_engine::protocol::decode_handshake(*handshake_payload);
    REQUIRE(decoded_handshake.has_value());
    REQUIRE(decoded_handshake->capabilities.size() == 1u);
    CHECK(decoded_handshake->capabilities[0].route == "endpoint.process.inventory");
    CHECK(decoded_handshake->capabilities[0].filter_key == "process.inventory.by_image_name");
    CHECK(decoded_handshake->capabilities[0].argument_types == std::vector<rule_engine::ValueType> {
                                                                   rule_engine::ValueType::string,
                                                               });
    CHECK(decoded_handshake->capabilities[0].result_kind == "subject_set");

    rule_engine::protocol::CandidateProviderRequestMessage request;
    request.route = "endpoint.process.inventory";
    request.timeout = std::chrono::milliseconds {1500};
    request.filters.push_back(rule_engine::protocol::CandidateProviderFilterRequest {
        .request_id = "process.inventory.by_image_name|string:powershell.exe",
        .filter_key = "process.inventory.by_image_name",
        .argument_kind = "string",
        .argument_value = "powershell.exe",
    });

    const auto request_payload = rule_engine::protocol::encode_candidate_provider_request(request);
    REQUIRE(request_payload.has_value());
    const auto decoded_request = rule_engine::protocol::decode_candidate_provider_request(*request_payload);
    REQUIRE(decoded_request.has_value());
    CHECK(decoded_request->route == "endpoint.process.inventory");
    CHECK(decoded_request->timeout == std::chrono::milliseconds {1500});
    REQUIRE(decoded_request->filters.size() == 1u);
    CHECK(decoded_request->filters[0].request_id == "process.inventory.by_image_name|string:powershell.exe");
    CHECK(decoded_request->filters[0].filter_key == "process.inventory.by_image_name");
    CHECK(decoded_request->filters[0].argument_kind == "string");
    CHECK(decoded_request->filters[0].argument_value == "powershell.exe");

    rule_engine::protocol::CandidateProviderResponseMessage response;
    response.route = "endpoint.process.inventory";
    response.results.push_back(rule_engine::protocol::CandidateProviderSubjectSet {
        .request_id = "process.inventory.by_image_name|string:powershell.exe",
        .filter_key = "process.inventory.by_image_name",
        .status = rule_engine::FactStatus::available,
        .subject_ids = {"pid:10", "pid:42"},
        .diagnostic = {},
        .ttl = std::chrono::seconds {30},
    });
    response.results.push_back(rule_engine::protocol::CandidateProviderSubjectSet {
        .request_id = "process.inventory.by_image_name|string:missing.exe",
        .filter_key = "process.inventory.by_image_name",
        .status = rule_engine::FactStatus::unavailable,
        .subject_ids = {},
        .diagnostic = "inventory unavailable",
        .ttl = std::chrono::seconds {0},
    });

    const auto response_payload = rule_engine::protocol::encode_candidate_provider_response(response);
    REQUIRE(response_payload.has_value());
    const auto decoded_response = rule_engine::protocol::decode_candidate_provider_response(*response_payload);
    REQUIRE(decoded_response.has_value());
    CHECK(decoded_response->route == "endpoint.process.inventory");
    REQUIRE(decoded_response->results.size() == 2u);
    CHECK(decoded_response->results[0].request_id == "process.inventory.by_image_name|string:powershell.exe");
    CHECK(decoded_response->results[0].filter_key == "process.inventory.by_image_name");
    CHECK(decoded_response->results[0].status == rule_engine::FactStatus::available);
    CHECK(decoded_response->results[0].subject_ids == std::vector<std::string> {"pid:10", "pid:42"});
    CHECK(decoded_response->results[0].diagnostic.empty());
    CHECK(decoded_response->results[0].ttl == std::chrono::seconds {30});
    CHECK(decoded_response->results[1].status == rule_engine::FactStatus::unavailable);
    CHECK(decoded_response->results[1].subject_ids.empty());
    CHECK(decoded_response->results[1].diagnostic == "inventory unavailable");
}

TEST_CASE("protocol typed messages round-trip pattern fact metadata") {
    rule_engine::PatternValue pattern;
    pattern.matched = true;
    pattern.matches.push_back(rule_engine::PatternMatchContext {
        .offset = 128u,
        .length = 4u,
        .bytes = {std::byte {'t'}, std::byte {'e'}, std::byte {'s'}, std::byte {'t'}},
        .before = {std::byte {'>'}},
        .after = {std::byte {'<'}},
        .scan_space = "process.memory",
        .region_permissions = "rx",
    });

    rule_engine::protocol::FactBatchResponseMessage response;
    response.route = "endpoint.scan.patterns";
    response.values.push_back(rule_engine::Fact {
        .subject_id = "pid:1",
        .key = "$a.pattern",
        .value = rule_engine::Value::pattern(std::move(pattern)),
        .status = rule_engine::FactStatus::available,
        .diagnostic = {},
        .ttl = std::chrono::seconds {0},
    });

    const auto encoded = rule_engine::protocol::encode_fact_batch_response(response);
    REQUIRE(encoded.has_value());
    const auto decoded = rule_engine::protocol::decode_fact_batch_response(*encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->values.size() == 1u);
    const auto *decoded_pattern = decoded->values[0].value.as_pattern();
    REQUIRE(decoded_pattern != nullptr);
    CHECK(decoded_pattern->matched);
    REQUIRE(decoded_pattern->matches.size() == 1u);
    CHECK(decoded_pattern->matches[0].offset == 128u);
    CHECK(decoded_pattern->matches[0].length == 4u);
    CHECK(decoded_pattern->matches[0].bytes ==
          std::vector<std::byte> {std::byte {'t'}, std::byte {'e'}, std::byte {'s'}, std::byte {'t'}});
    CHECK(decoded_pattern->matches[0].before == std::vector<std::byte> {std::byte {'>'}});
    CHECK(decoded_pattern->matches[0].after == std::vector<std::byte> {std::byte {'<'}});
    CHECK(decoded_pattern->matches[0].scan_space == "process.memory");
    CHECK(decoded_pattern->matches[0].region_permissions == "rx");
}

TEST_CASE("protocol decoders reject oversized counts before reading entries") {
    std::vector<std::byte> subjects;
    append_protocol_header(subjects, 2u);
    append_u32(subjects, 100000u);

    const auto decoded_subjects = rule_engine::protocol::decode_subject_list(subjects);
    REQUIRE_FALSE(decoded_subjects.has_value());
    REQUIRE_FALSE(decoded_subjects.error().diagnostics.empty());
    CHECK(decoded_subjects.error().diagnostics[0].message.find("count exceeds") != std::string::npos);

    std::vector<std::byte> response;
    append_protocol_header(response, 4u);
    append_string(response, "endpoint.scan.patterns");
    append_u32(response, 1u);
    append_string(response, "pid:1");
    append_string(response, "$a.pattern");
    append_u8(response, 1u);
    append_u8(response, 5u);
    append_u8(response, 1u);
    append_u32(response, 100000u);
    append_string(response, {});
    append_u32(response, 30u);

    const auto decoded_response = rule_engine::protocol::decode_fact_batch_response(response);
    REQUIRE_FALSE(decoded_response.has_value());
    REQUIRE_FALSE(decoded_response.error().diagnostics.empty());
    CHECK(decoded_response.error().diagnostics[0].message.find("count exceeds") != std::string::npos);

    std::vector<std::byte> array_response;
    append_protocol_header(array_response, 4u);
    append_string(array_response, "endpoint.process.image.pe");
    append_u32(array_response, 1u);
    append_string(array_response, "pid:1");
    append_string(array_response, "pe.imports");
    append_u8(array_response, 1u);
    append_u8(array_response, 7u);
    append_u32(array_response, 100000u);

    const auto decoded_array_response = rule_engine::protocol::decode_fact_batch_response(array_response);
    REQUIRE_FALSE(decoded_array_response.has_value());
    REQUIRE_FALSE(decoded_array_response.error().diagnostics.empty());
    CHECK(decoded_array_response.error().diagnostics[0].message.find("count exceeds") != std::string::npos);

    std::vector<std::byte> object_response;
    append_protocol_header(object_response, 4u);
    append_string(object_response, "endpoint.process.image.pe");
    append_u32(object_response, 1u);
    append_string(object_response, "pid:1");
    append_string(object_response, "pe.imports");
    append_u8(object_response, 1u);
    append_u8(object_response, 8u);
    append_u32(object_response, 100000u);

    const auto decoded_object_response = rule_engine::protocol::decode_fact_batch_response(object_response);
    REQUIRE_FALSE(decoded_object_response.has_value());
    REQUIRE_FALSE(decoded_object_response.error().diagnostics.empty());
    CHECK(decoded_object_response.error().diagnostics[0].message.find("count exceeds") != std::string::npos);

    std::vector<std::byte> candidate_request;
    append_protocol_header(candidate_request, 5u);
    append_string(candidate_request, "endpoint.process.inventory");
    append_u32(candidate_request, 1500u);
    append_u32(candidate_request, 100000u);

    const auto decoded_candidate_request = rule_engine::protocol::decode_candidate_provider_request(candidate_request);
    REQUIRE_FALSE(decoded_candidate_request.has_value());
    REQUIRE_FALSE(decoded_candidate_request.error().diagnostics.empty());
    CHECK(decoded_candidate_request.error().diagnostics[0].message.find("count exceeds") != std::string::npos);

    std::vector<std::byte> candidate_response;
    append_protocol_header(candidate_response, 6u);
    append_string(candidate_response, "endpoint.process.inventory");
    append_u32(candidate_response, 1u);
    append_string(candidate_response, "process.inventory.by_image_name|string:powershell.exe");
    append_string(candidate_response, "process.inventory.by_image_name");
    append_u8(candidate_response, 1u);
    append_u32(candidate_response, 100000u);

    const auto decoded_candidate_response =
        rule_engine::protocol::decode_candidate_provider_response(candidate_response);
    REQUIRE_FALSE(decoded_candidate_response.has_value());
    REQUIRE_FALSE(decoded_candidate_response.error().diagnostics.empty());
    CHECK(decoded_candidate_response.error().diagnostics[0].message.find("count exceeds") != std::string::npos);
}

TEST_CASE("Windows PE provider extracts image facts from the current executable") {
    std::wstring path;
    path.resize(32768u);
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    REQUIRE(size > 0u);
    path.resize(size);

    auto facts = rule_engine::windows::read_pe_image_facts("pid:self", std::filesystem::path {path});
    REQUIRE(facts.has_value());

    const auto valid = find_fact(*facts, "pe.is_valid");
    REQUIRE(valid.has_value());
    CHECK(valid->status == rule_engine::FactStatus::available);
    CHECK(valid->value.as_bool() == true);

    const auto machine = find_fact(*facts, "pe.machine");
    REQUIRE(machine.has_value());
    CHECK(machine->status == rule_engine::FactStatus::available);
    CHECK(machine->value.as_i64().value_or(0) > 0);

    const auto sections = find_fact(*facts, "pe.number_of_sections");
    REQUIRE(sections.has_value());
    CHECK(sections->status == rule_engine::FactStatus::available);
    CHECK(sections->value.as_i64().value_or(0) > 0);

    const auto image_size = find_fact(*facts, "pe.size_of_image");
    REQUIRE(image_size.has_value());
    CHECK(image_size->status == rule_engine::FactStatus::available);
    CHECK(image_size->value.as_i64().value_or(0) > 0);
}

TEST_CASE("Windows PE provider returns stable image identity facts for static caching") {
    std::wstring path;
    path.resize(32768u);
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    REQUIRE(size > 0u);
    path.resize(size);

    const std::filesystem::path image_path {path};
    auto facts = rule_engine::windows::read_pe_image_facts("pid:self", image_path);
    REQUIRE(facts.has_value());

    const auto identity_path = find_fact(*facts, "pe.identity.path");
    REQUIRE(identity_path.has_value());
    CHECK(identity_path->status == rule_engine::FactStatus::available);
    REQUIRE(identity_path->value.as_string() != nullptr);
    CHECK(*identity_path->value.as_string() == image_path.string());

    const auto file_id = find_fact(*facts, "pe.identity.file_id");
    REQUIRE(file_id.has_value());
    CHECK(file_id->status == rule_engine::FactStatus::available);
    REQUIRE(file_id->value.as_string() != nullptr);
    CHECK_FALSE(file_id->value.as_string()->empty());

    std::error_code ec;
    const auto expected_size = std::filesystem::file_size(image_path, ec);
    REQUIRE_FALSE(ec);

    const auto file_size = find_fact(*facts, "pe.identity.file_size");
    REQUIRE(file_size.has_value());
    CHECK(file_size->status == rule_engine::FactStatus::available);
    CHECK(file_size->value.as_i64() == static_cast<std::int64_t>(expected_size));

    const auto last_write_time = find_fact(*facts, "pe.identity.last_write_time");
    REQUIRE(last_write_time.has_value());
    CHECK(last_write_time->status == rule_engine::FactStatus::available);
    CHECK(last_write_time->value.as_i64().value_or(0) > 0);

    const auto scan_space_name = find_fact(*facts, "pe.identity.scan_space_name");
    REQUIRE(scan_space_name.has_value());
    CHECK(scan_space_name->status == rule_engine::FactStatus::available);
    CHECK(scan_space_name->value.as_string() != nullptr);
    CHECK(*scan_space_name->value.as_string() == "process.image.pe");

    const auto scan_space_version = find_fact(*facts, "pe.identity.scan_space_version");
    REQUIRE(scan_space_version.has_value());
    CHECK(scan_space_version->status == rule_engine::FactStatus::available);
    CHECK(scan_space_version->value.as_string() != nullptr);
    CHECK(*scan_space_version->value.as_string() == "v1");
}

TEST_CASE("Windows PE identity provider does not require parsing a valid PE image") {
    auto fixture = write_temp_binary(L"rule_engine_identity_only_fixture", {'n', 'o', 't', '-', 'p', 'e'});

    auto facts = rule_engine::windows::read_pe_image_identity_facts("fixture:identity", fixture.path);
    REQUIRE(facts.has_value());

    CHECK_FALSE(find_fact(*facts, "pe.is_valid").has_value());

    const auto identity_path = find_fact(*facts, "pe.identity.path");
    REQUIRE(identity_path.has_value());
    CHECK(identity_path->status == rule_engine::FactStatus::available);
    REQUIRE(identity_path->value.as_string() != nullptr);
    CHECK(*identity_path->value.as_string() == fixture.path.string());

    const auto file_size = find_fact(*facts, "pe.identity.file_size");
    REQUIRE(file_size.has_value());
    CHECK(file_size->status == rule_engine::FactStatus::available);
    CHECK(file_size->value.as_i64() == 6);
}

TEST_CASE("Default module registry advertises PE image identity facts") {
    auto registry = rule_engine::default_module_registry();

    const auto assert_identity_field = [&](const std::string_view key, const rule_engine::ValueType type) {
        const auto *field = registry.find_field(key);
        REQUIRE(field != nullptr);
        CHECK(field->key == key);
        CHECK(field->type == type);
        CHECK(field->route == "endpoint.process.image.pe");
        CHECK(field->cheap_prefetch);
        CHECK(field->cost_class == rule_engine::FactCostClass::static_image_header);
    };

    assert_identity_field("pe.identity.path", rule_engine::ValueType::string);
    assert_identity_field("pe.identity.file_id", rule_engine::ValueType::string);
    assert_identity_field("pe.identity.file_size", rule_engine::ValueType::integer);
    assert_identity_field("pe.identity.last_write_time", rule_engine::ValueType::integer);
    assert_identity_field("pe.identity.scan_space_name", rule_engine::ValueType::string);
    assert_identity_field("pe.identity.scan_space_version", rule_engine::ValueType::string);
}

TEST_CASE("Windows PE provider returns diagnostic facts for non-PE malformed and truncated fixtures") {
    const auto assert_invalid_fixture = [](const std::string_view subject, const std::vector<std::uint8_t> &bytes,
                                           const std::string_view expected_diagnostic) {
        auto fixture = write_temp_binary(L"rule_engine_invalid_pe_fixture", bytes);
        auto facts = rule_engine::windows::read_pe_image_facts(std::string {subject}, fixture.path);
        REQUIRE(facts.has_value());

        const auto valid = find_fact(*facts, "pe.is_valid");
        REQUIRE(valid.has_value());
        CHECK(valid->status == rule_engine::FactStatus::available);
        CHECK(valid->value.as_bool() == false);
        CHECK(valid->diagnostic.find(expected_diagnostic) != std::string::npos);

        const auto sections = find_fact(*facts, "pe.sections");
        REQUIRE(sections.has_value());
        CHECK(sections->value.is_undefined());
        CHECK(sections->diagnostic.find(expected_diagnostic) != std::string::npos);
    };

    assert_invalid_fixture("fixture:non-pe", {'n', 'o', 't', '-', 'p', 'e'}, "image is not a PE file");
    assert_invalid_fixture("fixture:malformed", unsupported_optional_header_bytes(), "unsupported PE optional header");
    assert_invalid_fixture("fixture:truncated", truncated_pe32_optional_header_bytes(),
                           "truncated PE32 optional header");
}

TEST_CASE("Windows PE provider parses synthetic PE32 and PE32 plus fixtures") {
    const auto assert_valid_fixture = [](const std::string_view subject, const std::vector<std::uint8_t> &bytes,
                                         const std::int64_t expected_machine, const std::int64_t expected_timestamp) {
        auto fixture = write_temp_binary(L"rule_engine_valid_pe_fixture", bytes);
        auto facts = rule_engine::windows::read_pe_image_facts(std::string {subject}, fixture.path);
        REQUIRE(facts.has_value());

        const auto valid = find_fact(*facts, "pe.is_valid");
        REQUIRE(valid.has_value());
        CHECK(valid->status == rule_engine::FactStatus::available);
        CHECK(valid->value.as_bool() == true);

        const auto machine = find_fact(*facts, "pe.machine");
        REQUIRE(machine.has_value());
        CHECK(machine->value.as_i64() == expected_machine);

        const auto timestamp = find_fact(*facts, "pe.timestamp");
        REQUIRE(timestamp.has_value());
        CHECK(timestamp->value.as_i64() == expected_timestamp);

        const auto sections = find_fact(*facts, "pe.sections");
        REQUIRE(sections.has_value());
        const auto *section_array = sections->value.as_array();
        REQUIRE(section_array != nullptr);
        CHECK(section_array->values.empty());
    };

    assert_valid_fixture("fixture:pe32", minimal_pe32_bytes(), IMAGE_FILE_MACHINE_I386, 0x65a5'1111);
    assert_valid_fixture("fixture:pe32plus", minimal_pe64_bytes(), IMAGE_FILE_MACHINE_AMD64, 0x65a5'2222);
}

TEST_CASE("Windows PE provider extracts header metadata from the current executable") {
    std::wstring path;
    path.resize(32768u);
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    REQUIRE(size > 0u);
    path.resize(size);

    auto facts = rule_engine::windows::read_pe_image_facts("pid:self", std::filesystem::path {path});
    REQUIRE(facts.has_value());

    const auto subsystem = find_fact(*facts, "pe.subsystem");
    REQUIRE(subsystem.has_value());
    CHECK(subsystem->status == rule_engine::FactStatus::available);
    CHECK(subsystem->value.as_i64().value_or(0) > 0);

    const auto characteristics = find_fact(*facts, "pe.characteristics");
    REQUIRE(characteristics.has_value());
    CHECK(characteristics->status == rule_engine::FactStatus::available);
    CHECK(characteristics->value.as_i64().value_or(0) > 0);

    const auto dll_characteristics = find_fact(*facts, "pe.dll_characteristics");
    REQUIRE(dll_characteristics.has_value());
    CHECK(dll_characteristics->status == rule_engine::FactStatus::available);
    CHECK(dll_characteristics->value.as_i64().has_value());

    const auto timestamp = find_fact(*facts, "pe.timestamp");
    REQUIRE(timestamp.has_value());
    CHECK(timestamp->status == rule_engine::FactStatus::available);
    CHECK(timestamp->value.as_i64().has_value());
}

TEST_CASE("Windows PE provider extracts section objects from the current executable") {
    std::wstring path;
    path.resize(32768u);
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    REQUIRE(size > 0u);
    path.resize(size);

    auto facts = rule_engine::windows::read_pe_image_facts("pid:self", std::filesystem::path {path});
    REQUIRE(facts.has_value());

    const auto section_count = find_fact(*facts, "pe.number_of_sections");
    REQUIRE(section_count.has_value());
    REQUIRE(section_count->status == rule_engine::FactStatus::available);
    const auto count = section_count->value.as_i64();
    REQUIRE(count.has_value());
    REQUIRE(*count > 0);

    const auto sections = find_fact(*facts, "pe.sections");
    REQUIRE(sections.has_value());
    REQUIRE(sections->status == rule_engine::FactStatus::available);
    const auto *section_array = sections->value.as_array();
    REQUIRE(section_array != nullptr);
    REQUIRE(static_cast<std::int64_t>(section_array->values.size()) == *count);

    const auto *first_section = section_array->values[0].as_object();
    REQUIRE(first_section != nullptr);
    const auto find_entry = [&](const std::string_view key) -> const rule_engine::Value * {
        const auto found =
            std::ranges::find_if(first_section->entries, [&](const auto &entry) { return entry.key == key; });
        if (found == first_section->entries.end()) {
            return nullptr;
        }
        return std::addressof(found->value);
    };

    REQUIRE(find_entry("name") != nullptr);
    REQUIRE(find_entry("name")->as_string() != nullptr);
    REQUIRE(find_entry("virtual_address") != nullptr);
    REQUIRE(find_entry("virtual_address")->as_i64().has_value());
    REQUIRE(find_entry("virtual_size") != nullptr);
    REQUIRE(find_entry("virtual_size")->as_i64().has_value());
    REQUIRE(find_entry("raw_data_offset") != nullptr);
    REQUIRE(find_entry("raw_data_offset")->as_i64().has_value());
    REQUIRE(find_entry("raw_data_size") != nullptr);
    REQUIRE(find_entry("raw_data_size")->as_i64().has_value());
    REQUIRE(find_entry("characteristics") != nullptr);
    REQUIRE(find_entry("characteristics")->as_i64().has_value());
    REQUIRE(find_entry("readable") != nullptr);
    REQUIRE(find_entry("readable")->as_bool().has_value());
    REQUIRE(find_entry("writable") != nullptr);
    REQUIRE(find_entry("writable")->as_bool().has_value());
    REQUIRE(find_entry("executable") != nullptr);
    REQUIRE(find_entry("executable")->as_bool().has_value());
}

TEST_CASE("Windows PE provider extracts import objects from the current executable") {
    std::wstring path;
    path.resize(32768u);
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    REQUIRE(size > 0u);
    path.resize(size);

    auto facts = rule_engine::windows::read_pe_image_facts("pid:self", std::filesystem::path {path});
    REQUIRE(facts.has_value());

    const auto imports = find_fact(*facts, "pe.imports");
    REQUIRE(imports.has_value());
    REQUIRE(imports->status == rule_engine::FactStatus::available);
    const auto *import_array = imports->value.as_array();
    REQUIRE(import_array != nullptr);
    REQUIRE_FALSE(import_array->values.empty());

    const auto *first_import = import_array->values[0].as_object();
    REQUIRE(first_import != nullptr);
    const auto find_entry = [&](const std::string_view key) -> const rule_engine::Value * {
        const auto found =
            std::ranges::find_if(first_import->entries, [&](const auto &entry) { return entry.key == key; });
        if (found == first_import->entries.end()) {
            return nullptr;
        }
        return std::addressof(found->value);
    };

    REQUIRE(find_entry("dll") != nullptr);
    REQUIRE(find_entry("dll")->as_string() != nullptr);
    CHECK_FALSE(find_entry("dll")->as_string()->empty());
    REQUIRE(find_entry("name") != nullptr);
    REQUIRE(find_entry("ordinal") != nullptr);
    REQUIRE(find_entry("hint") != nullptr);
    REQUIRE(find_entry("lookup_rva") != nullptr);
    REQUIRE(find_entry("lookup_rva")->as_i64().has_value());
    REQUIRE(find_entry("iat_rva") != nullptr);
    REQUIRE(find_entry("iat_rva")->as_i64().has_value());

    const auto *name = find_entry("name")->as_string();
    const auto ordinal = find_entry("ordinal")->as_i64();
    CHECK((name != nullptr || ordinal.has_value()));
}

TEST_CASE("Windows PE provider extracts export objects from a system DLL") {
    std::wstring system_dir;
    system_dir.resize(MAX_PATH);
    const auto system_dir_size = GetSystemDirectoryW(system_dir.data(), static_cast<UINT>(system_dir.size()));
    REQUIRE(system_dir_size > 0u);
    REQUIRE(system_dir_size < system_dir.size());
    system_dir.resize(system_dir_size);

    auto facts =
        rule_engine::windows::read_pe_image_facts("dll:kernel32", std::filesystem::path {system_dir} / "kernel32.dll");
    REQUIRE(facts.has_value());

    const auto exports = find_fact(*facts, "pe.exports");
    REQUIRE(exports.has_value());
    REQUIRE(exports->status == rule_engine::FactStatus::available);
    const auto *export_array = exports->value.as_array();
    REQUIRE(export_array != nullptr);
    REQUIRE_FALSE(export_array->values.empty());

    const auto *first_export = export_array->values[0].as_object();
    REQUIRE(first_export != nullptr);
    const auto find_entry = [&](const rule_engine::ObjectValue &object,
                                const std::string_view key) -> const rule_engine::Value * {
        const auto found = std::ranges::find_if(object.entries, [&](const auto &entry) { return entry.key == key; });
        if (found == object.entries.end()) {
            return nullptr;
        }
        return std::addressof(found->value);
    };

    REQUIRE(find_entry(*first_export, "module") != nullptr);
    REQUIRE(find_entry(*first_export, "module")->as_string() != nullptr);
    REQUIRE(find_entry(*first_export, "name") != nullptr);
    REQUIRE(find_entry(*first_export, "ordinal") != nullptr);
    REQUIRE(find_entry(*first_export, "ordinal")->as_i64().has_value());
    REQUIRE(find_entry(*first_export, "rva") != nullptr);
    REQUIRE(find_entry(*first_export, "rva")->as_i64().has_value());
    REQUIRE(find_entry(*first_export, "forwarded") != nullptr);
    REQUIRE(find_entry(*first_export, "forwarded")->as_bool().has_value());
    REQUIRE(find_entry(*first_export, "forwarder") != nullptr);

    const auto has_get_last_error = std::ranges::any_of(export_array->values, [&](const auto &value) {
        const auto *object = value.as_object();
        if (object == nullptr) {
            return false;
        }
        const auto *name = find_entry(*object, "name");
        if (name == nullptr || name->as_string() == nullptr) {
            return false;
        }
        return *name->as_string() == "GetLastError";
    });
    CHECK(has_get_last_error);
}

TEST_CASE("Windows PE provider extracts debug directory entries from the current executable") {
    std::wstring path;
    path.resize(32768u);
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    REQUIRE(size > 0u);
    path.resize(size);

    auto facts = rule_engine::windows::read_pe_image_facts("pid:self", std::filesystem::path {path});
    REQUIRE(facts.has_value());

    const auto debug_entries = find_fact(*facts, "pe.debug_entries");
    REQUIRE(debug_entries.has_value());
    REQUIRE(debug_entries->status == rule_engine::FactStatus::available);
    const auto *debug_array = debug_entries->value.as_array();
    REQUIRE(debug_array != nullptr);
    REQUIRE_FALSE(debug_array->values.empty());

    const auto *first_entry = debug_array->values[0].as_object();
    REQUIRE(first_entry != nullptr);
    const auto find_entry = [&](const std::string_view key) -> const rule_engine::Value * {
        const auto found =
            std::ranges::find_if(first_entry->entries, [&](const auto &entry) { return entry.key == key; });
        if (found == first_entry->entries.end()) {
            return nullptr;
        }
        return std::addressof(found->value);
    };

    REQUIRE(find_entry("type") != nullptr);
    REQUIRE(find_entry("type")->as_i64().has_value());
    REQUIRE(find_entry("timestamp") != nullptr);
    REQUIRE(find_entry("timestamp")->as_i64().has_value());
    REQUIRE(find_entry("major_version") != nullptr);
    REQUIRE(find_entry("major_version")->as_i64().has_value());
    REQUIRE(find_entry("minor_version") != nullptr);
    REQUIRE(find_entry("minor_version")->as_i64().has_value());
    REQUIRE(find_entry("size") != nullptr);
    REQUIRE(find_entry("size")->as_i64().has_value());
    REQUIRE(find_entry("address_of_raw_data") != nullptr);
    REQUIRE(find_entry("address_of_raw_data")->as_i64().has_value());
    REQUIRE(find_entry("pointer_to_raw_data") != nullptr);
    REQUIRE(find_entry("pointer_to_raw_data")->as_i64().has_value());
}

TEST_CASE("Windows PE provider extracts resource entries from a system DLL") {
    std::wstring system_dir;
    system_dir.resize(MAX_PATH);
    const auto system_dir_size = GetSystemDirectoryW(system_dir.data(), static_cast<UINT>(system_dir.size()));
    REQUIRE(system_dir_size > 0u);
    REQUIRE(system_dir_size < system_dir.size());
    system_dir.resize(system_dir_size);

    auto facts =
        rule_engine::windows::read_pe_image_facts("dll:kernel32", std::filesystem::path {system_dir} / "kernel32.dll");
    REQUIRE(facts.has_value());

    const auto resources = find_fact(*facts, "pe.resources");
    REQUIRE(resources.has_value());
    REQUIRE(resources->status == rule_engine::FactStatus::available);
    const auto *resource_array = resources->value.as_array();
    REQUIRE(resource_array != nullptr);
    REQUIRE_FALSE(resource_array->values.empty());

    const auto *first_resource = resource_array->values[0].as_object();
    REQUIRE(first_resource != nullptr);
    const auto find_entry = [&](const rule_engine::ObjectValue &object,
                                const std::string_view key) -> const rule_engine::Value * {
        const auto found = std::ranges::find_if(object.entries, [&](const auto &entry) { return entry.key == key; });
        if (found == object.entries.end()) {
            return nullptr;
        }
        return std::addressof(found->value);
    };

    REQUIRE(find_entry(*first_resource, "type_id") != nullptr);
    REQUIRE(find_entry(*first_resource, "type_name") != nullptr);
    REQUIRE(find_entry(*first_resource, "name_id") != nullptr);
    REQUIRE(find_entry(*first_resource, "name") != nullptr);
    REQUIRE(find_entry(*first_resource, "language_id") != nullptr);
    REQUIRE(find_entry(*first_resource, "rva") != nullptr);
    REQUIRE(find_entry(*first_resource, "rva")->as_i64().has_value());
    REQUIRE(find_entry(*first_resource, "size") != nullptr);
    REQUIRE(find_entry(*first_resource, "size")->as_i64().has_value());
    REQUIRE(find_entry(*first_resource, "code_page") != nullptr);
    REQUIRE(find_entry(*first_resource, "code_page")->as_i64().has_value());

    const auto has_version_resource = std::ranges::any_of(resource_array->values, [&](const auto &value) {
        const auto *object = value.as_object();
        if (object == nullptr) {
            return false;
        }
        const auto *type_id = find_entry(*object, "type_id");
        return type_id != nullptr && type_id->as_i64() == 16;
    });
    CHECK(has_version_resource);
}

TEST_CASE("Windows PE provider extracts certificate table entries from a fixture image") {
    auto fixture = write_pe32_certificate_fixture();

    auto facts = rule_engine::windows::read_pe_image_facts("fixture:certificate", fixture.path);
    REQUIRE(facts.has_value());

    const auto certificates = find_fact(*facts, "pe.certificates");
    REQUIRE(certificates.has_value());
    REQUIRE(certificates->status == rule_engine::FactStatus::available);
    const auto *certificate_array = certificates->value.as_array();
    REQUIRE(certificate_array != nullptr);
    REQUIRE(certificate_array->values.size() == 1u);

    const auto *certificate = certificate_array->values[0].as_object();
    REQUIRE(certificate != nullptr);
    const auto find_entry = [&](const rule_engine::ObjectValue &object,
                                const std::string_view key) -> const rule_engine::Value * {
        const auto found = std::ranges::find_if(object.entries, [&](const auto &entry) { return entry.key == key; });
        if (found == object.entries.end()) {
            return nullptr;
        }
        return std::addressof(found->value);
    };

    REQUIRE(find_entry(*certificate, "file_offset") != nullptr);
    CHECK(find_entry(*certificate, "file_offset")->as_i64() == 0x400);
    REQUIRE(find_entry(*certificate, "size") != nullptr);
    CHECK(find_entry(*certificate, "size")->as_i64() == 0x20);
    REQUIRE(find_entry(*certificate, "revision") != nullptr);
    CHECK(find_entry(*certificate, "revision")->as_i64() == 0x0200);
    REQUIRE(find_entry(*certificate, "type") != nullptr);
    CHECK(find_entry(*certificate, "type")->as_i64() == 0x0002);
    REQUIRE(find_entry(*certificate, "payload_size") != nullptr);
    CHECK(find_entry(*certificate, "payload_size")->as_i64() == 0x18);
}

TEST_CASE("Windows PE provider extracts TLS callbacks from a fixture image") {
    auto fixture = write_pe32_tls_fixture();

    auto facts = rule_engine::windows::read_pe_image_facts("fixture:tls", fixture.path);
    REQUIRE(facts.has_value());

    const auto callbacks = find_fact(*facts, "pe.tls_callbacks");
    REQUIRE(callbacks.has_value());
    REQUIRE(callbacks->status == rule_engine::FactStatus::available);
    const auto *callback_array = callbacks->value.as_array();
    REQUIRE(callback_array != nullptr);
    REQUIRE(callback_array->values.size() == 1u);

    const auto *callback = callback_array->values[0].as_object();
    REQUIRE(callback != nullptr);
    const auto find_entry = [&](const rule_engine::ObjectValue &object,
                                const std::string_view key) -> const rule_engine::Value * {
        const auto found = std::ranges::find_if(object.entries, [&](const auto &entry) { return entry.key == key; });
        if (found == object.entries.end()) {
            return nullptr;
        }
        return std::addressof(found->value);
    };

    REQUIRE(find_entry(*callback, "index") != nullptr);
    CHECK(find_entry(*callback, "index")->as_i64() == 0);
    REQUIRE(find_entry(*callback, "va") != nullptr);
    CHECK(find_entry(*callback, "va")->as_i64() == 0x0040'1234);
    REQUIRE(find_entry(*callback, "rva") != nullptr);
    CHECK(find_entry(*callback, "rva")->as_i64() == 0x1234);
}

TEST_CASE("Windows process provider can enumerate at least the current process") {
    auto subjects = rule_engine::windows::enumerate_process_subjects();
    REQUIRE(subjects.has_value());
    CHECK_FALSE(subjects->empty());
}

TEST_CASE("Windows process provider returns command line for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_snapshot_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.command_line",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 1u);

    const auto &fact = (*facts)[0];
    CHECK(fact.subject_id == subject_id);
    CHECK(fact.key == "process.command_line");
    REQUIRE(fact.status == rule_engine::FactStatus::available);
    const auto *command_line = fact.value.as_string();
    REQUIRE(command_line != nullptr);
    CHECK_FALSE(command_line->empty());
}

TEST_CASE("Windows process provider returns thread count for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_snapshot_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.thread_count",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 1u);

    const auto &fact = (*facts)[0];
    CHECK(fact.subject_id == subject_id);
    CHECK(fact.key == "process.thread_count");
    REQUIRE(fact.status == rule_engine::FactStatus::available);
    REQUIRE(fact.value.as_i64().has_value());
    CHECK(*fact.value.as_i64() > 0);
}

TEST_CASE("Windows process provider returns architecture for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_snapshot_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.architecture",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 1u);

    const auto &fact = (*facts)[0];
    CHECK(fact.subject_id == subject_id);
    CHECK(fact.key == "process.architecture");
    REQUIRE(fact.status == rule_engine::FactStatus::available);
    const auto *architecture = fact.value.as_string();
    REQUIRE(architecture != nullptr);
    CHECK(std::ranges::contains(
        std::array {
            std::string_view {"x86"},
            std::string_view {"x64"},
            std::string_view {"arm"},
            std::string_view {"arm64"},
            std::string_view {"unknown"},
        },
        *architecture));
}

TEST_CASE("Windows process provider returns integrity level for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_snapshot_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.integrity_level",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 1u);

    const auto &fact = (*facts)[0];
    CHECK(fact.subject_id == subject_id);
    CHECK(fact.key == "process.integrity_level");
    REQUIRE(fact.status == rule_engine::FactStatus::available);
    const auto *integrity_level = fact.value.as_string();
    REQUIRE(integrity_level != nullptr);
    CHECK(std::ranges::contains(
        std::array {
            std::string_view {"untrusted"},
            std::string_view {"low"},
            std::string_view {"medium"},
            std::string_view {"high"},
            std::string_view {"system"},
            std::string_view {"protected"},
            std::string_view {"unknown"},
        },
        *integrity_level));
}

TEST_CASE("Windows process provider returns user details for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_snapshot_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.user.sid",
        },
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.user.name",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    const auto &sid_fact = (*facts)[0];
    CHECK(sid_fact.subject_id == subject_id);
    CHECK(sid_fact.key == "process.user.sid");
    REQUIRE(sid_fact.status == rule_engine::FactStatus::available);
    const auto *sid = sid_fact.value.as_string();
    REQUIRE(sid != nullptr);
    CHECK(sid->starts_with("S-"));

    const auto &name_fact = (*facts)[1];
    CHECK(name_fact.subject_id == subject_id);
    CHECK(name_fact.key == "process.user.name");
    REQUIRE(name_fact.status == rule_engine::FactStatus::available);
    const auto *name = name_fact.value.as_string();
    REQUIRE(name != nullptr);
    CHECK_FALSE(name->empty());
}

TEST_CASE("Windows process provider returns token metadata for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_snapshot_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.token.elevated",
        },
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.token.type",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    const auto &elevated_fact = (*facts)[0];
    CHECK(elevated_fact.subject_id == subject_id);
    CHECK(elevated_fact.key == "process.token.elevated");
    REQUIRE(elevated_fact.status == rule_engine::FactStatus::available);
    REQUIRE(elevated_fact.value.as_bool().has_value());

    const auto &type_fact = (*facts)[1];
    CHECK(type_fact.subject_id == subject_id);
    CHECK(type_fact.key == "process.token.type");
    REQUIRE(type_fact.status == rule_engine::FactStatus::available);
    const auto *token_type = type_fact.value.as_string();
    REQUIRE(token_type != nullptr);
    CHECK(std::ranges::contains(
        std::array {
            std::string_view {"primary"},
            std::string_view {"impersonation"},
            std::string_view {"unknown"},
        },
        *token_type));
}

TEST_CASE("Windows process provider returns loaded module facts for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_snapshot_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.modules.count",
        },
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.modules.names",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    const auto &count_fact = (*facts)[0];
    CHECK(count_fact.subject_id == subject_id);
    CHECK(count_fact.key == "process.modules.count");
    REQUIRE(count_fact.status == rule_engine::FactStatus::available);
    const auto count = count_fact.value.as_i64();
    REQUIRE(count.has_value());
    CHECK(*count > 0);

    const auto &names_fact = (*facts)[1];
    CHECK(names_fact.subject_id == subject_id);
    CHECK(names_fact.key == "process.modules.names");
    REQUIRE(names_fact.status == rule_engine::FactStatus::available);
    const auto *names = names_fact.value.as_array();
    REQUIRE(names != nullptr);
    REQUIRE_FALSE(names->values.empty());
    CHECK(static_cast<std::int64_t>(names->values.size()) == *count);
    CHECK(std::ranges::all_of(names->values, [](const auto &value) {
        const auto *name = value.as_string();
        return name != nullptr && !name->empty();
    }));
}

TEST_CASE("Windows process provider returns memory region counts for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_snapshot_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.memory.regions.count",
        },
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.memory.regions.readable_count",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    const auto &count_fact = (*facts)[0];
    CHECK(count_fact.subject_id == subject_id);
    CHECK(count_fact.key == "process.memory.regions.count");
    REQUIRE(count_fact.status == rule_engine::FactStatus::available);
    const auto count = count_fact.value.as_i64();
    REQUIRE(count.has_value());
    CHECK(*count > 0);

    const auto &readable_count_fact = (*facts)[1];
    CHECK(readable_count_fact.subject_id == subject_id);
    CHECK(readable_count_fact.key == "process.memory.regions.readable_count");
    REQUIRE(readable_count_fact.status == rule_engine::FactStatus::available);
    const auto readable_count = readable_count_fact.value.as_i64();
    REQUIRE(readable_count.has_value());
    CHECK(*readable_count > 0);
    CHECK(*readable_count <= *count);
}

TEST_CASE("Windows process provider returns memory region array for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_snapshot_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.memory.regions",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 1u);

    const auto &fact = (*facts)[0];
    CHECK(fact.subject_id == subject_id);
    CHECK(fact.key == "process.memory.regions");
    REQUIRE(fact.status == rule_engine::FactStatus::available);
    const auto *regions = fact.value.as_array();
    REQUIRE(regions != nullptr);
    REQUIRE_FALSE(regions->values.empty());

    const auto *first_region = regions->values[0].as_object();
    REQUIRE(first_region != nullptr);
    const auto find_entry = [&](const std::string_view key) -> const rule_engine::Value * {
        const auto found =
            std::ranges::find_if(first_region->entries, [&](const auto &entry) { return entry.key == key; });
        if (found == first_region->entries.end()) {
            return nullptr;
        }
        return std::addressof(found->value);
    };

    REQUIRE(find_entry("base") != nullptr);
    REQUIRE(find_entry("base")->as_i64().has_value());
    REQUIRE(find_entry("size") != nullptr);
    REQUIRE(find_entry("size")->as_i64().has_value());
    REQUIRE(find_entry("state") != nullptr);
    REQUIRE(find_entry("state")->as_string() != nullptr);
    REQUIRE(find_entry("protection") != nullptr);
    REQUIRE(find_entry("protection")->as_string() != nullptr);
    REQUIRE(find_entry("type") != nullptr);
    REQUIRE(find_entry("type")->as_string() != nullptr);
    REQUIRE(find_entry("readable") != nullptr);
    REQUIRE(find_entry("readable")->as_bool().has_value());
    REQUIRE(find_entry("scan_space") != nullptr);
    REQUIRE(find_entry("scan_space")->as_string() != nullptr);
    CHECK(*find_entry("scan_space")->as_string() == "process.memory");
}

TEST_CASE("Windows process handle provider returns handle count for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_handle_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.handles.count",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 1u);

    const auto &fact = (*facts)[0];
    CHECK(fact.subject_id == subject_id);
    CHECK(fact.key == "process.handles.count");
    REQUIRE(fact.status == rule_engine::FactStatus::available);
    REQUIRE(fact.value.as_i64().has_value());
    CHECK(*fact.value.as_i64() > 0);
}

TEST_CASE("Windows process signer provider returns signer status for current process") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    auto facts = rule_engine::windows::read_process_signer_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.signer.status",
        },
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.signer.is_signed",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    const auto &fact = (*facts)[0];
    CHECK(fact.subject_id == subject_id);
    CHECK(fact.key == "process.signer.status");
    REQUIRE(fact.status == rule_engine::FactStatus::available);
    const auto *status = fact.value.as_string();
    REQUIRE(status != nullptr);
    CHECK_FALSE(status->empty());
    CHECK(std::ranges::contains(
        std::array {
            std::string_view {"trusted"},
            std::string_view {"unsigned"},
            std::string_view {"expired"},
            std::string_view {"revoked"},
            std::string_view {"untrusted_root"},
            std::string_view {"bad_digest"},
            std::string_view {"chain_error"},
            std::string_view {"untrusted"},
        },
        *status));

    const auto &is_signed_fact = (*facts)[1];
    CHECK(is_signed_fact.subject_id == subject_id);
    CHECK(is_signed_fact.key == "process.signer.is_signed");
    REQUIRE(is_signed_fact.status == rule_engine::FactStatus::available);
    const auto is_signed = is_signed_fact.value.as_bool();
    REQUIRE(is_signed.has_value());
    CHECK(*is_signed == (*status != "unsigned"));
}

TEST_CASE("Windows process signer image facts classify unsigned PE fixtures") {
    auto fixture = write_temp_binary_with_extension(L"rule_engine_unsigned_pe_fixture", minimal_pe32_bytes(), L".exe");

    auto facts = rule_engine::windows::read_process_signer_image_facts("fixture:unsigned-pe", fixture.path,
                                                                       std::array {
                                                                           rule_engine::windows::ProcessFactKey {
                                                                               .subject_id = "fixture:unsigned-pe",
                                                                               .key = "process.signer.status",
                                                                           },
                                                                           rule_engine::windows::ProcessFactKey {
                                                                               .subject_id = "fixture:unsigned-pe",
                                                                               .key = "process.signer.is_signed",
                                                                           },
                                                                       });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    CHECK((*facts)[0].subject_id == "fixture:unsigned-pe");
    CHECK((*facts)[0].key == "process.signer.status");
    REQUIRE((*facts)[0].status == rule_engine::FactStatus::available);
    const auto *status = (*facts)[0].value.as_string();
    REQUIRE(status != nullptr);
    CHECK(*status == "unsigned");

    CHECK((*facts)[1].subject_id == "fixture:unsigned-pe");
    CHECK((*facts)[1].key == "process.signer.is_signed");
    REQUIRE((*facts)[1].status == rule_engine::FactStatus::available);
    CHECK((*facts)[1].value.as_bool() == false);
}

TEST_CASE("Windows process signer image facts classify embedded-signed PE fixtures") {
    const std::array candidates {
        std::filesystem::path {R"(C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe)"},
        std::filesystem::path {R"(C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe)"},
        std::filesystem::path {R"(C:\Program Files\Git\cmd\git.exe)"},
        std::filesystem::path {R"(C:\Program Files\PowerShell\7\pwsh.exe)"},
    };
    const auto fixture_path = first_existing_path(candidates);
    REQUIRE(fixture_path.has_value());

    auto facts =
        rule_engine::windows::read_process_signer_image_facts("fixture:embedded-signed-pe", *fixture_path,
                                                              std::array {
                                                                  rule_engine::windows::ProcessFactKey {
                                                                      .subject_id = "fixture:embedded-signed-pe",
                                                                      .key = "process.signer.status",
                                                                  },
                                                                  rule_engine::windows::ProcessFactKey {
                                                                      .subject_id = "fixture:embedded-signed-pe",
                                                                      .key = "process.signer.is_signed",
                                                                  },
                                                              });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    REQUIRE((*facts)[0].status == rule_engine::FactStatus::available);
    const auto *status = (*facts)[0].value.as_string();
    REQUIRE(status != nullptr);
    CHECK(*status != "unsigned");

    REQUIRE((*facts)[1].status == rule_engine::FactStatus::available);
    CHECK((*facts)[1].value.as_bool() == true);
}

TEST_CASE("Windows process signer image facts classify catalog-signed PE fixtures") {
    const auto fixture_path = windows_directory() / "System32" / "drivers" / "acpi.sys";
    if (!std::filesystem::exists(fixture_path)) {
        SKIP("catalog-signed Windows driver fixture is unavailable");
    }

    auto facts =
        rule_engine::windows::read_process_signer_image_facts("fixture:catalog-signed-pe", fixture_path,
                                                              std::array {
                                                                  rule_engine::windows::ProcessFactKey {
                                                                      .subject_id = "fixture:catalog-signed-pe",
                                                                      .key = "process.signer.status",
                                                                  },
                                                                  rule_engine::windows::ProcessFactKey {
                                                                      .subject_id = "fixture:catalog-signed-pe",
                                                                      .key = "process.signer.is_signed",
                                                                  },
                                                              });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    REQUIRE((*facts)[0].status == rule_engine::FactStatus::available);
    const auto *status = (*facts)[0].value.as_string();
    REQUIRE(status != nullptr);
    CHECK(*status == "trusted");

    REQUIRE((*facts)[1].status == rule_engine::FactStatus::available);
    CHECK((*facts)[1].value.as_bool() == true);
}

TEST_CASE("Windows process signer image facts do not treat malformed embedded signatures as unsigned") {
    auto fixture = write_pe32_certificate_fixture();

    auto facts = rule_engine::windows::read_process_signer_image_facts(
        "fixture:malformed-embedded-signature", fixture.path,
        std::array {
            rule_engine::windows::ProcessFactKey {
                .subject_id = "fixture:malformed-embedded-signature",
                .key = "process.signer.status",
            },
            rule_engine::windows::ProcessFactKey {
                .subject_id = "fixture:malformed-embedded-signature",
                .key = "process.signer.is_signed",
            },
        });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    if ((*facts)[0].status == rule_engine::FactStatus::available) {
        const auto *status = (*facts)[0].value.as_string();
        REQUIRE(status != nullptr);
        CHECK(*status != "unsigned");
    } else {
        CHECK((*facts)[0].value.is_undefined());
        CHECK_FALSE((*facts)[0].diagnostic.empty());
    }

    if ((*facts)[1].status == rule_engine::FactStatus::available) {
        CHECK((*facts)[1].value.as_bool() != false);
    } else {
        CHECK((*facts)[1].value.is_undefined());
        CHECK_FALSE((*facts)[1].diagnostic.empty());
    }
}

TEST_CASE("Windows process signer image facts return timed-out diagnostics for expired deadlines") {
    auto fixture =
        write_temp_binary_with_extension(L"rule_engine_timeout_signer_fixture", minimal_pe32_bytes(), L".exe");

    auto facts = rule_engine::windows::read_process_signer_image_facts("fixture:signer-timeout", fixture.path,
                                                                       std::array {
                                                                           rule_engine::windows::ProcessFactKey {
                                                                               .subject_id = "fixture:signer-timeout",
                                                                               .key = "process.signer.status",
                                                                           },
                                                                           rule_engine::windows::ProcessFactKey {
                                                                               .subject_id = "fixture:signer-timeout",
                                                                               .key = "process.signer.is_signed",
                                                                           },
                                                                       },
                                                                       std::chrono::milliseconds {0});
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    for (const auto &fact : *facts) {
        CHECK(fact.status == rule_engine::FactStatus::timed_out);
        CHECK(fact.value.is_undefined());
        CHECK(fact.diagnostic.find("timed out") != std::string::npos);
    }
}

TEST_CASE("Windows process signer image facts keep malformed images diagnostic-only") {
    std::vector<std::uint8_t> non_pe_bytes(sizeof(IMAGE_DOS_HEADER), 0u);
    non_pe_bytes[0] = 'n';
    non_pe_bytes[1] = 'o';

    auto fixture = write_temp_binary_with_extension(L"rule_engine_malformed_signer_fixture", non_pe_bytes, L".exe");

    auto facts = rule_engine::windows::read_process_signer_image_facts("fixture:malformed-pe", fixture.path,
                                                                       std::array {
                                                                           rule_engine::windows::ProcessFactKey {
                                                                               .subject_id = "fixture:malformed-pe",
                                                                               .key = "process.signer.status",
                                                                           },
                                                                           rule_engine::windows::ProcessFactKey {
                                                                               .subject_id = "fixture:malformed-pe",
                                                                               .key = "process.signer.is_signed",
                                                                           },
                                                                       });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    for (const auto &fact : *facts) {
        CHECK(fact.status == rule_engine::FactStatus::unavailable);
        CHECK(fact.value.is_undefined());
        CHECK(fact.diagnostic.find("image is not a PE file") != std::string::npos);
    }
}

TEST_CASE("Windows process signer provider keeps inaccessible processes diagnostic-only") {
    constexpr std::string_view system_subject {"pid:4"};
    auto facts = rule_engine::windows::read_process_signer_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = std::string {system_subject},
            .key = "process.signer.status",
        },
        rule_engine::windows::ProcessFactKey {
            .subject_id = std::string {system_subject},
            .key = "process.signer.is_signed",
        },
    });
    REQUIRE(facts.has_value());
    REQUIRE(facts->size() == 2u);

    for (const auto &fact : *facts) {
        CHECK(fact.subject_id == system_subject);
        CHECK(fact.status == rule_engine::FactStatus::access_denied);
        CHECK(fact.value.is_undefined());
        CHECK(fact.diagnostic.find("OpenProcess failed") != std::string::npos);
    }
}

TEST_CASE("localhost client signer route propagates expired request deadlines") {
    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.process.signer";
    request.timeout = std::chrono::milliseconds {0};
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = subject_id,
        .key = "process.signer.status",
    });
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = subject_id,
        .key = "process.signer.is_signed",
    });

    auto response = rule_engine::client_protocol::handle_client_fact_batch(request);
    REQUIRE(response.values.size() == 2u);
    for (const auto &fact : response.values) {
        CHECK(fact.status == rule_engine::FactStatus::timed_out);
        CHECK(fact.value.is_undefined());
        CHECK(fact.diagnostic.find("timed out") != std::string::npos);
    }
}

TEST_CASE("Windows process providers return unavailable facts for exited processes") {
    const auto subject_id = "pid:" + std::to_string(start_and_wait_for_exited_process());

    auto snapshot_facts = rule_engine::windows::read_process_snapshot_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.pid",
        },
    });
    REQUIRE(snapshot_facts.has_value());
    REQUIRE(snapshot_facts->size() == 1u);
    CHECK((*snapshot_facts)[0].status == rule_engine::FactStatus::unavailable);
    CHECK((*snapshot_facts)[0].diagnostic.find("process not found") != std::string::npos);

    auto handle_facts = rule_engine::windows::read_process_handle_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.handles.count",
        },
    });
    REQUIRE(handle_facts.has_value());
    REQUIRE(handle_facts->size() == 1u);
    CHECK((*handle_facts)[0].status == rule_engine::FactStatus::unavailable);
    CHECK((*handle_facts)[0].diagnostic.find("process not found") != std::string::npos);

    auto signer_facts = rule_engine::windows::read_process_signer_facts(std::array {
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.signer.status",
        },
        rule_engine::windows::ProcessFactKey {
            .subject_id = subject_id,
            .key = "process.signer.is_signed",
        },
    });
    REQUIRE(signer_facts.has_value());
    REQUIRE(signer_facts->size() == 2u);
    for (const auto &fact : *signer_facts) {
        CHECK(fact.status == rule_engine::FactStatus::unavailable);
        CHECK(fact.diagnostic.find("process not found") != std::string::npos);
    }
}

TEST_CASE("localhost client session advertises subjects and returns process and PE facts") {
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();

    const auto current_subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    rule_engine::protocol::FactBatchRequestMessage process_request;
    process_request.route = "endpoint.process.snapshot";
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.pid",
    });
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.name",
    });
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.thread_count",
    });
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.architecture",
    });
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.integrity_level",
    });
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.user.sid",
    });
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.user.name",
    });
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.token.elevated",
    });
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.token.type",
    });

    rule_engine::protocol::FactBatchRequestMessage pe_request;
    pe_request.route = "endpoint.process.image.pe";
    pe_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "pe.is_valid",
    });
    pe_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "pe.number_of_sections",
    });

    rule_engine::protocol::FactBatchRequestMessage handle_request;
    handle_request.route = "endpoint.process.handles";
    handle_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.handles.count",
    });

    rule_engine::protocol::FactBatchRequestMessage signer_request;
    signer_request.route = "endpoint.process.signer";
    signer_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.signer.status",
    });
    signer_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = current_subject_id,
        .key = "process.signer.is_signed",
    });

    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        std::vector<rule_engine::protocol::FactBatchRequestMessage> {
            process_request,
            pe_request,
            handle_request,
            signer_request,
        });
    REQUIRE(session.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(session->handshake.protocol == "rule-engine-client");
    CHECK(session->handshake.version == 1u);
    CHECK(std::ranges::any_of(session->handshake.capabilities,
                              [](const auto &capability) { return capability.route == "endpoint.process.snapshot"; }));
    CHECK(std::ranges::any_of(session->handshake.capabilities,
                              [](const auto &capability) { return capability.route == "endpoint.process.image.pe"; }));
    CHECK(std::ranges::any_of(session->handshake.capabilities,
                              [](const auto &capability) { return capability.route == "endpoint.process.handles"; }));
    CHECK(std::ranges::any_of(session->handshake.capabilities,
                              [](const auto &capability) { return capability.route == "endpoint.process.signer"; }));
    CHECK(std::ranges::any_of(session->subjects.subjects, [&](const auto &subject) {
        return subject.kind == "process" && subject.id == current_subject_id;
    }));

    REQUIRE(session->responses.size() == 4u);
    REQUIRE(session->responses[0].values.size() == 9u);
    CHECK(session->responses[0].values[0].key == "process.pid");
    CHECK(session->responses[0].values[0].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[0].value.as_i64() == static_cast<std::int64_t>(GetCurrentProcessId()));
    CHECK(session->responses[0].values[1].key == "process.name");
    CHECK(session->responses[0].values[1].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[1].value.as_string() != nullptr);
    CHECK(session->responses[0].values[2].key == "process.thread_count");
    CHECK(session->responses[0].values[2].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[2].value.as_i64().value_or(0) > 0);
    CHECK(session->responses[0].values[3].key == "process.architecture");
    CHECK(session->responses[0].values[3].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[3].value.as_string() != nullptr);
    CHECK(session->responses[0].values[4].key == "process.integrity_level");
    CHECK(session->responses[0].values[4].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[4].value.as_string() != nullptr);
    CHECK(session->responses[0].values[5].key == "process.user.sid");
    CHECK(session->responses[0].values[5].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[5].value.as_string() != nullptr);
    CHECK(session->responses[0].values[6].key == "process.user.name");
    CHECK(session->responses[0].values[6].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[6].value.as_string() != nullptr);
    CHECK(session->responses[0].values[7].key == "process.token.elevated");
    CHECK(session->responses[0].values[7].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[7].value.as_bool().has_value());
    CHECK(session->responses[0].values[8].key == "process.token.type");
    CHECK(session->responses[0].values[8].status == rule_engine::FactStatus::available);
    CHECK(session->responses[0].values[8].value.as_string() != nullptr);

    REQUIRE(session->responses[1].values.size() == 2u);
    CHECK(session->responses[1].values[0].key == "pe.is_valid");
    CHECK(session->responses[1].values[0].status == rule_engine::FactStatus::available);
    CHECK(session->responses[1].values[0].value.as_bool() == true);
    CHECK(session->responses[1].values[1].key == "pe.number_of_sections");
    CHECK(session->responses[1].values[1].status == rule_engine::FactStatus::available);
    CHECK(session->responses[1].values[1].value.as_i64().value_or(0) > 0);

    REQUIRE(session->responses[2].values.size() == 1u);
    CHECK(session->responses[2].values[0].key == "process.handles.count");
    CHECK(session->responses[2].values[0].status == rule_engine::FactStatus::available);
    CHECK(session->responses[2].values[0].value.as_i64().value_or(0) > 0);

    REQUIRE(session->responses[3].values.size() == 2u);
    CHECK(session->responses[3].values[0].key == "process.signer.status");
    CHECK(session->responses[3].values[0].status == rule_engine::FactStatus::available);
    const auto *signer_status = session->responses[3].values[0].value.as_string();
    REQUIRE(signer_status != nullptr);
    CHECK_FALSE(signer_status->empty());
    CHECK(session->responses[3].values[1].key == "process.signer.is_signed");
    CHECK(session->responses[3].values[1].status == rule_engine::FactStatus::available);
    const auto signer_is_signed = session->responses[3].values[1].value.as_bool();
    REQUIRE(signer_is_signed.has_value());
    CHECK(*signer_is_signed == (*signer_status != "unsigned"));
}

TEST_CASE("localhost client service accepts multiple sequential sessions") {
    const auto subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    rule_engine::protocol::FactBatchRequestMessage process_request;
    process_request.route = "endpoint.process.snapshot";
    process_request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = subject_id,
        .key = "process.pid",
    });
    process_request.expected_types.push_back(rule_engine::ValueType::integer);

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities = {},
                .extra_fact_handler = {},
                .max_sessions = 2u,
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    for (std::size_t index = 0; index < 2u; ++index) {
        auto session = rule_engine::client_protocol::run_client_session(
            rule_engine::client_protocol::ClientConnectionOptions {
                .host = "127.0.0.1",
                .port = port,
                .io_timeout = std::chrono::milliseconds {5000},
            },
            std::vector<rule_engine::protocol::FactBatchRequestMessage> {process_request});
        REQUIRE(session.has_value());
        REQUIRE(session->responses.size() == 1u);
        REQUIRE(session->responses[0].values.size() == 1u);
        CHECK(session->responses[0].values[0].subject_id == subject_id);
        CHECK(session->responses[0].values[0].key == "process.pid");
        CHECK(session->responses[0].values[0].status == rule_engine::FactStatus::available);
    }

    server.join();
    REQUIRE_FALSE(server_error.has_value());
}

TEST_CASE("localhost client service stops gracefully while waiting for a session") {
    using namespace std::chrono_literals;

    std::stop_source stop_source;
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = 500ms,
                .extra_capabilities = {},
                .extra_fact_handler = {},
                .max_sessions = 0u,
                .stop_token = stop_source.get_token(),
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    REQUIRE(listening.get() != 0u);

    const auto started = std::chrono::steady_clock::now();
    stop_source.request_stop();
    server.join();
    const auto elapsed = std::chrono::steady_clock::now() - started;

    REQUIRE_FALSE(server_error.has_value());
    CHECK(elapsed < 1s);
}

TEST_CASE("localhost client service cancels provider dispatch after shutdown is requested") {
    using namespace std::chrono_literals;

    std::stop_source stop_source;
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;
    bool provider_called {};

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = 500ms,
                .extra_capabilities = {rule_engine::protocol::Capability {.route = "endpoint.demo.cancel"}},
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.cancel") {
                        return std::nullopt;
                    }
                    provider_called = true;
                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    for (const auto &key : request.keys) {
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::integer(7),
                            .status = rule_engine::FactStatus::available,
                            .diagnostic = {},
                            .ttl = 30s,
                        });
                    }
                    return response;
                },
                .max_sessions = 1u,
                .stop_token = stop_source.get_token(),
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    asio::io_context io;
    asio::ip::tcp::socket socket {io};
    asio::error_code ec;
    socket.connect(asio::ip::tcp::endpoint {asio::ip::make_address("127.0.0.1", ec), port}, ec);
    REQUIRE_FALSE(ec);

    auto handshake_payload = read_protocol_frame(socket);
    REQUIRE(handshake_payload.has_value());
    auto handshake = rule_engine::protocol::decode_handshake(*handshake_payload);
    REQUIRE(handshake.has_value());

    auto subjects_payload = read_protocol_frame(socket);
    REQUIRE(subjects_payload.has_value());
    auto subjects = rule_engine::protocol::decode_subject_list(*subjects_payload);
    REQUIRE(subjects.has_value());

    stop_source.request_stop();

    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.demo.cancel";
    request.timeout = 500ms;
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:self",
        .key = "demo.cancel",
    });
    request.expected_types.push_back(rule_engine::ValueType::integer);

    auto request_payload = rule_engine::protocol::encode_fact_batch_request(request);
    REQUIRE(request_payload.has_value());
    REQUIRE_FALSE(write_protocol_frame(socket, *request_payload).has_value());

    auto response_payload = read_protocol_frame(socket);
    REQUIRE(response_payload.has_value());
    auto response = rule_engine::protocol::decode_fact_batch_response(*response_payload);
    REQUIRE(response.has_value());

    server.join();

    REQUIRE_FALSE(server_error.has_value());
    CHECK_FALSE(provider_called);
    REQUIRE(response->values.size() == 1u);
    CHECK(response->values[0].subject_id == "pid:self");
    CHECK(response->values[0].key == "demo.cancel");
    CHECK(response->values[0].status == rule_engine::FactStatus::unavailable);
    CHECK(response->values[0].diagnostic.find("cancel") != std::string::npos);
}

TEST_CASE("localhost client service exposes stop token to long custom provider handlers") {
    using namespace std::chrono_literals;

    std::stop_source stop_source;
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::promise<void> handler_entered_promise;
    auto handler_entered = handler_entered_promise.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = 2500ms,
                .extra_capabilities = {rule_engine::protocol::Capability {.route = "endpoint.demo.long_cancel"}},
                .extra_fact_handler_with_context =
                    [&](const rule_engine::protocol::FactBatchRequestMessage &request,
                        const rule_engine::client_protocol::ProviderRequestContext &context)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.long_cancel") {
                        return std::nullopt;
                    }
                    handler_entered_promise.set_value();
                    const auto deadline = std::chrono::steady_clock::now() + 5s;
                    while (!context.stop_token.stop_requested() && std::chrono::steady_clock::now() < deadline) {
                        std::this_thread::sleep_for(10ms);
                    }

                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    for (const auto &key : request.keys) {
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::undefined(),
                            .status = rule_engine::FactStatus::unavailable,
                            .diagnostic = "custom provider cancelled by shutdown",
                            .ttl = 0s,
                        });
                    }
                    return response;
                },
                .max_sessions = 1u,
                .stop_token = stop_source.get_token(),
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.demo.long_cancel";
    request.timeout = 2500ms;
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:self",
        .key = "demo.long_cancel",
    });
    request.expected_types.push_back(rule_engine::ValueType::integer);

    std::optional<rule_engine::client_protocol::ClientSession> client_session;
    std::optional<rule_engine::ErrorSet> client_error;
    std::thread client {[&] {
        auto session = rule_engine::client_protocol::run_client_session(
            rule_engine::client_protocol::ClientConnectionOptions {
                .host = "127.0.0.1",
                .port = port,
                .io_timeout = 2500ms,
            },
            std::vector<rule_engine::protocol::FactBatchRequestMessage> {request});
        if (session) {
            client_session = std::move(*session);
        } else {
            client_error = std::move(session.error());
        }
    }};

    REQUIRE(handler_entered.wait_for(5s) == std::future_status::ready);
    stop_source.request_stop();

    client.join();
    server.join();

    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(client_error.has_value());
    REQUIRE(client_session.has_value());
    REQUIRE(client_session->responses.size() == 1u);
    REQUIRE(client_session->responses[0].values.size() == 1u);
    CHECK(client_session->responses[0].values[0].status == rule_engine::FactStatus::unavailable);
    CHECK(client_session->responses[0].values[0].diagnostic.find("cancelled") != std::string::npos);
}

TEST_CASE("localhost client service can bound concurrent session workers") {
    using namespace std::chrono_literals;

    const auto make_request = [](const std::string_view subject_id) {
        rule_engine::protocol::FactBatchRequestMessage request;
        request.route = "endpoint.demo.concurrent";
        request.timeout = 5000ms;
        request.keys.push_back(rule_engine::protocol::FactKey {
            .subject_id = std::string {subject_id},
            .key = "demo.concurrent",
        });
        request.expected_types.push_back(rule_engine::ValueType::integer);
        return request;
    };

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::promise<void> first_handler_entered_promise;
    auto first_handler_entered = first_handler_entered_promise.get_future();
    std::promise<void> release_first_promise;
    auto release_first = release_first_promise.get_future().share();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = 5000ms,
                .extra_capabilities = {rule_engine::protocol::Capability {.route = "endpoint.demo.concurrent"}},
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.concurrent") {
                        return std::nullopt;
                    }
                    if (!request.keys.empty() && request.keys[0].subject_id == "pid:first") {
                        first_handler_entered_promise.set_value();
                        if (release_first.wait_for(5s) != std::future_status::ready) {
                            return std::nullopt;
                        }
                    }

                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    for (const auto &key : request.keys) {
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::integer(1),
                            .status = rule_engine::FactStatus::available,
                            .diagnostic = {},
                            .ttl = 30s,
                        });
                    }
                    return response;
                },
                .max_sessions = 2u,
                .max_session_workers = 2u,
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    std::optional<rule_engine::client_protocol::ClientSession> first_session;
    std::optional<rule_engine::ErrorSet> first_error;
    std::thread first_client {[&] {
        auto session = rule_engine::client_protocol::run_client_session(
            rule_engine::client_protocol::ClientConnectionOptions {
                .host = "127.0.0.1",
                .port = port,
                .io_timeout = 5000ms,
            },
            std::vector<rule_engine::protocol::FactBatchRequestMessage> {make_request("pid:first")});
        if (session) {
            first_session = std::move(*session);
        } else {
            first_error = std::move(session.error());
        }
    }};

    REQUIRE(first_handler_entered.wait_for(5s) == std::future_status::ready);
    auto second_session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = 1000ms,
        },
        std::vector<rule_engine::protocol::FactBatchRequestMessage> {make_request("pid:second")});

    release_first_promise.set_value();
    first_client.join();
    server.join();

    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(first_error.has_value());
    REQUIRE(first_session.has_value());
    REQUIRE(first_session->responses.size() == 1u);
    CHECK(first_session->responses[0].values[0].subject_id == "pid:first");
    REQUIRE(second_session.has_value());
    REQUIRE(second_session->responses.size() == 1u);
    CHECK(second_session->responses[0].values[0].subject_id == "pid:second");
}

TEST_CASE("localhost client session round-trips candidate provider subject sets") {
    using namespace std::chrono_literals;

    rule_engine::protocol::CandidateProviderRequestMessage candidate_request;
    candidate_request.route = "endpoint.process.inventory";
    candidate_request.timeout = std::chrono::milliseconds {2500};
    candidate_request.filters.push_back(rule_engine::protocol::CandidateProviderFilterRequest {
        .request_id = "process.inventory.by_image_name|string:powershell.exe",
        .filter_key = "process.inventory.by_image_name",
        .argument_kind = "string",
        .argument_value = "powershell.exe",
    });

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities =
                    {
                        rule_engine::protocol::Capability {
                            .route = "endpoint.process.inventory",
                            .filter_key = "process.inventory.by_image_name",
                            .argument_types = {rule_engine::ValueType::string},
                            .result_kind = "subject_set",
                        },
                    },
                .extra_fact_handler = {},
                .extra_candidate_provider_handler =
                    [](const rule_engine::protocol::CandidateProviderRequestMessage &request)
                    -> std::optional<rule_engine::protocol::CandidateProviderResponseMessage> {
                    rule_engine::protocol::CandidateProviderResponseMessage response;
                    response.route = request.route;
                    for (const auto &filter : request.filters) {
                        response.results.push_back(rule_engine::protocol::CandidateProviderSubjectSet {
                            .request_id = filter.request_id,
                            .filter_key = filter.filter_key,
                            .status = rule_engine::FactStatus::available,
                            .subject_ids = {"pid:10", "pid:42"},
                            .diagnostic = {},
                            .ttl = 30s,
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        {}, std::vector<rule_engine::protocol::CandidateProviderRequestMessage> {candidate_request});

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(session.has_value());
    CHECK(std::ranges::any_of(session->handshake.capabilities, [](const auto &capability) {
        return capability.route == "endpoint.process.inventory" &&
               capability.filter_key == "process.inventory.by_image_name" && capability.result_kind == "subject_set";
    }));
    REQUIRE(session->candidate_provider_responses.size() == 1u);
    CHECK(session->candidate_provider_responses[0].route == "endpoint.process.inventory");
    REQUIRE(session->candidate_provider_responses[0].results.size() == 1u);
    CHECK(session->candidate_provider_responses[0].results[0].request_id ==
          "process.inventory.by_image_name|string:powershell.exe");
    CHECK(session->candidate_provider_responses[0].results[0].status == rule_engine::FactStatus::available);
    CHECK(session->candidate_provider_responses[0].results[0].subject_ids ==
          std::vector<std::string> {"pid:10", "pid:42"});
    CHECK(session->candidate_provider_responses[0].results[0].ttl == 30s);
}

TEST_CASE("localhost optimizer plan uses candidate provider transport before exact VM") {
    using namespace std::chrono_literals;

    constexpr std::string_view source = R"(
import "process"

rule current_name {
    condition:
        process.name == "rule_engine_tests.exe"
}
)";
    auto parsed = rule_engine::parse_source("client_optimizer_plan.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    REQUIRE(plan.candidate_provider_requests.size() == 1u);

    const auto current_subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    const std::vector<rule_engine::Subject> requested_subjects {
        rule_engine::Subject {
            .kind = "process",
            .id = current_subject_id,
        },
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:0",
        },
    };

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities =
                    {
                        rule_engine::protocol::Capability {
                            .route = "endpoint.process.inventory",
                            .filter_key = "process.inventory.by_image_name",
                            .argument_types = {rule_engine::ValueType::string},
                            .result_kind = "subject_set",
                        },
                    },
                .extra_fact_handler = {},
                .extra_candidate_provider_handler =
                    [&](const rule_engine::protocol::CandidateProviderRequestMessage &request)
                    -> std::optional<rule_engine::protocol::CandidateProviderResponseMessage> {
                    rule_engine::protocol::CandidateProviderResponseMessage response;
                    response.route = request.route;
                    for (const auto &filter : request.filters) {
                        response.results.push_back(rule_engine::protocol::CandidateProviderSubjectSet {
                            .request_id = filter.request_id,
                            .filter_key = filter.filter_key,
                            .status = rule_engine::FactStatus::available,
                            .subject_ids = {current_subject_id},
                            .diagnostic = {},
                            .ttl = 30s,
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_optimizer_plan(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified, plan, requested_subjects,
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 2u,
            .vm_backpressure_subject_threshold = 1u,
            .provider_backpressure_request_threshold = 1u,
            .instrumentation = &instrumentation,
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());
    CHECK(evaluation->sweep.candidate_provider_requests == 1u);
    CHECK(evaluation->sweep.candidate_provider_subjects_returned == 1u);
    CHECK(evaluation->sweep.candidate_provider_broad_results == 0u);
    CHECK(evaluation->sweep.candidate_provider_fallback_predicate_evaluations == 0u);
    CHECK(evaluation->sweep.optimized_exact_vm_rule_executions == 1u);
    CHECK(evaluation->sweep.exact_vm_rule_executions_avoided == 1u);
    CHECK(evaluation->sweep.incomplete_subjects.empty());
    CHECK(instrumentation.candidate_provider_requests == 1u);
    CHECK(instrumentation.candidate_provider_filters_requested == 1u);
    CHECK(instrumentation.candidate_provider_subjects_returned == 1u);
    CHECK(instrumentation.candidate_provider_broad_results == 0u);
    CHECK(instrumentation.candidate_provider_filters_not_advertised == 0u);
    CHECK(instrumentation.provider_fact_keys_requested == 1u);
    REQUIRE(evaluation->facts.size() == 1u);
    CHECK(evaluation->facts[0].subject_id == current_subject_id);
    CHECK(evaluation->facts[0].key == "process.name");
    CHECK(evaluation->facts[0].status == rule_engine::FactStatus::available);
    REQUIRE(evaluation->candidate_provider_results.size() == 1u);
    CHECK(evaluation->candidate_provider_results[0].request_id == plan.candidate_provider_requests[0].id);
    CHECK(evaluation->candidate_provider_results[0].subject_ids == std::vector<std::string> {current_subject_id});
    REQUIRE(evaluation->evaluated_subjects.size() == requested_subjects.size());
    CHECK(evaluation->evaluated_subjects[0].id == current_subject_id);
    CHECK(evaluation->evaluated_subjects[1].id == "pid:0");
    const auto replayed_sweep =
        rule_engine::client_protocol::replay_optimized_client_evaluation(*verified, plan, *evaluation);
    CHECK(replayed_sweep.incomplete_subjects.empty());
    REQUIRE(replayed_sweep.subjects.size() == evaluation->sweep.subjects.size());
    REQUIRE(replayed_sweep.subjects[0].rule_results.size() == evaluation->sweep.subjects[0].rule_results.size());
    CHECK(replayed_sweep.subjects[0].rule_results[0].matched == evaluation->sweep.subjects[0].rule_results[0].matched);
    REQUIRE(replayed_sweep.subjects[1].rule_results.size() == evaluation->sweep.subjects[1].rule_results.size());
    CHECK(replayed_sweep.subjects[1].rule_results[0].matched == evaluation->sweep.subjects[1].rule_results[0].matched);
    const auto replay_report = rule_engine::client_protocol::replay_optimized_client_evaluation_with_parity_report(
        *verified, plan, *evaluation);
    CHECK(replay_report.subject_mismatches == 0u);
    CHECK(replay_report.rule_result_mismatches == 0u);
    CHECK(replay_report.trace_event_mismatches == 0u);
    CHECK(replay_report.sweep_metric_mismatches == 0u);
    CHECK(replay_report.sweep.exact_vm_rule_executions_avoided == evaluation->sweep.exact_vm_rule_executions_avoided);

    auto result_drift_session = *evaluation;
    result_drift_session.sweep.subjects[0].rule_results[0].matched =
        !result_drift_session.sweep.subjects[0].rule_results[0].matched;
    const auto result_drift_report =
        rule_engine::client_protocol::replay_optimized_client_evaluation_with_parity_report(*verified, plan,
                                                                                            result_drift_session);
    CHECK(result_drift_report.subject_mismatches == 0u);
    CHECK(result_drift_report.rule_result_mismatches == 1u);

    REQUIRE_FALSE(evaluation->sweep.trace_events.empty());
    auto trace_drift_session = *evaluation;
    trace_drift_session.sweep.trace_events[0].reason += " drift";
    const auto trace_drift_report = rule_engine::client_protocol::replay_optimized_client_evaluation_with_parity_report(
        *verified, plan, trace_drift_session);
    CHECK(trace_drift_report.rule_result_mismatches == 0u);
    CHECK(trace_drift_report.trace_event_mismatches == 1u);
    REQUIRE(evaluation->sweep.subjects.size() == 2u);
    CHECK(evaluation->sweep.subjects[0].subject_id == current_subject_id);
    CHECK(evaluation->sweep.subjects[0].exact_vm_rule_identifiers == std::vector<std::string> {"current_name"});
    REQUIRE(evaluation->sweep.subjects[0].rule_results.size() == 1u);
    CHECK(evaluation->sweep.subjects[0].rule_results[0].matched);
    CHECK(evaluation->sweep.subjects[1].subject_id == "pid:0");
    CHECK(evaluation->sweep.subjects[1].pruned_rule_identifiers == std::vector<std::string> {"current_name"});
    REQUIRE(evaluation->sweep.subjects[1].rule_results.size() == 1u);
    CHECK_FALSE(evaluation->sweep.subjects[1].rule_results[0].matched);
}

TEST_CASE("localhost optimizer plan reports broad candidate provider results before exact VM") {
    using namespace std::chrono_literals;

    constexpr std::string_view source = R"(
import "process"

rule current_name {
    condition:
        process.name == "rule_engine_tests.exe"
}
)";
    auto parsed = rule_engine::parse_source("client_optimizer_plan_broad_provider.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    REQUIRE(plan.candidate_provider_requests.size() == 1u);

    const auto current_subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    const std::vector<rule_engine::Subject> requested_subjects {
        rule_engine::Subject {
            .kind = "process",
            .id = current_subject_id,
        },
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:0",
        },
    };

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities =
                    {
                        rule_engine::protocol::Capability {
                            .route = "endpoint.process.inventory",
                            .filter_key = "process.inventory.by_image_name",
                            .argument_types = {rule_engine::ValueType::string},
                            .result_kind = "subject_set",
                        },
                    },
                .extra_fact_handler = {},
                .extra_candidate_provider_handler =
                    [&](const rule_engine::protocol::CandidateProviderRequestMessage &request)
                    -> std::optional<rule_engine::protocol::CandidateProviderResponseMessage> {
                    rule_engine::protocol::CandidateProviderResponseMessage response;
                    response.route = request.route;
                    for (const auto &filter : request.filters) {
                        response.results.push_back(rule_engine::protocol::CandidateProviderSubjectSet {
                            .request_id = filter.request_id,
                            .filter_key = filter.filter_key,
                            .status = rule_engine::FactStatus::available,
                            .subject_ids = {current_subject_id, "pid:0"},
                            .diagnostic = {},
                            .ttl = 30s,
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_optimizer_plan(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified, plan, requested_subjects,
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 2u,
            .vm_backpressure_subject_threshold = 1u,
            .provider_backpressure_request_threshold = 1u,
            .instrumentation = &instrumentation,
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());
    CHECK(evaluation->sweep.candidate_provider_requests == 1u);
    CHECK(evaluation->sweep.candidate_provider_subjects_returned == 2u);
    CHECK(evaluation->sweep.candidate_provider_broad_results == 1u);
    CHECK(evaluation->sweep.candidate_provider_fallback_predicate_evaluations == 0u);
    CHECK(evaluation->sweep.optimized_exact_vm_rule_executions == 2u);
    CHECK(evaluation->sweep.exact_vm_rule_executions_avoided == 0u);
    CHECK(evaluation->sweep.incomplete_subjects.empty());
    CHECK(instrumentation.candidate_provider_requests == 1u);
    CHECK(instrumentation.candidate_provider_filters_requested == 1u);
    CHECK(instrumentation.candidate_provider_subjects_returned == 2u);
    CHECK(instrumentation.candidate_provider_broad_results == 1u);
    CHECK(instrumentation.peak_pending_vm_subjects == 2u);
    CHECK(instrumentation.vm_backpressure_events == 1u);
    CHECK(instrumentation.peak_pending_provider_requests == 1u);
    CHECK(instrumentation.provider_backpressure_events == 0u);
    CHECK(instrumentation.provider_fact_keys_requested == 2u);
    REQUIRE(evaluation->facts.size() == 2u);
    REQUIRE(evaluation->sweep.subjects.size() == 2u);
    CHECK(evaluation->sweep.subjects[0].exact_vm_rule_identifiers == std::vector<std::string> {"current_name"});
    CHECK(evaluation->sweep.subjects[0].pruned_rule_identifiers.empty());
    CHECK(evaluation->sweep.subjects[1].exact_vm_rule_identifiers == std::vector<std::string> {"current_name"});
    CHECK(evaluation->sweep.subjects[1].pruned_rule_identifiers.empty());
    const auto replayed_sweep =
        rule_engine::client_protocol::replay_optimized_client_evaluation(*verified, plan, *evaluation);
    CHECK(replayed_sweep.candidate_provider_broad_results == 1u);
    CHECK(replayed_sweep.exact_vm_rule_executions_avoided == 0u);
}

TEST_CASE("localhost optimizer plan reuses static facts before provider materialization") {
    using namespace std::chrono_literals;

    constexpr std::string_view source = R"(
import "demo"

rule reusable_static_fact {
    condition:
        demo.import_count > 0
}
)";
    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields =
            {
                rule_engine::FieldDescriptor {
                    .key = "demo.import_count",
                    .type = rule_engine::ValueType::integer,
                    .route = "endpoint.demo.static",
                    .ttl = 30s,
                    .timeout = 5s,
                    .cheap_prefetch = false,
                    .cost_class = rule_engine::FactCostClass::broad_image_array,
                },
            },
        .functions = {},
    });

    auto parsed = rule_engine::parse_source("client_optimizer_plan_static_cache.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());
    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);

    const std::vector<rule_engine::Subject> requested_subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:static-a"},
        rule_engine::Subject {.kind = "process", .id = "pid:static-b"},
    };
    const rule_engine::optimizer::StaticFactCacheIdentity shared_identity {
        .path = "C:/Windows/System32/shared-static.exe",
        .file_id = "volume:42:file:7",
        .file_size = 4096u,
        .last_write_time = 1000u,
        .content_hash = "sha256:aaa",
        .signature_identity = "catalog:stable",
        .scan_space_name = "process.image.bytes",
        .scan_space_version = "v1",
    };

    std::vector<rule_engine::protocol::FactKey> observed_keys;
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities = {rule_engine::protocol::Capability {.route = "endpoint.demo.static"}},
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.static") {
                        return std::nullopt;
                    }
                    observed_keys.insert(observed_keys.end(), request.keys.begin(), request.keys.end());

                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    for (const auto &key : request.keys) {
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::integer(5),
                            .status = rule_engine::FactStatus::available,
                            .diagnostic = {},
                            .ttl = 30s,
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::optimizer::StaticFactCache static_cache;
    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_optimizer_plan(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified, plan, requested_subjects,
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 1u,
            .instrumentation = &instrumentation,
            .static_fact_cache = &static_cache,
            .static_fact_cache_candidates =
                {
                    rule_engine::optimizer::StaticFactCacheCandidate {
                        .subject_id = "pid:static-a",
                        .route = "endpoint.demo.static",
                        .key = "demo.import_count",
                        .cost_class = rule_engine::FactCostClass::broad_image_array,
                        .identity = shared_identity,
                        .content_addressable = true,
                    },
                    rule_engine::optimizer::StaticFactCacheCandidate {
                        .subject_id = "pid:static-b",
                        .route = "endpoint.demo.static",
                        .key = "demo.import_count",
                        .cost_class = rule_engine::FactCostClass::broad_image_array,
                        .identity = shared_identity,
                        .content_addressable = true,
                    },
                },
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());

    REQUIRE(observed_keys.size() == 1u);
    CHECK(observed_keys[0].subject_id == "pid:static-a");
    CHECK(observed_keys[0].key == "demo.import_count");
    CHECK(instrumentation.provider_requests == 1u);
    CHECK(instrumentation.provider_fact_keys_requested == 1u);
    CHECK(instrumentation.provider_facts_returned == 1u);
    CHECK(instrumentation.static_fact_cache_lookups == 2u);
    CHECK(instrumentation.static_fact_cache_hits == 1u);
    CHECK(instrumentation.static_fact_cache_misses == 1u);
    CHECK(instrumentation.static_fact_cache_reuses == 1u);
    CHECK(instrumentation.static_fact_cache_invalidations == 0u);

    REQUIRE(evaluation->facts.size() == 2u);
    CHECK(evaluation->facts[0].subject_id == "pid:static-a");
    CHECK(evaluation->facts[0].value.as_i64() == 5);
    CHECK(evaluation->facts[1].subject_id == "pid:static-b");
    CHECK(evaluation->facts[1].value.as_i64() == 5);
    REQUIRE(evaluation->sweep.subjects.size() == 2u);
    REQUIRE(evaluation->sweep.subjects[0].rule_results.size() == 1u);
    REQUIRE(evaluation->sweep.subjects[1].rule_results.size() == 1u);
    CHECK(evaluation->sweep.subjects[0].rule_results[0].matched);
    CHECK(evaluation->sweep.subjects[1].rule_results[0].matched);
    CHECK(std::ranges::any_of(evaluation->sweep.trace_events, [](const auto &event) {
        return event.event == "static_fact_cache_reused" && event.subject_id == "pid:static-b";
    }));

    const auto replay_report = rule_engine::client_protocol::replay_optimized_client_evaluation_with_parity_report(
        *verified, plan, *evaluation);
    CHECK(replay_report.subject_mismatches == 0u);
    CHECK(replay_report.rule_result_mismatches == 0u);
    CHECK(replay_report.trace_event_mismatches == 0u);
    CHECK(replay_report.sweep_metric_mismatches == 0u);
}

TEST_CASE("localhost optimizer plan derives static cache candidates from identity facts") {
    using namespace std::chrono_literals;

    constexpr std::string_view source = R"(
import "demo"

rule reusable_static_fact {
    condition:
        demo.import_count > 0
}
)";
    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields =
            {
                rule_engine::FieldDescriptor {
                    .key = "demo.import_count",
                    .type = rule_engine::ValueType::integer,
                    .route = "endpoint.demo.static",
                    .ttl = 30s,
                    .timeout = 5s,
                    .cheap_prefetch = false,
                    .cost_class = rule_engine::FactCostClass::broad_image_array,
                },
            },
        .functions = {},
    });

    auto parsed = rule_engine::parse_source("client_optimizer_plan_static_identity.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());
    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);

    const std::vector<rule_engine::Subject> requested_subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:identity-a"},
        rule_engine::Subject {.kind = "process", .id = "pid:identity-b"},
    };

    rule_engine::FactCache identity_facts;
    const auto store_string = [&](const std::string &subject_id, std::string key, std::string value) {
        identity_facts.store(rule_engine::Fact {
            .subject_id = subject_id,
            .key = std::move(key),
            .value = rule_engine::Value::string(std::move(value)),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = 30s,
        });
    };
    const auto store_integer = [&](const std::string &subject_id, std::string key, const std::int64_t value) {
        identity_facts.store(rule_engine::Fact {
            .subject_id = subject_id,
            .key = std::move(key),
            .value = rule_engine::Value::integer(value),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = 30s,
        });
    };
    const auto store_identity = [&](const std::string &subject_id) {
        store_string(subject_id, "static.identity.path", "C:/Windows/System32/shared-static.exe");
        store_string(subject_id, "static.identity.file_id", "volume:42:file:7");
        store_integer(subject_id, "static.identity.file_size", 4096);
        store_integer(subject_id, "static.identity.last_write_time", 1000);
        store_string(subject_id, "static.identity.content_hash", "sha256:aaa");
        store_string(subject_id, "static.identity.signature_identity", "catalog:stable");
        store_string(subject_id, "static.identity.scan_space_name", "process.image.bytes");
        store_string(subject_id, "static.identity.scan_space_version", "v1");
    };
    store_identity("pid:identity-a");
    store_identity("pid:identity-b");

    std::vector<rule_engine::protocol::FactKey> observed_keys;
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities = {rule_engine::protocol::Capability {.route = "endpoint.demo.static"}},
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.static") {
                        return std::nullopt;
                    }
                    observed_keys.insert(observed_keys.end(), request.keys.begin(), request.keys.end());

                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    for (const auto &key : request.keys) {
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::integer(7),
                            .status = rule_engine::FactStatus::available,
                            .diagnostic = {},
                            .ttl = 30s,
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::optimizer::StaticFactCache static_cache;
    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_optimizer_plan(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified, plan, requested_subjects,
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 1u,
            .instrumentation = &instrumentation,
            .static_fact_cache = &static_cache,
            .static_fact_identity_facts = &identity_facts,
            .static_fact_identity_fact_keys =
                rule_engine::optimizer::StaticFactIdentityFactKeys {
                    .path = "static.identity.path",
                    .file_id = "static.identity.file_id",
                    .file_size = "static.identity.file_size",
                    .last_write_time = "static.identity.last_write_time",
                    .content_hash = "static.identity.content_hash",
                    .signature_identity = "static.identity.signature_identity",
                    .scan_space_name = "static.identity.scan_space_name",
                    .scan_space_version = "static.identity.scan_space_version",
                },
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());

    REQUIRE(observed_keys.size() == 1u);
    CHECK(observed_keys[0].subject_id == "pid:identity-a");
    CHECK(observed_keys[0].key == "demo.import_count");
    CHECK(instrumentation.provider_requests == 1u);
    CHECK(instrumentation.provider_fact_keys_requested == 1u);
    CHECK(instrumentation.provider_facts_returned == 1u);
    CHECK(instrumentation.static_fact_cache_lookups == 2u);
    CHECK(instrumentation.static_fact_cache_hits == 1u);
    CHECK(instrumentation.static_fact_cache_misses == 1u);
    CHECK(instrumentation.static_fact_cache_reuses == 1u);
    CHECK(instrumentation.static_fact_cache_invalidations == 0u);

    REQUIRE(evaluation->facts.size() == 2u);
    CHECK(evaluation->facts[0].subject_id == "pid:identity-a");
    CHECK(evaluation->facts[0].value.as_i64() == 7);
    CHECK(evaluation->facts[1].subject_id == "pid:identity-b");
    CHECK(evaluation->facts[1].value.as_i64() == 7);
    CHECK(std::ranges::any_of(evaluation->sweep.trace_events, [](const auto &event) {
        return event.event == "static_fact_cache_reused" && event.subject_id == "pid:identity-b";
    }));

    const auto replay_report = rule_engine::client_protocol::replay_optimized_client_evaluation_with_parity_report(
        *verified, plan, *evaluation);
    CHECK(replay_report.subject_mismatches == 0u);
    CHECK(replay_report.rule_result_mismatches == 0u);
    CHECK(replay_report.trace_event_mismatches == 0u);
    CHECK(replay_report.sweep_metric_mismatches == 0u);
}

TEST_CASE("localhost optimizer plan prefetches production PE identity facts before static cache derivation") {
    using namespace std::chrono_literals;

    constexpr std::string_view source = R"(
import "demo"

rule reusable_static_fact {
    condition:
        demo.import_count > 0
}
)";
    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields =
            {
                rule_engine::FieldDescriptor {
                    .key = "demo.import_count",
                    .type = rule_engine::ValueType::integer,
                    .route = "endpoint.demo.static",
                    .ttl = 30s,
                    .timeout = 5s,
                    .cheap_prefetch = false,
                    .cost_class = rule_engine::FactCostClass::broad_image_array,
                },
            },
        .functions = {},
    });

    auto parsed = rule_engine::parse_source("client_optimizer_plan_static_identity_prefetch.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());
    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);

    const std::vector<rule_engine::Subject> requested_subjects {
        rule_engine::Subject {.kind = "process", .id = "pid:prefetch-a"},
        rule_engine::Subject {.kind = "process", .id = "pid:prefetch-b"},
    };

    std::vector<rule_engine::protocol::FactKey> observed_identity_keys;
    std::vector<rule_engine::protocol::FactKey> observed_static_keys;
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities =
                    {
                        rule_engine::protocol::Capability {.route = "endpoint.demo.identity"},
                        rule_engine::protocol::Capability {.route = "endpoint.demo.static"},
                    },
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route == "endpoint.demo.identity") {
                        observed_identity_keys.insert(observed_identity_keys.end(), request.keys.begin(),
                                                      request.keys.end());
                        rule_engine::protocol::FactBatchResponseMessage response;
                        response.route = request.route;
                        for (const auto &key : request.keys) {
                            rule_engine::Value value = rule_engine::Value::undefined();
                            if (key.key == "pe.identity.path") {
                                value = rule_engine::Value::string("C:/Windows/System32/shared-static.exe");
                            } else if (key.key == "pe.identity.file_id") {
                                value = rule_engine::Value::string("volume:42:file:7");
                            } else if (key.key == "pe.identity.file_size") {
                                value = rule_engine::Value::integer(4096);
                            } else if (key.key == "pe.identity.last_write_time") {
                                value = rule_engine::Value::integer(1000);
                            } else if (key.key == "pe.identity.scan_space_name") {
                                value = rule_engine::Value::string("process.image.pe");
                            } else if (key.key == "pe.identity.scan_space_version") {
                                value = rule_engine::Value::string("v1");
                            }
                            response.values.push_back(rule_engine::Fact {
                                .subject_id = key.subject_id,
                                .key = key.key,
                                .value = std::move(value),
                                .status = rule_engine::FactStatus::available,
                                .diagnostic = {},
                                .ttl = 30s,
                            });
                        }
                        return response;
                    }
                    if (request.route != "endpoint.demo.static") {
                        return std::nullopt;
                    }
                    observed_static_keys.insert(observed_static_keys.end(), request.keys.begin(), request.keys.end());

                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    for (const auto &key : request.keys) {
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::integer(11),
                            .status = rule_engine::FactStatus::available,
                            .diagnostic = {},
                            .ttl = 30s,
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::optimizer::StaticFactCache static_cache;
    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_optimizer_plan(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified, plan, requested_subjects,
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 1u,
            .instrumentation = &instrumentation,
            .static_fact_cache = &static_cache,
            .static_fact_identity_route = "endpoint.demo.identity",
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());

    REQUIRE(observed_identity_keys.size() == 12u);
    CHECK(observed_identity_keys[0].subject_id == "pid:prefetch-a");
    CHECK(observed_identity_keys[0].key == "pe.identity.path");
    CHECK(observed_identity_keys[6].subject_id == "pid:prefetch-b");
    CHECK(observed_identity_keys[6].key == "pe.identity.path");
    REQUIRE(observed_static_keys.size() == 1u);
    CHECK(observed_static_keys[0].subject_id == "pid:prefetch-a");
    CHECK(observed_static_keys[0].key == "demo.import_count");

    CHECK(instrumentation.provider_rounds == 2u);
    CHECK(instrumentation.provider_requests == 2u);
    CHECK(instrumentation.provider_fact_keys_requested == 13u);
    CHECK(instrumentation.provider_facts_returned == 13u);
    CHECK(instrumentation.static_fact_cache_lookups == 2u);
    CHECK(instrumentation.static_fact_cache_hits == 1u);
    CHECK(instrumentation.static_fact_cache_misses == 1u);
    CHECK(instrumentation.static_fact_cache_reuses == 1u);

    REQUIRE(evaluation->facts.size() == 2u);
    CHECK(evaluation->facts[0].subject_id == "pid:prefetch-a");
    CHECK(evaluation->facts[0].value.as_i64() == 11);
    CHECK(evaluation->facts[1].subject_id == "pid:prefetch-b");
    CHECK(evaluation->facts[1].value.as_i64() == 11);
    CHECK(std::ranges::any_of(evaluation->sweep.trace_events, [](const auto &event) {
        return event.event == "static_fact_cache_reused" && event.subject_id == "pid:prefetch-b";
    }));

    const auto replay_report = rule_engine::client_protocol::replay_optimized_client_evaluation_with_parity_report(
        *verified, plan, *evaluation);
    CHECK(replay_report.subject_mismatches == 0u);
    CHECK(replay_report.rule_result_mismatches == 0u);
    CHECK(replay_report.trace_event_mismatches == 0u);
    CHECK(replay_report.sweep_metric_mismatches == 0u);
}

TEST_CASE("localhost optimizer plan reuses live PE header facts after production identity prefetch") {
    using namespace std::chrono_literals;

    auto first_process = start_hidden_ping_process();
    auto second_process = start_hidden_ping_process();

    constexpr std::string_view source = R"(
import "pe"

rule reusable_live_pe_header {
    condition:
        pe.number_of_sections > 0
}
)";
    auto parsed = rule_engine::parse_source("client_optimizer_plan_live_pe_header_static_identity.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);

    const std::vector<rule_engine::Subject> requested_subjects {
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(first_process.info.dwProcessId),
        },
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(second_process.info.dwProcessId),
        },
    };

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::optimizer::StaticFactCache static_cache;
    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_optimizer_plan(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified, plan, requested_subjects,
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 1u,
            .instrumentation = &instrumentation,
            .static_fact_cache = &static_cache,
            .static_fact_identity_route = "endpoint.process.image.pe",
        });

    server.join();
    if (server_error.has_value()) {
        INFO("server_error diagnostics: " << server_error->diagnostics.size());
        for (const auto &diagnostic : server_error->diagnostics) { INFO(diagnostic.message); }
    }
    if (!evaluation.has_value()) {
        INFO("evaluation diagnostics: " << evaluation.error().diagnostics.size());
        for (const auto &diagnostic : evaluation.error().diagnostics) { INFO(diagnostic.message); }
    }
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());

    CHECK(instrumentation.provider_rounds == 2u);
    CHECK(instrumentation.provider_requests == 2u);
    CHECK(instrumentation.provider_fact_keys_requested == 13u);
    CHECK(instrumentation.provider_facts_returned == 13u);
    CHECK(instrumentation.static_fact_cache_lookups == 2u);
    CHECK(instrumentation.static_fact_cache_hits == 1u);
    CHECK(instrumentation.static_fact_cache_misses == 1u);
    CHECK(instrumentation.static_fact_cache_reuses == 1u);
    CHECK(instrumentation.static_fact_cache_provider_fact_keys_avoided == 1u);

    REQUIRE(evaluation->evaluated_subjects.size() == 2u);
    CHECK(std::ranges::any_of(evaluation->sweep.trace_events, [&](const auto &event) {
        return event.event == "static_fact_cache_reused" && event.subject_id == requested_subjects[1].id;
    }));

    const auto replay_report = rule_engine::client_protocol::replay_optimized_client_evaluation_with_parity_report(
        *verified, plan, *evaluation);
    CHECK(replay_report.subject_mismatches == 0u);
    CHECK(replay_report.rule_result_mismatches == 0u);
    CHECK(replay_report.trace_event_mismatches == 0u);
    CHECK(replay_report.sweep_metric_mismatches == 0u);
}

TEST_CASE("localhost optimizer plan reuses live PE import facts after production identity prefetch") {
    using namespace std::chrono_literals;

    auto first_process = start_hidden_ping_process();
    auto second_process = start_hidden_ping_process();

    constexpr std::string_view source = R"(
import "pe"

rule reusable_live_pe_imports {
    condition:
        for any imported in pe.imports : (imported["dll"] contains "KERNEL32.dll")
}
)";
    auto parsed = rule_engine::parse_source("client_optimizer_plan_live_pe_import_static_identity.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);

    const std::vector<rule_engine::Subject> requested_subjects {
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(first_process.info.dwProcessId),
        },
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(second_process.info.dwProcessId),
        },
    };

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::optimizer::StaticFactCache static_cache;
    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_optimizer_plan(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified, plan, requested_subjects,
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 1u,
            .instrumentation = &instrumentation,
            .static_fact_cache = &static_cache,
            .static_fact_identity_route = "endpoint.process.image.pe",
        });

    server.join();
    if (server_error.has_value()) {
        INFO("server_error diagnostics: " << server_error->diagnostics.size());
        for (const auto &diagnostic : server_error->diagnostics) { INFO(diagnostic.message); }
    }
    if (!evaluation.has_value()) {
        INFO("evaluation diagnostics: " << evaluation.error().diagnostics.size());
        for (const auto &diagnostic : evaluation.error().diagnostics) { INFO(diagnostic.message); }
    }
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());

    CHECK(instrumentation.provider_rounds == 2u);
    CHECK(instrumentation.provider_requests == 2u);
    CHECK(instrumentation.provider_fact_keys_requested == 13u);
    CHECK(instrumentation.provider_facts_returned == 13u);
    CHECK(instrumentation.static_fact_cache_lookups == 2u);
    CHECK(instrumentation.static_fact_cache_hits == 1u);
    CHECK(instrumentation.static_fact_cache_misses == 1u);
    CHECK(instrumentation.static_fact_cache_reuses == 1u);
    CHECK(instrumentation.static_fact_cache_provider_fact_keys_avoided == 1u);

    const auto *first_imports = find_fact(evaluation->facts, requested_subjects[0].id, "pe.imports");
    REQUIRE(first_imports != nullptr);
    REQUIRE(first_imports->status == rule_engine::FactStatus::available);
    REQUIRE(first_imports->value.as_array() != nullptr);
    REQUIRE_FALSE(first_imports->value.as_array()->values.empty());

    const auto *second_imports = find_fact(evaluation->facts, requested_subjects[1].id, "pe.imports");
    REQUIRE(second_imports != nullptr);
    REQUIRE(second_imports->status == rule_engine::FactStatus::available);
    REQUIRE(second_imports->value.as_array() != nullptr);
    REQUIRE_FALSE(second_imports->value.as_array()->values.empty());

    REQUIRE(evaluation->evaluated_subjects.size() == 2u);
    CHECK(std::ranges::any_of(evaluation->sweep.trace_events, [&](const auto &event) {
        return event.event == "static_fact_cache_reused" && event.subject_id == requested_subjects[1].id;
    }));

    const auto replay_report = rule_engine::client_protocol::replay_optimized_client_evaluation_with_parity_report(
        *verified, plan, *evaluation);
    CHECK(replay_report.subject_mismatches == 0u);
    CHECK(replay_report.rule_result_mismatches == 0u);
    CHECK(replay_report.trace_event_mismatches == 0u);
    CHECK(replay_report.sweep_metric_mismatches == 0u);
}

namespace {
    void assert_live_pe_array_fact_static_reuse(const std::string_view source_name,
                                                const std::string_view source,
                                                const std::string_view fact_key) {
        using namespace std::chrono_literals;

        auto first_process = start_hidden_ping_process();
        auto second_process = start_hidden_ping_process();

        auto parsed = rule_engine::parse_source(source_name, source);
        REQUIRE(parsed.has_value());
        auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
        REQUIRE(verified.has_value());
        REQUIRE(verified->rules.size() == 1u);
        REQUIRE(verified->rules[0].facts.size() == 1u);
        CHECK(verified->rules[0].facts[0].key == fact_key);
        const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);

        const std::vector<rule_engine::Subject> requested_subjects {
            rule_engine::Subject {
                .kind = "process",
                .id = "pid:" + std::to_string(first_process.info.dwProcessId),
            },
            rule_engine::Subject {
                .kind = "process",
                .id = "pid:" + std::to_string(second_process.info.dwProcessId),
            },
        };

        std::promise<std::uint16_t> listening_port;
        auto listening = listening_port.get_future();
        std::optional<rule_engine::ErrorSet> server_error;

        std::thread server {[&] {
            auto result = rule_engine::client_protocol::serve_client_once(
                rule_engine::client_protocol::ClientListenOptions {
                    .bind_address = "127.0.0.1",
                    .port = 0u,
                    .pattern_fixture_path = {},
                    .io_timeout = std::chrono::milliseconds {5000},
                },
                [&](const std::uint16_t port) { listening_port.set_value(port); });
            if (!result) {
                server_error = std::move(result.error());
            }
        }};

        REQUIRE(listening.wait_for(5s) == std::future_status::ready);
        const auto port = listening.get();
        rule_engine::optimizer::StaticFactCache static_cache;
        rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
        auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_optimizer_plan(
            rule_engine::client_protocol::ClientConnectionOptions {
                .host = "127.0.0.1",
                .port = port,
                .io_timeout = std::chrono::milliseconds {5000},
            },
            *verified, plan, requested_subjects,
            rule_engine::client_protocol::ClientEvaluationOptions {
                .max_subject_concurrency = 1u,
                .instrumentation = &instrumentation,
                .static_fact_cache = &static_cache,
                .static_fact_identity_route = "endpoint.process.image.pe",
            });

        server.join();
        if (server_error.has_value()) {
            INFO("server_error diagnostics: " << server_error->diagnostics.size());
            for (const auto &diagnostic : server_error->diagnostics) { INFO(diagnostic.message); }
        }
        if (!evaluation.has_value()) {
            INFO("evaluation diagnostics: " << evaluation.error().diagnostics.size());
            for (const auto &diagnostic : evaluation.error().diagnostics) { INFO(diagnostic.message); }
        }
        REQUIRE_FALSE(server_error.has_value());
        REQUIRE(evaluation.has_value());

        CHECK(instrumentation.provider_rounds == 2u);
        CHECK(instrumentation.provider_requests == 2u);
        CHECK(instrumentation.provider_fact_keys_requested == 13u);
        CHECK(instrumentation.provider_facts_returned == 13u);
        CHECK(instrumentation.static_fact_cache_lookups == 2u);
        CHECK(instrumentation.static_fact_cache_hits == 1u);
        CHECK(instrumentation.static_fact_cache_misses == 1u);
        CHECK(instrumentation.static_fact_cache_reuses == 1u);
        CHECK(instrumentation.static_fact_cache_provider_fact_keys_avoided == 1u);

        const auto *first_fact = find_fact(evaluation->facts, requested_subjects[0].id, fact_key);
        REQUIRE(first_fact != nullptr);
        REQUIRE(first_fact->status == rule_engine::FactStatus::available);
        const auto *first_array = first_fact->value.as_array();
        REQUIRE(first_array != nullptr);

        const auto *second_fact = find_fact(evaluation->facts, requested_subjects[1].id, fact_key);
        REQUIRE(second_fact != nullptr);
        REQUIRE(second_fact->status == rule_engine::FactStatus::available);
        const auto *second_array = second_fact->value.as_array();
        REQUIRE(second_array != nullptr);
        CHECK(second_array->values.size() == first_array->values.size());
        if (!first_array->values.empty()) {
            CHECK(first_array->values[0].as_object() != nullptr);
            REQUIRE_FALSE(second_array->values.empty());
            CHECK(second_array->values[0].as_object() != nullptr);
        }

        REQUIRE(evaluation->evaluated_subjects.size() == 2u);
        CHECK(std::ranges::any_of(evaluation->sweep.trace_events, [&](const auto &event) {
            return event.event == "static_fact_cache_reused" && event.subject_id == requested_subjects[1].id &&
                   event.predicate_id == "endpoint.process.image.pe|" + std::string {fact_key};
        }));
        REQUIRE(evaluation->sweep.subjects.size() == 2u);
        REQUIRE(evaluation->sweep.subjects[0].rule_results.size() == 1u);
        REQUIRE(evaluation->sweep.subjects[1].rule_results.size() == 1u);
        CHECK(evaluation->sweep.subjects[0].rule_results[0].matched ==
              evaluation->sweep.subjects[1].rule_results[0].matched);

        const auto replay_report = rule_engine::client_protocol::replay_optimized_client_evaluation_with_parity_report(
            *verified, plan, *evaluation);
        CHECK(replay_report.subject_mismatches == 0u);
        CHECK(replay_report.rule_result_mismatches == 0u);
        CHECK(replay_report.trace_event_mismatches == 0u);
        CHECK(replay_report.sweep_metric_mismatches == 0u);
    }
} // namespace

TEST_CASE("localhost optimizer plan reuses live PE export facts after production identity prefetch") {
    constexpr std::string_view source = R"(
import "pe"

rule reusable_live_pe_exports {
    condition:
        for all exported in pe.exports : (exported["rva"] >= 0)
}
)";
    assert_live_pe_array_fact_static_reuse(
        "client_optimizer_plan_live_pe_export_static_identity.yar", source, "pe.exports");
}

TEST_CASE("localhost optimizer plan reuses live PE resource facts after production identity prefetch") {
    constexpr std::string_view source = R"(
import "pe"

rule reusable_live_pe_resources {
    condition:
        for all resource in pe.resources : (resource["rva"] >= 0)
}
)";
    assert_live_pe_array_fact_static_reuse(
        "client_optimizer_plan_live_pe_resource_static_identity.yar", source, "pe.resources");
}

TEST_CASE("localhost optimizer plan reuses live PE debug directory facts after production identity prefetch") {
    constexpr std::string_view source = R"(
import "pe"

rule reusable_live_pe_debug_entries {
    condition:
        for all entry in pe.debug_entries : (entry["type"] >= 0)
}
)";
    assert_live_pe_array_fact_static_reuse(
        "client_optimizer_plan_live_pe_debug_static_identity.yar", source, "pe.debug_entries");
}

TEST_CASE("localhost optimizer plan reuses live PE certificate facts after production identity prefetch") {
    constexpr std::string_view source = R"(
import "pe"

rule reusable_live_pe_certificates {
    condition:
        for all certificate in pe.certificates : (certificate["file_offset"] >= 0)
}
)";
    assert_live_pe_array_fact_static_reuse(
        "client_optimizer_plan_live_pe_certificate_static_identity.yar", source, "pe.certificates");
}

TEST_CASE("localhost optimizer plan reuses live PE TLS callback facts after production identity prefetch") {
    constexpr std::string_view source = R"(
import "pe"

rule reusable_live_pe_tls_callbacks {
    condition:
        for all callback in pe.tls_callbacks : (callback["rva"] >= 0)
}
)";
    assert_live_pe_array_fact_static_reuse(
        "client_optimizer_plan_live_pe_tls_static_identity.yar", source, "pe.tls_callbacks");
}

TEST_CASE("localhost optimizer plan falls back when candidate provider filter is not advertised") {
    constexpr std::string_view source = R"(
import "process"

rule current_name {
    condition:
        process.name == "rule_engine_tests.exe"
}
)";
    auto parsed = rule_engine::parse_source("client_optimizer_plan_fallback.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());
    const auto plan = rule_engine::optimizer::build_optimizer_plan(*verified);
    REQUIRE(plan.candidate_provider_requests.size() == 1u);

    const auto current_subject_id = "pid:" + std::to_string(GetCurrentProcessId());
    const std::vector<rule_engine::Subject> requested_subjects {
        rule_engine::Subject {
            .kind = "process",
            .id = current_subject_id,
        },
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:0",
        },
    };

    bool candidate_provider_called {false};
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities = {},
                .extra_fact_handler = {},
                .extra_candidate_provider_handler = [&](const rule_engine::protocol::CandidateProviderRequestMessage &)
                    -> std::optional<rule_engine::protocol::CandidateProviderResponseMessage> {
                    candidate_provider_called = true;
                    return std::nullopt;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_optimizer_plan(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified, plan, requested_subjects,
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 2u,
            .instrumentation = &instrumentation,
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());
    CHECK_FALSE(candidate_provider_called);
    CHECK(evaluation->sweep.candidate_provider_requests == 1u);
    CHECK(evaluation->sweep.candidate_provider_subjects_returned == 0u);
    CHECK(evaluation->sweep.candidate_provider_fallback_predicate_evaluations == 2u);
    CHECK(evaluation->sweep.incomplete_subjects.empty());
    CHECK(instrumentation.candidate_provider_requests == 0u);
    CHECK(instrumentation.candidate_provider_filters_requested == 0u);
    CHECK(instrumentation.candidate_provider_subjects_returned == 0u);
    CHECK(instrumentation.candidate_provider_filters_not_advertised == 1u);
    CHECK(instrumentation.provider_fact_keys_requested == 2u);
    REQUIRE(evaluation->facts.size() == 2u);
    CHECK(std::ranges::any_of(evaluation->facts, [&](const auto &fact) {
        return fact.subject_id == current_subject_id && fact.key == "process.name";
    }));
    CHECK(std::ranges::any_of(
        evaluation->facts, [](const auto &fact) { return fact.subject_id == "pid:0" && fact.key == "process.name"; }));
    CHECK(evaluation->candidate_provider_results.empty());
    REQUIRE(evaluation->evaluated_subjects.size() == requested_subjects.size());
    CHECK(evaluation->evaluated_subjects[0].id == current_subject_id);
    CHECK(evaluation->evaluated_subjects[1].id == "pid:0");
    const auto replayed_sweep =
        rule_engine::client_protocol::replay_optimized_client_evaluation(*verified, plan, *evaluation);
    CHECK(replayed_sweep.incomplete_subjects.empty());
    REQUIRE(replayed_sweep.subjects.size() == evaluation->sweep.subjects.size());
    REQUIRE(replayed_sweep.subjects[0].rule_results.size() == evaluation->sweep.subjects[0].rule_results.size());
    CHECK(replayed_sweep.subjects[0].rule_results[0].matched == evaluation->sweep.subjects[0].rule_results[0].matched);
    REQUIRE(replayed_sweep.subjects[1].rule_results.size() == evaluation->sweep.subjects[1].rule_results.size());
    CHECK(replayed_sweep.subjects[1].rule_results[0].matched == evaluation->sweep.subjects[1].rule_results[0].matched);
    REQUIRE(evaluation->sweep.subjects.size() == 2u);
    CHECK(evaluation->sweep.subjects[0].subject_id == current_subject_id);
    REQUIRE(evaluation->sweep.subjects[0].rule_results.size() == 1u);
    CHECK(evaluation->sweep.subjects[0].rule_results[0].matched);
    CHECK(evaluation->sweep.subjects[1].subject_id == "pid:0");
    REQUIRE(evaluation->sweep.subjects[1].rule_results.size() == 1u);
    CHECK_FALSE(evaluation->sweep.subjects[1].rule_results[0].matched);
}

TEST_CASE("client connection times out when handshake is not received") {
    using namespace std::chrono_literals;
    using asio::ip::tcp;

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<asio::error_code> server_error;

    std::thread server {[&] {
        asio::io_context io;
        asio::error_code ec;
        tcp::acceptor acceptor {io};
        const tcp::endpoint endpoint {asio::ip::make_address("127.0.0.1", ec), 0u};
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        acceptor.open(endpoint.protocol(), ec);
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        const auto local = acceptor.local_endpoint(ec);
        if (ec) {
            server_error = ec;
            listening_port.set_value(0u);
            return;
        }
        listening_port.set_value(local.port());
        tcp::socket socket {io};
        acceptor.accept(socket, ec);
        if (ec) {
            server_error = ec;
            return;
        }
        std::this_thread::sleep_for(400ms);
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = 100ms,
        },
        {});

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(session.has_value());
    REQUIRE_FALSE(session.error().diagnostics.empty());
    CHECK(session.error().diagnostics[0].message.find("timed out") != std::string::npos);
}

TEST_CASE("client connection applies fact request timeout while waiting for a response") {
    using namespace std::chrono_literals;
    using asio::ip::tcp;

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<std::string> server_error;

    std::thread server {[&] {
        asio::io_context io;
        asio::error_code ec;
        tcp::acceptor acceptor {io};
        const tcp::endpoint endpoint {asio::ip::make_address("127.0.0.1", ec), 0u};
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.open(endpoint.protocol(), ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        const auto local = acceptor.local_endpoint(ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        listening_port.set_value(local.port());

        tcp::socket socket {io};
        acceptor.accept(socket, ec);
        if (ec) {
            server_error = ec.message();
            return;
        }

        rule_engine::protocol::HandshakeMessage handshake;
        handshake.protocol = "rule-engine-client";
        handshake.version = 1u;
        handshake.capabilities.push_back(rule_engine::protocol::Capability {.route = "endpoint.process.snapshot"});
        auto handshake_payload = rule_engine::protocol::encode_handshake(handshake);
        if (!handshake_payload) {
            server_error = "handshake encode failed";
            return;
        }
        if (auto error = write_protocol_frame(socket, *handshake_payload); error.has_value()) {
            server_error = std::move(*error);
            return;
        }

        rule_engine::protocol::SubjectListMessage subjects;
        subjects.subjects.push_back(rule_engine::Subject {.kind = "process", .id = "pid:self"});
        auto subjects_payload = rule_engine::protocol::encode_subject_list(subjects);
        if (!subjects_payload) {
            server_error = "subject list encode failed";
            return;
        }
        if (auto error = write_protocol_frame(socket, *subjects_payload); error.has_value()) {
            server_error = std::move(*error);
            return;
        }

        std::this_thread::sleep_for(1200ms);
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.process.snapshot";
    request.timeout = 100ms;
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:self",
        .key = "process.pid",
    });

    const auto started = std::chrono::steady_clock::now();
    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = 2500ms,
        },
        std::vector<rule_engine::protocol::FactBatchRequestMessage> {request});
    const auto elapsed = std::chrono::steady_clock::now() - started;

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(session.has_value());
    REQUIRE_FALSE(session.error().diagnostics.empty());
    CHECK(session.error().diagnostics[0].message.find("timed out") != std::string::npos);
    CHECK(elapsed < 1s);
}

TEST_CASE("client evaluator rejects provider responses with unrequested facts") {
    using namespace std::chrono_literals;
    using asio::ip::tcp;

    constexpr std::string_view source = R"(
import "process"

global rule allow_scan {
    condition:
        scan_mode == "on"
}

rule injected_process_name {
    condition:
        process.name == "evil.exe"
}
)";

    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.globals.push_back(rule_engine::GlobalDescriptor {
        .name = "scan_mode",
        .type = rule_engine::ValueType::string,
        .key = "global.scan_mode",
        .route = "endpoint.globals",
        .ttl = std::chrono::seconds {30},
        .cheap_prefetch = true,
    });

    auto parsed = rule_engine::parse_source("injected_fact.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<std::string> server_error;

    std::thread server {[&] {
        asio::io_context io;
        asio::error_code ec;
        tcp::acceptor acceptor {io};
        const tcp::endpoint endpoint {asio::ip::make_address("127.0.0.1", ec), 0u};
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.open(endpoint.protocol(), ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.bind(endpoint, ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        const auto local = acceptor.local_endpoint(ec);
        if (ec) {
            server_error = ec.message();
            listening_port.set_value(0u);
            return;
        }
        listening_port.set_value(local.port());

        tcp::socket socket {io};
        acceptor.accept(socket, ec);
        if (ec) {
            server_error = ec.message();
            return;
        }

        rule_engine::protocol::HandshakeMessage handshake;
        handshake.protocol = "rule-engine-client";
        handshake.version = 1u;
        handshake.capabilities.push_back(rule_engine::protocol::Capability {.route = "endpoint.globals"});
        handshake.capabilities.push_back(rule_engine::protocol::Capability {.route = "endpoint.process.snapshot"});
        auto handshake_payload = rule_engine::protocol::encode_handshake(handshake);
        if (!handshake_payload || write_protocol_frame(socket, *handshake_payload).has_value()) {
            server_error = "handshake write failed";
            return;
        }

        rule_engine::protocol::SubjectListMessage subjects;
        subjects.subjects.push_back(rule_engine::Subject {.kind = "process", .id = "pid:1"});
        auto subjects_payload = rule_engine::protocol::encode_subject_list(subjects);
        if (!subjects_payload || write_protocol_frame(socket, *subjects_payload).has_value()) {
            server_error = "subject write failed";
            return;
        }

        auto request_payload = read_protocol_frame(socket);
        if (!request_payload) {
            server_error = std::move(request_payload.error());
            return;
        }

        rule_engine::protocol::FactBatchResponseMessage response;
        response.route = "endpoint.globals";
        response.values.push_back(rule_engine::Fact {
            .subject_id = "pid:1",
            .key = "global.scan_mode",
            .value = rule_engine::Value::string("on"),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {30},
        });
        response.values.push_back(rule_engine::Fact {
            .subject_id = "pid:1",
            .key = "process.name",
            .value = rule_engine::Value::string("evil.exe"),
            .status = rule_engine::FactStatus::available,
            .diagnostic = {},
            .ttl = std::chrono::seconds {0},
        });
        auto response_payload = rule_engine::protocol::encode_fact_batch_response(response);
        if (!response_payload || write_protocol_frame(socket, *response_payload).has_value()) {
            server_error = "fact response write failed";
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = 2500ms,
        },
        *verified, rule_engine::Subject {.kind = "process", .id = "pid:1"});

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(evaluation.has_value());
    REQUIRE_FALSE(evaluation.error().diagnostics.empty());
    CHECK(evaluation.error().diagnostics[0].message.find("unrequested fact") != std::string::npos);
}

TEST_CASE("client evaluator retries descriptor timed-out facts before caching diagnostics") {
    using namespace std::chrono_literals;

    constexpr std::string_view source = R"(
import "demo"

rule retry_demo_fact {
    condition:
        demo.value == 7
}
)";

    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields =
            {
                rule_engine::FieldDescriptor {
                    .key = "demo.value",
                    .type = rule_engine::ValueType::integer,
                    .route = "endpoint.demo.retry",
                    .ttl = 30s,
                    .timeout = 5s,
                    .retry_policy = rule_engine::ProviderRetryPolicy::timed_out,
                    .retry_budget = 1u,
                    .cancellation_diagnostic = "demo value cancelled",
                    .cheap_prefetch = true,
                },
            },
        .functions = {},
    });

    auto parsed = rule_engine::parse_source("retry_demo_fact.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;
    std::size_t attempts {};

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = 5000ms,
                .extra_capabilities = {rule_engine::protocol::Capability {.route = "endpoint.demo.retry"}},
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.retry") {
                        return std::nullopt;
                    }

                    ++attempts;
                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    for (const auto &key : request.keys) {
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = attempts == 1u ? rule_engine::Value::undefined() :
                                                       rule_engine::Value::integer(7),
                            .status = attempts == 1u ? rule_engine::FactStatus::timed_out :
                                                       rule_engine::FactStatus::available,
                            .diagnostic = attempts == 1u ? std::string {"transient demo timeout"} : std::string {},
                            .ttl = attempts == 1u ? 0s : 30s,
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = 5000ms,
        },
        *verified, rule_engine::Subject {.kind = "process", .id = "pid:self"});

    server.join();

    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].matched);
    CHECK(evaluation->final_step.rule_results[0].diagnostics.empty());
    CHECK(attempts == 2u);
}

TEST_CASE("client evaluator uses descriptor cancellation diagnostics when stopped before provider dispatch") {
    using namespace std::chrono_literals;

    constexpr std::string_view source = R"(
import "demo"

rule cancelled_demo_fact {
    condition:
        demo.value == 7
}
)";

    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields =
            {
                rule_engine::FieldDescriptor {
                    .key = "demo.value",
                    .type = rule_engine::ValueType::integer,
                    .route = "endpoint.demo.cancel_descriptor",
                    .ttl = 30s,
                    .timeout = 5s,
                    .retry_policy = rule_engine::ProviderRetryPolicy::none,
                    .retry_budget = 0u,
                    .cancellation_diagnostic = "demo value descriptor cancellation",
                    .cheap_prefetch = true,
                },
            },
        .functions = {},
    });

    auto parsed = rule_engine::parse_source("cancelled_demo_fact.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;
    bool provider_called {};

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = 5000ms,
                .extra_capabilities = {rule_engine::protocol::Capability {.route = "endpoint.demo.cancel_descriptor"}},
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.cancel_descriptor") {
                        return std::nullopt;
                    }
                    provider_called = true;
                    return std::nullopt;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(5s) == std::future_status::ready);
    const auto port = listening.get();
    REQUIRE(port != 0u);

    std::stop_source stop_source;
    stop_source.request_stop();
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = 5000ms,
        },
        *verified, std::vector<rule_engine::Subject> {rule_engine::Subject {.kind = "process", .id = "pid:self"}},
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 1u,
            .max_provider_rounds = 16u,
            .stop_token = stop_source.get_token(),
        });

    server.join();

    REQUIRE_FALSE(server_error.has_value());
    CHECK_FALSE(provider_called);
    REQUIRE(evaluation.has_value());
    REQUIRE(evaluation->evaluations.size() == 1u);
    REQUIRE(evaluation->evaluations[0].final_step.rule_results.size() == 1u);
    const auto &result = evaluation->evaluations[0].final_step.rule_results[0];
    CHECK_FALSE(result.matched);
    REQUIRE(result.diagnostics.size() == 1u);
    CHECK(result.diagnostics[0].message == "demo value descriptor cancellation");
}

TEST_CASE("localhost client session resolves custom module function facts") {
    constexpr std::string_view source = R"(
import "process"
import "demo"

rule custom_module_function {
    condition:
        demo.score(process.pid, "alpha") > 7
}
)";
    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields = {},
        .functions =
            {
                rule_engine::FunctionDescriptor {
                    .name = "score",
                    .parameters = {rule_engine::ValueType::integer, rule_engine::ValueType::string},
                    .return_type = rule_engine::ValueType::integer,
                    .key_prefix = "demo.score",
                    .route = "endpoint.demo.functions",
                    .ttl = std::chrono::seconds {30},
                    .cheap_prefetch = false,
                },
            },
    });

    auto parsed = rule_engine::parse_source("custom_function_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;
    std::string observed_route;
    std::vector<std::string> observed_keys;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities =
                    {
                        rule_engine::protocol::Capability {.route = "endpoint.demo.functions"},
                    },
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.functions") {
                        return std::nullopt;
                    }

                    observed_route = request.route;
                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    response.values.reserve(request.keys.size());
                    for (const auto &key : request.keys) {
                        observed_keys.push_back(key.key);
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::integer(9),
                            .status = rule_engine::FactStatus::available,
                            .diagnostic = {},
                            .ttl = std::chrono::seconds {30},
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(std::ranges::any_of(evaluation->handshake.capabilities,
                              [](const auto &capability) { return capability.route == "endpoint.demo.functions"; }));
    CHECK(observed_route == "endpoint.demo.functions");
    CHECK(observed_keys ==
          std::vector<std::string> {"demo.score(i:" + std::to_string(GetCurrentProcessId()) + ",s:616c706861)"});
    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "custom_module_function");
    CHECK(evaluation->final_step.rule_results[0].matched);
}

TEST_CASE("custom binding examples parse verify and serve configured facts") {
    auto registry = rule_engine::default_module_registry();
    auto loaded_module =
        rule_engine::load_module_config_file(fixture_path("examples/custom_binding/demo.module"), registry);
    REQUIRE(loaded_module.has_value());

    auto parsed = rule_engine::parse_file(fixture_path("examples/custom_binding/demo_rule.yar"));
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    const auto routes = rule_engine::required_provider_routes(*verified);
    CHECK(routes ==
          std::vector<std::string> {"endpoint.demo.fields", "endpoint.demo.functions", "endpoint.demo.globals"});

    auto fixtures =
        rule_engine::custom_facts::load_custom_fact_fixture_file(fixture_path("examples/custom_binding/demo.facts"));
    REQUIRE(fixtures.has_value());
    REQUIRE(fixtures->capabilities.size() == 3u);
    REQUIRE(fixtures->facts.size() == 3u);

    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.demo.functions";
    request.timeout = std::chrono::milliseconds {12000};
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:example",
        .key = "demo.score(i:42,s:616c706861)",
    });

    const auto response = rule_engine::custom_facts::read_custom_fact_fixture_response(request, *fixtures);
    REQUIRE(response.has_value());
    REQUIRE(response->values.size() == 1u);
    CHECK(response->values[0].subject_id == "pid:example");
    CHECK(response->values[0].key == "demo.score(i:42,s:616c706861)");
    CHECK(response->values[0].value.as_i64() == 9);
}

TEST_CASE("localhost client session resolves configured custom module fact fixtures") {
    auto registry = rule_engine::default_module_registry();
    auto loaded_module =
        rule_engine::load_module_config_file(fixture_path("tests/fixtures/custom_binding/demo.module"), registry);
    REQUIRE(loaded_module.has_value());

    auto parsed = rule_engine::parse_file(fixture_path("tests/fixtures/custom_binding/demo_rule.yar"));
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    auto fixtures = rule_engine::custom_facts::load_custom_fact_fixture_file(
        fixture_path("tests/fixtures/custom_binding/demo.facts"));
    REQUIRE(fixtures.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities = fixtures->capabilities,
                .extra_fact_handler = [fixtures](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    return rule_engine::custom_facts::read_custom_fact_fixture_response(request, *fixtures);
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "configured_custom_module_function");
    CHECK(evaluation->final_step.rule_results[0].matched);
}

TEST_CASE("client session rejects explicit requests for routes missing from client capabilities") {
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.demo.functions";
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:" + std::to_string(GetCurrentProcessId()),
        .key = "demo.score(i:" + std::to_string(GetCurrentProcessId()) + ",s:616c706861)",
    });

    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        std::vector<rule_engine::protocol::FactBatchRequestMessage> {request});

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(session.has_value());
    REQUIRE_FALSE(session.error().diagnostics.empty());
    CHECK(session.error().diagnostics[0].message.find("does not advertise provider route endpoint.demo.functions") !=
          std::string::npos);
}

TEST_CASE("client evaluator preflights verified provider routes before short-circuit evaluation") {
    constexpr std::string_view source = R"(
import "process"
import "demo"

rule short_circuit_custom_module_function {
    condition:
        false and demo.score(process.pid, "alpha") > 7
}
)";
    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields = {},
        .functions =
            {
                rule_engine::FunctionDescriptor {
                    .name = "score",
                    .parameters = {rule_engine::ValueType::integer, rule_engine::ValueType::string},
                    .return_type = rule_engine::ValueType::integer,
                    .key_prefix = "demo.score",
                    .route = "endpoint.demo.functions",
                    .ttl = std::chrono::seconds {30},
                    .cheap_prefetch = false,
                },
            },
    });

    auto parsed = rule_engine::parse_source("short_circuit_missing_custom_capability.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(evaluation.has_value());
    REQUIRE_FALSE(evaluation.error().diagnostics.empty());
    CHECK(evaluation.error().diagnostics[0].message.find("required provider route endpoint.demo.functions") !=
          std::string::npos);
}

TEST_CASE("client evaluator rejects provider facts with descriptor type mismatches") {
    constexpr std::string_view source = R"(
import "process"
import "demo"

rule custom_module_function {
    condition:
        demo.score(process.pid, "alpha") > 7
}
)";
    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields = {},
        .functions =
            {
                rule_engine::FunctionDescriptor {
                    .name = "score",
                    .parameters = {rule_engine::ValueType::integer, rule_engine::ValueType::string},
                    .return_type = rule_engine::ValueType::integer,
                    .key_prefix = "demo.score",
                    .route = "endpoint.demo.functions",
                    .ttl = std::chrono::seconds {30},
                    .cheap_prefetch = false,
                },
            },
    });

    auto parsed = rule_engine::parse_source("wrong_custom_fact_type.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities =
                    {
                        rule_engine::protocol::Capability {.route = "endpoint.demo.functions"},
                    },
                .extra_fact_handler = [](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.functions") {
                        return std::nullopt;
                    }
                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    for (const auto &key : request.keys) {
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::string("wrong"),
                            .status = rule_engine::FactStatus::available,
                            .diagnostic = {},
                            .ttl = std::chrono::seconds {30},
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE_FALSE(evaluation.has_value());
    REQUIRE_FALSE(evaluation.error().diagnostics.empty());
    CHECK(evaluation.error().diagnostics[0].message.find("expected integer") != std::string::npos);
}

TEST_CASE("localhost client session resumes VM evaluation with provider facts") {
    constexpr std::string_view source = R"(
import "process"
import "pe"

rule current_test_process {
    condition:
        process.name == "rule_engine_tests.exe" and pe.number_of_sections > 0
}
)";
    auto parsed = rule_engine::parse_source("client_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "current_test_process");
    CHECK(evaluation->final_step.rule_results[0].matched);
}

TEST_CASE("localhost client session evaluates multiple subjects with provider batching") {
    constexpr std::string_view source = R"(
import "process"

rule has_pid {
    condition:
        process.pid > 0
}
)";
    auto parsed = rule_engine::parse_source("client_multi_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        std::vector<rule_engine::Subject> {
            rule_engine::Subject {
                .kind = "process",
                .id = "pid:" + std::to_string(GetCurrentProcessId()),
            },
            rule_engine::Subject {
                .kind = "process",
                .id = "pid:0",
            },
        },
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 2u,
            .instrumentation = &instrumentation,
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(evaluation->evaluations.size() == 2u);
    REQUIRE(evaluation->evaluations[0].final_step.rule_results.size() == 1u);
    CHECK(evaluation->evaluations[0].subject.id == "pid:" + std::to_string(GetCurrentProcessId()));
    CHECK(evaluation->evaluations[0].final_step.rule_results[0].identifier == "has_pid");
    CHECK(evaluation->evaluations[0].final_step.rule_results[0].matched);
    CHECK(evaluation->evaluations[1].subject.id == "pid:0");
    CHECK(evaluation->evaluations[1].final_step.state == rule_engine::EvaluationState::complete);
    CHECK(instrumentation.provider_rounds == 1u);
    CHECK(instrumentation.provider_requests == 1u);
    CHECK(instrumentation.provider_fact_keys_requested == 2u);
    CHECK(instrumentation.provider_facts_returned == 2u);
}

TEST_CASE("localhost client session evaluates multiple subjects with custom provider routes") {
    constexpr std::string_view source = R"(
import "demo"

rule custom_multi_subject {
    condition:
        demo.score(42, "alpha") > 7
}
)";
    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields = {},
        .functions =
            {
                rule_engine::FunctionDescriptor {
                    .name = "score",
                    .parameters = {rule_engine::ValueType::integer, rule_engine::ValueType::string},
                    .return_type = rule_engine::ValueType::integer,
                    .key_prefix = "demo.score",
                    .route = "endpoint.demo.functions",
                    .ttl = std::chrono::seconds {30},
                    .cheap_prefetch = false,
                },
            },
    });

    auto parsed = rule_engine::parse_source("client_custom_multi_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    auto live_subjects = rule_engine::windows::enumerate_process_subjects();
    REQUIRE(live_subjects.has_value());
    REQUIRE(live_subjects->size() >= 2u);
    const std::vector<rule_engine::Subject> requested_subjects {
        (*live_subjects)[0],
        (*live_subjects)[1],
    };
    REQUIRE(requested_subjects[0].id != requested_subjects[1].id);
    const auto matching_subject_id = requested_subjects[0].id;

    std::vector<rule_engine::protocol::FactKey> observed_keys;
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities = {rule_engine::protocol::Capability {.route = "endpoint.demo.functions"}},
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.functions") {
                        return std::nullopt;
                    }
                    observed_keys = request.keys;
                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    for (const auto &key : request.keys) {
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::integer(key.subject_id == matching_subject_id ? 9 : 3),
                            .status = rule_engine::FactStatus::available,
                            .diagnostic = {},
                            .ttl = std::chrono::seconds {30},
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified, requested_subjects,
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 2u,
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(std::ranges::any_of(evaluation->handshake.capabilities,
                              [](const auto &capability) { return capability.route == "endpoint.demo.functions"; }));
    REQUIRE(observed_keys.size() == 2u);
    CHECK(observed_keys[0].subject_id == requested_subjects[0].id);
    CHECK(observed_keys[0].key == "demo.score(i:42,s:616c706861)");
    CHECK(observed_keys[1].subject_id == requested_subjects[1].id);
    CHECK(observed_keys[1].key == "demo.score(i:42,s:616c706861)");

    REQUIRE(evaluation->evaluations.size() == 2u);
    REQUIRE(evaluation->evaluations[0].final_step.rule_results.size() == 1u);
    REQUIRE(evaluation->evaluations[1].final_step.rule_results.size() == 1u);
    CHECK(evaluation->evaluations[0].final_step.rule_results[0].identifier == "custom_multi_subject");
    CHECK(evaluation->evaluations[0].final_step.rule_results[0].matched);
    CHECK(evaluation->evaluations[1].final_step.rule_results[0].identifier == "custom_multi_subject");
    CHECK_FALSE(evaluation->evaluations[1].final_step.rule_results[0].matched);
}

TEST_CASE("localhost client evaluation reports scheduler queue pressure without changing results") {
    constexpr std::string_view source = R"(
import "demo"

rule queued_custom_facts {
    condition:
        demo.weight > 2 and demo.score(42, "alpha") > 7
}
)";
    rule_engine::ModuleRegistry registry = rule_engine::default_module_registry();
    registry.modules.push_back(rule_engine::ModuleDescriptor {
        .name = "demo",
        .fields =
            {
                rule_engine::FieldDescriptor {
                    .key = "demo.weight",
                    .type = rule_engine::ValueType::integer,
                    .route = "endpoint.demo.fields",
                    .ttl = std::chrono::seconds {30},
                    .timeout = std::chrono::seconds {5},
                    .cheap_prefetch = true,
                },
            },
        .functions =
            {
                rule_engine::FunctionDescriptor {
                    .name = "score",
                    .parameters = {rule_engine::ValueType::integer, rule_engine::ValueType::string},
                    .return_type = rule_engine::ValueType::integer,
                    .key_prefix = "demo.score",
                    .route = "endpoint.demo.functions",
                    .ttl = std::chrono::seconds {30},
                    .timeout = std::chrono::seconds {5},
                    .cheap_prefetch = true,
                },
            },
    });

    auto parsed = rule_engine::parse_source("client_scheduler_pressure.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, registry);
    REQUIRE(verified.has_value());

    const std::vector<rule_engine::Subject> requested_subjects {
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:queue-a",
        },
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:queue-b",
        },
    };

    std::vector<std::string> observed_routes;
    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
                .extra_capabilities =
                    {
                        rule_engine::protocol::Capability {.route = "endpoint.demo.fields"},
                        rule_engine::protocol::Capability {.route = "endpoint.demo.functions"},
                    },
                .extra_fact_handler = [&](const rule_engine::protocol::FactBatchRequestMessage &request)
                    -> std::optional<rule_engine::protocol::FactBatchResponseMessage> {
                    if (request.route != "endpoint.demo.fields" && request.route != "endpoint.demo.functions") {
                        return std::nullopt;
                    }
                    observed_routes.push_back(request.route);

                    rule_engine::protocol::FactBatchResponseMessage response;
                    response.route = request.route;
                    for (const auto &key : request.keys) {
                        response.values.push_back(rule_engine::Fact {
                            .subject_id = key.subject_id,
                            .key = key.key,
                            .value = rule_engine::Value::integer(9),
                            .status = rule_engine::FactStatus::available,
                            .diagnostic = {},
                            .ttl = std::chrono::seconds {30},
                        });
                    }
                    return response;
                },
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    rule_engine::client_protocol::ClientEvaluationInstrumentation instrumentation;
    auto evaluation = rule_engine::client_protocol::evaluate_subjects_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified, requested_subjects,
        rule_engine::client_protocol::ClientEvaluationOptions {
            .max_subject_concurrency = 2u,
            .vm_backpressure_subject_threshold = 1u,
            .provider_backpressure_request_threshold = 1u,
            .instrumentation = &instrumentation,
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(observed_routes == std::vector<std::string> {"endpoint.demo.fields", "endpoint.demo.functions"});
    CHECK(evaluation->evaluations.size() == 2u);
    for (const auto &subject_evaluation : evaluation->evaluations) {
        REQUIRE(subject_evaluation.final_step.rule_results.size() == 1u);
        CHECK(subject_evaluation.final_step.rule_results[0].identifier == "queued_custom_facts");
        CHECK(subject_evaluation.final_step.rule_results[0].matched);
    }
    CHECK(instrumentation.provider_rounds == 1u);
    CHECK(instrumentation.provider_requests == 2u);
    CHECK(instrumentation.provider_fact_keys_requested == 4u);
    CHECK(instrumentation.provider_facts_returned == 4u);
    CHECK(instrumentation.peak_pending_vm_subjects == 2u);
    CHECK(instrumentation.vm_backpressure_events == 1u);
    CHECK(instrumentation.peak_pending_provider_requests == 2u);
    CHECK(instrumentation.provider_backpressure_events == 1u);
}

TEST_CASE("localhost client session evaluates fixture-backed pattern facts") {
    constexpr std::string_view source = R"(
rule fixture_pattern {
    strings:
        $needle = "needle" ascii
    condition:
        $needle and #needle == 1 and @needle[1] == 4096 and !needle[1] == 6
}
)";
    auto parsed = rule_engine::parse_source("client_pattern_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());

    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "fixture_pattern");
    CHECK(evaluation->final_step.rule_results[0].matched);
}

TEST_CASE("pattern fixture scan directives produce literal match contexts") {
    const auto fixture_path = std::filesystem::temp_directory_path() /
                              ("rule-engine-pattern-scan-fixture-" + std::to_string(GetCurrentProcessId()) + ".txt");
    {
        std::ofstream fixture {fixture_path};
        REQUIRE(fixture);
        fixture << "scan $custom configured.file r-- 41416e6565646c655a5a 6e6565646c65\n";
        fixture << "scan $absent configured.file r-- 41416e6565646c655a5a ffffff\n";
    }

    auto loaded = rule_engine::patterns::load_pattern_fixture_file(fixture_path);
    std::filesystem::remove(fixture_path);
    REQUIRE(loaded.has_value());

    const auto facts = rule_engine::patterns::read_fixture_pattern_facts(
        std::array {
            rule_engine::protocol::FactKey {.subject_id = "pid:42", .key = "$custom.pattern"},
            rule_engine::protocol::FactKey {.subject_id = "pid:42", .key = "$custom.matches"},
            rule_engine::protocol::FactKey {.subject_id = "pid:42", .key = "$absent.pattern"},
            rule_engine::protocol::FactKey {.subject_id = "pid:42", .key = "$absent.matches"},
        },
        *loaded);
    REQUIRE(facts.size() == 4u);

    REQUIRE(facts[0].status == rule_engine::FactStatus::available);
    const auto *custom = facts[0].value.as_pattern();
    REQUIRE(custom != nullptr);
    REQUIRE(custom->matched);
    REQUIRE(custom->matches.size() == 1u);
    const auto &match = custom->matches[0];
    CHECK(match.offset == 2u);
    CHECK(match.length == 6u);
    CHECK(match.bytes == std::vector<std::byte> {
                             std::byte {'n'},
                             std::byte {'e'},
                             std::byte {'e'},
                             std::byte {'d'},
                             std::byte {'l'},
                             std::byte {'e'},
                         });
    CHECK(match.before == std::vector<std::byte> {std::byte {'A'}, std::byte {'A'}});
    CHECK(match.after == std::vector<std::byte> {std::byte {'Z'}, std::byte {'Z'}});
    CHECK(match.scan_space == "configured.file");
    CHECK(match.region_permissions == "r--");

    CHECK(facts[1].value.as_bool() == true);

    REQUIRE(facts[2].status == rule_engine::FactStatus::available);
    const auto *absent = facts[2].value.as_pattern();
    REQUIRE(absent != nullptr);
    CHECK_FALSE(absent->matched);
    CHECK(absent->matches.empty());
    CHECK(facts[3].value.as_bool() == false);
}

TEST_CASE("pattern fixture scan_file directives scan file bytes") {
    const auto data = write_temp_binary(L"rule_engine_scan_file", std::vector<std::uint8_t> {
                                                                      'A',
                                                                      'A',
                                                                      'n',
                                                                      'e',
                                                                      'e',
                                                                      'd',
                                                                      'l',
                                                                      'e',
                                                                      'Z',
                                                                      'Z',
                                                                  });
    const auto fixture_path = std::filesystem::temp_directory_path() /
                              ("rule-engine-pattern-scan-file-" + std::to_string(GetCurrentProcessId()) + ".txt");
    {
        std::ofstream fixture {fixture_path};
        REQUIRE(fixture);
        fixture << "scan_file $file file.bytes r-- " << data.path.string() << " 6e6565646c65\n";
    }

    auto loaded = rule_engine::patterns::load_pattern_fixture_file(fixture_path);
    std::filesystem::remove(fixture_path);
    REQUIRE(loaded.has_value());

    const auto facts = rule_engine::patterns::read_fixture_pattern_facts(
        std::array {
            rule_engine::protocol::FactKey {.subject_id = "pid:42", .key = "$file.pattern"},
            rule_engine::protocol::FactKey {.subject_id = "pid:42", .key = "$file.matches"},
        },
        *loaded);
    REQUIRE(facts.size() == 2u);

    REQUIRE(facts[0].status == rule_engine::FactStatus::available);
    const auto *pattern = facts[0].value.as_pattern();
    REQUIRE(pattern != nullptr);
    REQUIRE(pattern->matched);
    REQUIRE(pattern->matches.size() == 1u);
    CHECK(pattern->matches[0].offset == 2u);
    CHECK(pattern->matches[0].length == 6u);
    CHECK(pattern->matches[0].scan_space == "file.bytes");
    CHECK(pattern->matches[0].region_permissions == "r--");
    CHECK(pattern->matches[0].before == std::vector<std::byte> {std::byte {'A'}, std::byte {'A'}});
    CHECK(pattern->matches[0].after == std::vector<std::byte> {std::byte {'Z'}, std::byte {'Z'}});
    CHECK(facts[1].value.as_bool() == true);
}

TEST_CASE("pattern fixture scan spaces use rule-derived scan plans") {
    const auto data = write_temp_binary(L"rule_engine_rule_scan_space", std::vector<std::uint8_t> {
                                                                            'A',
                                                                            'A',
                                                                            'n',
                                                                            'e',
                                                                            'e',
                                                                            'd',
                                                                            'l',
                                                                            'e',
                                                                            'Z',
                                                                            'Z',
                                                                        });
    const auto fixture_path = std::filesystem::temp_directory_path() /
                              ("rule-engine-rule-scan-space-" + std::to_string(GetCurrentProcessId()) + ".txt");
    {
        std::ofstream fixture {fixture_path};
        REQUIRE(fixture);
        fixture << "scan_file_space file.bytes r-- " << data.path.string() << "\n";
    }

    auto loaded = rule_engine::patterns::load_pattern_fixture_file(fixture_path);
    std::filesystem::remove(fixture_path);
    REQUIRE(loaded.has_value());

    const std::vector<rule_engine::PatternScanPlan> scan_plans {
        rule_engine::PatternScanPlan {
            .pattern_key = "$rule",
            .literal =
                {
                    std::byte {'n'},
                    std::byte {'e'},
                    std::byte {'e'},
                    std::byte {'d'},
                    std::byte {'l'},
                    std::byte {'e'},
                },
        },
    };
    const auto facts = rule_engine::patterns::read_fixture_pattern_facts(
        std::array {
            rule_engine::protocol::FactKey {.subject_id = "pid:42", .key = "$rule.pattern"},
            rule_engine::protocol::FactKey {.subject_id = "pid:42", .key = "$rule.matches"},
        },
        *loaded, scan_plans);
    REQUIRE(facts.size() == 2u);

    const auto *pattern = facts[0].value.as_pattern();
    REQUIRE(pattern != nullptr);
    REQUIRE(pattern->matched);
    REQUIRE(pattern->matches.size() == 1u);
    CHECK(pattern->matches[0].offset == 2u);
    CHECK(pattern->matches[0].scan_space == "file.bytes");
    CHECK(facts[1].value.as_bool() == true);
}

TEST_CASE("client pattern handler scans current process image bytes") {
    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.scan.patterns";
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:" + std::to_string(GetCurrentProcessId()),
        .key = "$mz.pattern",
    });
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:" + std::to_string(GetCurrentProcessId()),
        .key = "$mz.matches",
    });
    request.expected_types = {rule_engine::ValueType::pattern, rule_engine::ValueType::boolean};
    request.scan_plans.push_back(rule_engine::PatternScanPlan {
        .pattern_key = "$mz",
        .literal = {std::byte {'M'}, std::byte {'Z'}},
    });

    const auto response = rule_engine::client_protocol::handle_client_fact_batch(request);
    REQUIRE(response.values.size() == 2u);
    REQUIRE(response.values[0].status == rule_engine::FactStatus::available);
    const auto *pattern = response.values[0].value.as_pattern();
    REQUIRE(pattern != nullptr);
    REQUIRE(pattern->matched);
    REQUIRE_FALSE(pattern->matches.empty());
    CHECK(pattern->matches[0].offset == 0u);
    CHECK(pattern->matches[0].scan_space == "process.image.bytes");
    CHECK(pattern->matches[0].region_permissions == "r--");
    CHECK(response.values[1].value.as_bool() == true);
}

TEST_CASE("client scan route returns current process image bytes facts") {
    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.scan.patterns";
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:" + std::to_string(GetCurrentProcessId()),
        .key = "process.image.bytes",
    });
    request.expected_types = {rule_engine::ValueType::bytes};

    const auto response = rule_engine::client_protocol::handle_client_fact_batch(request);
    REQUIRE(response.values.size() == 1u);
    CHECK(response.values[0].key == "process.image.bytes");
    REQUIRE(response.values[0].status == rule_engine::FactStatus::available);
    const auto *bytes = response.values[0].value.as_bytes();
    REQUIRE(bytes != nullptr);
    REQUIRE(bytes->size() >= 2u);
    CHECK((*bytes)[0] == std::byte {'M'});
    CHECK((*bytes)[1] == std::byte {'Z'});
}

TEST_CASE("localhost client session scans mapped image sections from rule-derived literals") {
    constexpr std::string_view probe = "rule_engine_mapped_section_probe_literal";
    const auto fixture_path = std::filesystem::temp_directory_path() /
                              ("rule-engine-section-scan-session-" + std::to_string(GetCurrentProcessId()) + ".txt");
    {
        std::ofstream fixture {fixture_path};
        REQUIRE(fixture);
        fixture << "scan_process_image_sections\n";
    }

    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.scan.patterns";
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:" + std::to_string(GetCurrentProcessId()),
        .key = "$probe.pattern",
    });
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:" + std::to_string(GetCurrentProcessId()),
        .key = "$probe.matches",
    });
    request.expected_types = {rule_engine::ValueType::pattern, rule_engine::ValueType::boolean};
    request.scan_plans.push_back(rule_engine::PatternScanPlan {
        .pattern_key = "$probe",
        .literal = ascii_bytes(probe),
    });

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = fixture_path,
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    const auto ready = listening.wait_for(std::chrono::seconds {5});
    if (ready != std::future_status::ready) {
        server.join();
        std::filesystem::remove(fixture_path);
        REQUIRE_FALSE(server_error.has_value());
        REQUIRE(ready == std::future_status::ready);
    }
    const auto port = listening.get();
    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        std::vector<rule_engine::protocol::FactBatchRequestMessage> {request});

    server.join();
    std::filesystem::remove(fixture_path);
    if (server_error.has_value() && !server_error->diagnostics.empty()) {
        INFO(server_error->diagnostics[0].message);
    }
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(session.has_value());
    REQUIRE(session->responses.size() == 1u);
    REQUIRE(session->responses[0].values.size() == 2u);

    const auto *pattern = session->responses[0].values[0].value.as_pattern();
    REQUIRE(pattern != nullptr);
    REQUIRE(pattern->matched);
    const auto section_match = std::ranges::find_if(
        pattern->matches, [](const auto &match) { return match.scan_space.starts_with("process.image.section."); });
    REQUIRE(section_match != pattern->matches.end());
    CHECK(section_match->region_permissions.size() == 3u);
    CHECK(session->responses[0].values[1].value.as_bool() == true);
}

TEST_CASE("localhost client session scans readable memory regions from rule-derived literals") {
    const auto probe = std::string {"rule_engine_readable_memory_probe_literal_"} +
                       std::to_string(GetCurrentProcessId()) + "_" + std::to_string(GetCurrentThreadId());
    VirtualMemory memory {4096u};
    REQUIRE(memory.value != nullptr);
    std::memcpy(memory.value, probe.data(), probe.size());

    const auto fixture_path = std::filesystem::temp_directory_path() /
                              ("rule-engine-memory-scan-session-" + std::to_string(GetCurrentProcessId()) + ".txt");
    {
        std::ofstream fixture {fixture_path};
        REQUIRE(fixture);
        fixture << "scan_readable_memory_regions " << reinterpret_cast<std::uintptr_t>(memory.value) << " 4096\n";
    }

    rule_engine::protocol::FactBatchRequestMessage request;
    request.route = "endpoint.scan.patterns";
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:" + std::to_string(GetCurrentProcessId()),
        .key = "$probe.pattern",
    });
    request.keys.push_back(rule_engine::protocol::FactKey {
        .subject_id = "pid:" + std::to_string(GetCurrentProcessId()),
        .key = "$probe.matches",
    });
    request.expected_types = {rule_engine::ValueType::pattern, rule_engine::ValueType::boolean};
    request.scan_plans.push_back(rule_engine::PatternScanPlan {
        .pattern_key = "$probe",
        .literal = ascii_bytes(probe),
    });

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = fixture_path,
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    const auto ready = listening.wait_for(std::chrono::seconds {5});
    if (ready != std::future_status::ready) {
        server.join();
        std::filesystem::remove(fixture_path);
        REQUIRE_FALSE(server_error.has_value());
        REQUIRE(ready == std::future_status::ready);
    }
    const auto port = listening.get();
    auto session = rule_engine::client_protocol::run_client_session(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        std::vector<rule_engine::protocol::FactBatchRequestMessage> {request});

    server.join();
    std::filesystem::remove(fixture_path);
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(session.has_value());
    REQUIRE(session->responses.size() == 1u);
    REQUIRE(session->responses[0].values.size() == 2u);

    const auto *pattern = session->responses[0].values[0].value.as_pattern();
    REQUIRE(pattern != nullptr);
    REQUIRE(pattern->matched);
    const auto memory_match = std::ranges::find_if(
        pattern->matches, [](const auto &match) { return match.scan_space.starts_with("process.memory.region."); });
    REQUIRE(memory_match != pattern->matches.end());
    CHECK(memory_match->bytes == ascii_bytes(probe));
    CHECK_FALSE(memory_match->region_permissions.empty());
    CHECK(session->responses[0].values[1].value.as_bool() == true);
}

TEST_CASE("localhost client session evaluates configured pattern fixture facts") {
    const auto fixture_path = std::filesystem::temp_directory_path() /
                              ("rule-engine-pattern-fixture-" + std::to_string(GetCurrentProcessId()) + ".txt");
    {
        std::ofstream fixture {fixture_path};
        REQUIRE(fixture);
        fixture << "$custom true 8192 5 configured.scan rw 68656c6c6f\n";
    }

    constexpr std::string_view source = R"(
rule configured_pattern {
    strings:
        $custom = "hello" ascii
    condition:
        $custom and #custom == 1 and @custom[1] == 8192 and !custom[1] == 5
}
)";
    auto parsed = rule_engine::parse_source("configured_pattern_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = fixture_path,
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    std::filesystem::remove(fixture_path);

    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "configured_pattern");
    CHECK(evaluation->final_step.rule_results[0].matched);
}

TEST_CASE("localhost client session evaluates configured literal scan facts") {
    const auto fixture_path = std::filesystem::temp_directory_path() /
                              ("rule-engine-pattern-scan-session-" + std::to_string(GetCurrentProcessId()) + ".txt");
    {
        std::ofstream fixture {fixture_path};
        REQUIRE(fixture);
        fixture << "scan $custom configured.scan rw 41416e6565646c655a5a 6e6565646c65\n";
    }

    constexpr std::string_view source = R"(
rule configured_scan {
    strings:
        $custom = "needle" ascii
    condition:
        $custom and #custom == 1 and @custom[1] == 2 and !custom[1] == 6
}
)";
    auto parsed = rule_engine::parse_source("configured_scan_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = fixture_path,
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });
    REQUIRE(evaluation.has_value());

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    std::filesystem::remove(fixture_path);

    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "configured_scan");
    CHECK(evaluation->final_step.rule_results[0].matched);
}

TEST_CASE("localhost client session evaluates rule-derived literal scan plans") {
    const auto data = write_temp_binary(L"rule_engine_rule_plan_session", std::vector<std::uint8_t> {
                                                                              'A',
                                                                              'A',
                                                                              'n',
                                                                              'e',
                                                                              'e',
                                                                              'd',
                                                                              'l',
                                                                              'e',
                                                                              'Z',
                                                                              'Z',
                                                                          });
    const auto fixture_path = std::filesystem::temp_directory_path() /
                              ("rule-engine-rule-plan-session-" + std::to_string(GetCurrentProcessId()) + ".txt");
    {
        std::ofstream fixture {fixture_path};
        REQUIRE(fixture);
        fixture << "scan_file_space file.bytes r-- " << data.path.string() << "\n";
    }

    constexpr std::string_view source = R"(
rule rule_derived_scan {
    strings:
        $custom = "needle" ascii
    condition:
        $custom and #custom == 1 and @custom[1] == 2 and !custom[1] == 6
}
)";
    auto parsed = rule_engine::parse_source("rule_derived_scan_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = fixture_path,
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    std::filesystem::remove(fixture_path);
    REQUIRE(evaluation.has_value());
    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "rule_derived_scan");
    CHECK(evaluation->final_step.rule_results[0].matched);
}

TEST_CASE("localhost client session scans process image bytes from rule-derived literals") {
    constexpr std::string_view source = R"(
rule process_image_mz {
    strings:
        $mz = "MZ" ascii
    condition:
        $mz at 0
}
)";
    auto parsed = rule_engine::parse_source("process_image_scan_eval.yar", source);
    REQUIRE(parsed.has_value());
    auto verified = rule_engine::verify(*parsed, rule_engine::default_module_registry());
    REQUIRE(verified.has_value());

    std::promise<std::uint16_t> listening_port;
    auto listening = listening_port.get_future();
    std::optional<rule_engine::ErrorSet> server_error;

    std::thread server {[&] {
        auto result = rule_engine::client_protocol::serve_client_once(
            rule_engine::client_protocol::ClientListenOptions {
                .bind_address = "127.0.0.1",
                .port = 0u,
                .pattern_fixture_path = {},
                .io_timeout = std::chrono::milliseconds {5000},
            },
            [&](const std::uint16_t port) { listening_port.set_value(port); });
        if (!result) {
            server_error = std::move(result.error());
        }
    }};

    REQUIRE(listening.wait_for(std::chrono::seconds {5}) == std::future_status::ready);
    const auto port = listening.get();
    auto evaluation = rule_engine::client_protocol::evaluate_subject_with_client(
        rule_engine::client_protocol::ClientConnectionOptions {
            .host = "127.0.0.1",
            .port = port,
            .io_timeout = std::chrono::milliseconds {5000},
        },
        *verified,
        rule_engine::Subject {
            .kind = "process",
            .id = "pid:" + std::to_string(GetCurrentProcessId()),
        });

    server.join();
    REQUIRE_FALSE(server_error.has_value());
    REQUIRE(evaluation.has_value());
    CHECK(evaluation->final_step.state == rule_engine::EvaluationState::complete);
    REQUIRE(evaluation->final_step.rule_results.size() == 1u);
    CHECK(evaluation->final_step.rule_results[0].identifier == "process_image_mz");
    CHECK(evaluation->final_step.rule_results[0].matched);
}
