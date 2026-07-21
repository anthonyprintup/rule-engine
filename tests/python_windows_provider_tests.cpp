#include "rule_engine/python/windows/provider.hpp"

#include <catch2/catch_test_macros.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace py = rule_engine::python;
namespace win = rule_engine::python::windows;

namespace {

    template<typename T>
    concept HasPredicate = requires(T value) { value.predicate; };

    template<typename T>
    concept HasVerdict = requires(T value) { value.verdict; };

    template<typename T>
    concept HasRuleId = requires(T value) { value.rule_id; };

    [[nodiscard]] std::uint64_t current_creation_time() {
        FILETIME creation {};
        FILETIME exit {};
        FILETIME kernel {};
        FILETIME user {};
        REQUIRE(GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user) != FALSE);
        return (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U) | creation.dwLowDateTime;
    }

    [[nodiscard]] py::SubjectKey current_process() {
        return win::process_subject(py::PeerId {"peer:test"}, GetCurrentProcessId(), current_creation_time());
    }

    [[nodiscard]] std::filesystem::path current_image_path() {
        std::wstring path(32'768U, L'\0');
        const auto length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        REQUIRE(length > 0U);
        REQUIRE(length < path.size());
        path.resize(length);
        return std::filesystem::path {path};
    }

    [[nodiscard]] const py::FactRecord &fact_record(const py::FrozenValue &value) {
        REQUIRE(value.value.valid());
        const auto *record = std::get_if<py::FactRecord>(&value.value.node->data);
        REQUIRE(record != nullptr);
        return *record;
    }

    [[nodiscard]] py::FactRequest request(py::SubjectKey subject, std::string route,
                                          const std::uint64_t deadline = 0U) {
        return py::FactRequest {.request_id = py::RequestId {"request:test"},
                                .subject = std::move(subject),
                                .route = py::FactRoute {.provider = "windows", .fact = std::move(route)},
                                .expected_schema = py::SchemaId {"schema:test"},
                                .deadline_unix_ms = deadline};
    }

    [[nodiscard]] std::string hex_bytes(const std::span<const std::byte> bytes) {
        constexpr std::string_view digits {"0123456789abcdef"};
        std::string output;
        output.reserve(bytes.size() * 2U);
        for (const auto value : bytes) {
            const auto number = std::to_integer<unsigned int>(value);
            output.push_back(digits[(number >> 4U) & 0x0fU]);
            output.push_back(digits[number & 0x0fU]);
        }
        return output;
    }

    [[nodiscard]] std::uint64_t unsigned_fact(const py::FactValue &value) {
        REQUIRE(value.valid());
        const auto *integer = std::get_if<py::IntegerValue>(&value.node->data);
        REQUIRE(integer != nullptr);
        std::uint64_t output {};
        const auto [end, ec] =
            std::from_chars(integer->decimal.data(), integer->decimal.data() + integer->decimal.size(), output);
        REQUIRE(ec == std::errc {});
        REQUIRE(end == integer->decimal.data() + integer->decimal.size());
        return output;
    }

    template<typename Space> void complete_scan_space_metadata(Space &space) {
        if constexpr (requires { space.identity; }) {
            space.identity = space.kind;
        }
        if constexpr (requires { space.subject_generation; }) {
            space.subject_generation = 1U;
        }
    }

    template<typename Plan> void complete_scan_plan_metadata(Plan &plan) {
        if constexpr (requires { plan.pattern_ids; }) {
            plan.pattern_ids = {plan.plan_id};
        }
    }

    [[nodiscard]] py::ScanRequest scan_request(std::string request_id, py::SubjectKey subject, std::string kind,
                                               const std::uint64_t begin, const std::uint64_t size,
                                               const std::uint32_t permissions, std::string plan_id,
                                               std::string encoded_pattern, const std::uint32_t maximum_matches) {
        py::ScanRequest output {};
        output.request_id = py::RequestId {std::move(request_id)};
        output.subject = std::move(subject);
        output.space.kind = std::move(kind);
        output.space.begin = begin;
        output.space.size = size;
        output.space.permissions = permissions;
        complete_scan_space_metadata(output.space);
        output.plan.plan_id = std::move(plan_id);
        output.plan.encoded_pattern = std::move(encoded_pattern);
        output.plan.maximum_bytes = size;
        output.plan.maximum_matches = maximum_matches;
        complete_scan_plan_metadata(output.plan);
        output.deadline_unix_ms = win::unix_time_ms() + 5'000U;
        return output;
    }

} // namespace

static_assert(!HasPredicate<py::FactRequest>);
static_assert(!HasPredicate<py::ScanRequest>);
static_assert(!HasVerdict<py::FactResponse>);
static_assert(!HasVerdict<py::ScanResponse>);
static_assert(!HasRuleId<py::FactRequest>);
static_assert(!HasRuleId<py::ScanRequest>);

TEST_CASE("Windows process identities reject PID reuse by creation time") {
    const auto first = win::process_subject(py::PeerId {"peer:test"}, 42U, 100U);
    const auto reused = win::process_subject(py::PeerId {"peer:test"}, 42U, 101U);

    REQUIRE(first.valid());
    REQUIRE(reused.valid());
    REQUIRE(py::canonical_subject_key(first) != py::canonical_subject_key(reused));
}

TEST_CASE("Windows authoritative inventories distinguish valid empty and invalid snapshots") {
    auto empty = win::make_inventory_snapshot(py::PeerId {"peer:test"},
                                              py::SchemaId {std::string {win::process_schema}}, std::nullopt, 7U, {});
    auto repeated = win::make_inventory_snapshot(
        py::PeerId {"peer:test"}, py::SchemaId {std::string {win::process_schema}}, std::nullopt, 7U, {});

    REQUIRE(empty.authoritative);
    REQUIRE(empty.status == py::FactTerminalStatus::value);
    REQUIRE(empty.commit.item_count == 0U);
    REQUIRE(empty.commit.canonical_digest.starts_with("sha256:"));
    REQUIRE(empty.commit.canonical_digest == repeated.commit.canonical_digest);

    const auto subject = win::process_subject(py::PeerId {"peer:test"}, 1U, 2U);
    std::vector<win::SubjectObservation> duplicates {
        {.subject = subject, .eager_fields = {}},
        {.subject = subject, .eager_fields = {}},
    };
    auto invalid =
        win::make_inventory_snapshot(py::PeerId {"peer:test"}, py::SchemaId {std::string {win::process_schema}},
                                     std::nullopt, 8U, std::move(duplicates));
    REQUIRE_FALSE(invalid.authoritative);
    REQUIRE(invalid.items.empty());
    REQUIRE(invalid.commit.canonical_digest.empty());
    REQUIRE(invalid.diagnostic.has_value());
}

TEST_CASE("Windows nested identities retain their complete process parent") {
    const auto process = win::process_subject(py::PeerId {"peer:test"}, 11U, 22U);
    const auto first = win::memory_region_subject(process, 0x1000U, 0x2000U);
    const auto second = win::memory_region_subject(process, 0x1000U, 0x3000U);

    REQUIRE(first.valid());
    REQUIRE(first.parent != nullptr);
    REQUIRE(py::canonical_subject_key(*first.parent) == py::canonical_subject_key(process));
    REQUIRE(py::canonical_subject_key(first) != py::canonical_subject_key(second));
}

TEST_CASE("Windows process inventory is authoritative and includes the current creation identity") {
    const auto snapshot = win::enumerate_process_inventory(py::PeerId {"peer:test"}, 1U);
    REQUIRE(snapshot.authoritative);
    REQUIRE(snapshot.status == py::FactTerminalStatus::value);
    REQUIRE(snapshot.commit.item_count == snapshot.items.size());

    const auto pid = static_cast<std::uint64_t>(GetCurrentProcessId());
    const auto creation = current_creation_time();
    const auto found = std::ranges::find_if(snapshot.items, [&](const win::SubjectObservation &item) {
        const auto *observed_pid = std::get_if<std::uint64_t>(&item.subject.identity[0].value);
        const auto *observed_creation = std::get_if<std::uint64_t>(&item.subject.identity[1].value);
        return observed_pid != nullptr && observed_creation != nullptr && *observed_pid == pid &&
               *observed_creation == creation;
    });
    REQUIRE(found != snapshot.items.end());
}

TEST_CASE("Windows fact dispatch returns typed values and typed terminal statuses") {
    const auto subject = current_process();
    for (const auto route :
         {"process.pid", "process.name", "process.path", "process.architecture", "process.command_line", "process.user",
          "process.token", "process.modules", "process.memory.summary", "process.handles.count"}) {
        const auto response = win::dispatch_fact(request(subject, route));
        INFO(route);
        REQUIRE(response.status == py::FactTerminalStatus::value);
        REQUIRE(response.value.has_value());
        REQUIRE(response.value->valid());
    }
    for (const auto route : {"process.user.sid", "process.user.name", "process.token.elevated", "process.token.type",
                             "process.integrity_level", "process.modules.count", "process.modules.names",
                             "process.memory.regions.count", "process.memory.regions.readable_count",
                             "process.memory.regions", "process.signer.status", "process.signer.is_signed"}) {
        const auto response = win::dispatch_fact(request(subject, route));
        INFO(route);
        REQUIRE(response.status == py::FactTerminalStatus::value);
        REQUIRE(response.value.has_value());
    }

    const auto unsupported = win::dispatch_fact(request(subject, "process.evaluate_predicate"));
    REQUIRE(unsupported.status == py::FactTerminalStatus::unsupported);
    REQUIRE_FALSE(unsupported.value.has_value());
    REQUIRE(unsupported.diagnostic.has_value());

    const auto timed_out = win::dispatch_fact(request(subject, "process.name", win::unix_time_ms() - 1U));
    REQUIRE(timed_out.status == py::FactTerminalStatus::timed_out);
    REQUIRE_FALSE(timed_out.value.has_value());
}

TEST_CASE("Windows stale process subjects fail closed rather than aliasing a reused PID") {
    auto stale = current_process();
    stale.identity[1].value = current_creation_time() + 1U;
    const auto response = win::dispatch_fact(request(std::move(stale), "process.name"));
    REQUIRE(response.status == py::FactTerminalStatus::unavailable);
    REQUIRE_FALSE(response.value.has_value());
    REQUIRE(response.diagnostic.has_value());
}

TEST_CASE("Windows signer facts are rich frozen records even for an unsigned image") {
    const auto signer = win::read_process_signer(current_process());
    REQUIRE(signer.has_value());
    REQUIRE(signer->canonical_digest.starts_with("sha256:"));
    REQUIRE(signer->label.classification == py::Classification::sensitive);
    const auto &record = fact_record(*signer);
    REQUIRE(record.schema.value == win::signer_value_schema);
    REQUIRE(record.fields.size() == 8U);
}

TEST_CASE("Windows PE inspection exposes independently parented rich nested inventories") {
    const auto process = current_process();
    const auto pe = win::inspect_pe_image(process, current_image_path(), 3U);
    REQUIRE(pe.has_value());
    REQUIRE(pe->value.canonical_digest.starts_with("sha256:"));
    REQUIRE(fact_record(pe->value).schema.value == win::pe_value_schema);
    REQUIRE(pe->image.subject.parent != nullptr);
    REQUIRE(py::canonical_subject_key(*pe->image.subject.parent) == py::canonical_subject_key(process));

    for (const auto *inventory : {&pe->sections, &pe->imports, &pe->exports, &pe->debug_entries, &pe->resources,
                                  &pe->certificates, &pe->tls_callbacks}) {
        REQUIRE(inventory->authoritative);
        REQUIRE(inventory->commit.item_count == inventory->items.size());
        for (const auto &item : inventory->items) {
            REQUIRE(item.subject.parent != nullptr);
            REQUIRE(py::canonical_subject_key(*item.subject.parent) == py::canonical_subject_key(pe->image.subject));
        }
    }
    REQUIRE_FALSE(pe->sections.items.empty());

    auto stale_image = pe->image.subject;
    stale_image.identity[1].value = std::get<std::uint64_t>(stale_image.identity[1].value) + 1U;
    const auto stale_response = win::dispatch_fact(request(std::move(stale_image), "image.path"));
    REQUIRE(stale_response.status == py::FactTerminalStatus::unavailable);
    REQUIRE_FALSE(stale_response.value.has_value());

    for (const auto route :
         {"image.path", "image.volume_serial", "image.file_id", "image.size", "image.last_write_time", "pe.is_valid",
          "pe.machine", "pe.sections", "pe.imports", "pe.certificates"}) {
        const auto response = win::dispatch_fact(request(pe->image.subject, route));
        INFO(route);
        REQUIRE(response.status == py::FactTerminalStatus::value);
        REQUIRE(response.value.has_value());
    }
}

TEST_CASE("Windows file scans execute an explicit bounded plan and return no verdict") {
    const auto process = current_process();
    const auto response =
        win::dispatch_scan(scan_request("scan:file", process, "process.image.file", 0U, 4'096U,
                                        py::optimizer::scan_permission_read, "mz", "bytes:4d5a", 16U));
    INFO((response.diagnostic.has_value() ? response.diagnostic->message : std::string {"no diagnostic"}));
    REQUIRE(response.status == py::FactTerminalStatus::value);
    REQUIRE_FALSE(response.truncated);
    REQUIRE_FALSE(response.matches.empty());
    REQUIRE(response.matches.front().offset == 0U);
}

TEST_CASE("Windows mapped-image scans bind the current process creation identity") {
    const auto base = reinterpret_cast<std::uint64_t>(GetModuleHandleW(nullptr));
    REQUIRE(base != 0U);
    const auto response =
        win::dispatch_scan(scan_request("scan:mapped", current_process(), "process.image.mapped", base, 4'096U,
                                        py::optimizer::scan_permission_read, "mz", "bytes:4d5a", 16U));
    INFO((response.diagnostic.has_value() ? response.diagnostic->message : std::string {"no diagnostic"}));
    REQUIRE(response.status == py::FactTerminalStatus::value);
    REQUIRE_FALSE(response.matches.empty());
    REQUIRE(response.matches.front().offset == 0U);
}

TEST_CASE("Windows mapped-section scans stay inside the current nested section identity") {
    const auto process = current_process();
    const auto pe = win::inspect_pe_image(process, current_image_path(), 4U);
    REQUIRE(pe.has_value());
    const auto section = std::ranges::find_if(pe->sections.items, [](const win::SubjectObservation &item) {
        std::uint64_t virtual_size {};
        std::uint64_t raw_size {};
        for (const auto &field : item.eager_fields) {
            const auto *integer =
                field.value.valid() ? std::get_if<py::IntegerValue>(&field.value.node->data) : nullptr;
            if (integer == nullptr) {
                continue;
            }
            std::uint64_t parsed {};
            const auto [end, ec] =
                std::from_chars(integer->decimal.data(), integer->decimal.data() + integer->decimal.size(), parsed);
            if (ec != std::errc {} || end != integer->decimal.data() + integer->decimal.size()) {
                continue;
            }
            if (field.field_id == 3U) {
                virtual_size = parsed;
            } else if (field.field_id == 5U) {
                raw_size = parsed;
            }
        }
        return std::max(virtual_size, raw_size) >= 16U;
    });
    REQUIRE(section != pe->sections.items.end());
    const auto rva = std::get<std::uint64_t>(section->subject.identity[0].value);
    const auto base = reinterpret_cast<std::uint64_t>(GetModuleHandleW(nullptr));
    const auto begin = base + rva;
    std::array<std::byte, 4> prefix {};
    SIZE_T received {};
    REQUIRE(ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void *>(static_cast<std::uintptr_t>(begin)),
                              prefix.data(), prefix.size(), &received) != FALSE);
    REQUIRE(received == prefix.size());

    std::uint64_t extent {};
    for (const auto &field : section->eager_fields) {
        if (field.field_id == 3U || field.field_id == 5U) {
            extent = std::max(extent, unsigned_fact(field.value));
        }
    }
    const auto size = std::min<std::uint64_t>(extent, 4'096U);
    const auto response = win::dispatch_scan(
        scan_request("scan:section", section->subject, "process.image.mapped_section", begin, size,
                     py::optimizer::scan_permission_read, "section-prefix", "bytes:" + hex_bytes(prefix), 16U));
    INFO((response.diagnostic.has_value() ? response.diagnostic->message : std::string {"no diagnostic"}));
    REQUIRE(response.status == py::FactTerminalStatus::value);
    REQUIRE_FALSE(response.matches.empty());
    REQUIRE(response.matches.front().offset == 0U);
}

TEST_CASE("Windows readable-memory scans tolerate live privilege and lifetime races without leaking") {
    constexpr std::string_view marker {"rule-engine-python-windows-provider-marker"};
    auto *allocation =
        static_cast<std::byte *>(VirtualAlloc(nullptr, 4'096U, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    REQUIRE(allocation != nullptr);
    struct AllocationGuard {
        void *value {};
        ~AllocationGuard() noexcept { static_cast<void>(VirtualFree(value, 0, MEM_RELEASE)); }
    } guard {.value = allocation};
    std::ranges::copy(std::as_bytes(std::span {marker}), allocation);

    const auto address = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(allocation));
    const auto region = win::memory_region_subject(current_process(), address, address);
    const auto response =
        win::dispatch_scan(scan_request("scan:memory", region, "process.memory", address, 4'096U,
                                        py::optimizer::scan_permission_read | py::optimizer::scan_permission_write,
                                        "marker", "bytes:" + hex_bytes(std::as_bytes(std::span {marker})), 4U));
    INFO((response.diagnostic.has_value() ? response.diagnostic->message : std::string {"no diagnostic"}));
    REQUIRE(response.status == py::FactTerminalStatus::value);
    REQUIRE(response.matches.size() == 1U);
    REQUIRE(response.matches.front().offset == 0U);
    REQUIRE(response.matches.front().length == marker.size());
}

TEST_CASE("Windows memory-region inventory is complete or explicitly non-authoritative") {
    const auto snapshot = win::enumerate_memory_region_inventory(current_process(), 9U, win::unix_time_ms() + 5'000U);
    REQUIRE(snapshot.authoritative);
    REQUIRE_FALSE(snapshot.items.empty());
    REQUIRE(snapshot.commit.item_count == snapshot.items.size());
    for (const auto &item : snapshot.items) {
        REQUIRE(item.subject.parent != nullptr);
        REQUIRE(item.subject.descriptor.value == win::memory_region_schema);
    }
}
