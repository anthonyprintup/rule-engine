#include "rule_engine/python/protocol/snapshot.hpp"
#include "rule_engine/python/windows/provider.hpp"
#include "rule_engine/python/windows/runtime.hpp"

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
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace py = rule_engine::python;
namespace proto = rule_engine::python::protocol_v2;
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
        const auto descriptor = win::find_windows_fact_descriptor(subject.descriptor, route);
        const auto fallback = py::resolve_schema_identity(py::SchemaCatalog {}, py::SchemaId {"bool"});
        REQUIRE(fallback.has_value());
        const auto schema = !descriptor.has_value() ? *fallback : descriptor->value_schema;
        return py::FactRequest {.request_id = py::RequestId {"request:test"},
                                .subject = std::move(subject),
                                .route = py::FactRoute {.provider = "windows", .fact = std::move(route)},
                                .expected_schema = schema.id,
                                .expected_schema_hash = schema.canonical_hash,
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

    [[nodiscard]] win::WindowsAgentRuntimeIdentity runtime_identity() {
        return win::WindowsAgentRuntimeIdentity {.session = py::SessionId {"session:test"},
                                                 .peer = py::PeerId {"peer:test"},
                                                 .session_fence = 7U,
                                                 .generation = 3U,
                                                 .route = "windows"};
    }

    [[nodiscard]] proto::WorkLeaseMessage
    runtime_work(std::vector<py::FactRequest> facts, std::vector<py::ScanRequest> scans = {},
                 std::string work_id = "work:test", std::string attempt_id = "attempt:1",
                 const std::uint64_t work_fence = 11U, const std::uint64_t generation = 3U) {
        const auto identity = runtime_identity();
        return proto::WorkLeaseMessage {.session = identity.session,
                                        .peer = identity.peer,
                                        .session_fence = identity.session_fence,
                                        .work_id = std::move(work_id),
                                        .attempt_id = std::move(attempt_id),
                                        .work_fence = work_fence,
                                        .generation = generation,
                                        .server_sequence = 1U,
                                        .route = identity.route,
                                        .facts = std::move(facts),
                                        .scans = std::move(scans)};
    }

    [[nodiscard]] proto::CancelWorkMessage runtime_cancel(const proto::WorkLeaseMessage &work,
                                                          std::vector<py::RequestId> requests = {}) {
        return proto::CancelWorkMessage {.session = work.session,
                                         .peer = work.peer,
                                         .session_fence = work.session_fence,
                                         .work_id = work.work_id,
                                         .attempt_id = work.attempt_id,
                                         .work_fence = work.work_fence,
                                         .server_sequence = work.server_sequence,
                                         .route = work.route,
                                         .requests = std::move(requests)};
    }

    [[nodiscard]] win::SubjectObservation observation(py::SubjectKey subject, const std::uint64_t marker) {
        return win::SubjectObservation {
            .subject = std::move(subject),
            .eager_fields = {
                {.field_id = 100U, .value = py::make_fact(py::IntegerValue {.decimal = std::to_string(marker)})}}};
    }

    [[nodiscard]] win::InventoryProjectionRequest
    projection_request(std::string snapshot_id, py::SchemaId schema,
                       std::optional<py::SubjectKey> parent = std::nullopt, const std::size_t chunk_items = 1'024U) {
        return win::InventoryProjectionRequest {.snapshot_id = std::move(snapshot_id),
                                                .parent = std::move(parent),
                                                .subject_schema = std::move(schema),
                                                .chunk_items = chunk_items};
    }

} // namespace

static_assert(!HasPredicate<py::FactRequest>);
static_assert(!HasPredicate<py::ScanRequest>);
static_assert(!HasVerdict<py::FactResponse>);
static_assert(!HasVerdict<py::ScanResponse>);
static_assert(!HasRuleId<py::FactRequest>);
static_assert(!HasRuleId<py::ScanRequest>);
static_assert(!HasPredicate<proto::WorkLeaseMessage>);
static_assert(!HasVerdict<proto::WorkResultMessage>);
static_assert(!HasRuleId<win::WindowsAgentProviderRuntime>);

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
        const auto fact_request = request(subject, route);
        const auto response = win::dispatch_fact(fact_request);
        INFO(route);
        REQUIRE(response.status == py::FactTerminalStatus::value);
        REQUIRE(response.value.has_value());
        REQUIRE(response.value->valid());
        REQUIRE(py::fact_response_schema_matches(fact_request, response));
    }
    for (const auto route : {"process.user.sid", "process.user.name", "process.token.elevated", "process.token.type",
                             "process.integrity_level", "process.modules.count", "process.modules.names",
                             "process.memory.regions.count", "process.memory.regions.readable_count",
                             "process.memory.regions", "process.signer.status", "process.signer.is_signed"}) {
        const auto fact_request = request(subject, route);
        const auto response = win::dispatch_fact(fact_request);
        INFO(route);
        REQUIRE(response.status == py::FactTerminalStatus::value);
        REQUIRE(response.value.has_value());
        REQUIRE(py::fact_response_schema_matches(fact_request, response));
    }

    const auto unsupported = win::dispatch_fact(request(subject, "process.evaluate_predicate"));
    REQUIRE(unsupported.status == py::FactTerminalStatus::unsupported);
    REQUIRE_FALSE(unsupported.value.has_value());
    REQUIRE_FALSE(unsupported.returned_schema.has_value());
    REQUIRE(unsupported.diagnostic.has_value());

    const auto timed_out = win::dispatch_fact(request(subject, "process.name", win::unix_time_ms() - 1U));
    REQUIRE(timed_out.status == py::FactTerminalStatus::timed_out);
    REQUIRE_FALSE(timed_out.value.has_value());
    REQUIRE_FALSE(timed_out.returned_schema.has_value());

    auto wrong_schema = request(subject, "process.pid");
    wrong_schema.expected_schema_hash = "fnv1a64:0000000000000000";
    const auto rejected_schema = win::dispatch_fact(wrong_schema);
    REQUIRE(rejected_schema.status == py::FactTerminalStatus::failed);
    REQUIRE_FALSE(rejected_schema.value.has_value());
    REQUIRE_FALSE(rejected_schema.returned_schema.has_value());
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

TEST_CASE("Windows agent runtime binds typed fact and scan batches and replays exact duplicates") {
    win::WindowsAgentProviderRuntime runtime {runtime_identity()};
    const auto process = current_process();
    auto fact = request(process, "process.pid", win::unix_time_ms() + 5'000U);
    fact.request_id = py::RequestId {"runtime:fact"};
    auto scan = scan_request("runtime:scan", process, "process.image.file", 0U, 4'096U,
                             py::optimizer::scan_permission_read, "mz", "bytes:4d5a", 4U);
    const auto work = runtime_work({fact}, {scan});

    const auto first = runtime.dispatch(work);
    REQUIRE(first.has_value());
    REQUIRE(first->originating_session == work.session);
    REQUIRE(first->originating_session_fence == work.session_fence);
    REQUIRE(first->facts.size() == 1U);
    REQUIRE(first->facts.front().status == py::FactTerminalStatus::value);
    REQUIRE(first->scans.size() == 1U);
    REQUIRE(first->scans.front().status == py::FactTerminalStatus::value);
    REQUIRE_FALSE(first->scans.front().matches.empty());
    REQUIRE(std::holds_alternative<proto::WorkResultMessage>(proto::DurableAgentBody {*first}));

    const auto duplicate = runtime.dispatch(work);
    REQUIRE(duplicate.has_value());
    REQUIRE(runtime.tracked_work() == 1U);
    REQUIRE(win::canonical_provider_value(*duplicate->facts.front().value) ==
            win::canonical_provider_value(*first->facts.front().value));
    REQUIRE(duplicate->scans.front().matches.front().offset == first->scans.front().matches.front().offset);

    auto conflicting = work;
    ++conflicting.facts.front().deadline_unix_ms;
    const auto conflict = runtime.dispatch(conflicting);
    REQUIRE_FALSE(conflict.has_value());
    REQUIRE(conflict.error().code == win::AgentRuntimeErrorCode::work_conflict);

    auto stale_session = work;
    stale_session.work_id = "runtime:stale-session";
    stale_session.session = py::SessionId {"session:old"};
    const auto session_failure = runtime.dispatch(stale_session);
    REQUIRE_FALSE(session_failure.has_value());
    REQUIRE(session_failure.error().code == win::AgentRuntimeErrorCode::stale_session);

    auto stale_fence = work;
    stale_fence.work_id = "runtime:stale-fence";
    --stale_fence.session_fence;
    const auto fence_failure = runtime.dispatch(stale_fence);
    REQUIRE_FALSE(fence_failure.has_value());
    REQUIRE(fence_failure.error().code == win::AgentRuntimeErrorCode::stale_fence);

    auto stale_generation = work;
    stale_generation.work_id = "runtime:stale-generation";
    --stale_generation.generation;
    const auto generation_failure = runtime.dispatch(stale_generation);
    REQUIRE_FALSE(generation_failure.has_value());
    REQUIRE(generation_failure.error().code == win::AgentRuntimeErrorCode::stale_generation);

    auto expired_fact = request(process, "process.pid", win::unix_time_ms() - 1U);
    expired_fact.request_id = py::RequestId {"runtime:expired"};
    const auto expired = runtime.dispatch(runtime_work({expired_fact}, {}, "runtime:expired-work"));
    REQUIRE(expired.has_value());
    REQUIRE(expired->facts.front().status == py::FactTerminalStatus::timed_out);
}

TEST_CASE("Windows agent runtime honors exact cancellation and work fences without dispatching semantics") {
    win::WindowsAgentProviderRuntime runtime {runtime_identity()};
    const auto process = current_process();
    auto first = request(process, "process.pid", win::unix_time_ms() + 5'000U);
    first.request_id = py::RequestId {"runtime:cancel:first"};
    auto second = request(process, "process.creation_time", win::unix_time_ms() + 5'000U);
    second.request_id = py::RequestId {"runtime:cancel:second"};
    const auto work = runtime_work({first, second}, {}, "runtime:cancel-work");

    REQUIRE(runtime.cancel(runtime_cancel(work, {first.request_id})).has_value());
    const auto result = runtime.dispatch(work);
    REQUIRE(result.has_value());
    REQUIRE(result->facts.size() == 2U);
    REQUIRE(result->facts[0].status == py::FactTerminalStatus::canceled);
    REQUIRE(result->facts[0].diagnostic.has_value());
    REQUIRE(result->facts[1].status == py::FactTerminalStatus::value);

    auto stale_cancel = runtime_cancel(work);
    --stale_cancel.session_fence;
    const auto stale = runtime.cancel(stale_cancel);
    REQUIRE_FALSE(stale.has_value());
    REQUIRE(stale.error().code == win::AgentRuntimeErrorCode::stale_fence);

    auto duplicate_cancel = runtime_cancel(work, {first.request_id, first.request_id});
    const auto malformed = runtime.cancel(duplicate_cancel);
    REQUIRE_FALSE(malformed.has_value());
    REQUIRE(malformed.error().code == win::AgentRuntimeErrorCode::invalid_work);

    auto superseding = work;
    superseding.attempt_id = "attempt:2";
    ++superseding.work_fence;
    ++superseding.server_sequence;
    const auto newer = runtime.dispatch(superseding);
    REQUIRE(newer.has_value());
    const auto old = runtime.dispatch(work);
    REQUIRE_FALSE(old.has_value());
    REQUIRE(old.error().code == win::AgentRuntimeErrorCode::stale_fence);

    const auto empty = runtime.dispatch(runtime_work({}, {}, "runtime:empty"));
    REQUIRE_FALSE(empty.has_value());
    REQUIRE(empty.error().code == win::AgentRuntimeErrorCode::invalid_work);
}

TEST_CASE("Windows inventory projection retains last-good state across duplicates invalid stages and reconciliation") {
    win::WindowsAgentProviderRuntime runtime {runtime_identity()};
    const auto peer = py::PeerId {"peer:test"};
    const auto schema = py::SchemaId {std::string {win::process_schema}};
    const auto first = win::process_subject(peer, 10U, 100U);
    const auto second = win::process_subject(peer, 20U, 200U);
    const auto initial =
        win::make_inventory_snapshot(peer, schema, std::nullopt, 1U, {observation(second, 2U), observation(first, 1U)});
    const auto published =
        runtime.project_inventory(projection_request("snapshot:1", schema, std::nullopt, 1U), initial);
    REQUIRE(published.has_value());
    REQUIRE_FALSE(published->duplicate);
    REQUIRE(published->observations.size() == 2U);
    REQUIRE(published->removals.empty());
    REQUIRE(published->durable_messages.size() == 4U);
    REQUIRE(published->inventory_digest == initial.commit.canonical_digest);
    REQUIRE(published->protocol_digest.starts_with("sha256:"));
    REQUIRE(published->observations.front().canonical_digest == initial.commit.canonical_digest);
    REQUIRE(std::holds_alternative<proto::AuthoritativeSnapshotBegin>(published->durable_messages[0]));
    REQUIRE(std::holds_alternative<proto::AuthoritativeSnapshotChunk>(published->durable_messages[1]));
    const auto &first_chunk = std::get<proto::AuthoritativeSnapshotChunk>(published->durable_messages[1]);
    REQUIRE(py::canonical_subject_key(first_chunk.subjects.front()) == py::canonical_subject_key(first));
    const auto identity = runtime_identity();
    proto::AuthoritativeSnapshotAssembler assembler {identity.peer, identity.session, identity.session_fence, schema,
                                                     std::nullopt};
    REQUIRE(assembler.begin(std::get<proto::AuthoritativeSnapshotBegin>(published->durable_messages[0])).has_value());
    REQUIRE(assembler.append(std::get<proto::AuthoritativeSnapshotChunk>(published->durable_messages[1])).has_value());
    REQUIRE(assembler.append(std::get<proto::AuthoritativeSnapshotChunk>(published->durable_messages[2])).has_value());
    const auto assembled =
        assembler.commit(std::get<proto::AuthoritativeSnapshotCommit>(published->durable_messages[3]));
    REQUIRE(assembled.has_value());
    REQUIRE(assembled->current.size() == 2U);
    REQUIRE(assembled->canonical_digest == published->protocol_digest);

    const auto duplicate = runtime.project_inventory(projection_request("snapshot:duplicate", schema), initial);
    REQUIRE(duplicate.has_value());
    REQUIRE(duplicate->duplicate);
    REQUIRE(duplicate->durable_messages.empty());
    REQUIRE(runtime.last_good_generation(schema, std::nullopt) == 1U);

    auto corrupted =
        win::make_inventory_snapshot(peer, schema, std::nullopt, 2U, {observation(first, 1U), observation(second, 2U)});
    corrupted.commit.canonical_digest = "sha256:corrupted";
    const auto digest_rejected = runtime.project_inventory(projection_request("snapshot:corrupted", schema), corrupted);
    REQUIRE_FALSE(digest_rejected.has_value());
    REQUIRE(digest_rejected.error().code == win::AgentRuntimeErrorCode::invalid_inventory);
    REQUIRE(runtime.last_good_generation(schema, std::nullopt) == 1U);

    const auto invalid = win::invalid_inventory_snapshot(peer, schema, 2U,
                                                         win::ProviderError {.code = win::ProviderErrorCode::malformed,
                                                                             .operation = "test inventory",
                                                                             .message = "interrupted enumeration",
                                                                             .platform_code = 0U});
    const auto rejected = runtime.project_inventory(projection_request("snapshot:invalid", schema), invalid);
    REQUIRE_FALSE(rejected.has_value());
    REQUIRE(rejected.error().code == win::AgentRuntimeErrorCode::invalid_inventory);
    REQUIRE(runtime.last_good_generation(schema, std::nullopt) == 1U);

    const auto reconciled = win::make_inventory_snapshot(peer, schema, std::nullopt, 3U, {observation(first, 9U)});
    const auto reconciliation = runtime.project_inventory(projection_request("snapshot:3", schema), reconciled);
    REQUIRE(reconciliation.has_value());
    REQUIRE(reconciliation->observations.size() == 1U);
    REQUIRE(reconciliation->removals.size() == 1U);
    REQUIRE(py::canonical_subject_key(reconciliation->removals.front().subject) == py::canonical_subject_key(second));
    REQUIRE(reconciliation->removals.front().canonical_digest == reconciled.commit.canonical_digest);
    REQUIRE(runtime.last_good_generation(schema, std::nullopt) == 3U);

    const auto stale = win::make_inventory_snapshot(peer, schema, std::nullopt, 2U, {observation(first, 9U)});
    const auto stale_result = runtime.project_inventory(projection_request("snapshot:stale", schema), stale);
    REQUIRE_FALSE(stale_result.has_value());
    REQUIRE(stale_result.error().code == win::AgentRuntimeErrorCode::stale_generation);
    REQUIRE(runtime.last_good_generation(schema, std::nullopt) == 3U);

    const auto empty = win::make_inventory_snapshot(peer, schema, std::nullopt, 4U, {});
    const auto emptied = runtime.project_inventory(projection_request("snapshot:4", schema), empty);
    REQUIRE(emptied.has_value());
    REQUIRE(emptied->observations.empty());
    REQUIRE(emptied->removals.size() == 1U);
    REQUIRE(emptied->durable_messages.size() == 2U);
    REQUIRE(std::holds_alternative<proto::AuthoritativeSnapshotBegin>(emptied->durable_messages.front()));
    REQUIRE(std::holds_alternative<proto::AuthoritativeSnapshotCommit>(emptied->durable_messages.back()));

    win::WindowsAgentRuntimeLimits tight_limits;
    tight_limits.maximum_last_good_inventory_bytes = 1U;
    win::WindowsAgentProviderRuntime bounded {runtime_identity(), tight_limits};
    const auto bounded_result = bounded.project_inventory(projection_request("snapshot:bounded", schema), initial);
    REQUIRE_FALSE(bounded_result.has_value());
    REQUIRE(bounded_result.error().code == win::AgentRuntimeErrorCode::limit_exceeded);
    REQUIRE(bounded.last_good_scopes() == 0U);
}

TEST_CASE("Windows inventory projection emits descendant removals before a removed parent") {
    win::WindowsAgentProviderRuntime runtime {runtime_identity()};
    const auto peer = py::PeerId {"peer:test"};
    const auto process_schema = py::SchemaId {std::string {win::process_schema}};
    const auto memory_schema = py::SchemaId {std::string {win::memory_region_schema}};
    const auto process = win::process_subject(peer, 30U, 300U);
    const auto region = win::memory_region_subject(process, 0x1000U, 0x2000U);

    const auto root = win::make_inventory_snapshot(peer, process_schema, std::nullopt, 1U, {observation(process, 1U)});
    REQUIRE(runtime.project_inventory(projection_request("root:1", process_schema), root).has_value());
    const auto child = win::make_inventory_snapshot(peer, memory_schema, process, 1U, {observation(region, 2U)});
    REQUIRE(runtime.project_inventory(projection_request("child:1", memory_schema, process), child).has_value());
    REQUIRE(runtime.last_good_scopes() == 2U);

    const auto empty_root = win::make_inventory_snapshot(peer, process_schema, std::nullopt, 2U, {});
    const auto cascade = runtime.project_inventory(projection_request("root:2", process_schema), empty_root);
    REQUIRE(cascade.has_value());
    REQUIRE(cascade->removals.size() == 2U);
    REQUIRE(cascade->removals[0].subject.descriptor == memory_schema);
    REQUIRE(cascade->removals[1].subject.descriptor == process_schema);
    REQUIRE(runtime.last_good_scopes() == 1U);
    REQUIRE_FALSE(runtime.last_good_generation(memory_schema, process).has_value());
    REQUIRE(runtime.last_good_generation(process_schema, std::nullopt) == 2U);
}
