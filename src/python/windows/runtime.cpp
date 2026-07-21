#include "rule_engine/python/windows/runtime.hpp"

#include "rule_engine/python/protocol/snapshot.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace rule_engine::python::windows {
    namespace {

        using protocol_v2::AuthoritativeSnapshotBegin;
        using protocol_v2::AuthoritativeSnapshotChunk;
        using protocol_v2::AuthoritativeSnapshotCommit;
        using protocol_v2::CancelWorkMessage;
        using protocol_v2::DurableAgentBody;
        using protocol_v2::ProtocolErrorCode;
        using protocol_v2::ProtocolLimits;
        using protocol_v2::WorkLeaseMessage;
        using protocol_v2::WorkResultMessage;

        [[nodiscard]] AgentRuntimeError runtime_error(const AgentRuntimeErrorCode code, std::string message) {
            return AgentRuntimeError {.code = code, .message = std::move(message)};
        }

        [[nodiscard]] bool configured(const WindowsAgentRuntimeIdentity &identity,
                                      const WindowsAgentRuntimeLimits &limits) noexcept {
            return !identity.session.empty() && !identity.peer.empty() && identity.session_fence != 0U &&
                   identity.generation != 0U && identity.route == provider_name && limits.maximum_tracked_work != 0U &&
                   limits.maximum_inventory_scopes != 0U && limits.maximum_cached_result_bytes != 0U &&
                   limits.maximum_last_good_inventory_bytes != 0U;
        }

        void append_token(std::string &output, const std::string_view token) {
            output.append(std::to_string(token.size()));
            output.push_back(':');
            output.append(token);
        }

        template<typename Integer> void append_integer(std::string &output, const Integer value) {
            append_token(output, std::to_string(value));
        }

        void append_label(std::string &output, const DataLabel &label) {
            append_integer(output, static_cast<std::uint8_t>(label.classification));
            append_integer(output, label.categories.size());
            for (const auto &category : label.categories) { append_token(output, category); }
        }

        [[nodiscard]] std::string work_fingerprint(const WorkLeaseMessage &work) {
            std::string canonical;
            append_token(canonical, "windows-agent-work-v1");
            append_token(canonical, work.route);
            append_integer(canonical, work.generation);
            append_integer(canonical, work.facts.size());
            for (const auto &request : work.facts) {
                append_token(canonical, request.request_id.value);
                append_token(canonical, canonical_subject_key(request.subject));
                append_token(canonical, request.route.provider);
                append_token(canonical, request.route.fact);
                append_token(canonical, request.expected_schema.value);
                append_integer(canonical, request.deadline_unix_ms);
            }
            append_integer(canonical, work.scans.size());
            for (const auto &request : work.scans) {
                append_token(canonical, request.request_id.value);
                append_token(canonical, canonical_subject_key(request.subject));
                append_token(canonical, request.space.kind);
                append_integer(canonical, request.space.begin);
                append_integer(canonical, request.space.size);
                append_integer(canonical, request.space.permissions);
                append_token(canonical, request.space.identity);
                append_label(canonical, request.space.label);
                append_integer(canonical, request.space.subject_generation);
                append_token(canonical, request.plan.plan_id);
                append_token(canonical, request.plan.encoded_pattern);
                append_integer(canonical, request.plan.maximum_bytes);
                append_integer(canonical, request.plan.maximum_matches);
                append_integer(canonical, request.plan.context_bytes_before);
                append_integer(canonical, request.plan.context_bytes_after);
                append_integer(canonical, static_cast<std::uint8_t>(request.plan.result_mode));
                append_integer(canonical, request.plan.pattern_ids.size());
                for (const auto &pattern_id : request.plan.pattern_ids) { append_token(canonical, pattern_id); }
                append_integer(canonical, request.deadline_unix_ms);
            }
            return sha256_digest(std::as_bytes(std::span {canonical}));
        }

        [[nodiscard]] bool same_subject(const SubjectKey &left, const SubjectKey &right) {
            const auto canonical = canonical_subject_key(left);
            return !canonical.empty() && canonical == canonical_subject_key(right);
        }

        [[nodiscard]] std::expected<void, AgentRuntimeError> validate_work(const WorkLeaseMessage &work,
                                                                           const WindowsAgentRuntimeIdentity &identity,
                                                                           const ProtocolLimits &limits) {
            if (work.session != identity.session || work.peer != identity.peer) {
                return std::unexpected(
                    runtime_error(AgentRuntimeErrorCode::stale_session, "work does not belong to the active session"));
            }
            if (work.session_fence != identity.session_fence) {
                return std::unexpected(
                    runtime_error(AgentRuntimeErrorCode::stale_fence, "work session fence is stale"));
            }
            if (work.generation != identity.generation) {
                return std::unexpected(
                    runtime_error(AgentRuntimeErrorCode::stale_generation, "work generation is not active"));
            }
            if (work.route != identity.route || work.work_id.empty() || work.attempt_id.empty() ||
                work.work_fence == 0U || work.server_sequence == 0U || (work.facts.empty() && work.scans.empty()) ||
                work.work_id.size() > limits.maximum_string_bytes ||
                work.attempt_id.size() > limits.maximum_string_bytes ||
                work.facts.size() > limits.maximum_fact_requests || work.scans.size() > limits.maximum_scan_requests) {
                return std::unexpected(
                    runtime_error(AgentRuntimeErrorCode::invalid_work, "work envelope is incomplete or oversized"));
            }

            std::unordered_set<std::string> request_ids;
            request_ids.reserve(work.facts.size() + work.scans.size());
            for (const auto &request : work.facts) {
                if (request.request_id.empty() || request.request_id.value.size() > limits.maximum_string_bytes ||
                    !request_ids.insert(request.request_id.value).second || !request.subject.valid() ||
                    request.subject.peer != identity.peer || request.route.provider != identity.route ||
                    request.route.fact.empty() || request.route.fact.size() > limits.maximum_string_bytes ||
                    request.expected_schema.empty() ||
                    request.expected_schema.value.size() > limits.maximum_string_bytes ||
                    request.deadline_unix_ms == 0U) {
                    return std::unexpected(runtime_error(
                        AgentRuntimeErrorCode::invalid_work,
                        "fact request is not bound to the work peer, route, schema, deadline, and unique identity"));
                }
            }
            for (const auto &request : work.scans) {
                std::unordered_set<std::string_view> pattern_ids;
                pattern_ids.reserve(request.plan.pattern_ids.size());
                const auto valid_patterns =
                    !request.plan.pattern_ids.empty() &&
                    request.plan.pattern_ids.size() <= limits.maximum_scan_patterns &&
                    std::ranges::all_of(request.plan.pattern_ids, [&](const std::string &pattern_id) {
                        return !pattern_id.empty() && pattern_id.size() <= limits.maximum_string_bytes &&
                               pattern_ids.insert(pattern_id).second;
                    });
                if (request.request_id.empty() || request.request_id.value.size() > limits.maximum_string_bytes ||
                    !request_ids.insert(request.request_id.value).second || !request.subject.valid() ||
                    request.subject.peer != identity.peer || request.space.kind.empty() ||
                    request.space.kind.size() > limits.maximum_string_bytes || request.space.identity.empty() ||
                    request.space.subject_generation == 0U ||
                    request.space.identity.size() > limits.maximum_string_bytes || request.plan.plan_id.empty() ||
                    request.plan.plan_id.size() > limits.maximum_string_bytes || request.plan.encoded_pattern.empty() ||
                    request.plan.encoded_pattern.size() > limits.maximum_blob_bytes || !valid_patterns ||
                    request.plan.maximum_bytes == 0U || request.plan.maximum_bytes > request.space.size ||
                    request.plan.maximum_bytes > limits.maximum_blob_bytes || request.plan.maximum_matches == 0U ||
                    request.plan.maximum_matches > limits.maximum_scan_matches || request.deadline_unix_ms == 0U ||
                    request.space.size == 0U ||
                    request.space.size > (std::numeric_limits<std::uint64_t>::max)() - request.space.begin ||
                    (request.plan.result_mode != ScanResultMode::exact_complete &&
                     request.plan.result_mode != ScanResultMode::existential) ||
                    request.plan.context_bytes_before > limits.maximum_blob_bytes ||
                    request.plan.context_bytes_after > limits.maximum_blob_bytes) {
                    return std::unexpected(runtime_error(AgentRuntimeErrorCode::invalid_work,
                                                         "scan request is outside its authenticated typed bounds"));
                }
            }
            return {};
        }

        [[nodiscard]] bool fact_response_valid(const FactRequest &request, const FactResponse &response) {
            return response.request_id == request.request_id && same_subject(response.subject, request.subject) &&
                   (response.status == FactTerminalStatus::value ? response.value.has_value() :
                                                                   !response.value.has_value());
        }

        [[nodiscard]] bool scan_response_valid(const ScanRequest &request, const ScanResponse &response,
                                               const ProtocolLimits &limits) {
            if (response.request_id != request.request_id || !same_subject(response.subject, request.subject) ||
                response.truncated || response.mode != request.plan.result_mode ||
                response.matches.size() > request.plan.maximum_matches ||
                (response.mode == ScanResultMode::existential && response.matches.size() > 1U) ||
                (response.status != FactTerminalStatus::value && !response.matches.empty())) {
                return false;
            }
            std::unordered_set<std::string_view> allowed_patterns;
            allowed_patterns.reserve(request.plan.pattern_ids.size());
            for (const auto &pattern_id : request.plan.pattern_ids) { allowed_patterns.insert(pattern_id); }
            return std::ranges::all_of(response.matches, [&](const ScanMatch &match) {
                const auto matched_size = static_cast<std::uint64_t>(match.matched_bytes.size());
                return allowed_patterns.contains(match.pattern_id) && match.scan_space_id == request.space.identity &&
                       match.permission_snapshot == request.space.permissions && match.label == request.space.label &&
                       match.subject_generation == request.space.subject_generation &&
                       match.offset <= request.space.size && match.length <= request.space.size - match.offset &&
                       match.offset <= (std::numeric_limits<std::uint64_t>::max)() - request.space.begin &&
                       match.absolute_address == request.space.begin + match.offset && matched_size == match.length &&
                       match.before_bytes.size() <= request.plan.context_bytes_before &&
                       match.after_bytes.size() <= request.plan.context_bytes_after &&
                       match.before_bytes.size() <= match.offset &&
                       match.after_bytes.size() <= request.space.size - match.offset - match.length &&
                       match.matched_bytes.size() <= limits.maximum_blob_bytes &&
                       match.before_bytes.size() <= limits.maximum_blob_bytes - match.matched_bytes.size() &&
                       match.after_bytes.size() <=
                           limits.maximum_blob_bytes - match.matched_bytes.size() - match.before_bytes.size();
            });
        }

        void add_size(std::size_t &total, const std::size_t amount) noexcept {
            total = amount > (std::numeric_limits<std::size_t>::max)() - total ?
                        (std::numeric_limits<std::size_t>::max)() :
                        total + amount;
        }

        [[nodiscard]] std::size_t result_storage_bytes(const WorkResultMessage &result) {
            std::size_t bytes {};
            add_size(bytes, result.originating_session.value.size());
            add_size(bytes, result.peer.value.size());
            add_size(bytes, result.work_id.size());
            add_size(bytes, result.attempt_id.size());
            for (const auto &response : result.facts) {
                add_size(bytes, response.request_id.value.size());
                add_size(bytes, canonical_subject_key(response.subject).size());
                if (response.value.has_value()) {
                    add_size(bytes, canonical_provider_value(*response.value).size());
                }
                if (response.diagnostic.has_value()) {
                    add_size(bytes, response.diagnostic->code.size());
                    add_size(bytes, response.diagnostic->message.size());
                }
            }
            for (const auto &response : result.scans) {
                add_size(bytes, response.request_id.value.size());
                add_size(bytes, canonical_subject_key(response.subject).size());
                if (response.diagnostic.has_value()) {
                    add_size(bytes, response.diagnostic->code.size());
                    add_size(bytes, response.diagnostic->message.size());
                }
                for (const auto &match : response.matches) {
                    add_size(bytes, match.pattern_id.size());
                    add_size(bytes, match.scan_space_id.size());
                    add_size(bytes, match.matched_bytes.size());
                    add_size(bytes, match.before_bytes.size());
                    add_size(bytes, match.after_bytes.size());
                    for (const auto &category : match.label.categories) { add_size(bytes, category.size()); }
                }
            }
            return bytes;
        }

        [[nodiscard]] Diagnostic canceled_diagnostic() {
            return Diagnostic {.code = "windows.provider.canceled",
                               .severity = DiagnosticSeverity::error,
                               .message = "request was canceled before provider dispatch",
                               .span = std::nullopt,
                               .related = {}};
        }

        [[nodiscard]] FactResponse canceled_response(const FactRequest &request) {
            return FactResponse {.request_id = request.request_id,
                                 .subject = request.subject,
                                 .status = FactTerminalStatus::canceled,
                                 .value = std::nullopt,
                                 .diagnostic = canceled_diagnostic()};
        }

        [[nodiscard]] ScanResponse canceled_response(const ScanRequest &request) {
            return ScanResponse {.request_id = request.request_id,
                                 .subject = request.subject,
                                 .status = FactTerminalStatus::canceled,
                                 .matches = {},
                                 .truncated = false,
                                 .diagnostic = canceled_diagnostic(),
                                 .mode = request.plan.result_mode};
        }

        [[nodiscard]] std::string scope_identity(const SchemaId &schema, const std::optional<SubjectKey> &parent) {
            std::string output;
            append_token(output, schema.value);
            append_token(output, parent.has_value() ? canonical_subject_key(*parent) : std::string_view {});
            return output;
        }

        [[nodiscard]] std::string observation_signature(const SubjectObservation &observation) {
            auto eager =
                make_fact(FactRecord {.schema = observation.subject.descriptor, .fields = observation.eager_fields});
            std::string output;
            append_token(output, canonical_subject_key(observation.subject));
            append_token(output, canonical_provider_value(eager));
            return output;
        }

        [[nodiscard]] std::size_t subject_depth(const SubjectKey &subject) noexcept {
            std::size_t depth {1U};
            auto parent = subject.parent;
            while (parent != nullptr) {
                ++depth;
                parent = parent->parent;
            }
            return depth;
        }

        [[nodiscard]] bool is_subject_or_descendant(const SubjectKey &subject,
                                                    const std::unordered_set<std::string> &ancestors) {
            const SubjectKey *current = &subject;
            while (current != nullptr) {
                if (ancestors.contains(canonical_subject_key(*current))) {
                    return true;
                }
                current = current->parent.get();
            }
            return false;
        }

        [[nodiscard]] AgentRuntimeError snapshot_protocol_error(const protocol_v2::ProtocolError &error) {
            return runtime_error(error.code == ProtocolErrorCode::limit_exceeded ?
                                     AgentRuntimeErrorCode::limit_exceeded :
                                     AgentRuntimeErrorCode::invalid_inventory,
                                 error.message);
        }

    } // namespace

    WindowsAgentProviderRuntime::WindowsAgentProviderRuntime(WindowsAgentRuntimeIdentity identity,
                                                             WindowsAgentRuntimeLimits limits):
        identity_ {std::move(identity)}, limits_ {std::move(limits)} {}

    WindowsAgentProviderRuntime::WorkState *
    WindowsAgentProviderRuntime::find_work(const std::string_view work_id) noexcept {
        const auto found =
            std::ranges::find_if(work_, [work_id](const WorkState &state) { return state.work_id == work_id; });
        return found == work_.end() ? nullptr : std::addressof(*found);
    }

    const WindowsAgentProviderRuntime::InventoryState *
    WindowsAgentProviderRuntime::find_inventory(const std::string_view scope_key) const noexcept {
        const auto found = std::ranges::find_if(
            inventories_, [scope_key](const InventoryState &state) { return state.scope_key == scope_key; });
        return found == inventories_.end() ? nullptr : std::addressof(*found);
    }

    std::expected<WorkResultMessage, AgentRuntimeError>
    WindowsAgentProviderRuntime::dispatch(const WorkLeaseMessage &work) {
        if (!configured(identity_, limits_)) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::invalid_configuration, "Windows provider runtime is not bound"));
        }
        if (auto valid = validate_work(work, identity_, limits_.protocol); !valid) {
            return std::unexpected(std::move(valid.error()));
        }
        auto fingerprint = work_fingerprint(work);
        if (fingerprint.empty()) {
            return std::unexpected(runtime_error(AgentRuntimeErrorCode::provider_violation,
                                                 "work request fingerprint could not be calculated"));
        }

        auto *state = find_work(work.work_id);
        if (state != nullptr && state->work_fence > work.work_fence) {
            return std::unexpected(runtime_error(AgentRuntimeErrorCode::stale_fence, "work fence is stale"));
        }
        if (state != nullptr && state->work_fence == work.work_fence) {
            if (state->attempt_id != work.attempt_id || state->generation != work.generation) {
                return std::unexpected(
                    runtime_error(AgentRuntimeErrorCode::work_conflict, "work attempt conflicts at the same fence"));
            }
            if (!state->fingerprint.empty() && state->fingerprint != fingerprint) {
                return std::unexpected(runtime_error(AgentRuntimeErrorCode::work_conflict,
                                                     "duplicate work changed its authenticated request batch"));
            }
            if (state->result.has_value()) {
                return *state->result;
            }
        } else {
            if (state == nullptr) {
                if (work_.size() >= limits_.maximum_tracked_work) {
                    return std::unexpected(
                        runtime_error(AgentRuntimeErrorCode::limit_exceeded, "tracked work identity limit is reached"));
                }
                work_.push_back(WorkState {});
                state = std::addressof(work_.back());
            } else {
                cached_result_bytes_ -= state->cached_result_bytes;
            }
            *state = WorkState {};
            state->work_id = work.work_id;
            state->attempt_id = work.attempt_id;
            state->work_fence = work.work_fence;
            state->generation = work.generation;
        }

        state->fingerprint = std::move(fingerprint);
        state->request_ids.clear();
        state->request_ids.reserve(work.facts.size() + work.scans.size());
        for (const auto &request : work.facts) { state->request_ids.push_back(request.request_id); }
        for (const auto &request : work.scans) { state->request_ids.push_back(request.request_id); }
        if (!state->cancel_all && std::ranges::any_of(state->canceled_requests, [&](const std::string &request_id) {
                return std::ranges::none_of(state->request_ids,
                                            [&](const RequestId &known) { return known.value == request_id; });
            })) {
            return std::unexpected(runtime_error(AgentRuntimeErrorCode::work_conflict,
                                                 "pending cancellation names a request outside the work batch"));
        }

        WorkResultMessage result {.originating_session = work.session,
                                  .peer = work.peer,
                                  .originating_session_fence = work.session_fence,
                                  .work_id = work.work_id,
                                  .attempt_id = work.attempt_id,
                                  .work_fence = work.work_fence,
                                  .generation = work.generation,
                                  .facts = {},
                                  .scans = {}};
        result.facts.reserve(work.facts.size());
        for (const auto &request : work.facts) {
            auto response = state->cancel_all || state->canceled_requests.contains(request.request_id.value) ?
                                canceled_response(request) :
                                dispatch_fact(request);
            if (!fact_response_valid(request, response)) {
                return std::unexpected(runtime_error(AgentRuntimeErrorCode::provider_violation,
                                                     "fact provider returned an invalid response identity or status"));
            }
            result.facts.push_back(std::move(response));
        }
        result.scans.reserve(work.scans.size());
        for (const auto &request : work.scans) {
            auto response = state->cancel_all || state->canceled_requests.contains(request.request_id.value) ?
                                canceled_response(request) :
                                dispatch_scan(request);
            if (!scan_response_valid(request, response, limits_.protocol)) {
                return std::unexpected(runtime_error(AgentRuntimeErrorCode::provider_violation,
                                                     "scan provider returned metadata outside the request bounds"));
            }
            result.scans.push_back(std::move(response));
        }
        const auto result_bytes = result_storage_bytes(result);
        if (result_bytes <= limits_.maximum_cached_result_bytes - cached_result_bytes_) {
            state->cached_result_bytes = result_bytes;
            state->result = result;
            cached_result_bytes_ += result_bytes;
        }
        return result;
    }

    std::expected<void, AgentRuntimeError> WindowsAgentProviderRuntime::cancel(const CancelWorkMessage &message) {
        if (!configured(identity_, limits_)) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::invalid_configuration, "Windows provider runtime is not bound"));
        }
        if (message.session != identity_.session || message.peer != identity_.peer) {
            return std::unexpected(runtime_error(AgentRuntimeErrorCode::stale_session,
                                                 "cancellation does not belong to the active session"));
        }
        if (message.session_fence != identity_.session_fence) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::stale_fence, "cancellation session fence is stale"));
        }
        if (message.route != identity_.route || message.work_id.empty() || message.attempt_id.empty() ||
            message.work_fence == 0U || message.server_sequence == 0U) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::invalid_work, "cancellation identity is incomplete"));
        }
        std::unordered_set<std::string_view> requests;
        requests.reserve(message.requests.size());
        if (message.requests.size() > limits_.protocol.maximum_collection_items ||
            std::ranges::any_of(message.requests, [&](const RequestId &request) {
                return request.empty() || request.value.size() > limits_.protocol.maximum_string_bytes ||
                       !requests.insert(request.value).second;
            })) {
            return std::unexpected(runtime_error(AgentRuntimeErrorCode::invalid_work,
                                                 "cancellation request identities are empty or duplicated"));
        }

        auto *state = find_work(message.work_id);
        if (state != nullptr && state->work_fence > message.work_fence) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::stale_fence, "cancellation work fence is stale"));
        }
        if (state != nullptr && state->work_fence == message.work_fence && state->attempt_id != message.attempt_id) {
            return std::unexpected(runtime_error(AgentRuntimeErrorCode::work_conflict,
                                                 "cancellation attempt conflicts at the same fence"));
        }
        if (state == nullptr || state->work_fence < message.work_fence) {
            if (state == nullptr) {
                if (work_.size() >= limits_.maximum_tracked_work) {
                    return std::unexpected(
                        runtime_error(AgentRuntimeErrorCode::limit_exceeded, "tracked work identity limit is reached"));
                }
                work_.push_back(WorkState {});
                state = std::addressof(work_.back());
            } else {
                cached_result_bytes_ -= state->cached_result_bytes;
            }
            *state = WorkState {};
            state->work_id = message.work_id;
            state->attempt_id = message.attempt_id;
            state->work_fence = message.work_fence;
            state->generation = identity_.generation;
        }
        if (state->result.has_value()) {
            return {};
        }
        if (!state->request_ids.empty() && std::ranges::any_of(message.requests, [&](const RequestId &request) {
                return std::ranges::none_of(state->request_ids,
                                            [&](const RequestId &known) { return known == request; });
            })) {
            return std::unexpected(runtime_error(AgentRuntimeErrorCode::work_conflict,
                                                 "cancellation names a request outside the accepted work batch"));
        }
        if (message.requests.empty()) {
            state->cancel_all = true;
            state->canceled_requests.clear();
        } else if (!state->cancel_all) {
            for (const auto &request : message.requests) { state->canceled_requests.insert(request.value); }
        }
        return {};
    }

    std::expected<InventoryProjection, AgentRuntimeError>
    WindowsAgentProviderRuntime::project_inventory(const InventoryProjectionRequest &request,
                                                   const InventorySnapshot &inventory) {
        if (!configured(identity_, limits_)) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::invalid_configuration, "Windows provider runtime is not bound"));
        }
        if (request.snapshot_id.empty() || request.subject_schema.empty() || request.chunk_items == 0U ||
            request.chunk_items > limits_.protocol.maximum_collection_items ||
            request.chunk_items > limits_.protocol.maximum_snapshot_items ||
            (request.parent.has_value() && (!request.parent->valid() || request.parent->peer != identity_.peer))) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::invalid_inventory, "inventory projection request is invalid"));
        }
        if (!inventory.authoritative || inventory.status != FactTerminalStatus::value ||
            inventory.diagnostic.has_value() || inventory.begin.peer != identity_.peer ||
            inventory.begin.subject_schema != request.subject_schema || inventory.begin.generation == 0U ||
            inventory.commit.peer != inventory.begin.peer ||
            inventory.commit.subject_schema != inventory.begin.subject_schema ||
            inventory.commit.generation != inventory.begin.generation ||
            inventory.commit.item_count != inventory.items.size() || inventory.commit.canonical_digest.empty() ||
            inventory.items.size() > limits_.protocol.maximum_snapshot_items) {
            return std::unexpected(runtime_error(AgentRuntimeErrorCode::invalid_inventory,
                                                 "inventory is partial, inconsistent, or outside the active peer"));
        }

        auto verified = make_inventory_snapshot(inventory.begin.peer, inventory.begin.subject_schema, request.parent,
                                                inventory.begin.generation, inventory.items);
        if (!verified.authoritative || verified.commit.canonical_digest != inventory.commit.canonical_digest) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::invalid_inventory, "inventory digest or parent scope is invalid"));
        }

        auto sorted_items = inventory.items;
        std::ranges::sort(sorted_items, [](const SubjectObservation &left, const SubjectObservation &right) {
            return canonical_subject_key(left.subject) < canonical_subject_key(right.subject);
        });
        std::vector<SubjectKey> subjects;
        subjects.reserve(sorted_items.size());
        std::size_t observation_bytes {};
        for (const auto &item : sorted_items) {
            auto signature = observation_signature(item);
            if (signature.size() > limits_.protocol.maximum_snapshot_bytes - observation_bytes) {
                return std::unexpected(runtime_error(AgentRuntimeErrorCode::limit_exceeded,
                                                     "inventory eager observation bytes exceed the limit"));
            }
            observation_bytes += signature.size();
            subjects.push_back(item.subject);
        }
        auto protocol_digest = protocol_v2::authoritative_snapshot_digest(subjects, limits_.protocol);
        if (!protocol_digest) {
            return std::unexpected(snapshot_protocol_error(protocol_digest.error()));
        }

        const auto key = scope_identity(request.subject_schema, request.parent);
        const auto *previous = find_inventory(key);
        if (previous != nullptr && inventory.begin.generation < previous->generation) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::stale_generation, "inventory generation is stale"));
        }
        if (previous != nullptr && inventory.begin.generation == previous->generation) {
            if (inventory.commit.canonical_digest != previous->inventory_digest ||
                *protocol_digest != previous->protocol_digest) {
                return std::unexpected(runtime_error(AgentRuntimeErrorCode::stale_generation,
                                                     "inventory conflicts at an already committed generation"));
            }
            return InventoryProjection {.generation = inventory.begin.generation,
                                        .inventory_digest = inventory.commit.canonical_digest,
                                        .protocol_digest = *protocol_digest,
                                        .durable_messages = {},
                                        .observations = {},
                                        .removals = {},
                                        .duplicate = true};
        }
        if (previous == nullptr && inventories_.size() >= limits_.maximum_inventory_scopes) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::limit_exceeded, "last-good inventory scope limit is reached"));
        }

        std::unordered_map<std::string, std::string> old_signatures;
        if (previous != nullptr) {
            old_signatures.reserve(previous->items.size());
            for (const auto &item : previous->items) {
                old_signatures.emplace(canonical_subject_key(item.subject), observation_signature(item));
            }
        }
        std::unordered_set<std::string> current_keys;
        current_keys.reserve(sorted_items.size());
        std::vector<ProjectedObservation> observations;
        for (const auto &item : sorted_items) {
            const auto subject_key = canonical_subject_key(item.subject);
            current_keys.insert(subject_key);
            const auto signature = observation_signature(item);
            const auto old = old_signatures.find(subject_key);
            if (old == old_signatures.end() || old->second != signature) {
                observations.push_back(ProjectedObservation {.observation = item,
                                                             .generation = inventory.begin.generation,
                                                             .canonical_digest = inventory.commit.canonical_digest});
            }
        }

        std::vector<SubjectKey> removed_subjects;
        std::unordered_set<std::string> removed_keys;
        if (previous != nullptr) {
            removed_subjects.reserve(previous->items.size());
            for (const auto &item : previous->items) {
                auto subject_key = canonical_subject_key(item.subject);
                if (!current_keys.contains(subject_key) && removed_keys.insert(subject_key).second) {
                    removed_subjects.push_back(item.subject);
                }
            }
        }
        std::unordered_set<std::string> removed_ancestors = removed_keys;
        std::vector<std::string> cascade_scopes;
        for (const auto &state : inventories_) {
            if (state.scope_key == key || !state.parent.has_value() ||
                !is_subject_or_descendant(*state.parent, removed_ancestors)) {
                continue;
            }
            cascade_scopes.push_back(state.scope_key);
            for (const auto &item : state.items) {
                auto subject_key = canonical_subject_key(item.subject);
                if (removed_keys.insert(subject_key).second) {
                    removed_subjects.push_back(item.subject);
                }
            }
        }
        std::size_t reclaimed_bytes = previous == nullptr ? 0U : previous->storage_bytes;
        for (const auto &state : inventories_) {
            if (std::ranges::find(cascade_scopes, state.scope_key) != cascade_scopes.end()) {
                add_size(reclaimed_bytes, state.storage_bytes);
            }
        }
        if (reclaimed_bytes > last_good_inventory_bytes_) {
            return std::unexpected(runtime_error(AgentRuntimeErrorCode::provider_violation,
                                                 "last-good inventory accounting is inconsistent"));
        }
        const auto retained_bytes = last_good_inventory_bytes_ - reclaimed_bytes;
        if (retained_bytes > limits_.maximum_last_good_inventory_bytes ||
            observation_bytes > limits_.maximum_last_good_inventory_bytes - retained_bytes) {
            return std::unexpected(
                runtime_error(AgentRuntimeErrorCode::limit_exceeded, "last-good inventory byte limit is reached"));
        }
        std::ranges::sort(removed_subjects, [](const SubjectKey &left, const SubjectKey &right) {
            const auto left_depth = subject_depth(left);
            const auto right_depth = subject_depth(right);
            return left_depth != right_depth ? left_depth > right_depth :
                                               canonical_subject_key(left) < canonical_subject_key(right);
        });
        std::vector<ProjectedRemoval> removals;
        removals.reserve(removed_subjects.size());
        for (auto &subject : removed_subjects) {
            removals.push_back(ProjectedRemoval {.subject = std::move(subject),
                                                 .generation = inventory.begin.generation,
                                                 .canonical_digest = inventory.commit.canonical_digest});
        }

        std::vector<DurableAgentBody> messages;
        messages.reserve(2U + (subjects.size() + request.chunk_items - 1U) / request.chunk_items);
        messages.emplace_back(AuthoritativeSnapshotBegin {.session = identity_.session,
                                                          .peer = identity_.peer,
                                                          .session_fence = identity_.session_fence,
                                                          .snapshot_id = request.snapshot_id,
                                                          .parent = request.parent,
                                                          .subject_schema = request.subject_schema,
                                                          .generation = inventory.begin.generation,
                                                          .expected_count = subjects.size(),
                                                          .expected_digest = *protocol_digest});
        std::uint32_t chunk_index {};
        for (std::size_t offset = 0U; offset < subjects.size(); offset += request.chunk_items) {
            const auto count = std::min(request.chunk_items, subjects.size() - offset);
            messages.emplace_back(AuthoritativeSnapshotChunk {
                .session = identity_.session,
                .peer = identity_.peer,
                .session_fence = identity_.session_fence,
                .snapshot_id = request.snapshot_id,
                .generation = inventory.begin.generation,
                .chunk_index = chunk_index++,
                .subjects = std::vector<SubjectKey> {subjects.begin() + static_cast<std::ptrdiff_t>(offset),
                                                     subjects.begin() + static_cast<std::ptrdiff_t>(offset + count)},
            });
        }
        messages.emplace_back(AuthoritativeSnapshotCommit {.session = identity_.session,
                                                           .peer = identity_.peer,
                                                           .session_fence = identity_.session_fence,
                                                           .snapshot_id = request.snapshot_id,
                                                           .generation = inventory.begin.generation,
                                                           .item_count = subjects.size(),
                                                           .canonical_digest = *protocol_digest});

        std::erase_if(inventories_, [&](const InventoryState &state) {
            return std::ranges::find(cascade_scopes, state.scope_key) != cascade_scopes.end();
        });
        auto current =
            std::ranges::find_if(inventories_, [&](const InventoryState &state) { return state.scope_key == key; });
        InventoryState committed {.scope_key = key,
                                  .subject_schema = request.subject_schema,
                                  .parent = request.parent,
                                  .generation = inventory.begin.generation,
                                  .inventory_digest = inventory.commit.canonical_digest,
                                  .protocol_digest = *protocol_digest,
                                  .storage_bytes = observation_bytes,
                                  .items = std::move(sorted_items)};
        if (current == inventories_.end()) {
            inventories_.push_back(std::move(committed));
        } else {
            *current = std::move(committed);
        }
        last_good_inventory_bytes_ = retained_bytes + observation_bytes;

        return InventoryProjection {.generation = inventory.begin.generation,
                                    .inventory_digest = inventory.commit.canonical_digest,
                                    .protocol_digest = std::move(*protocol_digest),
                                    .durable_messages = std::move(messages),
                                    .observations = std::move(observations),
                                    .removals = std::move(removals),
                                    .duplicate = false};
    }

    std::optional<std::uint64_t>
    WindowsAgentProviderRuntime::last_good_generation(const SchemaId &schema,
                                                      const std::optional<SubjectKey> &parent) const {
        const auto *state = find_inventory(scope_identity(schema, parent));
        return state == nullptr ? std::nullopt : std::optional {state->generation};
    }

} // namespace rule_engine::python::windows
