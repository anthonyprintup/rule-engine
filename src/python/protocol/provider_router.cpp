#include "rule_engine/python/protocol/provider_router.hpp"

#include "rule_engine/python/protocol/snapshot.hpp"
#include "rule_engine/python/protocol/spool.hpp"

#include <algorithm>
#include <limits>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace rule_engine::python::protocol_v2 {
    namespace {

        [[nodiscard]] ProviderDispatchError provider_error(const ProviderDispatchErrorCode code, std::string message) {
            return ProviderDispatchError {.code = code, .message = std::move(message)};
        }

        [[nodiscard]] bool response_status_valid(const FactResponse &response) {
            return response.status == FactTerminalStatus::value ? response.value.has_value() :
                                                                  !response.value.has_value();
        }

        [[nodiscard]] bool scan_status_valid(const ScanResponse &response) {
            if (response.truncated ||
                (response.mode != ScanResultMode::exact_complete && response.mode != ScanResultMode::existential) ||
                (response.mode == ScanResultMode::existential && response.matches.size() > 1)) {
                return false;
            }
            if (response.status == FactTerminalStatus::value) {
                return true;
            }
            return response.matches.empty();
        }

        [[nodiscard]] bool same_subject(const SubjectKey &left, const SubjectKey &right) {
            const auto left_key = canonical_subject_key(left);
            return !left_key.empty() && left_key == canonical_subject_key(right);
        }

        [[nodiscard]] bool scan_pattern_ids_valid(const ScanPlan &plan, const ProtocolLimits &limits) {
            if (plan.pattern_ids.empty() || plan.pattern_ids.size() > limits.maximum_scan_patterns) {
                return false;
            }
            std::unordered_set<std::string_view> unique_ids;
            unique_ids.reserve(plan.pattern_ids.size());
            return std::ranges::all_of(plan.pattern_ids, [&](const std::string &pattern_id) {
                return !pattern_id.empty() && pattern_id.size() <= limits.maximum_string_bytes &&
                       unique_ids.insert(pattern_id).second;
            });
        }

    } // namespace

    std::expected<void, ProviderDispatchError> WindowsAgentProviderRouter::bind(std::string route,
                                                                                IWindowsAgentProvider &provider) {
        if (route.empty()) {
            return std::unexpected(
                provider_error(ProviderDispatchErrorCode::invalid_request, "provider route must not be empty"));
        }
        if (find(route) != nullptr) {
            return std::unexpected(
                provider_error(ProviderDispatchErrorCode::duplicate_route, "provider route is already bound"));
        }
        bindings_.push_back(Binding {.route = std::move(route), .provider = &provider});
        return {};
    }

    IWindowsAgentProvider *WindowsAgentProviderRouter::find(const std::string_view route) const noexcept {
        const auto found =
            std::ranges::find_if(bindings_, [route](const Binding &binding) { return binding.route == route; });
        return found == bindings_.end() ? nullptr : found->provider;
    }

    std::expected<WorkResultMessage, ProviderDispatchError>
    WindowsAgentProviderRouter::dispatch(const WorkLeaseMessage &work, const ProtocolLimits &limits) const {
        auto *provider = find(work.route);
        if (provider == nullptr) {
            return std::unexpected(provider_error(ProviderDispatchErrorCode::unknown_route, "work route is not bound"));
        }
        if (work.session.empty() || work.peer.empty() || work.session_fence == 0 || work.work_id.empty() ||
            work.attempt_id.empty() || work.work_fence == 0 || work.generation == 0 ||
            work.facts.size() > limits.maximum_fact_requests || work.scans.size() > limits.maximum_scan_requests ||
            (work.facts.empty() && work.scans.empty())) {
            return std::unexpected(
                provider_error(ProviderDispatchErrorCode::invalid_request, "work envelope is invalid"));
        }

        std::unordered_set<std::string> request_ids;
        request_ids.reserve(work.facts.size() + work.scans.size());
        for (const auto &request : work.facts) {
            if (request.request_id.empty() || !request_ids.insert(request.request_id.value).second ||
                !request.subject.valid() || request.subject.peer != work.peer || request.route.provider != work.route ||
                request.route.fact.empty() || request.expected_schema.empty()) {
                return std::unexpected(provider_error(ProviderDispatchErrorCode::invalid_request,
                                                      "fact request is not bound to the work route and subject"));
            }
        }
        for (const auto &request : work.scans) {
            if (request.request_id.empty() || !request_ids.insert(request.request_id.value).second ||
                !request.subject.valid() || request.subject.peer != work.peer || request.space.kind.empty() ||
                request.space.identity.empty() || request.space.subject_generation == 0 ||
                request.plan.plan_id.empty() || !scan_pattern_ids_valid(request.plan, limits) ||
                request.plan.maximum_bytes == 0 || request.plan.maximum_bytes > limits.maximum_blob_bytes ||
                request.plan.maximum_matches == 0 || request.plan.maximum_matches > limits.maximum_scan_matches ||
                request.plan.context_bytes_before > limits.maximum_blob_bytes ||
                request.plan.context_bytes_after > limits.maximum_blob_bytes ||
                (request.plan.result_mode != ScanResultMode::exact_complete &&
                 request.plan.result_mode != ScanResultMode::existential) ||
                request.space.size > std::numeric_limits<std::uint64_t>::max() - request.space.begin) {
                return std::unexpected(provider_error(ProviderDispatchErrorCode::invalid_request,
                                                      "scan request is outside its typed bounds"));
            }
        }

        std::vector<FactResponse> fact_results;
        if (!work.facts.empty()) {
            auto result = provider->resolve_facts(work.facts);
            if (!result) {
                return std::unexpected(std::move(result.error()));
            }
            fact_results = std::move(*result);
        }
        std::vector<ScanResponse> scan_results;
        if (!work.scans.empty()) {
            auto result = provider->resolve_scans(work.scans);
            if (!result) {
                return std::unexpected(std::move(result.error()));
            }
            scan_results = std::move(*result);
        }

        if (fact_results.size() != work.facts.size() || scan_results.size() != work.scans.size()) {
            return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                  "provider did not return exactly one result per request"));
        }

        std::unordered_map<std::string, FactResponse> facts_by_id;
        facts_by_id.reserve(fact_results.size());
        for (auto &response : fact_results) {
            if (response.request_id.empty() || !response_status_valid(response) ||
                !facts_by_id.emplace(response.request_id.value, std::move(response)).second) {
                return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                      "provider returned an invalid or duplicate fact result"));
            }
        }
        std::unordered_map<std::string, ScanResponse> scans_by_id;
        scans_by_id.reserve(scan_results.size());
        for (auto &response : scan_results) {
            if (response.request_id.empty() || !scan_status_valid(response) ||
                !scans_by_id.emplace(response.request_id.value, std::move(response)).second) {
                return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                      "provider returned an invalid or duplicate scan result"));
            }
        }

        WorkResultMessage output {
            .originating_session = work.session,
            .peer = work.peer,
            .originating_session_fence = work.session_fence,
            .work_id = work.work_id,
            .attempt_id = work.attempt_id,
            .work_fence = work.work_fence,
            .generation = work.generation,
            .facts = {},
            .scans = {},
        };
        output.facts.reserve(work.facts.size());
        for (const auto &request : work.facts) {
            auto found = facts_by_id.find(request.request_id.value);
            if (found == facts_by_id.end() || !same_subject(found->second.subject, request.subject)) {
                return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                      "fact result request or subject does not match"));
            }
            output.facts.push_back(std::move(found->second));
        }

        output.scans.reserve(work.scans.size());
        for (const auto &request : work.scans) {
            auto found = scans_by_id.find(request.request_id.value);
            if (found == scans_by_id.end() || !same_subject(found->second.subject, request.subject) ||
                found->second.mode != request.plan.result_mode ||
                found->second.matches.size() > request.plan.maximum_matches) {
                return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                      "scan result request, subject, or count does not match"));
            }
            std::unordered_set<std::string_view> allowed_pattern_ids;
            allowed_pattern_ids.reserve(request.plan.pattern_ids.size());
            for (const auto &pattern_id : request.plan.pattern_ids) { allowed_pattern_ids.insert(pattern_id); }
            for (const auto &match : found->second.matches) {
                if (!allowed_pattern_ids.contains(match.pattern_id) || match.scan_space_id != request.space.identity ||
                    match.permission_snapshot != request.space.permissions || match.label != request.space.label ||
                    match.subject_generation != request.space.subject_generation || match.offset > request.space.size ||
                    match.length > request.space.size - match.offset ||
                    match.offset > std::numeric_limits<std::uint64_t>::max() - request.space.begin ||
                    match.absolute_address != request.space.begin + match.offset ||
                    match.matched_bytes.size() != match.length ||
                    match.before_bytes.size() > request.plan.context_bytes_before ||
                    match.after_bytes.size() > request.plan.context_bytes_after ||
                    match.before_bytes.size() > match.offset ||
                    match.after_bytes.size() > request.space.size - match.offset - match.length ||
                    match.matched_bytes.size() > limits.maximum_blob_bytes ||
                    match.before_bytes.size() > limits.maximum_blob_bytes - match.matched_bytes.size() ||
                    match.after_bytes.size() >
                        limits.maximum_blob_bytes - match.matched_bytes.size() - match.before_bytes.size()) {
                    return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                          "scan result metadata is outside the authenticated request"));
                }
            }
            std::ranges::sort(found->second.matches, [](const ScanMatch &left, const ScanMatch &right) {
                if (left.offset != right.offset) {
                    return left.offset < right.offset;
                }
                if (left.pattern_id != right.pattern_id) {
                    return left.pattern_id < right.pattern_id;
                }
                return left.length < right.length;
            });
            output.scans.push_back(std::move(found->second));
        }
        return output;
    }

    std::expected<void, ProviderDispatchError>
    WindowsAgentProviderRouter::cancel(const CancelWorkMessage &message) const {
        auto *provider = find(message.route);
        if (provider == nullptr) {
            return std::unexpected(
                provider_error(ProviderDispatchErrorCode::unknown_route, "cancel route is not bound"));
        }
        if (message.session.empty() || message.peer.empty() || message.session_fence == 0 || message.work_id.empty() ||
            message.attempt_id.empty() || message.work_fence == 0) {
            return std::unexpected(
                provider_error(ProviderDispatchErrorCode::invalid_request, "cancel envelope is invalid"));
        }
        provider->cancel(message.requests);
        return {};
    }

    WindowsProviderSpoolAdapter::WindowsProviderSpoolAdapter(const WindowsAgentProviderRouter &router,
                                                             SqliteAgentSpool &spool) noexcept:
        router_ {&router}, spool_ {&spool} {}

    std::expected<std::uint64_t, ProviderDispatchError>
    WindowsProviderSpoolAdapter::dispatch_and_spool(const WorkLeaseMessage &work, const ProtocolLimits &limits) const {
        if (router_ == nullptr || spool_ == nullptr) {
            return std::unexpected(
                provider_error(ProviderDispatchErrorCode::provider_failure, "provider spool adapter is not bound"));
        }
        auto result = router_->dispatch(work, limits);
        if (!result) {
            return std::unexpected(std::move(result.error()));
        }
        auto sequence = spool_->enqueue(DurableAgentBody {std::move(*result)});
        if (!sequence) {
            return std::unexpected(provider_error(sequence.error().code == ProtocolErrorCode::backpressured ?
                                                      ProviderDispatchErrorCode::provider_failure :
                                                      ProviderDispatchErrorCode::provider_violation,
                                                  "typed provider result could not enter the durable spool"));
        }
        return *sequence;
    }

    std::expected<SpoolPublication, ProviderDispatchError>
    WindowsProviderSpoolAdapter::enumerate_and_spool(const SnapshotEnumerationRequest &request,
                                                     IWindowsSubjectEnumerator &enumerator,
                                                     const ProtocolLimits &limits) const {
        if (spool_ == nullptr || request.session.empty() || request.peer.empty() || request.session_fence == 0 ||
            request.snapshot_id.empty() || request.subject_schema.empty() || request.generation == 0 ||
            request.chunk_items == 0 || request.chunk_items > limits.maximum_snapshot_items) {
            return std::unexpected(
                provider_error(ProviderDispatchErrorCode::invalid_request, "snapshot enumeration request is invalid"));
        }
        auto subjects = enumerator.enumerate(request);
        if (!subjects) {
            return std::unexpected(std::move(subjects.error()));
        }
        if (subjects->size() > limits.maximum_snapshot_items) {
            return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                  "snapshot enumeration exceeds the item limit"));
        }

        std::vector<std::pair<std::string, SubjectKey>> canonical;
        canonical.reserve(subjects->size());
        std::unordered_set<std::string> identities;
        std::size_t canonical_bytes {};
        const auto expected_parent =
            request.parent.has_value() ? canonical_subject_key(*request.parent) : std::string {};
        for (auto &subject : *subjects) {
            const auto identity = canonical_subject_key(subject);
            const auto parent = subject.parent == nullptr ? std::string {} : canonical_subject_key(*subject.parent);
            if (identity.empty() || subject.peer != request.peer || subject.descriptor != request.subject_schema ||
                parent != expected_parent || !identities.insert(identity).second ||
                identity.size() > limits.maximum_snapshot_bytes - canonical_bytes) {
                return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                      "snapshot enumerator returned invalid or duplicate subjects"));
            }
            canonical_bytes += identity.size();
            canonical.emplace_back(identity, std::move(subject));
        }
        std::ranges::sort(canonical, {}, &std::pair<std::string, SubjectKey>::first);
        subjects->clear();
        subjects->reserve(canonical.size());
        for (auto &item : canonical) { subjects->push_back(std::move(item.second)); }
        auto digest = authoritative_snapshot_digest(*subjects, limits);
        if (!digest) {
            return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                  "snapshot enumeration cannot be canonicalized"));
        }

        SpoolPublication publication;
        const auto append = [this, &publication](DurableAgentBody body) -> std::expected<void, ProviderDispatchError> {
            auto sequence = spool_->enqueue(body);
            if (!sequence) {
                return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_failure,
                                                      "snapshot message could not enter the durable spool"));
            }
            publication.sequences.push_back(*sequence);
            return {};
        };
        if (auto queued = append(AuthoritativeSnapshotBegin {
                .session = request.session,
                .peer = request.peer,
                .session_fence = request.session_fence,
                .snapshot_id = request.snapshot_id,
                .parent = request.parent,
                .subject_schema = request.subject_schema,
                .generation = request.generation,
                .expected_count = subjects->size(),
                .expected_digest = *digest,
            });
            !queued) {
            return std::unexpected(std::move(queued.error()));
        }
        std::uint32_t chunk_index {};
        for (std::size_t offset = 0; offset < subjects->size(); offset += request.chunk_items) {
            const auto count = std::min(request.chunk_items, subjects->size() - offset);
            std::vector<SubjectKey> chunk(subjects->begin() + static_cast<std::ptrdiff_t>(offset),
                                          subjects->begin() + static_cast<std::ptrdiff_t>(offset + count));
            if (auto queued = append(AuthoritativeSnapshotChunk {
                    .session = request.session,
                    .peer = request.peer,
                    .session_fence = request.session_fence,
                    .snapshot_id = request.snapshot_id,
                    .generation = request.generation,
                    .chunk_index = chunk_index++,
                    .subjects = std::move(chunk),
                });
                !queued) {
                return std::unexpected(std::move(queued.error()));
            }
        }
        if (auto queued = append(AuthoritativeSnapshotCommit {
                .session = request.session,
                .peer = request.peer,
                .session_fence = request.session_fence,
                .snapshot_id = request.snapshot_id,
                .generation = request.generation,
                .item_count = subjects->size(),
                .canonical_digest = *digest,
            });
            !queued) {
            return std::unexpected(std::move(queued.error()));
        }
        return publication;
    }

} // namespace rule_engine::python::protocol_v2
