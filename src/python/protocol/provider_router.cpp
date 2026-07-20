#include "rule_engine/python/protocol/provider_router.hpp"

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
            if (response.truncated) {
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
                request.plan.plan_id.empty() || request.plan.maximum_bytes > limits.maximum_blob_bytes ||
                request.plan.maximum_matches > limits.maximum_scan_matches ||
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
                found->second.matches.size() > request.plan.maximum_matches) {
                return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                      "scan result request, subject, or count does not match"));
            }
            for (const auto &match : found->second.matches) {
                if (match.offset > request.space.size || match.length > request.space.size - match.offset) {
                    return std::unexpected(provider_error(ProviderDispatchErrorCode::provider_violation,
                                                          "scan result is outside the requested space"));
                }
            }
            std::ranges::sort(found->second.matches, [](const ScanMatch &left, const ScanMatch &right) {
                if (left.offset != right.offset) {
                    return left.offset < right.offset;
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

} // namespace rule_engine::python::protocol_v2
