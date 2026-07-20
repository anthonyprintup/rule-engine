#include "rule_engine/python/events/reference_runtime.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <functional>
#include <limits>
#include <ranges>
#include <type_traits>
#include <utility>

namespace rule_engine::python::events {
    namespace {

        Error make_error(const ErrorCode code, std::string message) {
            return Error {.code = code, .message = std::move(message)};
        }

        void append_token(std::string &output, const std::string_view token) {
            std::array<char, 32> length {};
            const auto [end, status] = std::to_chars(length.data(), length.data() + length.size(), token.size());
            if (status == std::errc {}) {
                output.append(length.data(), end);
            }
            output.push_back(':');
            output.append(token);
            output.push_back(';');
        }

        std::string bytes_as_hex(const std::vector<std::byte> &bytes) {
            constexpr std::string_view digits = "0123456789abcdef";
            std::string result;
            result.reserve(bytes.size() * 2U);
            for (const auto value : bytes) {
                const auto number = std::to_integer<unsigned int>(value);
                result.push_back(digits[(number >> 4U) & 0xFU]);
                result.push_back(digits[number & 0xFU]);
            }
            return result;
        }

        bool label_is_canonical(const DataLabel &label) {
            if (std::ranges::any_of(label.categories, [](const std::string &category) { return category.empty(); })) {
                return false;
            }
            return std::ranges::is_sorted(label.categories) &&
                   std::ranges::adjacent_find(label.categories) == label.categories.end();
        }

        std::optional<PayloadShape> payload_shape(const FrozenValue &value) {
            if (!value.value.valid()) {
                return std::nullopt;
            }
            return std::visit(
                []<typename Value>(const Value &) -> PayloadShape {
                    using ValueType = std::remove_cvref_t<Value>;
                    if constexpr (std::is_same_v<ValueType, std::monostate>) {
                        return PayloadShape::null_value;
                    } else if constexpr (std::is_same_v<ValueType, bool>) {
                        return PayloadShape::boolean;
                    } else if constexpr (std::is_same_v<ValueType, IntegerValue>) {
                        return PayloadShape::integer;
                    } else if constexpr (std::is_same_v<ValueType, double>) {
                        return PayloadShape::floating_point;
                    } else if constexpr (std::is_same_v<ValueType, UnicodeValue>) {
                        return PayloadShape::unicode;
                    } else if constexpr (std::is_same_v<ValueType, BytesValue>) {
                        return PayloadShape::bytes;
                    } else if constexpr (std::is_same_v<ValueType, EnumValue>) {
                        return PayloadShape::enumeration;
                    } else if constexpr (std::is_same_v<ValueType, FactList>) {
                        return PayloadShape::list;
                    } else if constexpr (std::is_same_v<ValueType, FactMap>) {
                        return PayloadShape::map;
                    } else {
                        return PayloadShape::record;
                    }
                },
                value.value.node->data);
        }

        bool labels_equal(const DataLabel &left, const DataLabel &right) { return left == right; }

        bool frozen_values_equal(const FrozenValue &left, const FrozenValue &right) {
            return left.canonical_digest == right.canonical_digest && labels_equal(left.label, right.label);
        }

        bool frozen_value_matches_schema(const FrozenValue &value, const SchemaId &schema) {
            if (!value.value.valid()) {
                return false;
            }
            if (const auto *record = std::get_if<FactRecord>(&value.value.node->data)) {
                return record->schema == schema;
            }
            if (const auto *enumeration = std::get_if<EnumValue>(&value.value.node->data)) {
                return enumeration->schema == schema;
            }
            return true;
        }

        bool subjects_equal(const std::optional<SubjectKey> &left, const std::optional<SubjectKey> &right) {
            if (left.has_value() != right.has_value()) {
                return false;
            }
            if (!left) {
                return true;
            }
            return canonical_subject_key(*left) == canonical_subject_key(*right);
        }

        bool events_equivalent(const EventEnvelope &left, const EventEnvelope &right) {
            return left.id == right.id && left.schema == right.schema && left.tenant == right.tenant &&
                   left.peer == right.peer && subjects_equal(left.subject, right.subject) &&
                   left.producer_unix_ms == right.producer_unix_ms && left.ingest_unix_ms == right.ingest_unix_ms &&
                   left.label == right.label && left.causation == right.causation &&
                   frozen_values_equal(left.payload, right.payload);
        }

        bool schemas_equal(const EventSchema &left, const EventSchema &right) {
            return left.id == right.id && left.family == right.family && left.payload_shape == right.payload_shape &&
                   left.payload_record_schema == right.payload_record_schema &&
                   left.label_ceiling == right.label_ceiling && left.subject_required == right.subject_required;
        }

        std::string history_fingerprint(const HistoryPlan &plan) {
            std::string output;
            append_token(output, "history-plan-v1");
            append_token(output, plan.tenant.value);
            append_token(output, plan.peer ? plan.peer->value : "*");
            append_token(output, plan.fleet_history ? "fleet" : "peer");

            std::vector<std::string> schemas;
            schemas.reserve(plan.schemas.size());
            for (const auto &schema : plan.schemas) { schemas.push_back(schema.value); }
            std::ranges::sort(schemas);
            for (const auto &schema : schemas) { append_token(output, schema); }
            append_token(output, plan.time_basis == HistoryTimeBasis::ingest ? "ingest" : "producer");
            append_token(output, std::to_string(plan.begin_unix_ms));
            append_token(output, std::to_string(plan.end_unix_ms));
            append_token(output, std::to_string(plan.limit));
            append_token(output, std::to_string(plan.page_rows));
            append_token(output, std::to_string(static_cast<std::uint32_t>(plan.result_ceiling.classification)));
            for (const auto &category : plan.result_ceiling.categories) { append_token(output, category); }
            return output;
        }

        std::uint64_t selected_timestamp(const EventEnvelope &event, const HistoryTimeBasis basis) {
            return basis == HistoryTimeBasis::ingest ? event.ingest_unix_ms : event.producer_unix_ms;
        }

        bool contains_schema(const std::vector<SchemaId> &schemas, const SchemaId &schema) {
            return std::ranges::find(schemas, schema) != schemas.end();
        }

        std::string namespace_key(const TenantId &tenant, const ExecutableId &owner,
                                  const std::string_view namespace_id) {
            std::string output;
            append_token(output, "state-namespace-v1");
            append_token(output, tenant.value);
            append_token(output, owner.value);
            append_token(output, namespace_id);
            return output;
        }

        std::string namespace_key(const StateAddress &address) {
            return namespace_key(address.tenant, address.owner, address.namespace_id);
        }

        std::string address_key(const StateAddress &address) {
            std::string output = namespace_key(address);
            append_token(output, address.schema.value);
            append_token(output, address.peer ? address.peer->value : "");
            append_token(output, address.scope);
            append_token(output, address.key);
            return output;
        }

        bool executable_in(const std::vector<ExecutableId> &values, const ExecutableId &needle) {
            return std::ranges::find(values, needle) != values.end();
        }

        std::expected<const StateNamespace *, Error>
        state_namespace_for(const StateAddress &address,
                            const std::map<std::string, StateNamespace, std::less<>> &namespaces) {
            const auto found = namespaces.find(namespace_key(address));
            if (found == namespaces.end()) {
                return std::unexpected(make_error(ErrorCode::not_found, "state namespace is not registered"));
            }
            if (found->second.schema != address.schema) {
                return std::unexpected(make_error(ErrorCode::schema_mismatch, "state address schema does not match"));
            }
            return &found->second;
        }

        bool may_read_state(const StateAccess &access, const StateNamespace &state_namespace) {
            return access.tenant == state_namespace.tenant &&
                   (access.actor == state_namespace.owner ||
                    executable_in(state_namespace.shared_readers, access.actor) ||
                    executable_in(state_namespace.shared_writers, access.actor));
        }

        bool may_write_state(const StateAccess &access, const StateNamespace &state_namespace) {
            return access.tenant == state_namespace.tenant &&
                   (access.actor == state_namespace.owner ||
                    executable_in(state_namespace.shared_writers, access.actor));
        }

        bool canonical_integer(const std::string_view value) {
            if (value.empty()) {
                return false;
            }
            std::size_t begin {};
            if (value.front() == '-') {
                if (value.size() == 1 || value == "-0") {
                    return false;
                }
                begin = 1;
            }
            if (value[begin] == '0' && value.size() - begin != 1) {
                return false;
            }
            return std::ranges::all_of(value.substr(begin),
                                       [](const char character) { return character >= '0' && character <= '9'; });
        }

        std::expected<void, Error> append_correlation_key(std::string &output, const CorrelationKey &key,
                                                          const EventRuntimeLimits &limits, const std::uint32_t depth) {
            if (depth > limits.maximum_group_key_depth) {
                return std::unexpected(
                    make_error(ErrorCode::invalid_bounds, "correlation group key exceeds the depth limit"));
            }

            const auto result = std::visit(
                [&output, &limits, depth]<typename Value>(const Value &value) -> std::expected<void, Error> {
                    using ValueType = std::remove_cvref_t<Value>;
                    if constexpr (std::is_same_v<ValueType, std::monostate>) {
                        append_token(output, "none");
                    } else if constexpr (std::is_same_v<ValueType, bool>) {
                        append_token(output, value ? "bool:1" : "bool:0");
                    } else if constexpr (std::is_same_v<ValueType, IntegerValue>) {
                        if (!canonical_integer(value.decimal)) {
                            return std::unexpected(
                                make_error(ErrorCode::invalid_identity, "group-key integer is not canonical"));
                        }
                        append_token(output, "int:" + value.decimal);
                    } else if constexpr (std::is_same_v<ValueType, UnicodeValue>) {
                        append_token(output, "str:" + value.utf8);
                    } else if constexpr (std::is_same_v<ValueType, BytesValue>) {
                        append_token(output, "bytes:" + bytes_as_hex(value.bytes));
                    } else if constexpr (std::is_same_v<ValueType, EnumValue>) {
                        if (value.schema.empty() || value.member.empty()) {
                            return std::unexpected(
                                make_error(ErrorCode::invalid_identity, "group-key enum is incomplete"));
                        }
                        append_token(output, "enum:" + value.schema.value);
                        append_token(output, value.member);
                    } else {
                        append_token(output, "tuple");
                        append_token(output, std::to_string(value.size()));
                        for (const auto &item : value) {
                            auto appended = append_correlation_key(output, item, limits, depth + 1U);
                            if (!appended) {
                                return appended;
                            }
                        }
                        append_token(output, "tuple-end");
                    }

                    if (output.size() > limits.maximum_group_key_bytes) {
                        return std::unexpected(
                            make_error(ErrorCode::invalid_bounds, "correlation group key exceeds the byte limit"));
                    }
                    return {};
                },
                key.value);
            return result;
        }

        bool purge_matches_event(const PurgeRequest &request, const EventEnvelope &event) {
            return event.tenant == request.tenant && (!request.peer || event.peer == *request.peer) &&
                   event.ingest_unix_ms >= request.begin_ingest_unix_ms &&
                   event.ingest_unix_ms < request.end_ingest_unix_ms;
        }

        bool purge_matches_state(const PurgeRequest &request, const StateSnapshotCell &cell) {
            return cell.address.tenant == request.tenant &&
                   (!request.peer || (cell.address.peer && *cell.address.peer == *request.peer)) &&
                   cell.modified_ingest_unix_ms >= request.begin_ingest_unix_ms &&
                   cell.modified_ingest_unix_ms < request.end_ingest_unix_ms;
        }

    } // namespace

    std::expected<StateRead, Error> StateOverlay::read(const StateAddress &address) {
        const auto state_namespace = state_namespace_for(address, namespaces_);
        if (!state_namespace) {
            return std::unexpected(state_namespace.error());
        }
        if (!may_read_state(access_, **state_namespace)) {
            return std::unexpected(make_error(ErrorCode::unauthorized, "state read is outside the owner namespace"));
        }

        const auto key = address_key(address);
        for (auto mutation = staged_.rbegin(); mutation != staged_.rend(); ++mutation) {
            if (address_key(mutation->address) == key) {
                return StateRead {.value = mutation->value, .version = mutation->expected_version};
            }
        }

        const auto found = snapshot_.find(key);
        const auto version = found == snapshot_.end() ? 0 : found->second.version;
        read_versions_.insert_or_assign(key, version);
        return StateRead {.value = found == snapshot_.end() ? std::nullopt : found->second.value, .version = version};
    }

    std::expected<void, Error> StateOverlay::write(const StateAddress &address, FrozenValue value) {
        const auto state_namespace = state_namespace_for(address, namespaces_);
        if (!state_namespace) {
            return std::unexpected(state_namespace.error());
        }
        if (!may_write_state(access_, **state_namespace)) {
            return std::unexpected(make_error(ErrorCode::unauthorized, "state write is outside the owner namespace"));
        }
        if (!value.value.valid() || value.canonical_digest.empty()) {
            return std::unexpected(make_error(ErrorCode::schema_mismatch, "state value is not frozen"));
        }
        if (!frozen_value_matches_schema(value, (*state_namespace)->schema)) {
            return std::unexpected(make_error(ErrorCode::schema_mismatch, "state value schema does not match"));
        }
        if (!label_is_canonical(value.label) || !may_flow_to(value.label, (*state_namespace)->label_ceiling)) {
            return std::unexpected(make_error(ErrorCode::invalid_label, "state value exceeds its namespace ceiling"));
        }

        const auto key = address_key(address);
        const auto snapshot = snapshot_.find(key);
        const auto expected = read_versions_.contains(key) ?
                                  read_versions_.at(key) :
                                  (snapshot == snapshot_.end() ? 0 : snapshot->second.version);
        read_versions_.insert_or_assign(key, expected);

        const auto existing = std::ranges::find_if(
            staged_, [&key](const StateStagedMutation &mutation) { return address_key(mutation.address) == key; });
        if (existing != staged_.end()) {
            existing->value = std::move(value);
            return {};
        }
        staged_.push_back(StateStagedMutation {
            .address = address,
            .expected_version = expected,
            .value = std::move(value),
        });
        return {};
    }

    std::expected<void, Error> StateOverlay::erase(const StateAddress &address) {
        const auto state_namespace = state_namespace_for(address, namespaces_);
        if (!state_namespace) {
            return std::unexpected(state_namespace.error());
        }
        if (!may_write_state(access_, **state_namespace)) {
            return std::unexpected(make_error(ErrorCode::unauthorized, "state erase is outside the owner namespace"));
        }

        const auto key = address_key(address);
        const auto snapshot = snapshot_.find(key);
        const auto expected = read_versions_.contains(key) ?
                                  read_versions_.at(key) :
                                  (snapshot == snapshot_.end() ? 0 : snapshot->second.version);
        read_versions_.insert_or_assign(key, expected);

        const auto existing = std::ranges::find_if(
            staged_, [&key](const StateStagedMutation &mutation) { return address_key(mutation.address) == key; });
        if (existing != staged_.end()) {
            existing->value.reset();
            return {};
        }
        staged_.push_back(StateStagedMutation {
            .address = address,
            .expected_version = expected,
            .value = std::nullopt,
        });
        return {};
    }

    std::expected<void, Error> CapturedInputs::capture(std::string key, FrozenValue value) {
        if (sealed_) {
            return std::unexpected(make_error(ErrorCode::replay_diverged, "captured-input bundle is sealed"));
        }
        if (key.empty() || !value.value.valid() || value.canonical_digest.empty() || !label_is_canonical(value.label)) {
            return std::unexpected(make_error(ErrorCode::invalid_identity, "captured input is incomplete"));
        }
        const auto existing = values_.find(key);
        if (existing != values_.end()) {
            if (frozen_values_equal(existing->second, value)) {
                return {};
            }
            return std::unexpected(make_error(ErrorCode::duplicate_conflict, "captured-input key changed its value"));
        }
        values_.emplace(std::move(key), std::move(value));
        return {};
    }

    std::expected<const FrozenValue *, Error> CapturedInputs::resolve(const std::string_view key) const {
        const auto found = values_.find(key);
        if (found != values_.end()) {
            return &found->second;
        }
        if (sealed_) {
            return std::unexpected(
                make_error(ErrorCode::replay_diverged, "replay reached an uncaptured external input"));
        }
        return std::unexpected(make_error(ErrorCode::not_found, "external input has not been captured"));
    }

    std::expected<void, Error> SharedRetryBudget::charge(const std::uint64_t units) {
        if (consumed > limit || units > limit - consumed) {
            return std::unexpected(make_error(ErrorCode::budget_exhausted, "shared retry budget is exhausted"));
        }
        consumed += units;
        return {};
    }

    std::expected<std::uint32_t, Error> MvccRetryController::begin_attempt() {
        if (finished_ || attempt_active_ || attempts_started_ >= maximum_attempts) {
            return std::unexpected(make_error(ErrorCode::replay_exhausted, "MVCC replay attempts are exhausted"));
        }
        ++attempts_started_;
        attempt_active_ = true;
        return attempts_started_;
    }

    ConflictDisposition MvccRetryController::state_conflict() {
        if (!attempt_active_) {
            finished_ = true;
            return ConflictDisposition::exhausted;
        }
        attempt_active_ = false;
        inputs.seal();
        if (attempts_started_ < maximum_attempts) {
            return ConflictDisposition::retry;
        }
        finished_ = true;
        return ConflictDisposition::exhausted;
    }

    void MvccRetryController::complete() noexcept {
        attempt_active_ = false;
        finished_ = true;
    }

    std::expected<std::string, Error> canonical_group_key(const CorrelationKey &key, const EventRuntimeLimits &limits) {
        if (limits.maximum_group_key_bytes == 0 || limits.maximum_group_key_depth == 0) {
            return std::unexpected(make_error(ErrorCode::invalid_bounds, "group-key limits must be positive"));
        }
        std::string output;
        append_token(output, "correlation-key-v1");
        auto appended = append_correlation_key(output, key, limits, 1);
        if (!appended) {
            return std::unexpected(appended.error());
        }
        return output;
    }

    std::expected<void, Error> validate_correlation_dag(const std::vector<CorrelationEdge> &edges) {
        std::map<std::string, std::set<std::string, std::less<>>, std::less<>> adjacency;
        std::map<std::string, std::size_t, std::less<>> indegree;
        for (const auto &edge : edges) {
            if (edge.source.empty() || edge.target.empty()) {
                return std::unexpected(make_error(ErrorCode::invalid_identity, "correlation edge is incomplete"));
            }
            adjacency.try_emplace(edge.source.value);
            adjacency.try_emplace(edge.target.value);
            indegree.try_emplace(edge.source.value, 0);
            indegree.try_emplace(edge.target.value, 0);
            if (adjacency[edge.source.value].insert(edge.target.value).second) {
                ++indegree[edge.target.value];
            }
        }

        std::set<std::string, std::less<>> ready;
        for (const auto &[node, degree] : indegree) {
            if (degree == 0) {
                ready.insert(node);
            }
        }

        std::size_t visited {};
        while (!ready.empty()) {
            const auto node = *ready.begin();
            ready.erase(ready.begin());
            ++visited;
            for (const auto &target : adjacency[node]) {
                auto &degree = indegree[target];
                --degree;
                if (degree == 0) {
                    ready.insert(target);
                }
            }
        }
        if (visited != indegree.size()) {
            return std::unexpected(make_error(ErrorCode::causation_cycle, "correlation event graph contains a cycle"));
        }
        return {};
    }

    std::expected<void, Error> InMemoryReferenceRuntime::register_event_schema(EventSchema schema) {
        if (schema.id.empty() || !label_is_canonical(schema.label_ceiling)) {
            return std::unexpected(make_error(ErrorCode::invalid_schema, "event schema is incomplete"));
        }
        if (schema.payload_shape != PayloadShape::record && schema.payload_record_schema) {
            return std::unexpected(
                make_error(ErrorCode::invalid_schema, "only record payloads may name a record schema"));
        }

        std::scoped_lock lock {mutex_};
        const auto existing = event_schemas_.find(schema.id.value);
        if (existing != event_schemas_.end()) {
            if (schemas_equal(existing->second, schema)) {
                return {};
            }
            return std::unexpected(
                make_error(ErrorCode::duplicate_conflict, "event schema ID already has another descriptor"));
        }
        event_schemas_.emplace(schema.id.value, std::move(schema));
        return {};
    }

    std::expected<void, Error> InMemoryReferenceRuntime::validate_event(const EventEnvelope &event) const {
        if (event.id.empty() || event.schema.empty() || event.tenant.empty() || event.peer.empty()) {
            return std::unexpected(make_error(ErrorCode::invalid_identity, "event identity is incomplete"));
        }
        if (event.producer_unix_ms == 0 || event.ingest_unix_ms == 0) {
            return std::unexpected(make_error(ErrorCode::invalid_bounds, "event timestamps must be non-zero"));
        }
        if (!event.payload.value.valid() || event.payload.canonical_digest.empty()) {
            return std::unexpected(make_error(ErrorCode::schema_mismatch, "event payload is not frozen"));
        }
        if (!label_is_canonical(event.label) || !label_is_canonical(event.payload.label) ||
            !may_flow_to(event.payload.label, event.label)) {
            return std::unexpected(make_error(ErrorCode::invalid_label, "event label does not dominate its payload"));
        }
        if (event.subject && (!event.subject->valid() || event.subject->peer != event.peer)) {
            return std::unexpected(make_error(ErrorCode::invalid_identity, "event subject is invalid for its peer"));
        }

        const auto schema = event_schemas_.find(event.schema.value);
        if (schema == event_schemas_.end()) {
            return std::unexpected(make_error(ErrorCode::invalid_schema, "event schema is not registered"));
        }
        if (schema->second.subject_required && !event.subject) {
            return std::unexpected(make_error(ErrorCode::schema_mismatch, "event schema requires a subject"));
        }
        if (!may_flow_to(event.label, schema->second.label_ceiling)) {
            return std::unexpected(make_error(ErrorCode::invalid_label, "event exceeds its schema label ceiling"));
        }
        const auto actual_shape = payload_shape(event.payload);
        if (!actual_shape || *actual_shape != schema->second.payload_shape) {
            return std::unexpected(make_error(ErrorCode::schema_mismatch, "event payload shape does not match"));
        }
        if (schema->second.payload_record_schema) {
            const auto *record = std::get_if<FactRecord>(&event.payload.value.node->data);
            if (record == nullptr || record->schema != *schema->second.payload_record_schema) {
                return std::unexpected(make_error(ErrorCode::schema_mismatch, "event record schema does not match"));
            }
        }
        return {};
    }

    std::expected<EventAdmission, Error> InMemoryReferenceRuntime::append_event(EventEnvelope event) {
        std::scoped_lock lock {mutex_};
        auto valid = validate_event(event);
        if (!valid) {
            return std::unexpected(valid.error());
        }
        if (event_tombstones_.contains(event.id.value)) {
            return std::unexpected(
                make_error(ErrorCode::duplicate_conflict, "purged event ID is protected by a tombstone"));
        }

        const auto duplicate = event_index_.find(event.id.value);
        if (duplicate != event_index_.end()) {
            const auto &stored = events_[duplicate->second];
            if (!events_equivalent(stored.envelope, event)) {
                return std::unexpected(
                    make_error(ErrorCode::duplicate_conflict, "event ID already has different content"));
            }
            return EventAdmission {.ingest_position = stored.ingest_position,
                                   .duplicate = true,
                                   .causation_depth = stored.causation_depth};
        }

        std::uint32_t depth {};
        if (event.causation) {
            if (*event.causation == event.id) {
                return std::unexpected(make_error(ErrorCode::causation_cycle, "event causes itself"));
            }
            const auto parent = event_index_.find(event.causation->value);
            if (parent == event_index_.end()) {
                return std::unexpected(make_error(ErrorCode::not_found, "causation parent is not available"));
            }
            const auto &parent_event = events_[parent->second];
            if (parent_event.envelope.tenant != event.tenant) {
                return std::unexpected(make_error(ErrorCode::unauthorized, "causation cannot cross tenants"));
            }
            depth = parent_event.causation_depth + 1U;
            if (depth > limits_.maximum_causation_depth) {
                return std::unexpected(
                    make_error(ErrorCode::causation_depth_exceeded, "event causation depth is exhausted"));
            }
        }

        const auto position = next_ingest_position_++;
        const auto index = events_.size();
        event_index_.emplace(event.id.value, index);
        events_.push_back(StoredEvent {
            .envelope = std::move(event),
            .ingest_position = position,
            .causation_depth = depth,
        });
        return EventAdmission {.ingest_position = position, .duplicate = false, .causation_depth = depth};
    }

    std::expected<HistoryPage, Error> InMemoryReferenceRuntime::query_history(const HistoryPlan &plan) const {
        if (plan.tenant.empty() || plan.schemas.empty() ||
            std::ranges::any_of(plan.schemas, [](const SchemaId &schema) { return schema.empty(); })) {
            return std::unexpected(make_error(ErrorCode::invalid_schema, "history type and tenant are required"));
        }
        if ((!plan.peer && !plan.fleet_history) || plan.begin_unix_ms >= plan.end_unix_ms || plan.limit == 0 ||
            plan.page_rows == 0 || plan.page_rows > plan.limit || plan.limit > limits_.maximum_history_rows ||
            plan.page_rows > limits_.maximum_history_page_rows ||
            plan.end_unix_ms - plan.begin_unix_ms > limits_.maximum_history_span_ms ||
            !label_is_canonical(plan.result_ceiling)) {
            return std::unexpected(make_error(ErrorCode::invalid_bounds, "history query is not fully bounded"));
        }

        const auto fingerprint = history_fingerprint(plan);
        if (plan.after && (plan.after->plan_fingerprint != fingerprint || plan.after->snapshot_ingest_position == 0 ||
                           plan.after->event.empty() || plan.after->returned_rows >= plan.limit)) {
            return std::unexpected(make_error(ErrorCode::invalid_cursor, "history cursor does not match its plan"));
        }

        std::scoped_lock lock {mutex_};
        const auto snapshot_position = plan.after ? plan.after->snapshot_ingest_position : next_ingest_position_ - 1U;
        std::vector<const StoredEvent *> matches;
        for (const auto &stored : events_) {
            const auto &event = stored.envelope;
            const auto timestamp = selected_timestamp(event, plan.time_basis);
            if (stored.ingest_position > snapshot_position || event.tenant != plan.tenant ||
                (plan.peer && event.peer != *plan.peer) || !contains_schema(plan.schemas, event.schema) ||
                timestamp < plan.begin_unix_ms || timestamp >= plan.end_unix_ms) {
                continue;
            }
            if (!may_flow_to(event.label, plan.result_ceiling)) {
                return std::unexpected(
                    make_error(ErrorCode::invalid_label, "history result exceeds the query label ceiling"));
            }
            if (plan.after && (timestamp < plan.after->selected_timestamp ||
                               (timestamp == plan.after->selected_timestamp && event.id <= plan.after->event))) {
                continue;
            }
            matches.push_back(&stored);
        }

        std::ranges::sort(matches, [&plan](const StoredEvent *left, const StoredEvent *right) {
            const auto left_time = selected_timestamp(left->envelope, plan.time_basis);
            const auto right_time = selected_timestamp(right->envelope, plan.time_basis);
            return left_time < right_time || (left_time == right_time && left->envelope.id < right->envelope.id);
        });

        const auto already_returned = plan.after ? plan.after->returned_rows : 0U;
        const auto remaining_limit = plan.limit - already_returned;
        const auto page_count = std::min<std::size_t>({matches.size(), plan.page_rows, remaining_limit});
        HistoryPage page;
        page.events.reserve(page_count);
        for (std::size_t index = 0; index < page_count; ++index) { page.events.push_back(matches[index]->envelope); }

        if (page_count < matches.size() && page_count < remaining_limit && !page.events.empty()) {
            const auto &last = page.events.back();
            page.next = HistoryCursor {
                .plan_fingerprint = fingerprint,
                .snapshot_ingest_position = snapshot_position,
                .selected_timestamp = selected_timestamp(last, plan.time_basis),
                .event = last.id,
                .returned_rows = already_returned + static_cast<std::uint32_t>(page_count),
            };
        }
        return page;
    }

    std::string InMemoryReferenceRuntime::state_namespace_key(const StateNamespace &state_namespace) {
        return namespace_key(state_namespace.tenant, state_namespace.owner, state_namespace.namespace_id);
    }

    std::string InMemoryReferenceRuntime::state_address_key(const StateAddress &address) {
        return address_key(address);
    }

    std::expected<void, Error> InMemoryReferenceRuntime::register_state_namespace(StateNamespace state_namespace) {
        if (state_namespace.tenant.empty() || state_namespace.owner.empty() || state_namespace.namespace_id.empty() ||
            state_namespace.schema.empty() || !label_is_canonical(state_namespace.label_ceiling)) {
            return std::unexpected(make_error(ErrorCode::invalid_schema, "state namespace is incomplete"));
        }
        const auto key = state_namespace_key(state_namespace);
        std::scoped_lock lock {mutex_};
        const auto existing = state_namespaces_.find(key);
        if (existing != state_namespaces_.end()) {
            if (existing->second.tenant == state_namespace.tenant && existing->second.owner == state_namespace.owner &&
                existing->second.namespace_id == state_namespace.namespace_id &&
                existing->second.schema == state_namespace.schema &&
                existing->second.label_ceiling == state_namespace.label_ceiling &&
                existing->second.shared_readers == state_namespace.shared_readers &&
                existing->second.shared_writers == state_namespace.shared_writers) {
                return {};
            }
            return std::unexpected(
                make_error(ErrorCode::duplicate_conflict, "state namespace already has another descriptor"));
        }
        state_namespaces_.emplace(key, std::move(state_namespace));
        return {};
    }

    std::expected<StateOverlay, Error> InMemoryReferenceRuntime::begin_state(const StateAccess access) const {
        if (access.tenant.empty() || access.actor.empty() || access.evaluation_ingest_unix_ms == 0) {
            return std::unexpected(make_error(ErrorCode::invalid_identity, "state access identity is incomplete"));
        }
        std::scoped_lock lock {mutex_};
        StateOverlay overlay;
        overlay.access_ = access;
        overlay.namespaces_ = state_namespaces_;
        overlay.snapshot_ = state_cells_;
        overlay.purge_epoch_ = purge_epoch_;
        return overlay;
    }

    std::expected<StateCommitReceipt, Error> InMemoryReferenceRuntime::commit_state(StateOverlay &overlay,
                                                                                    const bool commit) {
        if (!commit) {
            overlay.staged_.clear();
            overlay.read_versions_.clear();
            return StateCommitReceipt {.committed = false, .writes = 0, .highest_version = 0};
        }

        std::scoped_lock lock {mutex_};
        if (overlay.purge_epoch_ != purge_epoch_) {
            return std::unexpected(make_error(ErrorCode::state_conflict, "purge epoch changed during evaluation"));
        }
        for (const auto &[key, expected] : overlay.read_versions_) {
            const auto current = state_cells_.find(key);
            const auto actual = current == state_cells_.end() ? 0 : current->second.version;
            if (actual != expected) {
                return std::unexpected(make_error(ErrorCode::state_conflict, "state MVCC version changed"));
            }
        }
        for (const auto &mutation : overlay.staged_) {
            const auto state_namespace = state_namespaces_.find(namespace_key(mutation.address));
            if (state_namespace == state_namespaces_.end() ||
                state_namespace->second.schema != mutation.address.schema ||
                !may_write_state(overlay.access_, state_namespace->second)) {
                return std::unexpected(
                    make_error(ErrorCode::unauthorized, "state namespace changed or access was revoked"));
            }
            if (mutation.value && !may_flow_to(mutation.value->label, state_namespace->second.label_ceiling)) {
                return std::unexpected(make_error(ErrorCode::invalid_label, "state value exceeds current ceiling"));
            }
            if (mutation.value && !frozen_value_matches_schema(*mutation.value, state_namespace->second.schema)) {
                return std::unexpected(make_error(ErrorCode::schema_mismatch, "state value schema changed"));
            }
        }

        std::uint64_t highest_version {};
        for (const auto &mutation : overlay.staged_) {
            const auto key = state_address_key(mutation.address);
            const auto current = state_cells_.find(key);
            const auto current_version = current == state_cells_.end() ? 0 : current->second.version;
            const auto new_version = current_version + 1U;
            state_cells_.insert_or_assign(
                key, StateSnapshotCell {.address = mutation.address,
                                        .value = mutation.value,
                                        .version = new_version,
                                        .modified_ingest_unix_ms = overlay.access_.evaluation_ingest_unix_ms});
            highest_version = std::max(highest_version, new_version);
        }

        const auto writes = static_cast<std::uint32_t>(overlay.staged_.size());
        overlay.staged_.clear();
        overlay.read_versions_.clear();
        return StateCommitReceipt {.committed = true, .writes = writes, .highest_version = highest_version};
    }

    std::string InMemoryReferenceRuntime::group_key(const CorrelationGroupId &group) {
        std::string output;
        append_token(output, "correlation-group-v1");
        append_token(output, group.tenant.value);
        append_token(output, group.executable.value);
        append_token(output, group.binding.value);
        append_token(output, group.canonical_key);
        return output;
    }

    std::expected<CorrelationLease, Error> InMemoryReferenceRuntime::claim_group(const CorrelationGroupId &group) {
        if (group.tenant.empty() || group.executable.empty() || group.binding.empty() || group.canonical_key.empty()) {
            return std::unexpected(make_error(ErrorCode::invalid_identity, "correlation group is incomplete"));
        }
        std::scoped_lock lock {mutex_};
        auto &state = groups_[group_key(group)];
        if (state.active_token) {
            return std::unexpected(make_error(ErrorCode::group_busy, "correlation group is already claimed"));
        }
        const auto token = state.next_token++;
        state.active_token = token;
        return CorrelationLease {.group = group, .expected_cursor = state.cursor, .token = token};
    }

    std::expected<WindowAdmission, Error>
    InMemoryReferenceRuntime::admit_group_event(const CorrelationLease &lease, const EventEnvelope &event,
                                                const CorrelationTimePolicy &policy,
                                                const std::uint64_t server_now_unix_ms) {
        std::scoped_lock lock {mutex_};
        const auto found = groups_.find(group_key(lease.group));
        if (found == groups_.end() || !found->second.active_token || *found->second.active_token != lease.token ||
            found->second.cursor != lease.expected_cursor || event.tenant != lease.group.tenant ||
            !event_index_.contains(event.id.value)) {
            return std::unexpected(make_error(ErrorCode::stale_group_lease, "correlation group lease is stale"));
        }

        auto &state = found->second;
        if (policy.time_basis == HistoryTimeBasis::ingest) {
            state.watermark = std::max(state.watermark, event.ingest_unix_ms);
            return WindowAdmission {.selected_timestamp = event.ingest_unix_ms,
                                    .watermark = state.watermark,
                                    .late_beyond_watermark = false};
        }

        if (event.producer_unix_ms > server_now_unix_ms &&
            event.producer_unix_ms - server_now_unix_ms > policy.accepted_clock_skew_ms) {
            return std::unexpected(
                make_error(ErrorCode::invalid_bounds, "producer timestamp exceeds accepted clock skew"));
        }

        const auto previous_watermark = state.watermark;
        const auto late = event.producer_unix_ms < previous_watermark;
        state.maximum_producer_timestamp = std::max(state.maximum_producer_timestamp, event.producer_unix_ms);
        const auto data_watermark = state.maximum_producer_timestamp > policy.allowed_lateness_ms ?
                                        state.maximum_producer_timestamp - policy.allowed_lateness_ms :
                                        0;
        const auto skew_adjusted_now =
            server_now_unix_ms > policy.accepted_clock_skew_ms ? server_now_unix_ms - policy.accepted_clock_skew_ms : 0;
        const auto idle_watermark =
            skew_adjusted_now > policy.allowed_lateness_ms ? skew_adjusted_now - policy.allowed_lateness_ms : 0;
        state.watermark = std::max({state.watermark, data_watermark, idle_watermark});
        return WindowAdmission {
            .selected_timestamp = event.producer_unix_ms, .watermark = state.watermark, .late_beyond_watermark = late};
    }

    std::expected<std::uint64_t, Error>
    InMemoryReferenceRuntime::complete_group(const CorrelationLease &lease, const CorrelationCompletion completion) {
        std::scoped_lock lock {mutex_};
        const auto found = groups_.find(group_key(lease.group));
        if (found == groups_.end() || !found->second.active_token || *found->second.active_token != lease.token ||
            found->second.cursor != lease.expected_cursor) {
            return std::unexpected(make_error(ErrorCode::stale_group_lease, "correlation group lease is stale"));
        }

        const auto advances = completion == CorrelationCompletion::committed ||
                              completion == CorrelationCompletion::defined_fault ||
                              completion == CorrelationCompletion::quarantined;
        if (advances) {
            ++found->second.cursor;
        }
        found->second.active_token.reset();
        return found->second.cursor;
    }

    std::uint64_t InMemoryReferenceRuntime::group_cursor(const CorrelationGroupId &group) const {
        std::scoped_lock lock {mutex_};
        const auto found = groups_.find(group_key(group));
        return found == groups_.end() ? 0 : found->second.cursor;
    }

    std::expected<void, Error> InMemoryReferenceRuntime::retain(const RetentionProfile &profile, RetentionIntent intent,
                                                                const std::uint64_t now_unix_ms) {
        if (profile.id.empty() || intent.id.empty() || intent.tenant.empty() || intent.event.empty() ||
            intent.profile != profile.id || profile.maximum_ttl_ms == 0 || profile.maximum_intents == 0 ||
            intent.expires_unix_ms <= now_unix_ms || intent.expires_unix_ms - now_unix_ms > profile.maximum_ttl_ms ||
            !label_is_canonical(profile.label_ceiling) || !label_is_canonical(intent.label) ||
            !may_flow_to(intent.label, profile.label_ceiling)) {
            return std::unexpected(make_error(ErrorCode::invalid_bounds, "retention intent exceeds its profile"));
        }

        std::scoped_lock lock {mutex_};
        const auto event = event_index_.find(intent.event.value);
        if (event == event_index_.end() || events_[event->second].envelope.tenant != intent.tenant) {
            return std::unexpected(make_error(ErrorCode::not_found, "retention event is unavailable"));
        }
        if (std::ranges::any_of(retention_intents_,
                                [&intent](const RetentionIntent &existing) { return existing.id == intent.id; })) {
            return std::unexpected(make_error(ErrorCode::duplicate_conflict, "retention intent ID is reused"));
        }
        const auto count = std::ranges::count_if(
            retention_intents_, [&profile](const RetentionIntent &existing) { return existing.profile == profile.id; });
        if (count >= profile.maximum_intents || retention_intents_.size() >= limits_.maximum_retention_intents) {
            return std::unexpected(make_error(ErrorCode::quota_exceeded, "retention intent quota is exhausted"));
        }
        retention_intents_.push_back(std::move(intent));
        return {};
    }

    std::expected<CaptureReceipt, Error> InMemoryReferenceRuntime::capture(const CaptureProfile &profile,
                                                                           CaptureIntent intent,
                                                                           const std::uint64_t now_unix_ms) {
        if (profile.id.empty() || intent.id.empty() || intent.tenant.empty() || intent.peer.empty() ||
            intent.profile != profile.id || intent.anchor.empty() || intent.reason.empty() ||
            intent.dedupe_key.empty() || profile.maximum_ttl_ms == 0 || profile.maximum_pending == 0 ||
            intent.expires_unix_ms <= now_unix_ms || intent.expires_unix_ms - now_unix_ms > profile.maximum_ttl_ms ||
            !intent.parameters.value.valid() || intent.parameters.canonical_digest.empty() ||
            !label_is_canonical(profile.label_ceiling) ||
            !may_flow_to(intent.parameters.label, profile.label_ceiling) ||
            (intent.subject && (!intent.subject->valid() || intent.subject->peer != intent.peer))) {
            return std::unexpected(make_error(ErrorCode::invalid_bounds, "capture intent exceeds its profile"));
        }

        std::scoped_lock lock {mutex_};
        const auto anchor = event_index_.find(intent.anchor.value);
        if (anchor == event_index_.end() || events_[anchor->second].envelope.tenant != intent.tenant ||
            events_[anchor->second].envelope.peer != intent.peer) {
            return std::unexpected(make_error(ErrorCode::not_found, "capture anchor is unavailable"));
        }

        std::string dedupe;
        append_token(dedupe, intent.tenant.value);
        append_token(dedupe, profile.id);
        append_token(dedupe, intent.dedupe_key);
        const auto duplicate = capture_dedupe_.find(dedupe);
        if (duplicate != capture_dedupe_.end()) {
            const auto original = std::ranges::find_if(capture_intents_, [&duplicate](const CaptureIntent &existing) {
                return existing.id == duplicate->second;
            });
            const auto original_dry_run = original == capture_intents_.end() ? intent.dry_run : original->dry_run;
            return CaptureReceipt {.id = duplicate->second, .duplicate = true, .dry_run = original_dry_run};
        }

        const auto count = std::ranges::count_if(
            capture_intents_, [&profile](const CaptureIntent &existing) { return existing.profile == profile.id; });
        if (count >= profile.maximum_pending || capture_intents_.size() >= limits_.maximum_capture_intents) {
            return std::unexpected(make_error(ErrorCode::quota_exceeded, "capture intent quota is exhausted"));
        }

        const auto id = intent.id;
        const auto dry_run = intent.dry_run;
        capture_dedupe_.emplace(std::move(dedupe), id);
        capture_intents_.push_back(std::move(intent));
        return CaptureReceipt {.id = id, .duplicate = false, .dry_run = dry_run};
    }

    PurgePreview InMemoryReferenceRuntime::preview_purge_locked(const PurgeRequest &request) const {
        PurgePreview preview;
        std::set<std::string, std::less<>> selected_events;
        for (const auto &stored : events_) {
            if (purge_matches_event(request, stored.envelope)) {
                ++preview.events;
                selected_events.insert(stored.envelope.id.value);
            }
        }
        preview.state_cells =
            static_cast<std::uint64_t>(std::ranges::count_if(state_cells_, [&request](const auto &entry) {
                return entry.second.value.has_value() && purge_matches_state(request, entry.second);
            }));
        preview.retention_intents = static_cast<std::uint64_t>(
            std::ranges::count_if(retention_intents_, [&request, &selected_events](const RetentionIntent &intent) {
                return intent.tenant == request.tenant && selected_events.contains(intent.event.value);
            }));
        preview.capture_intents = static_cast<std::uint64_t>(
            std::ranges::count_if(capture_intents_, [&request, &selected_events](const CaptureIntent &intent) {
                return intent.tenant == request.tenant && (!request.peer || intent.peer == *request.peer) &&
                       selected_events.contains(intent.anchor.value);
            }));
        return preview;
    }

    std::expected<PurgePreview, Error> InMemoryReferenceRuntime::preview_purge(const PurgeRequest &request) const {
        if (request.tenant.empty() || request.begin_ingest_unix_ms >= request.end_ingest_unix_ms ||
            request.reason.empty()) {
            return std::unexpected(make_error(ErrorCode::invalid_bounds, "purge request is incomplete"));
        }
        std::scoped_lock lock {mutex_};
        return preview_purge_locked(request);
    }

    std::expected<PurgeAudit, Error> InMemoryReferenceRuntime::purge(const PurgeRequest &request) {
        if (request.tenant.empty() || request.begin_ingest_unix_ms >= request.end_ingest_unix_ms ||
            request.reason.empty()) {
            return std::unexpected(make_error(ErrorCode::invalid_bounds, "purge request is incomplete"));
        }

        std::scoped_lock lock {mutex_};
        const auto preview = preview_purge_locked(request);
        std::set<std::string, std::less<>> selected_events;
        std::vector<EventId> tombstones;
        for (const auto &stored : events_) {
            if (purge_matches_event(request, stored.envelope)) {
                selected_events.insert(stored.envelope.id.value);
                event_tombstones_.insert(stored.envelope.id.value);
                tombstones.push_back(stored.envelope.id);
            }
        }
        std::erase_if(events_, [&selected_events](const StoredEvent &stored) {
            return selected_events.contains(stored.envelope.id.value);
        });
        event_index_.clear();
        for (std::size_t index = 0; index < events_.size(); ++index) {
            event_index_.emplace(events_[index].envelope.id.value, index);
        }

        std::erase_if(state_cells_,
                      [&request](const auto &entry) { return purge_matches_state(request, entry.second); });
        std::erase_if(retention_intents_, [&request, &selected_events](const RetentionIntent &intent) {
            return intent.tenant == request.tenant && selected_events.contains(intent.event.value);
        });
        std::erase_if(capture_intents_, [&request, &selected_events](const CaptureIntent &intent) {
            return intent.tenant == request.tenant && (!request.peer || intent.peer == *request.peer) &&
                   selected_events.contains(intent.anchor.value);
        });
        capture_dedupe_.clear();
        for (const auto &intent : capture_intents_) {
            std::string dedupe;
            append_token(dedupe, intent.tenant.value);
            append_token(dedupe, intent.profile);
            append_token(dedupe, intent.dedupe_key);
            capture_dedupe_.emplace(std::move(dedupe), intent.id);
        }

        ++purge_epoch_;
        PurgeAudit audit {
            .purge_epoch = purge_epoch_,
            .request = request,
            .removed = preview,
            .tombstones = std::move(tombstones),
        };
        purge_audits_.push_back(audit);
        return audit;
    }

    std::vector<PurgeAudit> InMemoryReferenceRuntime::purge_audits() const {
        std::scoped_lock lock {mutex_};
        return purge_audits_;
    }

} // namespace rule_engine::python::events
