#include "rule_engine/python/cluster/store.hpp"

#include "rule_engine/python/cluster/migrations.hpp"
#include "serialization.hpp"

#if defined(RULE_ENGINE_USE_WINSQLITE3)
#include <winsqlite/winsqlite3.h>
#else
#include <sqlite3.h>
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace rule_engine::python::cluster {
    namespace {

        StoreError sqlite_error(sqlite3 *database, const int result, std::string context) {
            const auto primary = result & 0xff;
            StoreErrorCode code = StoreErrorCode::unavailable;
            bool retryable = false;
            if (primary == SQLITE_BUSY || primary == SQLITE_LOCKED) {
                code = StoreErrorCode::conflict;
                retryable = true;
            } else if (primary == SQLITE_CONSTRAINT || primary == SQLITE_MISMATCH || primary == SQLITE_RANGE) {
                code = StoreErrorCode::constraint_violation;
            } else if (primary == SQLITE_NOTADB || primary == SQLITE_CORRUPT || primary == SQLITE_SCHEMA) {
                code = StoreErrorCode::incompatible_schema;
            }
            if (database != nullptr) {
                context += ": ";
                context += sqlite3_errmsg(database);
            }
            return StoreError {.code = code, .message = std::move(context), .retryable = retryable};
        }

        StoreError shape_error(std::string message) {
            return StoreError {
                .code = StoreErrorCode::constraint_violation, .message = std::move(message), .retryable = false};
        }

        StoreError stale_error(std::string message) {
            return StoreError {.code = StoreErrorCode::stale_fence, .message = std::move(message), .retryable = false};
        }

        std::expected<std::int64_t, StoreError> sqlite_integer(const std::uint64_t value, const std::string_view name) {
            if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                return std::unexpected(shape_error(std::string {name} + " exceeds the durable SQL integer range"));
            }
            return static_cast<std::int64_t>(value);
        }

        std::uint64_t saturating_add(const std::uint64_t left, const std::uint64_t right) {
            if (right > std::numeric_limits<std::uint64_t>::max() - left) {
                return std::numeric_limits<std::uint64_t>::max();
            }
            return left + right;
        }

        struct Statement {
            sqlite3_stmt *value {};

            explicit Statement(sqlite3_stmt *statement): value {statement} {}
            ~Statement() {
                if (value != nullptr) {
                    sqlite3_finalize(value);
                }
            }
            Statement(const Statement &) = delete;
            Statement &operator=(const Statement &) = delete;
            Statement(Statement &&other) noexcept: value {std::exchange(other.value, nullptr)} {}
            Statement &operator=(Statement &&) = delete;
        };

        std::expected<Statement, StoreError> prepare(sqlite3 *database, const std::string_view sql) {
            sqlite3_stmt *statement {};
            const auto result =
                sqlite3_prepare_v2(database, sql.data(), static_cast<int>(sql.size()), &statement, nullptr);
            if (result != SQLITE_OK) {
                return std::unexpected(sqlite_error(database, result, "failed to prepare SQL statement"));
            }
            return Statement {statement};
        }

        std::expected<void, StoreError> bind_text(sqlite3 *database, Statement &statement, const int index,
                                                  const std::string_view value) {
            const auto result = sqlite3_bind_text(statement.value, index, value.data(), static_cast<int>(value.size()),
                                                  SQLITE_TRANSIENT);
            if (result != SQLITE_OK) {
                return std::unexpected(sqlite_error(database, result, "failed to bind SQL text parameter"));
            }
            return {};
        }

        std::expected<void, StoreError> bind_blob(sqlite3 *database, Statement &statement, const int index,
                                                  const std::span<const std::byte> value) {
            const auto result = sqlite3_bind_blob(statement.value, index, value.data(), static_cast<int>(value.size()),
                                                  SQLITE_TRANSIENT);
            if (result != SQLITE_OK) {
                return std::unexpected(sqlite_error(database, result, "failed to bind SQL blob parameter"));
            }
            return {};
        }

        std::expected<void, StoreError> bind_null(sqlite3 *database, Statement &statement, const int index) {
            const auto result = sqlite3_bind_null(statement.value, index);
            if (result != SQLITE_OK) {
                return std::unexpected(sqlite_error(database, result, "failed to bind SQL null parameter"));
            }
            return {};
        }

        std::expected<void, StoreError> bind_i64(sqlite3 *database, Statement &statement, const int index,
                                                 const std::uint64_t value, const std::string_view name) {
            const auto converted = sqlite_integer(value, name);
            if (!converted) {
                return std::unexpected(converted.error());
            }
            const auto result = sqlite3_bind_int64(statement.value, index, *converted);
            if (result != SQLITE_OK) {
                return std::unexpected(sqlite_error(database, result, "failed to bind SQL integer parameter"));
            }
            return {};
        }

        std::expected<void, StoreError> expect_done(sqlite3 *database, Statement &statement) {
            const auto result = sqlite3_step(statement.value);
            if (result != SQLITE_DONE) {
                return std::unexpected(sqlite_error(database, result, "SQL mutation failed"));
            }
            return {};
        }

        std::expected<bool, StoreError> step_row(sqlite3 *database, Statement &statement) {
            const auto result = sqlite3_step(statement.value);
            if (result == SQLITE_ROW) {
                return true;
            }
            if (result == SQLITE_DONE) {
                return false;
            }
            return std::unexpected(sqlite_error(database, result, "SQL query failed"));
        }

        std::string column_text(Statement &statement, const int column) {
            const auto *text = sqlite3_column_text(statement.value, column);
            const auto size = sqlite3_column_bytes(statement.value, column);
            if (text == nullptr || size <= 0) {
                return {};
            }
            return std::string {reinterpret_cast<const char *>(text), static_cast<std::size_t>(size)};
        }

        std::vector<std::byte> column_blob(Statement &statement, const int column) {
            const auto *data = sqlite3_column_blob(statement.value, column);
            const auto size = sqlite3_column_bytes(statement.value, column);
            if (data == nullptr || size <= 0) {
                return {};
            }
            const auto *begin = static_cast<const std::byte *>(data);
            return std::vector<std::byte> {begin, begin + size};
        }

        std::expected<void, StoreError> execute(sqlite3 *database, const std::string_view sql) {
            char *message {};
            const auto result = sqlite3_exec(database, std::string {sql}.c_str(), nullptr, nullptr, &message);
            if (result == SQLITE_OK) {
                return {};
            }
            std::string detail = "SQL batch failed";
            if (message != nullptr) {
                detail += ": ";
                detail += message;
                sqlite3_free(message);
            }
            return std::unexpected(sqlite_error(database, result, std::move(detail)));
        }

        struct SqlTransaction {
            sqlite3 *database {};
            bool active {};

            explicit SqlTransaction(sqlite3 *selected): database {selected}, active {true} {}

            ~SqlTransaction() {
                if (active) {
                    static_cast<void>(execute(database, "ROLLBACK"));
                }
            }
            SqlTransaction(const SqlTransaction &) = delete;
            SqlTransaction &operator=(const SqlTransaction &) = delete;
            SqlTransaction(SqlTransaction &&) = delete;
            SqlTransaction &operator=(SqlTransaction &&) = delete;

            [[nodiscard]] static std::expected<std::unique_ptr<SqlTransaction>, StoreError> begin(sqlite3 *database) {
                if (auto started = execute(database, "BEGIN IMMEDIATE"); !started) {
                    return std::unexpected(started.error());
                }
                return std::unique_ptr<SqlTransaction>(new SqlTransaction {database});
            }

            [[nodiscard]] std::expected<void, StoreError> commit() {
                if (auto committed = execute(database, "COMMIT"); !committed) {
                    return std::unexpected(committed.error());
                }
                active = false;
                return {};
            }
        };

        template<typename Value>
        std::expected<std::vector<std::byte>, StoreError> encode_for_store(const Value &value) {
            auto encoded = serialization::encode(value);
            if (!encoded) {
                return std::unexpected(shape_error("store serialization failed: " + encoded.error().message));
            }
            return std::move(*encoded);
        }

        template<typename Value, typename Decode>
        std::expected<Value, StoreError> decode_from_store(const std::span<const std::byte> bytes, Decode decode) {
            auto decoded = decode(bytes);
            if (!decoded) {
                return std::unexpected(
                    StoreError {.code = StoreErrorCode::incompatible_schema,
                                .message = "stored value failed validation: " + decoded.error().message,
                                .retryable = false});
            }
            return std::move(*decoded);
        }

        bool frozen_matches(const std::optional<FrozenValue> &left, const std::optional<FrozenValue> &right) {
            if (left.has_value() != right.has_value()) {
                return false;
            }
            if (!left) {
                return true;
            }
            const auto encoded_left = serialization::encode(*left);
            const auto encoded_right = serialization::encode(*right);
            return encoded_left && encoded_right && *encoded_left == *encoded_right;
        }

        bool state_matches(const StateMutation &left, const StateMutation &right) {
            return left.owner == right.owner && left.namespace_name == right.namespace_name && left.key == right.key &&
                   left.expected_version == right.expected_version && frozen_matches(left.value, right.value);
        }

        bool effect_matches(const EffectIntent &left, const EffectIntent &right) {
            const auto encoded_left = serialization::encode(left);
            const auto encoded_right = serialization::encode(right);
            return encoded_left && encoded_right && *encoded_left == *encoded_right;
        }

        std::expected<void, StoreError> validate_shape(const RuntimeTransaction &transaction) {
            if (const auto valid = serialization::validate(transaction); !valid) {
                return std::unexpected(shape_error(valid.error().message));
            }
            if (transaction.input.id.empty() || transaction.input.schema.empty() || transaction.input.tenant.empty() ||
                transaction.input.peer.empty() || !transaction.input.payload.value.valid() ||
                transaction.input.payload.canonical_digest.empty()) {
                return std::unexpected(shape_error("input event identity or payload is invalid"));
            }
            if (transaction.cursor.consumer.empty() ||
                transaction.cursor.expected_position == std::numeric_limits<std::uint64_t>::max() ||
                transaction.cursor.new_position != transaction.cursor.expected_position + 1U ||
                transaction.fence_token == 0) {
                return std::unexpected(shape_error("cursor or fence is invalid"));
            }
            if (transaction.evaluation.state_mutations.size() != transaction.state.size() ||
                !std::ranges::equal(transaction.evaluation.state_mutations, transaction.state, state_matches)) {
                return std::unexpected(shape_error("evaluation and transaction state mutations disagree"));
            }
            if (transaction.evaluation.committed_effects.size() != transaction.journal.size() ||
                !std::ranges::equal(transaction.evaluation.committed_effects, transaction.journal, effect_matches)) {
                return std::unexpected(shape_error("evaluation and transaction effect journals disagree"));
            }
            if (transaction.evaluation.outcome == EvaluationOutcome::canceled &&
                (!transaction.state.empty() || !transaction.emitted_events.empty() || !transaction.journal.empty() ||
                 !transaction.outbox.empty())) {
                return std::unexpected(shape_error("a canceled evaluation cannot commit user state or effects"));
            }
            return {};
        }

        std::expected<void, StoreError>
        append_durable_audit(sqlite3 *database, const std::uint64_t at_unix_ms, const std::string_view actor,
                             const std::string_view action, const std::string_view resource,
                             const std::string_view outcome, const std::string_view detail) {
            auto statement = prepare(database, "INSERT INTO re_audit(at_unix_ms,actor,action,resource,outcome,detail) "
                                               "VALUES(?1,?2,?3,?4,?5,?6)");
            if (!statement) {
                return std::unexpected(statement.error());
            }
            if (auto bound = bind_i64(database, *statement, 1, at_unix_ms, "audit timestamp"); !bound) {
                return std::unexpected(bound.error());
            }
            const std::array values {actor, action, resource, outcome, detail};
            for (std::size_t index = 0; index < values.size(); ++index) {
                if (auto bound = bind_text(database, *statement, static_cast<int>(index + 2U), values[index]); !bound) {
                    return std::unexpected(bound.error());
                }
            }
            return expect_done(database, *statement);
        }

        std::expected<void, StoreError> apply_migrations(sqlite3 *database) {
            auto version_query = prepare(database, "PRAGMA user_version");
            if (!version_query) {
                return std::unexpected(version_query.error());
            }
            auto row = step_row(database, *version_query);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                return std::unexpected(sqlite_error(database, SQLITE_SCHEMA, "SQLite did not report schema version"));
            }
            auto current = static_cast<std::uint32_t>(sqlite3_column_int(version_query->value, 0));
            if (current > runtime_store_schema_version) {
                return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                                   .message = "runtime store schema is newer than this binary",
                                                   .retryable = false});
            }

            for (const auto &migration : runtime_store_migrations()) {
                if (migration.version <= current) {
                    continue;
                }
                auto transaction = SqlTransaction::begin(database);
                if (!transaction) {
                    return std::unexpected(transaction.error());
                }
                if (auto applied = execute(database, migration.sqlite_sql); !applied) {
                    return std::unexpected(applied.error());
                }
                auto record = prepare(database, "INSERT INTO re_schema_migrations(version,name,applied_unix_ms) "
                                                "VALUES(?1,?2,CAST(strftime('%s','now') AS INTEGER)*1000)");
                if (!record) {
                    return std::unexpected(record.error());
                }
                sqlite3_bind_int(record->value, 1, static_cast<int>(migration.version));
                if (auto bound = bind_text(database, *record, 2, migration.name); !bound) {
                    return std::unexpected(bound.error());
                }
                if (auto inserted = expect_done(database, *record); !inserted) {
                    return std::unexpected(inserted.error());
                }
                const auto pragma = "PRAGMA user_version=" + std::to_string(migration.version);
                if (auto updated = execute(database, pragma); !updated) {
                    return std::unexpected(updated.error());
                }
                if (auto committed = (*transaction)->commit(); !committed) {
                    return std::unexpected(committed.error());
                }
                current = migration.version;
            }
            return {};
        }

    } // namespace

    struct SqliteRuntimeStore::Impl {
        sqlite3 *database {};
        AuditTrail *audit {};
        mutable std::mutex mutex;
        RuntimeStoreHealth status;

        ~Impl() {
            if (database != nullptr) {
                sqlite3_close_v2(database);
            }
        }
    };

    SqliteRuntimeStore::SqliteRuntimeStore(std::unique_ptr<Impl> impl): impl_ {std::move(impl)} {}

    std::expected<std::unique_ptr<SqliteRuntimeStore>, StoreError>
    SqliteRuntimeStore::open(const SqliteDevConfig &config, AuditTrail &audit) {
        if (config.deployment_mode != DeploymentMode::single_node_dev || config.server_processes != 1 ||
            config.remote_cluster || config.high_availability) {
            return std::unexpected(shape_error("SQLite is restricted to one single_node_dev server process"));
        }
        if (config.database_path.empty() || !config.wal || !config.foreign_keys || config.busy_timeout.count() <= 0) {
            return std::unexpected(shape_error("SQLite path, WAL, foreign keys, and busy timeout are required"));
        }

        sqlite3 *database {};
        const auto opened =
            sqlite3_open_v2(config.database_path.c_str(), &database,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (opened != SQLITE_OK) {
            auto failure = sqlite_error(database, opened, "failed to open SQLite runtime store");
            if (database != nullptr) {
                sqlite3_close_v2(database);
            }
            return std::unexpected(std::move(failure));
        }
        sqlite3_extended_result_codes(database, 1);
        sqlite3_busy_timeout(database, static_cast<int>(config.busy_timeout.count()));

        if (auto configured =
                execute(database, "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;");
            !configured) {
            sqlite3_close_v2(database);
            return std::unexpected(configured.error());
        }
        if (auto migrated = apply_migrations(database); !migrated) {
            sqlite3_close_v2(database);
            return std::unexpected(migrated.error());
        }

        auto impl = std::make_unique<Impl>();
        impl->database = database;
        impl->audit = &audit;
        impl->status = RuntimeStoreHealth {.backend = StoreBackendKind::sqlite_dev,
                                           .driver_available = true,
                                           .connected = true,
                                           .migrations_compatible = true,
                                           .schema_version = runtime_store_schema_version,
                                           .server_version = sqlite3_libversion(),
                                           .detail = "SQLite single-process development store"};
        return std::unique_ptr<SqliteRuntimeStore>(new SqliteRuntimeStore {std::move(impl)});
    }

    SqliteRuntimeStore::~SqliteRuntimeStore() = default;

    std::expected<TransactionReceipt, StoreError>
    SqliteRuntimeStore::transact_event(const RuntimeTransaction &transaction) {
        if (auto shape = validate_shape(transaction); !shape) {
            return std::unexpected(shape.error());
        }
        const auto signature = encode_for_store(transaction);
        const auto input_blob = encode_for_store(transaction.input);
        const auto evaluation_blob = encode_for_store(transaction.evaluation);
        if (!signature || !input_blob || !evaluation_blob) {
            return std::unexpected(!signature  ? signature.error() :
                                   !input_blob ? input_blob.error() :
                                                 evaluation_blob.error());
        }

        struct EncodedEvent {
            const EventEnvelope *event {};
            std::vector<std::byte> bytes;
        };
        std::vector<EncodedEvent> emitted;
        emitted.reserve(transaction.emitted_events.size());
        for (const auto &event : transaction.emitted_events) {
            auto encoded = encode_for_store(event);
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            emitted.push_back(EncodedEvent {.event = &event, .bytes = std::move(*encoded)});
        }
        std::vector<std::vector<std::byte>> state_values;
        state_values.reserve(transaction.state.size());
        for (const auto &state : transaction.state) {
            if (!state.value) {
                state_values.emplace_back();
                continue;
            }
            auto encoded = encode_for_store(*state.value);
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            state_values.push_back(std::move(*encoded));
        }
        std::vector<std::vector<std::byte>> effects;
        effects.reserve(transaction.journal.size());
        for (const auto &effect : transaction.journal) {
            auto encoded = encode_for_store(effect);
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            effects.push_back(std::move(*encoded));
        }
        std::vector<std::vector<std::byte>> outbox;
        outbox.reserve(transaction.outbox.size());
        for (const auto &record : transaction.outbox) {
            auto encoded = encode_for_store(record);
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            outbox.push_back(std::move(*encoded));
        }

        const std::scoped_lock lock {impl_->mutex};
        auto sql_transaction = SqlTransaction::begin(impl_->database);
        if (!sql_transaction) {
            return std::unexpected(sql_transaction.error());
        }

        auto duplicate =
            prepare(impl_->database, "SELECT transaction_signature,receipt FROM re_receipts WHERE input_event_id=?1");
        if (!duplicate) {
            return std::unexpected(duplicate.error());
        }
        if (auto bound = bind_text(impl_->database, *duplicate, 1, transaction.input.id.value); !bound) {
            return std::unexpected(bound.error());
        }
        auto duplicate_row = step_row(impl_->database, *duplicate);
        if (!duplicate_row) {
            return std::unexpected(duplicate_row.error());
        }
        if (*duplicate_row) {
            if (column_blob(*duplicate, 0) != *signature) {
                return std::unexpected(shape_error("duplicate input event has different transaction content"));
            }
            return decode_from_store<TransactionReceipt>(column_blob(*duplicate, 1), serialization::decode_receipt);
        }

        auto fence_query = prepare(impl_->database, "SELECT fence FROM re_consumer_fences WHERE consumer=?1");
        if (!fence_query) {
            return std::unexpected(fence_query.error());
        }
        if (auto bound = bind_text(impl_->database, *fence_query, 1, transaction.cursor.consumer); !bound) {
            return std::unexpected(bound.error());
        }
        auto fence_row = step_row(impl_->database, *fence_query);
        if (!fence_row) {
            return std::unexpected(fence_row.error());
        }
        if (!*fence_row ||
            static_cast<std::uint64_t>(sqlite3_column_int64(fence_query->value, 0)) != transaction.fence_token) {
            return std::unexpected(stale_error("transaction does not own the current consumer fence"));
        }

        auto cursor_query = prepare(impl_->database, "SELECT position FROM re_cursors WHERE consumer=?1");
        if (!cursor_query) {
            return std::unexpected(cursor_query.error());
        }
        if (auto bound = bind_text(impl_->database, *cursor_query, 1, transaction.cursor.consumer); !bound) {
            return std::unexpected(bound.error());
        }
        auto cursor_row = step_row(impl_->database, *cursor_query);
        if (!cursor_row) {
            return std::unexpected(cursor_row.error());
        }
        const auto current_position =
            *cursor_row ? static_cast<std::uint64_t>(sqlite3_column_int64(cursor_query->value, 0)) : 0U;
        if (current_position != transaction.cursor.expected_position) {
            return std::unexpected(StoreError {
                .code = StoreErrorCode::conflict, .message = "consumer cursor precondition failed", .retryable = true});
        }

        std::set<std::string, std::less<>> event_ids;
        auto event_exists = prepare(impl_->database, "SELECT 1 FROM re_events WHERE event_id=?1");
        if (!event_exists) {
            return std::unexpected(event_exists.error());
        }
        const auto validate_event = [&](const EventEnvelope &event) -> std::expected<void, StoreError> {
            if (event.id.empty() || event.schema.empty() || event.tenant.empty() || event.peer.empty() ||
                !event.payload.value.valid() || event.payload.canonical_digest.empty() ||
                !event_ids.insert(event.id.value).second) {
                return std::unexpected(shape_error("event identity or payload is invalid or duplicated"));
            }
            sqlite3_reset(event_exists->value);
            sqlite3_clear_bindings(event_exists->value);
            if (auto bound = bind_text(impl_->database, *event_exists, 1, event.id.value); !bound) {
                return std::unexpected(bound.error());
            }
            auto row = step_row(impl_->database, *event_exists);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (*row) {
                return std::unexpected(shape_error("event ID is already committed"));
            }
            return {};
        };
        if (auto valid = validate_event(transaction.input); !valid) {
            return std::unexpected(valid.error());
        }
        for (const auto &event : transaction.emitted_events) {
            if (auto valid = validate_event(event); !valid) {
                return std::unexpected(valid.error());
            }
        }

        std::set<StoredStateKey> state_keys;
        auto state_version = prepare(impl_->database, "SELECT version FROM re_state_cells "
                                                      "WHERE owner_id=?1 AND namespace_name=?2 AND state_key=?3");
        if (!state_version) {
            return std::unexpected(state_version.error());
        }
        for (const auto &state : transaction.state) {
            const StoredStateKey key {.owner = state.owner, .namespace_name = state.namespace_name, .key = state.key};
            if (key.owner.empty() || key.namespace_name.empty() || key.key.empty() ||
                state.expected_version == std::numeric_limits<std::uint64_t>::max() || !state_keys.insert(key).second) {
                return std::unexpected(shape_error("state mutation is invalid or duplicated"));
            }
            sqlite3_reset(state_version->value);
            sqlite3_clear_bindings(state_version->value);
            if (auto bound = bind_text(impl_->database, *state_version, 1, key.owner.value); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_text(impl_->database, *state_version, 2, key.namespace_name); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_text(impl_->database, *state_version, 3, key.key); !bound) {
                return std::unexpected(bound.error());
            }
            auto row = step_row(impl_->database, *state_version);
            if (!row) {
                return std::unexpected(row.error());
            }
            const auto current = *row ? static_cast<std::uint64_t>(sqlite3_column_int64(state_version->value, 0)) : 0U;
            if (current != state.expected_version) {
                return std::unexpected(StoreError {
                    .code = StoreErrorCode::conflict, .message = "state MVCC precondition failed", .retryable = true});
            }
        }

        std::set<std::string, std::less<>> effect_ids;
        std::set<std::string, std::less<>> effect_keys;
        auto journal_exists =
            prepare(impl_->database, "SELECT 1 FROM re_effect_journal WHERE intent_id=?1 OR idempotency_key=?2");
        if (!journal_exists) {
            return std::unexpected(journal_exists.error());
        }
        for (const auto &effect : transaction.journal) {
            if (effect.id.empty() || effect.invocation.empty() || effect.owner.empty() || effect.binding.empty() ||
                effect.idempotency_key.empty() || !effect.span.valid() || !effect.payload.value.valid() ||
                effect.disposition != EffectDisposition::committed || !effect_ids.insert(effect.id.value).second ||
                !effect_keys.insert(effect.idempotency_key).second) {
                return std::unexpected(shape_error("effect journal entry is invalid or duplicated"));
            }
            sqlite3_reset(journal_exists->value);
            sqlite3_clear_bindings(journal_exists->value);
            if (auto bound = bind_text(impl_->database, *journal_exists, 1, effect.id.value); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_text(impl_->database, *journal_exists, 2, effect.idempotency_key); !bound) {
                return std::unexpected(bound.error());
            }
            auto row = step_row(impl_->database, *journal_exists);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (*row) {
                return std::unexpected(shape_error("effect intent or idempotency key is already committed"));
            }
        }
        std::set<std::string, std::less<>> outbox_ids;
        std::set<std::string, std::less<>> outbox_keys;
        for (const auto &record : transaction.outbox) {
            if (record.intent.empty() || record.destination.empty() || record.idempotency_key.empty() ||
                !record.payload.value.valid() || !effect_ids.contains(record.intent.value) ||
                !outbox_ids.insert(record.intent.value).second || !outbox_keys.insert(record.idempotency_key).second) {
                return std::unexpected(shape_error("outbox row must uniquely reference a committed effect"));
            }
        }

        auto insert_event = prepare(
            impl_->database, "INSERT INTO re_events(event_id,tenant_id,peer_id,schema_id,ingest_unix_ms,envelope) "
                             "VALUES(?1,?2,?3,?4,?5,?6)");
        if (!insert_event) {
            return std::unexpected(insert_event.error());
        }
        const auto persist_event = [&](const EventEnvelope &event,
                                       const std::span<const std::byte> bytes) -> std::expected<void, StoreError> {
            sqlite3_reset(insert_event->value);
            sqlite3_clear_bindings(insert_event->value);
            const std::array text_values {std::string_view {event.id.value}, std::string_view {event.tenant.value},
                                          std::string_view {event.peer.value}, std::string_view {event.schema.value}};
            for (std::size_t index = 0; index < text_values.size(); ++index) {
                if (auto bound =
                        bind_text(impl_->database, *insert_event, static_cast<int>(index + 1U), text_values[index]);
                    !bound) {
                    return std::unexpected(bound.error());
                }
            }
            if (auto bound = bind_i64(impl_->database, *insert_event, 5, event.ingest_unix_ms, "event ingest time");
                !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_blob(impl_->database, *insert_event, 6, bytes); !bound) {
                return std::unexpected(bound.error());
            }
            return expect_done(impl_->database, *insert_event);
        };
        if (auto inserted = persist_event(transaction.input, *input_blob); !inserted) {
            return std::unexpected(inserted.error());
        }
        for (const auto &event : emitted) {
            if (auto inserted = persist_event(*event.event, event.bytes); !inserted) {
                return std::unexpected(inserted.error());
            }
        }

        auto insert_state =
            prepare(impl_->database, "INSERT INTO re_state_cells(owner_id,namespace_name,state_key,version,value) "
                                     "VALUES(?1,?2,?3,?4,?5) "
                                     "ON CONFLICT(owner_id,namespace_name,state_key) DO UPDATE SET "
                                     "version=excluded.version,value=excluded.value");
        if (!insert_state) {
            return std::unexpected(insert_state.error());
        }
        for (std::size_t index = 0; index < transaction.state.size(); ++index) {
            const auto &state = transaction.state[index];
            sqlite3_reset(insert_state->value);
            sqlite3_clear_bindings(insert_state->value);
            if (auto bound = bind_text(impl_->database, *insert_state, 1, state.owner.value); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_text(impl_->database, *insert_state, 2, state.namespace_name); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_text(impl_->database, *insert_state, 3, state.key); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_i64(impl_->database, *insert_state, 4, state.expected_version + 1U, "state version");
                !bound) {
                return std::unexpected(bound.error());
            }
            const auto bound_value = state.value ? bind_blob(impl_->database, *insert_state, 5, state_values[index]) :
                                                   bind_null(impl_->database, *insert_state, 5);
            if (!bound_value) {
                return std::unexpected(bound_value.error());
            }
            if (auto inserted = expect_done(impl_->database, *insert_state); !inserted) {
                return std::unexpected(inserted.error());
            }
        }

        auto insert_result =
            prepare(impl_->database, "INSERT INTO re_results(input_event_id,evaluation) VALUES(?1,?2)");
        if (!insert_result) {
            return std::unexpected(insert_result.error());
        }
        if (auto bound = bind_text(impl_->database, *insert_result, 1, transaction.input.id.value); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_blob(impl_->database, *insert_result, 2, *evaluation_blob); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto inserted = expect_done(impl_->database, *insert_result); !inserted) {
            return std::unexpected(inserted.error());
        }

        auto insert_effect = prepare(
            impl_->database, "INSERT INTO re_effect_journal(intent_id,idempotency_key,effect) VALUES(?1,?2,?3)");
        if (!insert_effect) {
            return std::unexpected(insert_effect.error());
        }
        for (std::size_t index = 0; index < transaction.journal.size(); ++index) {
            const auto &effect = transaction.journal[index];
            sqlite3_reset(insert_effect->value);
            sqlite3_clear_bindings(insert_effect->value);
            if (auto bound = bind_text(impl_->database, *insert_effect, 1, effect.id.value); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_text(impl_->database, *insert_effect, 2, effect.idempotency_key); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_blob(impl_->database, *insert_effect, 3, effects[index]); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto inserted = expect_done(impl_->database, *insert_effect); !inserted) {
                return std::unexpected(inserted.error());
            }
        }

        auto insert_outbox =
            prepare(impl_->database, "INSERT INTO re_outbox(intent_id,idempotency_key,not_before_unix_ms,record,state) "
                                     "VALUES(?1,?2,?3,?4,0)");
        if (!insert_outbox) {
            return std::unexpected(insert_outbox.error());
        }
        for (std::size_t index = 0; index < transaction.outbox.size(); ++index) {
            const auto &record = transaction.outbox[index];
            sqlite3_reset(insert_outbox->value);
            sqlite3_clear_bindings(insert_outbox->value);
            if (auto bound = bind_text(impl_->database, *insert_outbox, 1, record.intent.value); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_text(impl_->database, *insert_outbox, 2, record.idempotency_key); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound =
                    bind_i64(impl_->database, *insert_outbox, 3, record.not_before_unix_ms, "outbox availability time");
                !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_blob(impl_->database, *insert_outbox, 4, outbox[index]); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto inserted = expect_done(impl_->database, *insert_outbox); !inserted) {
                return std::unexpected(inserted.error());
            }
        }

        auto cursor = prepare(impl_->database, "INSERT INTO re_cursors(consumer,position) VALUES(?1,?2) "
                                               "ON CONFLICT(consumer) DO UPDATE SET position=excluded.position");
        if (!cursor) {
            return std::unexpected(cursor.error());
        }
        if (auto bound = bind_text(impl_->database, *cursor, 1, transaction.cursor.consumer); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *cursor, 2, transaction.cursor.new_position, "cursor position");
            !bound) {
            return std::unexpected(bound.error());
        }
        if (auto updated = expect_done(impl_->database, *cursor); !updated) {
            return std::unexpected(updated.error());
        }

        TransactionReceipt receipt {.input = transaction.input.id,
                                    .committed_cursor = transaction.cursor.new_position,
                                    .emitted_events = {},
                                    .outbox_intents = {}};
        for (const auto &event : transaction.emitted_events) { receipt.emitted_events.push_back(event.id); }
        for (const auto &record : transaction.outbox) { receipt.outbox_intents.push_back(record.intent); }
        const auto receipt_blob = encode_for_store(receipt);
        if (!receipt_blob) {
            return std::unexpected(receipt_blob.error());
        }
        auto insert_receipt = prepare(
            impl_->database, "INSERT INTO re_receipts(input_event_id,transaction_signature,receipt) VALUES(?1,?2,?3)");
        if (!insert_receipt) {
            return std::unexpected(insert_receipt.error());
        }
        if (auto bound = bind_text(impl_->database, *insert_receipt, 1, transaction.input.id.value); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_blob(impl_->database, *insert_receipt, 2, *signature); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_blob(impl_->database, *insert_receipt, 3, *receipt_blob); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto inserted = expect_done(impl_->database, *insert_receipt); !inserted) {
            return std::unexpected(inserted.error());
        }
        if (auto audited =
                append_durable_audit(impl_->database, transaction.input.ingest_unix_ms, "runtime-store", "event.commit",
                                     transaction.input.id.value, "committed", transaction.cursor.consumer);
            !audited) {
            return std::unexpected(audited.error());
        }
        if (auto committed = (*sql_transaction)->commit(); !committed) {
            return std::unexpected(committed.error());
        }
        static_cast<void>(impl_->audit->append(transaction.input.ingest_unix_ms, "runtime-store", "event.commit",
                                               transaction.input.id.value, "committed", transaction.cursor.consumer));
        return receipt;
    }

    std::expected<void, StoreError> SqliteRuntimeStore::install_consumer_fence(const std::string_view consumer,
                                                                               const std::uint64_t fence) {
        if (consumer.empty() || fence == 0) {
            return std::unexpected(shape_error("consumer fence must be named and non-zero"));
        }
        const std::scoped_lock lock {impl_->mutex};
        auto statement = prepare(impl_->database, "INSERT INTO re_consumer_fences(consumer,fence) VALUES(?1,?2) "
                                                  "ON CONFLICT(consumer) DO UPDATE SET fence=excluded.fence "
                                                  "WHERE re_consumer_fences.fence<=excluded.fence");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 1, consumer); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *statement, 2, fence, "consumer fence"); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto updated = expect_done(impl_->database, *statement); !updated) {
            return std::unexpected(updated.error());
        }
        if (sqlite3_changes(impl_->database) == 0) {
            return std::unexpected(stale_error("consumer fence cannot move backward"));
        }
        return {};
    }

    std::expected<std::uint64_t, StoreError>
    SqliteRuntimeStore::load_consumer_fence(const std::string_view consumer) const {
        const std::scoped_lock lock {impl_->mutex};
        auto statement = prepare(impl_->database, "SELECT fence FROM re_consumer_fences WHERE consumer=?1");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 1, consumer); !bound) {
            return std::unexpected(bound.error());
        }
        auto row = step_row(impl_->database, *statement);
        if (!row) {
            return std::unexpected(row.error());
        }
        return *row ? static_cast<std::uint64_t>(sqlite3_column_int64(statement->value, 0)) : 0U;
    }

    std::expected<std::uint64_t, StoreError>
    SqliteRuntimeStore::load_agent_receipt(const AgentStreamId &stream) const {
        if (stream.tenant.empty() || stream.peer.empty() || stream.agent_epoch.empty()) {
            return std::unexpected(shape_error("agent stream is invalid"));
        }
        const std::scoped_lock lock {impl_->mutex};
        auto statement = prepare(impl_->database,
                                 "SELECT acknowledged_through FROM re_agent_receipts "
                                 "WHERE tenant_id=?1 AND peer_id=?2 AND agent_epoch=?3");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        const std::array values {std::string_view {stream.tenant.value}, std::string_view {stream.peer.value},
                                 std::string_view {stream.agent_epoch}};
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (auto bound = bind_text(impl_->database, *statement, static_cast<int>(index + 1U), values[index]);
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        auto row = step_row(impl_->database, *statement);
        if (!row) {
            return std::unexpected(row.error());
        }
        return *row ? static_cast<std::uint64_t>(sqlite3_column_int64(statement->value, 0)) : 0U;
    }

    std::expected<AgentMessageReceipt, StoreError>
    SqliteRuntimeStore::transact_agent_message(const AgentMessageCommit &message) {
        if (message.stream.tenant.empty() || message.stream.peer.empty() || message.stream.agent_epoch.empty() ||
            message.session.empty() || message.session_fence == 0 || message.sequence == 0 ||
            message.body_kind == 0 || message.body.empty()) {
            return std::unexpected(shape_error("agent message is invalid"));
        }
        const auto sequence = sqlite_integer(message.sequence, "agent sequence");
        const auto session_fence = sqlite_integer(message.session_fence, "agent session fence");
        const auto received_at = sqlite_integer(message.received_at_unix_ms, "agent received time");
        if (!sequence || !session_fence || !received_at) {
            return std::unexpected(!sequence       ? sequence.error() :
                                   !session_fence ? session_fence.error() :
                                                    received_at.error());
        }

        const std::scoped_lock lock {impl_->mutex};
        auto transaction = SqlTransaction::begin(impl_->database);
        if (!transaction) {
            return std::unexpected(transaction.error());
        }

        auto lease = prepare(impl_->database,
                             "SELECT owner,fence,lease_until_unix_ms,held FROM re_resource_leases "
                             "WHERE scope='agent-session' AND resource_key=?1");
        if (!lease) {
            return std::unexpected(lease.error());
        }
        const auto resource_key = message.stream.tenant.value + "/" + message.stream.peer.value;
        if (auto bound = bind_text(impl_->database, *lease, 1, resource_key); !bound) {
            return std::unexpected(bound.error());
        }
        auto lease_row = step_row(impl_->database, *lease);
        if (!lease_row) {
            return std::unexpected(lease_row.error());
        }
        if (!*lease_row || column_text(*lease, 0) != message.session.value ||
            static_cast<std::uint64_t>(sqlite3_column_int64(lease->value, 1)) != message.session_fence ||
            static_cast<std::uint64_t>(sqlite3_column_int64(lease->value, 2)) < message.received_at_unix_ms ||
            sqlite3_column_int(lease->value, 3) == 0) {
            return std::unexpected(stale_error("agent session lease is stale"));
        }

        auto create_receipt =
            prepare(impl_->database,
                    "INSERT INTO re_agent_receipts(tenant_id,peer_id,agent_epoch,acknowledged_through) "
                    "VALUES(?1,?2,?3,0) ON CONFLICT(tenant_id,peer_id,agent_epoch) DO NOTHING");
        if (!create_receipt) {
            return std::unexpected(create_receipt.error());
        }
        const std::array stream_values {
            std::string_view {message.stream.tenant.value},
            std::string_view {message.stream.peer.value},
            std::string_view {message.stream.agent_epoch},
        };
        for (std::size_t index = 0; index < stream_values.size(); ++index) {
            if (auto bound =
                    bind_text(impl_->database, *create_receipt, static_cast<int>(index + 1U), stream_values[index]);
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        if (auto created = expect_done(impl_->database, *create_receipt); !created) {
            return std::unexpected(created.error());
        }

        auto receipt =
            prepare(impl_->database,
                    "SELECT acknowledged_through FROM re_agent_receipts "
                    "WHERE tenant_id=?1 AND peer_id=?2 AND agent_epoch=?3");
        if (!receipt) {
            return std::unexpected(receipt.error());
        }
        for (std::size_t index = 0; index < stream_values.size(); ++index) {
            if (auto bound = bind_text(impl_->database, *receipt, static_cast<int>(index + 1U), stream_values[index]);
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        auto receipt_row = step_row(impl_->database, *receipt);
        if (!receipt_row || !*receipt_row) {
            return std::unexpected(receipt_row ? shape_error("agent receipt disappeared") : receipt_row.error());
        }
        const auto acknowledged = static_cast<std::uint64_t>(sqlite3_column_int64(receipt->value, 0));
        if (message.sequence <= acknowledged) {
            auto prior =
                prepare(impl_->database,
                        "SELECT body_kind,body FROM re_agent_messages "
                        "WHERE tenant_id=?1 AND peer_id=?2 AND agent_epoch=?3 AND sequence=?4");
            if (!prior) {
                return std::unexpected(prior.error());
            }
            for (std::size_t index = 0; index < stream_values.size(); ++index) {
                if (auto bound =
                        bind_text(impl_->database, *prior, static_cast<int>(index + 1U), stream_values[index]);
                    !bound) {
                    return std::unexpected(bound.error());
                }
            }
            sqlite3_bind_int64(prior->value, 4, *sequence);
            auto prior_row = step_row(impl_->database, *prior);
            if (!prior_row) {
                return std::unexpected(prior_row.error());
            }
            if (!*prior_row || sqlite3_column_int(prior->value, 0) != static_cast<int>(message.body_kind) ||
                column_blob(*prior, 1) != message.body) {
                return std::unexpected(shape_error("agent sequence replay does not match its durable body"));
            }
            return AgentMessageReceipt {.acknowledged_through = acknowledged, .duplicate = true};
        }
        if (acknowledged == std::numeric_limits<std::uint64_t>::max() || message.sequence != acknowledged + 1U) {
            return std::unexpected(
                StoreError {.code = StoreErrorCode::conflict,
                            .message = "agent message sequence is not contiguous",
                            .retryable = true});
        }

        auto insert =
            prepare(impl_->database,
                    "INSERT INTO re_agent_messages(tenant_id,peer_id,agent_epoch,sequence,session_id,session_fence,"
                    "received_at_unix_ms,body_kind,body) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)");
        if (!insert) {
            return std::unexpected(insert.error());
        }
        for (std::size_t index = 0; index < stream_values.size(); ++index) {
            if (auto bound = bind_text(impl_->database, *insert, static_cast<int>(index + 1U), stream_values[index]);
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        sqlite3_bind_int64(insert->value, 4, *sequence);
        if (auto bound = bind_text(impl_->database, *insert, 5, message.session.value); !bound) {
            return std::unexpected(bound.error());
        }
        sqlite3_bind_int64(insert->value, 6, *session_fence);
        sqlite3_bind_int64(insert->value, 7, *received_at);
        sqlite3_bind_int(insert->value, 8, static_cast<int>(message.body_kind));
        if (auto bound = bind_blob(impl_->database, *insert, 9, message.body); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto inserted = expect_done(impl_->database, *insert); !inserted) {
            return std::unexpected(inserted.error());
        }

        auto update =
            prepare(impl_->database,
                    "UPDATE re_agent_receipts SET acknowledged_through=?4 "
                    "WHERE tenant_id=?1 AND peer_id=?2 AND agent_epoch=?3 AND acknowledged_through=?5");
        if (!update) {
            return std::unexpected(update.error());
        }
        for (std::size_t index = 0; index < stream_values.size(); ++index) {
            if (auto bound = bind_text(impl_->database, *update, static_cast<int>(index + 1U), stream_values[index]);
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        sqlite3_bind_int64(update->value, 4, *sequence);
        sqlite3_bind_int64(update->value, 5, static_cast<sqlite3_int64>(acknowledged));
        if (auto updated = expect_done(impl_->database, *update); !updated) {
            return std::unexpected(updated.error());
        }
        if (sqlite3_changes(impl_->database) != 1) {
            return std::unexpected(
                StoreError {.code = StoreErrorCode::conflict,
                            .message = "agent receipt compare-and-swap failed",
                            .retryable = true});
        }
        if (auto audited = append_durable_audit(impl_->database, message.received_at_unix_ms, message.session.value,
                                                "agent.message.commit", resource_key, "committed",
                                                std::to_string(message.sequence));
            !audited) {
            return std::unexpected(audited.error());
        }
        if (auto committed = (*transaction)->commit(); !committed) {
            return std::unexpected(committed.error());
        }
        static_cast<void>(impl_->audit->append(message.received_at_unix_ms, message.session.value,
                                               "agent.message.commit", resource_key, "committed",
                                               std::to_string(message.sequence)));
        return AgentMessageReceipt {.acknowledged_through = message.sequence, .duplicate = false};
    }

    std::expected<std::optional<TransactionReceipt>, StoreError>
    SqliteRuntimeStore::load_receipt(const EventId &input) const {
        const std::scoped_lock lock {impl_->mutex};
        auto statement = prepare(impl_->database, "SELECT receipt FROM re_receipts WHERE input_event_id=?1");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 1, input.value); !bound) {
            return std::unexpected(bound.error());
        }
        auto row = step_row(impl_->database, *statement);
        if (!row) {
            return std::unexpected(row.error());
        }
        if (!*row) {
            return std::optional<TransactionReceipt> {};
        }
        auto decoded = decode_from_store<TransactionReceipt>(column_blob(*statement, 0), serialization::decode_receipt);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        return std::optional<TransactionReceipt> {std::move(*decoded)};
    }

    std::expected<std::optional<StoredStateCell>, StoreError>
    SqliteRuntimeStore::load_state(const StoredStateKey &key) const {
        const std::scoped_lock lock {impl_->mutex};
        auto statement = prepare(impl_->database, "SELECT version,value FROM re_state_cells "
                                                  "WHERE owner_id=?1 AND namespace_name=?2 AND state_key=?3");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        const std::array values {std::string_view {key.owner.value}, std::string_view {key.namespace_name},
                                 std::string_view {key.key}};
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (auto bound = bind_text(impl_->database, *statement, static_cast<int>(index + 1U), values[index]);
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        auto row = step_row(impl_->database, *statement);
        if (!row) {
            return std::unexpected(row.error());
        }
        if (!*row) {
            return std::optional<StoredStateCell> {};
        }
        StoredStateCell cell {.key = key,
                              .version = static_cast<std::uint64_t>(sqlite3_column_int64(statement->value, 0)),
                              .value = std::nullopt};
        if (sqlite3_column_type(statement->value, 1) != SQLITE_NULL) {
            auto decoded = decode_from_store<FrozenValue>(column_blob(*statement, 1), serialization::decode_frozen);
            if (!decoded) {
                return std::unexpected(decoded.error());
            }
            cell.value = std::move(*decoded);
        }
        return std::optional<StoredStateCell> {std::move(cell)};
    }

    std::expected<std::vector<EventEnvelope>, StoreError>
    SqliteRuntimeStore::read_history(const HistoryQuery &query) const {
        if (query.tenant.empty() || query.peer.empty() || query.schema.empty() || query.limit == 0 ||
            query.begin_ingest_unix_ms > query.end_ingest_unix_ms) {
            return std::unexpected(shape_error("history query is invalid"));
        }
        const std::scoped_lock lock {impl_->mutex};
        auto statement = prepare(impl_->database,
                                 "SELECT envelope FROM re_events WHERE tenant_id=?1 AND peer_id=?2 AND schema_id=?3 "
                                 "AND ingest_unix_ms BETWEEN ?4 AND ?5 ORDER BY ingest_unix_ms,event_id LIMIT ?6");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 1, query.tenant.value); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 2, query.peer.value); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 3, query.schema.value); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *statement, 4, query.begin_ingest_unix_ms, "history begin");
            !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *statement, 5, query.end_ingest_unix_ms, "history end"); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *statement, 6, query.limit, "history limit"); !bound) {
            return std::unexpected(bound.error());
        }
        std::vector<EventEnvelope> result;
        result.reserve(query.limit);
        while (true) {
            auto row = step_row(impl_->database, *statement);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                break;
            }
            auto decoded = decode_from_store<EventEnvelope>(column_blob(*statement, 0), serialization::decode_event);
            if (!decoded) {
                return std::unexpected(decoded.error());
            }
            result.push_back(std::move(*decoded));
        }
        return result;
    }

    std::expected<std::vector<OutboxLease>, StoreError>
    SqliteRuntimeStore::claim_outbox(const std::string_view owner, const std::uint64_t now_unix_ms,
                                     const std::uint64_t lease_duration_ms, const std::size_t limit) {
        if (owner.empty() || lease_duration_ms == 0 || limit == 0) {
            return std::unexpected(shape_error("outbox claim arguments are invalid"));
        }
        const auto lease_until = saturating_add(now_unix_ms, lease_duration_ms);
        const std::scoped_lock lock {impl_->mutex};
        auto transaction = SqlTransaction::begin(impl_->database);
        if (!transaction) {
            return std::unexpected(transaction.error());
        }
        auto select = prepare(impl_->database,
                              "SELECT intent_id,record,fence,attempts FROM re_outbox "
                              "WHERE (state=0 AND not_before_unix_ms<=?1) OR (state=1 AND lease_until_unix_ms<?1) "
                              "ORDER BY not_before_unix_ms,intent_id LIMIT ?2");
        if (!select) {
            return std::unexpected(select.error());
        }
        if (auto bound = bind_i64(impl_->database, *select, 1, now_unix_ms, "outbox claim time"); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *select, 2, limit, "outbox claim limit"); !bound) {
            return std::unexpected(bound.error());
        }
        struct Candidate {
            IntentId intent;
            OutboxRecord record;
            std::uint64_t fence {};
            std::uint32_t attempts {};
        };
        std::vector<Candidate> candidates;
        while (true) {
            auto row = step_row(impl_->database, *select);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                break;
            }
            auto decoded = decode_from_store<OutboxRecord>(column_blob(*select, 1), serialization::decode_outbox);
            if (!decoded) {
                return std::unexpected(decoded.error());
            }
            candidates.push_back(
                Candidate {.intent = IntentId {column_text(*select, 0)},
                           .record = std::move(*decoded),
                           .fence = static_cast<std::uint64_t>(sqlite3_column_int64(select->value, 2)),
                           .attempts = static_cast<std::uint32_t>(sqlite3_column_int(select->value, 3))});
        }
        auto update = prepare(impl_->database,
                              "UPDATE re_outbox SET state=1,owner=?1,fence=?2,lease_until_unix_ms=?3,attempts=?4 "
                              "WHERE intent_id=?5");
        if (!update) {
            return std::unexpected(update.error());
        }
        std::vector<OutboxLease> result;
        result.reserve(candidates.size());
        for (auto &candidate : candidates) {
            if (candidate.fence >= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ||
                candidate.attempts == std::numeric_limits<std::uint32_t>::max()) {
                return std::unexpected(StoreError {.code = StoreErrorCode::unavailable,
                                                   .message = "outbox fence or attempt space is exhausted",
                                                   .retryable = false});
            }
            ++candidate.fence;
            ++candidate.attempts;
            sqlite3_reset(update->value);
            sqlite3_clear_bindings(update->value);
            if (auto bound = bind_text(impl_->database, *update, 1, owner); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_i64(impl_->database, *update, 2, candidate.fence, "outbox fence"); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_i64(impl_->database, *update, 3, lease_until, "outbox lease expiry"); !bound) {
                return std::unexpected(bound.error());
            }
            sqlite3_bind_int(update->value, 4, static_cast<int>(candidate.attempts));
            if (auto bound = bind_text(impl_->database, *update, 5, candidate.intent.value); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto updated = expect_done(impl_->database, *update); !updated) {
                return std::unexpected(updated.error());
            }
            result.push_back(OutboxLease {.record = std::move(candidate.record),
                                          .owner = std::string {owner},
                                          .fence = candidate.fence,
                                          .lease_until_unix_ms = lease_until,
                                          .attempt = candidate.attempts});
        }
        if (!result.empty()) {
            if (auto audited = append_durable_audit(impl_->database, now_unix_ms, owner, "outbox.claim", "outbox",
                                                    "leased", std::to_string(result.size()));
                !audited) {
                return std::unexpected(audited.error());
            }
        }
        if (auto committed = (*transaction)->commit(); !committed) {
            return std::unexpected(committed.error());
        }
        if (!result.empty()) {
            static_cast<void>(impl_->audit->append(now_unix_ms, owner, "outbox.claim", "outbox", "leased",
                                                   std::to_string(result.size())));
        }
        return result;
    }

    std::expected<void, StoreError> SqliteRuntimeStore::settle_outbox(const OutboxSettlement &settlement) {
        const std::scoped_lock lock {impl_->mutex};
        auto transaction = SqlTransaction::begin(impl_->database);
        if (!transaction) {
            return std::unexpected(transaction.error());
        }
        std::string_view sql;
        std::string_view outcome;
        switch (settlement.kind) {
            case OutboxSettlementKind::delivered:
                sql = "UPDATE re_outbox SET state=2,terminal_detail=?1 WHERE intent_id=?2 AND state=1 AND owner=?3 "
                      "AND fence=?4 AND lease_until_unix_ms>=?5";
                outcome = "delivered";
                break;
            case OutboxSettlementKind::retry:
                if (settlement.retry_not_before_unix_ms <= settlement.now_unix_ms) {
                    return std::unexpected(shape_error("outbox retry must be scheduled in the future"));
                }
                sql = "UPDATE re_outbox SET state=0,owner='',lease_until_unix_ms=0,not_before_unix_ms=?6,"
                      "terminal_detail=?1 WHERE intent_id=?2 AND state=1 AND owner=?3 AND fence=?4 "
                      "AND lease_until_unix_ms>=?5";
                outcome = "retry";
                break;
            case OutboxSettlementKind::dead_letter:
                sql = "UPDATE re_outbox SET state=3,terminal_detail=?1 WHERE intent_id=?2 AND state=1 AND owner=?3 "
                      "AND fence=?4 AND lease_until_unix_ms>=?5";
                outcome = "dead_letter";
                break;
            default: return std::unexpected(shape_error("outbox settlement kind is invalid"));
        }
        auto statement = prepare(impl_->database, sql);
        if (!statement) {
            return std::unexpected(statement.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 1, settlement.detail); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 2, settlement.intent.value); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 3, settlement.owner); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *statement, 4, settlement.fence, "outbox settlement fence");
            !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *statement, 5, settlement.now_unix_ms, "outbox settlement time");
            !bound) {
            return std::unexpected(bound.error());
        }
        if (settlement.kind == OutboxSettlementKind::retry) {
            if (auto bound =
                    bind_i64(impl_->database, *statement, 6, settlement.retry_not_before_unix_ms, "outbox retry time");
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        if (auto updated = expect_done(impl_->database, *statement); !updated) {
            return std::unexpected(updated.error());
        }
        if (sqlite3_changes(impl_->database) != 1) {
            return std::unexpected(stale_error("outbox lease is stale"));
        }
        if (auto audited = append_durable_audit(impl_->database, settlement.now_unix_ms, settlement.owner,
                                                "outbox.settle", settlement.intent.value, outcome, settlement.detail);
            !audited) {
            return std::unexpected(audited.error());
        }
        if (auto committed = (*transaction)->commit(); !committed) {
            return std::unexpected(committed.error());
        }
        static_cast<void>(impl_->audit->append(settlement.now_unix_ms, settlement.owner, "outbox.settle",
                                               settlement.intent.value, outcome, settlement.detail));
        return {};
    }

    std::expected<FencedLease, StoreError> SqliteRuntimeStore::claim_lease(const LeaseResource &resource,
                                                                           const std::string_view owner,
                                                                           const std::uint64_t now_unix_ms,
                                                                           const std::uint64_t lease_duration_ms) {
        if (resource.scope.empty() || resource.key.empty() || owner.empty() || lease_duration_ms == 0) {
            return std::unexpected(shape_error("lease claim arguments are invalid"));
        }
        const auto lease_until = saturating_add(now_unix_ms, lease_duration_ms);
        const std::scoped_lock lock {impl_->mutex};
        auto transaction = SqlTransaction::begin(impl_->database);
        if (!transaction) {
            return std::unexpected(transaction.error());
        }
        auto select = prepare(impl_->database, "SELECT owner,fence,lease_until_unix_ms,held FROM re_resource_leases "
                                               "WHERE scope=?1 AND resource_key=?2");
        if (!select) {
            return std::unexpected(select.error());
        }
        if (auto bound = bind_text(impl_->database, *select, 1, resource.scope); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_text(impl_->database, *select, 2, resource.key); !bound) {
            return std::unexpected(bound.error());
        }
        auto row = step_row(impl_->database, *select);
        if (!row) {
            return std::unexpected(row.error());
        }
        std::uint64_t fence {};
        if (*row) {
            const auto current_owner = column_text(*select, 0);
            fence = static_cast<std::uint64_t>(sqlite3_column_int64(select->value, 1));
            const auto current_until = static_cast<std::uint64_t>(sqlite3_column_int64(select->value, 2));
            const auto held = sqlite3_column_int(select->value, 3) != 0;
            if (held && current_until >= now_unix_ms) {
                if (current_owner == owner) {
                    return FencedLease {.resource = resource,
                                        .owner = current_owner,
                                        .fence = fence,
                                        .lease_until_unix_ms = current_until};
                }
                return std::unexpected(StoreError {
                    .code = StoreErrorCode::conflict, .message = "lease is held by another owner", .retryable = true});
            }
        }
        if (fence >= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::unexpected(StoreError {
                .code = StoreErrorCode::unavailable, .message = "lease fence space is exhausted", .retryable = false});
        }
        ++fence;
        auto upsert =
            prepare(impl_->database,
                    "INSERT INTO re_resource_leases(scope,resource_key,owner,fence,lease_until_unix_ms,held) "
                    "VALUES(?1,?2,?3,?4,?5,1) ON CONFLICT(scope,resource_key) DO UPDATE SET "
                    "owner=excluded.owner,fence=excluded.fence,lease_until_unix_ms=excluded.lease_until_unix_ms,"
                    "held=1");
        if (!upsert) {
            return std::unexpected(upsert.error());
        }
        const std::array values {std::string_view {resource.scope}, std::string_view {resource.key}, owner};
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (auto bound = bind_text(impl_->database, *upsert, static_cast<int>(index + 1U), values[index]); !bound) {
                return std::unexpected(bound.error());
            }
        }
        if (auto bound = bind_i64(impl_->database, *upsert, 4, fence, "lease fence"); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *upsert, 5, lease_until, "lease expiry"); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto updated = expect_done(impl_->database, *upsert); !updated) {
            return std::unexpected(updated.error());
        }
        if (auto audited = append_durable_audit(impl_->database, now_unix_ms, owner, "lease.claim",
                                                resource.scope + ":" + resource.key, "leased", std::to_string(fence));
            !audited) {
            return std::unexpected(audited.error());
        }
        if (auto committed = (*transaction)->commit(); !committed) {
            return std::unexpected(committed.error());
        }
        static_cast<void>(impl_->audit->append(now_unix_ms, owner, "lease.claim", resource.scope + ":" + resource.key,
                                               "leased", std::to_string(fence)));
        return FencedLease {
            .resource = resource, .owner = std::string {owner}, .fence = fence, .lease_until_unix_ms = lease_until};
    }

    std::expected<FencedLease, StoreError> SqliteRuntimeStore::renew_lease(const FencedLease &lease,
                                                                           const std::uint64_t now_unix_ms,
                                                                           const std::uint64_t lease_duration_ms) {
        if (lease_duration_ms == 0) {
            return std::unexpected(shape_error("lease renewal duration must be positive"));
        }
        const auto lease_until = saturating_add(now_unix_ms, lease_duration_ms);
        const std::scoped_lock lock {impl_->mutex};
        auto statement = prepare(impl_->database,
                                 "UPDATE re_resource_leases SET lease_until_unix_ms=?1 WHERE scope=?2 AND "
                                 "resource_key=?3 AND owner=?4 AND fence=?5 AND held=1 AND lease_until_unix_ms>=?6");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        if (auto bound = bind_i64(impl_->database, *statement, 1, lease_until, "lease expiry"); !bound) {
            return std::unexpected(bound.error());
        }
        const std::array values {std::string_view {lease.resource.scope}, std::string_view {lease.resource.key},
                                 std::string_view {lease.owner}};
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (auto bound = bind_text(impl_->database, *statement, static_cast<int>(index + 2U), values[index]);
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        if (auto bound = bind_i64(impl_->database, *statement, 5, lease.fence, "lease fence"); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *statement, 6, now_unix_ms, "lease renewal time"); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto updated = expect_done(impl_->database, *statement); !updated) {
            return std::unexpected(updated.error());
        }
        if (sqlite3_changes(impl_->database) != 1) {
            return std::unexpected(stale_error("lease renewal is stale"));
        }
        return FencedLease {
            .resource = lease.resource, .owner = lease.owner, .fence = lease.fence, .lease_until_unix_ms = lease_until};
    }

    std::expected<void, StoreError> SqliteRuntimeStore::release_lease(const FencedLease &lease,
                                                                      const std::uint64_t now_unix_ms) {
        const std::scoped_lock lock {impl_->mutex};
        auto statement =
            prepare(impl_->database, "UPDATE re_resource_leases SET owner='',held=0,lease_until_unix_ms=?1,"
                                     "fence=CASE WHEN fence<9223372036854775807 THEN fence+1 ELSE fence END "
                                     "WHERE scope=?2 AND resource_key=?3 AND owner=?4 AND fence=?5 AND held=1 "
                                     "AND lease_until_unix_ms>=?1");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        if (auto bound = bind_i64(impl_->database, *statement, 1, now_unix_ms, "lease release time"); !bound) {
            return std::unexpected(bound.error());
        }
        const std::array values {std::string_view {lease.resource.scope}, std::string_view {lease.resource.key},
                                 std::string_view {lease.owner}};
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (auto bound = bind_text(impl_->database, *statement, static_cast<int>(index + 2U), values[index]);
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        if (auto bound = bind_i64(impl_->database, *statement, 5, lease.fence, "lease fence"); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto updated = expect_done(impl_->database, *statement); !updated) {
            return std::unexpected(updated.error());
        }
        if (sqlite3_changes(impl_->database) != 1) {
            return std::unexpected(stale_error("lease release is stale"));
        }
        return {};
    }

    std::expected<bool, StoreError> SqliteRuntimeStore::lease_is_current(const FencedLease &lease,
                                                                         const std::uint64_t now_unix_ms) const {
        const std::scoped_lock lock {impl_->mutex};
        auto statement =
            prepare(impl_->database, "SELECT 1 FROM re_resource_leases WHERE scope=?1 AND resource_key=?2 AND owner=?3 "
                                     "AND fence=?4 AND held=1 AND lease_until_unix_ms>=?5");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        const std::array values {std::string_view {lease.resource.scope}, std::string_view {lease.resource.key},
                                 std::string_view {lease.owner}};
        for (std::size_t index = 0; index < values.size(); ++index) {
            if (auto bound = bind_text(impl_->database, *statement, static_cast<int>(index + 1U), values[index]);
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        if (auto bound = bind_i64(impl_->database, *statement, 4, lease.fence, "lease fence"); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *statement, 5, now_unix_ms, "lease current time"); !bound) {
            return std::unexpected(bound.error());
        }
        return step_row(impl_->database, *statement);
    }

    std::expected<std::vector<LeaseSnapshot>, StoreError>
    SqliteRuntimeStore::inspect_leases(const std::uint64_t now_unix_ms) const {
        const std::scoped_lock lock {impl_->mutex};
        auto statement = prepare(impl_->database, "SELECT scope,resource_key,owner,fence,lease_until_unix_ms,held "
                                                  "FROM re_resource_leases ORDER BY scope,resource_key");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        std::vector<LeaseSnapshot> result;
        while (true) {
            auto row = step_row(impl_->database, *statement);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                break;
            }
            const auto until = static_cast<std::uint64_t>(sqlite3_column_int64(statement->value, 4));
            result.push_back(
                LeaseSnapshot {.resource = {.scope = column_text(*statement, 0), .key = column_text(*statement, 1)},
                               .owner = column_text(*statement, 2),
                               .fence = static_cast<std::uint64_t>(sqlite3_column_int64(statement->value, 3)),
                               .lease_until_unix_ms = until,
                               .held = sqlite3_column_int(statement->value, 5) != 0 && until >= now_unix_ms});
        }
        return result;
    }

    std::expected<RuntimeStoreSnapshot, StoreError> SqliteRuntimeStore::inspect() const {
        const std::scoped_lock lock {impl_->mutex};
        RuntimeStoreSnapshot snapshot;
        const auto read_blobs = [this](const std::string_view sql, auto decode,
                                       auto append) -> std::expected<void, StoreError> {
            auto statement = prepare(impl_->database, sql);
            if (!statement) {
                return std::unexpected(statement.error());
            }
            while (true) {
                auto row = step_row(impl_->database, *statement);
                if (!row) {
                    return std::unexpected(row.error());
                }
                if (!*row) {
                    break;
                }
                auto value = decode(column_blob(*statement, 0));
                if (!value) {
                    return std::unexpected(
                        StoreError {.code = StoreErrorCode::incompatible_schema,
                                    .message = "stored snapshot value is invalid: " + value.error().message,
                                    .retryable = false});
                }
                append(std::move(*value));
            }
            return {};
        };
        if (auto read = read_blobs("SELECT envelope FROM re_events ORDER BY event_id", serialization::decode_event,
                                   [&snapshot](EventEnvelope value) { snapshot.events.push_back(std::move(value)); });
            !read) {
            return std::unexpected(read.error());
        }
        auto cursors = prepare(impl_->database, "SELECT consumer,position FROM re_cursors ORDER BY consumer");
        if (!cursors) {
            return std::unexpected(cursors.error());
        }
        while (true) {
            auto row = step_row(impl_->database, *cursors);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                break;
            }
            snapshot.cursors.emplace_back(column_text(*cursors, 0),
                                          static_cast<std::uint64_t>(sqlite3_column_int64(cursors->value, 1)));
        }
        auto state =
            prepare(impl_->database, "SELECT owner_id,namespace_name,state_key,version,value FROM re_state_cells "
                                     "ORDER BY owner_id,namespace_name,state_key");
        if (!state) {
            return std::unexpected(state.error());
        }
        while (true) {
            auto row = step_row(impl_->database, *state);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                break;
            }
            StoredStateCell cell {.key = {.owner = ExecutableId {column_text(*state, 0)},
                                          .namespace_name = column_text(*state, 1),
                                          .key = column_text(*state, 2)},
                                  .version = static_cast<std::uint64_t>(sqlite3_column_int64(state->value, 3)),
                                  .value = std::nullopt};
            if (sqlite3_column_type(state->value, 4) != SQLITE_NULL) {
                auto decoded = decode_from_store<FrozenValue>(column_blob(*state, 4), serialization::decode_frozen);
                if (!decoded) {
                    return std::unexpected(decoded.error());
                }
                cell.value = std::move(*decoded);
            }
            snapshot.state.push_back(std::move(cell));
        }
        auto results =
            prepare(impl_->database, "SELECT input_event_id,evaluation FROM re_results ORDER BY input_event_id");
        if (!results) {
            return std::unexpected(results.error());
        }
        while (true) {
            auto row = step_row(impl_->database, *results);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                break;
            }
            auto decoded =
                decode_from_store<EvaluationResult>(column_blob(*results, 1), serialization::decode_evaluation);
            if (!decoded) {
                return std::unexpected(decoded.error());
            }
            snapshot.results.push_back(
                StoredResult {.input = EventId {column_text(*results, 0)}, .evaluation = std::move(*decoded)});
        }
        if (auto read =
                read_blobs("SELECT effect FROM re_effect_journal ORDER BY intent_id", serialization::decode_effect,
                           [&snapshot](EffectIntent value) { snapshot.journal.push_back(std::move(value)); });
            !read) {
            return std::unexpected(read.error());
        }
        auto outbox =
            prepare(impl_->database, "SELECT record,state,owner,fence,lease_until_unix_ms,attempts,terminal_detail "
                                     "FROM re_outbox ORDER BY intent_id");
        if (!outbox) {
            return std::unexpected(outbox.error());
        }
        while (true) {
            auto row = step_row(impl_->database, *outbox);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                break;
            }
            auto decoded = decode_from_store<OutboxRecord>(column_blob(*outbox, 0), serialization::decode_outbox);
            if (!decoded) {
                return std::unexpected(decoded.error());
            }
            snapshot.outbox.push_back(StoredOutboxRecord {
                .record = std::move(*decoded),
                .state = static_cast<StoredOutboxState>(sqlite3_column_int(outbox->value, 1)),
                .owner = column_text(*outbox, 2),
                .fence = static_cast<std::uint64_t>(sqlite3_column_int64(outbox->value, 3)),
                .lease_until_unix_ms = static_cast<std::uint64_t>(sqlite3_column_int64(outbox->value, 4)),
                .attempts = static_cast<std::uint32_t>(sqlite3_column_int(outbox->value, 5)),
                .terminal_detail = column_text(*outbox, 6),
            });
        }
        if (auto read =
                read_blobs("SELECT receipt FROM re_receipts ORDER BY input_event_id", serialization::decode_receipt,
                           [&snapshot](TransactionReceipt value) { snapshot.receipts.push_back(std::move(value)); });
            !read) {
            return std::unexpected(read.error());
        }
        auto agent_messages =
            prepare(impl_->database,
                    "SELECT tenant_id,peer_id,agent_epoch,session_id,session_fence,sequence,received_at_unix_ms,"
                    "body_kind,body FROM re_agent_messages ORDER BY tenant_id,peer_id,agent_epoch,sequence");
        if (!agent_messages) {
            return std::unexpected(agent_messages.error());
        }
        while (true) {
            auto row = step_row(impl_->database, *agent_messages);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                break;
            }
            snapshot.agent_messages.push_back(StoredAgentMessage {
                .commit = {
                    .stream = {.tenant = TenantId {column_text(*agent_messages, 0)},
                               .peer = PeerId {column_text(*agent_messages, 1)},
                               .agent_epoch = column_text(*agent_messages, 2)},
                    .session = SessionId {column_text(*agent_messages, 3)},
                    .session_fence =
                        static_cast<std::uint64_t>(sqlite3_column_int64(agent_messages->value, 4)),
                    .sequence = static_cast<std::uint64_t>(sqlite3_column_int64(agent_messages->value, 5)),
                    .received_at_unix_ms =
                        static_cast<std::uint64_t>(sqlite3_column_int64(agent_messages->value, 6)),
                    .body_kind = static_cast<std::uint8_t>(sqlite3_column_int(agent_messages->value, 7)),
                    .body = column_blob(*agent_messages, 8),
                },
            });
        }
        return snapshot;
    }

    RuntimeStoreHealth SqliteRuntimeStore::health() const {
        const std::scoped_lock lock {impl_->mutex};
        auto result = impl_->status;
        auto statement = prepare(impl_->database, "SELECT 1");
        if (!statement) {
            result.connected = false;
            result.detail = statement.error().message;
            return result;
        }
        const auto row = step_row(impl_->database, *statement);
        result.connected = row && *row;
        if (!result.connected && !row) {
            result.detail = row.error().message;
        }
        return result;
    }

} // namespace rule_engine::python::cluster
