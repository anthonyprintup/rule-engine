#include "rule_engine/python/cluster/store.hpp"

#include "rule_engine/python/cluster/migrations.hpp"
#include "serialization.hpp"

#if defined(RULE_ENGINE_HAS_POSTGRESQL)
#include <libpq-fe.h>
#endif

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::cluster {
    namespace {

        StoreError postgres_unavailable(std::string detail) {
            return StoreError {.code = StoreErrorCode::unavailable, .message = std::move(detail), .retryable = true};
        }

#if defined(RULE_ENGINE_HAS_POSTGRESQL)

        StoreError postgres_shape(std::string detail) {
            return StoreError {
                .code = StoreErrorCode::constraint_violation, .message = std::move(detail), .retryable = false};
        }

        struct PgResult {
            PGresult *value {};

            explicit PgResult(PGresult *result): value {result} {}
            ~PgResult() {
                if (value != nullptr) {
                    PQclear(value);
                }
            }
            PgResult(const PgResult &) = delete;
            PgResult &operator=(const PgResult &) = delete;
            PgResult(PgResult &&other) noexcept: value {std::exchange(other.value, nullptr)} {}
            PgResult &operator=(PgResult &&) = delete;
        };

        StoreError postgres_error(PGconn *connection, PGresult *result, std::string context) {
            const auto *state = result == nullptr ? nullptr : PQresultErrorField(result, PG_DIAG_SQLSTATE);
            StoreErrorCode code = StoreErrorCode::unavailable;
            bool retryable = true;
            if (state != nullptr && (std::string_view {state} == "40001" || std::string_view {state} == "40P01" ||
                                     std::string_view {state} == "55P03" || std::string_view {state} == "23505")) {
                code = StoreErrorCode::conflict;
            } else if (state != nullptr &&
                       (std::string_view {state}.starts_with("22") || std::string_view {state}.starts_with("23"))) {
                code = StoreErrorCode::constraint_violation;
                retryable = false;
            } else if (state != nullptr && std::string_view {state}.starts_with("42")) {
                code = StoreErrorCode::incompatible_schema;
                retryable = false;
            }
            const auto *message = result != nullptr ? PQresultErrorMessage(result) : PQerrorMessage(connection);
            if (message != nullptr && *message != '\0') {
                context += ": ";
                context += message;
            }
            return StoreError {.code = code, .message = std::move(context), .retryable = retryable};
        }

        std::expected<PgResult, StoreError> execute(PGconn *connection, const std::string_view sql) {
            auto *raw = PQexec(connection, std::string {sql}.c_str());
            if (raw == nullptr) {
                return std::unexpected(postgres_error(connection, nullptr, "PostgreSQL command failed"));
            }
            PgResult result {raw};
            const auto status = PQresultStatus(raw);
            if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
                return std::unexpected(postgres_error(connection, raw, "PostgreSQL command failed"));
            }
            return result;
        }

        std::expected<PgResult, StoreError> execute_params(PGconn *connection, const std::string_view sql,
                                                           const std::vector<std::string> &parameters) {
            std::vector<const char *> values;
            values.reserve(parameters.size());
            for (const auto &parameter : parameters) { values.push_back(parameter.c_str()); }
            auto *raw = PQexecParams(connection, std::string {sql}.c_str(), static_cast<int>(values.size()), nullptr,
                                     values.data(), nullptr, nullptr, 0);
            if (raw == nullptr) {
                return std::unexpected(postgres_error(connection, nullptr, "PostgreSQL parameterized command failed"));
            }
            PgResult result {raw};
            const auto status = PQresultStatus(raw);
            if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
                return std::unexpected(postgres_error(connection, raw, "PostgreSQL parameterized command failed"));
            }
            return result;
        }

        std::string bytea_text(const std::span<const std::byte> bytes) {
            constexpr std::string_view digits = "0123456789abcdef";
            std::string result;
            result.reserve(2U + bytes.size() * 2U);
            result += "\\x";
            for (const auto value : bytes) {
                const auto byte = std::to_integer<std::uint8_t>(value);
                result.push_back(digits[byte >> 4U]);
                result.push_back(digits[byte & 0x0fU]);
            }
            return result;
        }

        std::expected<std::vector<std::byte>, StoreError> parse_bytea(const std::string_view value) {
            if (!value.starts_with("\\x") || (value.size() - 2U) % 2U != 0U) {
                return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                                   .message = "PostgreSQL bytea value is not canonical hex",
                                                   .retryable = false});
            }
            const auto nibble = [](const char character) -> std::optional<std::uint8_t> {
                if (character >= '0' && character <= '9') {
                    return static_cast<std::uint8_t>(character - '0');
                }
                if (character >= 'a' && character <= 'f') {
                    return static_cast<std::uint8_t>(character - 'a' + 10);
                }
                if (character >= 'A' && character <= 'F') {
                    return static_cast<std::uint8_t>(character - 'A' + 10);
                }
                return std::nullopt;
            };
            std::vector<std::byte> result;
            result.reserve((value.size() - 2U) / 2U);
            for (std::size_t index = 2; index < value.size(); index += 2U) {
                const auto high = nibble(value[index]);
                const auto low = nibble(value[index + 1U]);
                if (!high || !low) {
                    return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                                       .message = "PostgreSQL bytea value contains invalid hex",
                                                       .retryable = false});
                }
                result.push_back(static_cast<std::byte>(static_cast<std::uint8_t>((*high << 4U) | *low)));
            }
            return result;
        }

        std::string field(PgResult &result, const int row, const int column) {
            if (PQgetisnull(result.value, row, column) != 0) {
                return {};
            }
            return std::string {PQgetvalue(result.value, row, column),
                                static_cast<std::size_t>(PQgetlength(result.value, row, column))};
        }

        std::expected<std::uint64_t, StoreError> parse_unsigned(const std::string_view value,
                                                                const std::string_view field_name) {
            std::uint64_t result {};
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
            if (parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size()) {
                return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                                   .message = "PostgreSQL returned invalid " + std::string {field_name},
                                                   .retryable = false});
            }
            return result;
        }

        template<typename Value>
        std::expected<std::vector<std::byte>, StoreError> encode_for_postgres(const Value &value) {
            auto encoded = serialization::encode(value);
            if (!encoded) {
                return std::unexpected(postgres_shape("store serialization failed: " + encoded.error().message));
            }
            return std::move(*encoded);
        }

        template<typename Value, typename Decode>
        std::expected<Value, StoreError> decode_from_postgres(const std::string_view value, Decode decode) {
            auto bytes = parse_bytea(value);
            if (!bytes) {
                return std::unexpected(bytes.error());
            }
            auto decoded = decode(*bytes);
            if (!decoded) {
                return std::unexpected(
                    StoreError {.code = StoreErrorCode::incompatible_schema,
                                .message = "stored PostgreSQL value is invalid: " + decoded.error().message,
                                .retryable = false});
            }
            return std::move(*decoded);
        }

        std::expected<void, StoreError> begin(PGconn *connection) {
            auto result = execute(connection, "BEGIN ISOLATION LEVEL READ COMMITTED");
            if (!result) {
                return std::unexpected(result.error());
            }
            return {};
        }

        std::expected<void, StoreError> begin_serializable(PGconn *connection) {
            auto result = execute(connection, "BEGIN ISOLATION LEVEL SERIALIZABLE");
            if (!result) {
                return std::unexpected(result.error());
            }
            return {};
        }

        std::expected<std::uint64_t, StoreError> database_now_unix_ms(PGconn *connection) {
            auto result = execute(connection, "SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint");
            if (!result) {
                return std::unexpected(result.error());
            }
            if (PQntuples(result->value) != 1) {
                return std::unexpected(postgres_unavailable("PostgreSQL did not return database time"));
            }
            return parse_unsigned(field(*result, 0, 0), "database time");
        }

        void rollback(PGconn *connection) { static_cast<void>(execute(connection, "ROLLBACK")); }

        std::expected<void, StoreError> commit(PGconn *connection) {
            auto result = execute(connection, "COMMIT");
            if (!result) {
                return std::unexpected(result.error());
            }
            return {};
        }

        struct RollbackGuard {
            PGconn *connection {};
            bool active {true};
            ~RollbackGuard() {
                if (active) {
                    rollback(connection);
                }
            }
        };

        std::expected<void, StoreError> migrate(PGconn *connection) {
            if (auto started = begin_serializable(connection); !started) {
                return std::unexpected(started.error());
            }
            RollbackGuard guard {.connection = connection, .active = true};
            auto locked = execute(connection, "SELECT pg_advisory_xact_lock(7275017013371665)");
            if (!locked) {
                return std::unexpected(locked.error());
            }
            auto relation = execute(connection, "SELECT to_regclass('public.re_schema_migrations') IS NOT NULL");
            if (!relation) {
                return std::unexpected(relation.error());
            }
            std::uint64_t current {};
            if (PQntuples(relation->value) == 1 && field(*relation, 0, 0) == "t") {
                auto version = execute(connection, "SELECT COALESCE(MAX(version),0) FROM re_schema_migrations");
                if (!version) {
                    return std::unexpected(version.error());
                }
                auto parsed = parse_unsigned(field(*version, 0, 0), "schema version");
                if (!parsed) {
                    return std::unexpected(parsed.error());
                }
                current = *parsed;
            }
            if (current > runtime_store_schema_version) {
                return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                                   .message = "runtime store schema is newer than this binary",
                                                   .retryable = false});
            }
            for (const auto &migration : runtime_store_migrations()) {
                if (migration.version <= current) {
                    continue;
                }
                auto applied = execute(connection, migration.postgresql_sql);
                if (!applied) {
                    return std::unexpected(applied.error());
                }
                auto recorded =
                    execute_params(connection,
                                   "INSERT INTO re_schema_migrations(version,name,applied_unix_ms) "
                                   "VALUES($1::integer,$2,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint)",
                                   {std::to_string(migration.version), std::string {migration.name}});
                if (!recorded) {
                    return std::unexpected(recorded.error());
                }
                current = migration.version;
            }
            if (auto committed = commit(connection); !committed) {
                return std::unexpected(committed.error());
            }
            guard.active = false;
            return {};
        }

#endif

    } // namespace

    struct PostgreSqlRuntimeStore::Impl {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        PGconn *connection {};
        mutable std::mutex mutex;
#endif
        AuditTrail *audit {};
        RuntimeStoreHealth status {.backend = StoreBackendKind::postgresql17,
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
                                   .driver_available = true,
#else
                                   .driver_available = false,
#endif
                                   .connected = false,
                                   .migrations_compatible = false,
                                   .schema_version = 0,
                                   .server_version = {},
                                   .detail = "PostgreSQL runtime store is not connected"};

        ~Impl() {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
            if (connection != nullptr) {
                PQfinish(connection);
            }
#endif
        }
    };

    PostgreSqlRuntimeStore::PostgreSqlRuntimeStore(std::unique_ptr<Impl> impl): impl_ {std::move(impl)} {}

    std::expected<std::unique_ptr<PostgreSqlRuntimeStore>, StoreError>
    PostgreSqlRuntimeStore::open(const PostgreSql17Config &config, AuditTrail &audit) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        if (config.connection_reference.starts_with("secret://")) {
            return std::unexpected(postgres_unavailable(
                "PostgreSQL connection reference requires secret resolution before opening the adapter"));
        }
        return open_resolved(config, config.connection_reference, audit);
#else
        static_cast<void>(config);
        static_cast<void>(audit);
        return std::unexpected(postgres_unavailable("libpq/PostgreSQL 17 driver was not discovered at build time"));
#endif
    }

    std::expected<std::unique_ptr<PostgreSqlRuntimeStore>, StoreError>
    PostgreSqlRuntimeStore::open_resolved(const PostgreSql17Config &config, const std::string_view connection_string,
                                          AuditTrail &audit) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        if (config.deployment_mode != DeploymentMode::production_cluster || config.server_major < 17 ||
            connection_string.empty() || !config.verify_tls_peer ||
            (config.server_processes > 1 && !config.external_ha_configured)) {
            return std::unexpected(postgres_shape("PostgreSQL 17 production configuration is invalid"));
        }
        const std::string connection {connection_string};
        const char *keywords[] {"dbname", "sslmode", "connect_timeout", nullptr};
        const char *values[] {connection.c_str(), "verify-full", "10", nullptr};
        auto *database = PQconnectdbParams(keywords, values, 1);
        if (database == nullptr || PQstatus(database) != CONNECTION_OK) {
            auto failure = postgres_error(database, nullptr, "failed to connect to PostgreSQL");
            if (database != nullptr) {
                PQfinish(database);
            }
            return std::unexpected(std::move(failure));
        }
        const auto server_version = PQserverVersion(database);
        if (server_version < 170000) {
            auto failure = StoreError {.code = StoreErrorCode::incompatible_schema,
                                       .message = "PostgreSQL server must be version 17 or newer",
                                       .retryable = false};
            PQfinish(database);
            return std::unexpected(std::move(failure));
        }
        if (PQsslInUse(database) == 0) {
            PQfinish(database);
            return std::unexpected(postgres_unavailable("PostgreSQL connection is not protected by verified TLS"));
        }
        auto timeout = execute_params(database, "SELECT set_config('statement_timeout',$1,false)",
                                      {std::to_string(config.statement_timeout.count())});
        if (!timeout) {
            auto failure = timeout.error();
            PQfinish(database);
            return std::unexpected(std::move(failure));
        }
        if (auto migrated = migrate(database); !migrated) {
            auto failure = migrated.error();
            PQfinish(database);
            return std::unexpected(std::move(failure));
        }
        auto impl = std::make_unique<Impl>();
        impl->connection = database;
        impl->audit = &audit;
        impl->status = RuntimeStoreHealth {.backend = StoreBackendKind::postgresql17,
                                           .driver_available = true,
                                           .connected = true,
                                           .migrations_compatible = true,
                                           .schema_version = runtime_store_schema_version,
                                           .server_version = std::to_string(server_version),
                                           .detail = "PostgreSQL 17+ active-active runtime store"};
        return std::unique_ptr<PostgreSqlRuntimeStore>(new PostgreSqlRuntimeStore {std::move(impl)});
#else
        static_cast<void>(config);
        static_cast<void>(connection_string);
        static_cast<void>(audit);
        return std::unexpected(postgres_unavailable("libpq/PostgreSQL 17 driver was not discovered at build time"));
#endif
    }

    PostgreSqlRuntimeStore::~PostgreSqlRuntimeStore() = default;

    std::expected<TransactionReceipt, StoreError>
    PostgreSqlRuntimeStore::transact_event(const RuntimeTransaction &transaction) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        if (auto valid = serialization::validate(transaction); !valid) {
            return std::unexpected(postgres_shape(valid.error().message));
        }
        auto signature = encode_for_postgres(transaction);
        auto input = encode_for_postgres(transaction.input);
        auto evaluation = encode_for_postgres(transaction.evaluation);
        if (!signature || !input || !evaluation) {
            return std::unexpected(!signature ? signature.error() : !input ? input.error() : evaluation.error());
        }
        const std::scoped_lock lock {impl_->mutex};
        if (auto started = begin(impl_->connection); !started) {
            return std::unexpected(started.error());
        }
        RollbackGuard guard {.connection = impl_->connection, .active = true};
        auto idempotency_lock =
            execute_params(impl_->connection, "SELECT pg_advisory_xact_lock(hashtextextended($1,7275017013371665))",
                           {transaction.input.id.value});
        if (!idempotency_lock) {
            return std::unexpected(idempotency_lock.error());
        }
        auto duplicate = execute_params(impl_->connection,
                                        "SELECT encode(transaction_signature,'hex'),encode(receipt,'hex') "
                                        "FROM re_receipts WHERE input_event_id=$1 FOR UPDATE",
                                        {transaction.input.id.value});
        if (!duplicate) {
            return std::unexpected(duplicate.error());
        }
        if (PQntuples(duplicate->value) == 1) {
            const auto existing_signature = "\\x" + field(*duplicate, 0, 0);
            if (existing_signature != bytea_text(*signature)) {
                return std::unexpected(postgres_shape("duplicate input event has different transaction content"));
            }
            auto receipt = decode_from_postgres<TransactionReceipt>("\\x" + field(*duplicate, 0, 1),
                                                                    serialization::decode_receipt);
            if (!receipt) {
                return std::unexpected(receipt.error());
            }
            return receipt;
        }
        auto fence =
            execute_params(impl_->connection, "SELECT fence FROM re_consumer_fences WHERE consumer=$1 FOR UPDATE",
                           {transaction.cursor.consumer});
        if (!fence) {
            return std::unexpected(fence.error());
        }
        if (PQntuples(fence->value) != 1 || field(*fence, 0, 0) != std::to_string(transaction.fence_token)) {
            return std::unexpected(StoreError {.code = StoreErrorCode::stale_fence,
                                               .message = "transaction does not own the current consumer fence",
                                               .retryable = false});
        }
        auto cursor = execute_params(impl_->connection, "SELECT position FROM re_cursors WHERE consumer=$1 FOR UPDATE",
                                     {transaction.cursor.consumer});
        if (!cursor) {
            return std::unexpected(cursor.error());
        }
        const auto current_position = PQntuples(cursor->value) == 1 ? field(*cursor, 0, 0) : "0";
        if (current_position != std::to_string(transaction.cursor.expected_position)) {
            return std::unexpected(StoreError {
                .code = StoreErrorCode::conflict, .message = "consumer cursor precondition failed", .retryable = true});
        }
        std::set<std::string, std::less<>> event_ids;
        const auto persist_event = [&](const EventEnvelope &event,
                                       const std::span<const std::byte> bytes) -> std::expected<void, StoreError> {
            if (event.id.empty() || event.schema.empty() || event.tenant.empty() || event.peer.empty() ||
                !event_ids.insert(event.id.value).second) {
                return std::unexpected(postgres_shape("event identity is invalid or duplicated"));
            }
            auto inserted =
                execute_params(impl_->connection,
                               "INSERT INTO re_events(event_id,tenant_id,peer_id,schema_id,ingest_unix_ms,envelope) "
                               "VALUES($1,$2,$3,$4,$5::bigint,$6::bytea)",
                               {event.id.value, event.tenant.value, event.peer.value, event.schema.value,
                                std::to_string(event.ingest_unix_ms), bytea_text(bytes)});
            if (!inserted) {
                return std::unexpected(inserted.error());
            }
            return {};
        };
        if (auto persisted = persist_event(transaction.input, *input); !persisted) {
            return std::unexpected(persisted.error());
        }
        for (const auto &event : transaction.emitted_events) {
            auto encoded = encode_for_postgres(event);
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            if (auto persisted = persist_event(event, *encoded); !persisted) {
                return std::unexpected(persisted.error());
            }
        }
        std::set<StoredStateKey> state_keys;
        for (const auto &state : transaction.state) {
            const StoredStateKey key {.owner = state.owner, .namespace_name = state.namespace_name, .key = state.key};
            if (key.owner.empty() || key.namespace_name.empty() || key.key.empty() ||
                state.expected_version == std::numeric_limits<std::uint64_t>::max() || !state_keys.insert(key).second) {
                return std::unexpected(postgres_shape("state mutation is invalid or duplicated"));
            }
            auto current = execute_params(impl_->connection,
                                          "SELECT version FROM re_state_cells WHERE owner_id=$1 AND namespace_name=$2 "
                                          "AND state_key=$3 FOR UPDATE",
                                          {key.owner.value, key.namespace_name, key.key});
            if (!current) {
                return std::unexpected(current.error());
            }
            const auto current_version = PQntuples(current->value) == 1 ? field(*current, 0, 0) : "0";
            if (current_version != std::to_string(state.expected_version)) {
                return std::unexpected(StoreError {
                    .code = StoreErrorCode::conflict, .message = "state MVCC precondition failed", .retryable = true});
            }
            auto persisted = [&]() -> std::expected<PgResult, StoreError> {
                if (state.value) {
                    auto encoded = encode_for_postgres(*state.value);
                    if (!encoded) {
                        return std::unexpected(encoded.error());
                    }
                    return execute_params(
                        impl_->connection,
                        "INSERT INTO re_state_cells(owner_id,namespace_name,state_key,version,value) "
                        "VALUES($1,$2,$3,$4::bigint,$5::bytea) ON CONFLICT(owner_id,namespace_name,state_key) "
                        "DO UPDATE SET version=excluded.version,value=excluded.value",
                        {key.owner.value, key.namespace_name, key.key, std::to_string(state.expected_version + 1U),
                         bytea_text(*encoded)});
                }
                return execute_params(
                    impl_->connection,
                    "INSERT INTO re_state_cells(owner_id,namespace_name,state_key,version,value) "
                    "VALUES($1,$2,$3,$4::bigint,NULL) ON CONFLICT(owner_id,namespace_name,state_key) "
                    "DO UPDATE SET version=excluded.version,value=NULL",
                    {key.owner.value, key.namespace_name, key.key, std::to_string(state.expected_version + 1U)});
            }();
            if (!persisted) {
                return std::unexpected(persisted.error());
            }
        }
        auto result =
            execute_params(impl_->connection, "INSERT INTO re_results(input_event_id,evaluation) VALUES($1,$2::bytea)",
                           {transaction.input.id.value, bytea_text(*evaluation)});
        if (!result) {
            return std::unexpected(result.error());
        }
        std::set<std::string, std::less<>> effects;
        for (const auto &effect : transaction.journal) {
            if (effect.id.empty() || effect.idempotency_key.empty() ||
                effect.disposition != EffectDisposition::committed || !effects.insert(effect.id.value).second) {
                return std::unexpected(postgres_shape("effect journal entry is invalid or duplicated"));
            }
            auto encoded = encode_for_postgres(effect);
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            auto inserted = execute_params(
                impl_->connection,
                "INSERT INTO re_effect_journal(intent_id,idempotency_key,effect) VALUES($1,$2,$3::bytea)",
                {effect.id.value, effect.idempotency_key, bytea_text(*encoded)});
            if (!inserted) {
                return std::unexpected(inserted.error());
            }
        }
        std::set<std::string, std::less<>> outbox_ids;
        for (const auto &record : transaction.outbox) {
            if (record.intent.empty() || record.destination.empty() || record.idempotency_key.empty() ||
                !effects.contains(record.intent.value) || !outbox_ids.insert(record.intent.value).second) {
                return std::unexpected(postgres_shape("outbox row does not reference a unique committed effect"));
            }
            auto encoded = encode_for_postgres(record);
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            auto inserted =
                execute_params(impl_->connection,
                               "INSERT INTO re_outbox(intent_id,idempotency_key,not_before_unix_ms,record,state) "
                               "VALUES($1,$2,$3::bigint,$4::bytea,0)",
                               {record.intent.value, record.idempotency_key, std::to_string(record.not_before_unix_ms),
                                bytea_text(*encoded)});
            if (!inserted) {
                return std::unexpected(inserted.error());
            }
        }
        auto advanced = execute_params(impl_->connection,
                                       "INSERT INTO re_cursors(consumer,position) VALUES($1,$2::bigint) "
                                       "ON CONFLICT(consumer) DO UPDATE SET position=excluded.position",
                                       {transaction.cursor.consumer, std::to_string(transaction.cursor.new_position)});
        if (!advanced) {
            return std::unexpected(advanced.error());
        }
        TransactionReceipt receipt {.input = transaction.input.id,
                                    .committed_cursor = transaction.cursor.new_position,
                                    .emitted_events = {},
                                    .outbox_intents = {}};
        for (const auto &event : transaction.emitted_events) { receipt.emitted_events.push_back(event.id); }
        for (const auto &record : transaction.outbox) { receipt.outbox_intents.push_back(record.intent); }
        auto encoded_receipt = encode_for_postgres(receipt);
        if (!encoded_receipt) {
            return std::unexpected(encoded_receipt.error());
        }
        auto persisted_receipt = execute_params(
            impl_->connection,
            "INSERT INTO re_receipts(input_event_id,transaction_signature,receipt) VALUES($1,$2::bytea,$3::bytea)",
            {transaction.input.id.value, bytea_text(*signature), bytea_text(*encoded_receipt)});
        if (!persisted_receipt) {
            return std::unexpected(persisted_receipt.error());
        }
        auto audit = execute_params(impl_->connection,
                                    "INSERT INTO re_audit(at_unix_ms,actor,action,resource,outcome,detail) "
                                    "VALUES($1::bigint,$2,$3,$4,$5,$6)",
                                    {std::to_string(transaction.input.ingest_unix_ms), "runtime-store", "event.commit",
                                     transaction.input.id.value, "committed", transaction.cursor.consumer});
        if (!audit) {
            return std::unexpected(audit.error());
        }
        if (auto committed = commit(impl_->connection); !committed) {
            return std::unexpected(committed.error());
        }
        guard.active = false;
        static_cast<void>(impl_->audit->append(transaction.input.ingest_unix_ms, "runtime-store", "event.commit",
                                               transaction.input.id.value, "committed", transaction.cursor.consumer));
        return receipt;
#else
        static_cast<void>(transaction);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<void, StoreError> PostgreSqlRuntimeStore::install_consumer_fence(const std::string_view consumer,
                                                                                   const std::uint64_t fence) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        if (consumer.empty() || fence == 0) {
            return std::unexpected(postgres_shape("consumer fence must be named and non-zero"));
        }
        const std::scoped_lock lock {impl_->mutex};
        auto result = execute_params(
            impl_->connection,
            "INSERT INTO re_consumer_fences(consumer,fence) VALUES($1,$2::bigint) "
            "ON CONFLICT(consumer) DO UPDATE SET fence=excluded.fence WHERE re_consumer_fences.fence<=excluded.fence "
            "RETURNING fence",
            {std::string {consumer}, std::to_string(fence)});
        if (!result) {
            return std::unexpected(result.error());
        }
        if (PQntuples(result->value) != 1) {
            return std::unexpected(StoreError {.code = StoreErrorCode::stale_fence,
                                               .message = "consumer fence cannot move backward",
                                               .retryable = false});
        }
        return {};
#else
        static_cast<void>(consumer);
        static_cast<void>(fence);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<std::uint64_t, StoreError>
    PostgreSqlRuntimeStore::load_consumer_fence(const std::string_view consumer) const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        const std::scoped_lock lock {impl_->mutex};
        auto result = execute_params(impl_->connection, "SELECT fence FROM re_consumer_fences WHERE consumer=$1",
                                     {std::string {consumer}});
        if (!result) {
            return std::unexpected(result.error());
        }
        if (PQntuples(result->value) == 0) {
            return 0U;
        }
        return parse_unsigned(field(*result, 0, 0), "consumer fence");
#else
        static_cast<void>(consumer);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<std::uint64_t, StoreError>
    PostgreSqlRuntimeStore::load_agent_receipt(const AgentStreamId &stream) const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        if (stream.tenant.empty() || stream.peer.empty() || stream.agent_epoch.empty()) {
            return std::unexpected(postgres_shape("agent stream is invalid"));
        }
        const std::scoped_lock lock {impl_->mutex};
        auto result =
            execute_params(impl_->connection,
                           "SELECT acknowledged_through FROM re_agent_receipts "
                           "WHERE tenant_id=$1 AND peer_id=$2 AND agent_epoch=$3",
                           {stream.tenant.value, stream.peer.value, stream.agent_epoch});
        if (!result) {
            return std::unexpected(result.error());
        }
        if (PQntuples(result->value) == 0) {
            return 0U;
        }
        return parse_unsigned(field(*result, 0, 0), "agent receipt");
#else
        static_cast<void>(stream);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<AgentMessageReceipt, StoreError>
    PostgreSqlRuntimeStore::transact_agent_message(const AgentMessageCommit &message) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        if (message.stream.tenant.empty() || message.stream.peer.empty() || message.stream.agent_epoch.empty() ||
            message.session.empty() || message.session_fence == 0 || message.sequence == 0 ||
            message.body_kind == 0 || message.body.empty()) {
            return std::unexpected(postgres_shape("agent message is invalid"));
        }
        const std::scoped_lock lock {impl_->mutex};
        if (auto started = begin(impl_->connection); !started) {
            return std::unexpected(started.error());
        }
        RollbackGuard guard {.connection = impl_->connection, .active = true};
        const auto resource_key = message.stream.tenant.value + "/" + message.stream.peer.value;
        const auto stream_lock =
            message.stream.tenant.value + "\n" + message.stream.peer.value + "\n" + message.stream.agent_epoch;
        auto locked =
            execute_params(impl_->connection,
                           "SELECT pg_advisory_xact_lock(hashtextextended($1,7275017013371665))", {stream_lock});
        if (!locked) {
            return std::unexpected(locked.error());
        }
        auto lease =
            execute_params(impl_->connection,
                           "SELECT owner,fence,lease_until_unix_ms,held FROM re_resource_leases "
                           "WHERE scope='agent-session' AND resource_key=$1 FOR SHARE",
                           {resource_key});
        if (!lease) {
            return std::unexpected(lease.error());
        }
        if (PQntuples(lease->value) != 1) {
            return std::unexpected(StoreError {.code = StoreErrorCode::stale_fence,
                                               .message = "agent session lease is stale",
                                               .retryable = false});
        }
        auto lease_fence = parse_unsigned(field(*lease, 0, 1), "agent session fence");
        auto lease_until = parse_unsigned(field(*lease, 0, 2), "agent session lease expiry");
        if (!lease_fence || !lease_until) {
            return std::unexpected(!lease_fence ? lease_fence.error() : lease_until.error());
        }
        if (field(*lease, 0, 0) != message.session.value || *lease_fence != message.session_fence ||
            *lease_until < message.received_at_unix_ms || field(*lease, 0, 3) != "t") {
            return std::unexpected(StoreError {.code = StoreErrorCode::stale_fence,
                                               .message = "agent session lease is stale",
                                               .retryable = false});
        }
        auto created =
            execute_params(impl_->connection,
                           "INSERT INTO re_agent_receipts(tenant_id,peer_id,agent_epoch,acknowledged_through) "
                           "VALUES($1,$2,$3,0) ON CONFLICT(tenant_id,peer_id,agent_epoch) DO NOTHING",
                           {message.stream.tenant.value, message.stream.peer.value, message.stream.agent_epoch});
        if (!created) {
            return std::unexpected(created.error());
        }
        auto receipt =
            execute_params(impl_->connection,
                           "SELECT acknowledged_through FROM re_agent_receipts "
                           "WHERE tenant_id=$1 AND peer_id=$2 AND agent_epoch=$3 FOR UPDATE",
                           {message.stream.tenant.value, message.stream.peer.value, message.stream.agent_epoch});
        if (!receipt) {
            return std::unexpected(receipt.error());
        }
        if (PQntuples(receipt->value) != 1) {
            return std::unexpected(postgres_shape("agent receipt disappeared"));
        }
        auto acknowledged = parse_unsigned(field(*receipt, 0, 0), "agent receipt");
        if (!acknowledged) {
            return std::unexpected(acknowledged.error());
        }
        if (message.sequence <= *acknowledged) {
            auto prior =
                execute_params(impl_->connection,
                               "SELECT body_kind,encode(body,'hex') FROM re_agent_messages "
                               "WHERE tenant_id=$1 AND peer_id=$2 AND agent_epoch=$3 AND sequence=$4::bigint",
                               {message.stream.tenant.value, message.stream.peer.value, message.stream.agent_epoch,
                                std::to_string(message.sequence)});
            if (!prior) {
                return std::unexpected(prior.error());
            }
            if (PQntuples(prior->value) != 1) {
                return std::unexpected(postgres_shape("agent sequence replay has no durable body"));
            }
            auto prior_kind = parse_unsigned(field(*prior, 0, 0), "agent body kind");
            if (!prior_kind) {
                return std::unexpected(prior_kind.error());
            }
            auto prior_body = parse_bytea("\\x" + field(*prior, 0, 1));
            if (!prior_body) {
                return std::unexpected(prior_body.error());
            }
            if (*prior_kind != message.body_kind || *prior_body != message.body) {
                return std::unexpected(postgres_shape("agent sequence replay does not match its durable body"));
            }
            return AgentMessageReceipt {.acknowledged_through = *acknowledged, .duplicate = true};
        }
        if (*acknowledged == std::numeric_limits<std::uint64_t>::max() ||
            message.sequence != *acknowledged + 1U) {
            return std::unexpected(
                StoreError {.code = StoreErrorCode::conflict,
                            .message = "agent message sequence is not contiguous",
                            .retryable = true});
        }
        auto inserted =
            execute_params(impl_->connection,
                           "INSERT INTO re_agent_messages(tenant_id,peer_id,agent_epoch,sequence,session_id,"
                           "session_fence,received_at_unix_ms,body_kind,body) "
                           "VALUES($1,$2,$3,$4::bigint,$5,$6::bigint,$7::bigint,$8::smallint,$9::bytea)",
                           {message.stream.tenant.value, message.stream.peer.value, message.stream.agent_epoch,
                            std::to_string(message.sequence), message.session.value,
                            std::to_string(message.session_fence), std::to_string(message.received_at_unix_ms),
                            std::to_string(message.body_kind), bytea_text(message.body)});
        if (!inserted) {
            return std::unexpected(inserted.error());
        }
        auto updated =
            execute_params(impl_->connection,
                           "UPDATE re_agent_receipts SET acknowledged_through=$4::bigint "
                           "WHERE tenant_id=$1 AND peer_id=$2 AND agent_epoch=$3 "
                           "AND acknowledged_through=$5::bigint RETURNING acknowledged_through",
                           {message.stream.tenant.value, message.stream.peer.value, message.stream.agent_epoch,
                            std::to_string(message.sequence), std::to_string(*acknowledged)});
        if (!updated) {
            return std::unexpected(updated.error());
        }
        if (PQntuples(updated->value) != 1) {
            return std::unexpected(
                StoreError {.code = StoreErrorCode::conflict,
                            .message = "agent receipt compare-and-swap failed",
                            .retryable = true});
        }
        auto audit =
            execute_params(impl_->connection,
                           "INSERT INTO re_audit(at_unix_ms,actor,action,resource,outcome,detail) "
                           "VALUES($1::bigint,$2,$3,$4,$5,$6)",
                           {std::to_string(message.received_at_unix_ms), message.session.value,
                            "agent.message.commit", resource_key, "committed", std::to_string(message.sequence)});
        if (!audit) {
            return std::unexpected(audit.error());
        }
        if (auto committed = commit(impl_->connection); !committed) {
            return std::unexpected(committed.error());
        }
        guard.active = false;
        static_cast<void>(impl_->audit->append(message.received_at_unix_ms, message.session.value,
                                               "agent.message.commit", resource_key, "committed",
                                               std::to_string(message.sequence)));
        return AgentMessageReceipt {.acknowledged_through = message.sequence, .duplicate = false};
#else
        static_cast<void>(message);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<std::optional<TransactionReceipt>, StoreError>
    PostgreSqlRuntimeStore::load_receipt(const EventId &input) const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        const std::scoped_lock lock {impl_->mutex};
        auto result = execute_params(
            impl_->connection, "SELECT encode(receipt,'hex') FROM re_receipts WHERE input_event_id=$1", {input.value});
        if (!result) {
            return std::unexpected(result.error());
        }
        if (PQntuples(result->value) == 0) {
            return std::optional<TransactionReceipt> {};
        }
        auto receipt =
            decode_from_postgres<TransactionReceipt>("\\x" + field(*result, 0, 0), serialization::decode_receipt);
        if (!receipt) {
            return std::unexpected(receipt.error());
        }
        return std::optional<TransactionReceipt> {std::move(*receipt)};
#else
        static_cast<void>(input);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<std::optional<StoredStateCell>, StoreError>
    PostgreSqlRuntimeStore::load_state(const StoredStateKey &key) const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        const std::scoped_lock lock {impl_->mutex};
        auto result = execute_params(
            impl_->connection,
            "SELECT version,CASE WHEN value IS NULL THEN NULL ELSE encode(value,'hex') END FROM re_state_cells "
            "WHERE owner_id=$1 AND namespace_name=$2 AND state_key=$3",
            {key.owner.value, key.namespace_name, key.key});
        if (!result) {
            return std::unexpected(result.error());
        }
        if (PQntuples(result->value) == 0) {
            return std::optional<StoredStateCell> {};
        }
        auto version = parse_unsigned(field(*result, 0, 0), "state version");
        if (!version) {
            return std::unexpected(version.error());
        }
        StoredStateCell cell {.key = key, .version = *version, .value = std::nullopt};
        if (PQgetisnull(result->value, 0, 1) == 0) {
            auto value = decode_from_postgres<FrozenValue>("\\x" + field(*result, 0, 1), serialization::decode_frozen);
            if (!value) {
                return std::unexpected(value.error());
            }
            cell.value = std::move(*value);
        }
        return std::optional<StoredStateCell> {std::move(cell)};
#else
        static_cast<void>(key);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<std::vector<EventEnvelope>, StoreError>
    PostgreSqlRuntimeStore::read_history(const HistoryQuery &query) const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        if (query.tenant.empty() || query.peer.empty() || query.schema.empty() || query.limit == 0 ||
            query.begin_ingest_unix_ms > query.end_ingest_unix_ms) {
            return std::unexpected(postgres_shape("history query is invalid"));
        }
        const std::scoped_lock lock {impl_->mutex};
        auto result = execute_params(
            impl_->connection,
            "SELECT encode(envelope,'hex') FROM re_events WHERE tenant_id=$1 AND peer_id=$2 AND schema_id=$3 "
            "AND ingest_unix_ms BETWEEN $4::bigint AND $5::bigint ORDER BY ingest_unix_ms,event_id LIMIT $6::bigint",
            {query.tenant.value, query.peer.value, query.schema.value, std::to_string(query.begin_ingest_unix_ms),
             std::to_string(query.end_ingest_unix_ms), std::to_string(query.limit)});
        if (!result) {
            return std::unexpected(result.error());
        }
        std::vector<EventEnvelope> events;
        events.reserve(static_cast<std::size_t>(PQntuples(result->value)));
        for (int row = 0; row < PQntuples(result->value); ++row) {
            auto event =
                decode_from_postgres<EventEnvelope>("\\x" + field(*result, row, 0), serialization::decode_event);
            if (!event) {
                return std::unexpected(event.error());
            }
            events.push_back(std::move(*event));
        }
        return events;
#else
        static_cast<void>(query);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<std::vector<OutboxLease>, StoreError>
    PostgreSqlRuntimeStore::claim_outbox(const std::string_view owner, const std::uint64_t now_unix_ms,
                                         const std::uint64_t lease_duration_ms, const std::size_t limit) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        static_cast<void>(now_unix_ms);
        if (owner.empty() || lease_duration_ms == 0 || limit == 0 ||
            lease_duration_ms > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ||
            limit > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::unexpected(postgres_shape("outbox claim arguments are invalid"));
        }
        const std::scoped_lock lock {impl_->mutex};
        auto result = execute_params(
            impl_->connection,
            "WITH timing AS (SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint AS now_ms), "
            "candidates AS (SELECT o.intent_id,t.now_ms FROM re_outbox AS o CROSS JOIN timing AS t WHERE "
            "(o.state=0 AND o.not_before_unix_ms<=t.now_ms) OR (o.state=1 AND o.lease_until_unix_ms<t.now_ms) "
            "ORDER BY o.not_before_unix_ms,o.intent_id FOR UPDATE OF o SKIP LOCKED LIMIT $1::bigint) "
            "UPDATE re_outbox AS o SET state=1,owner=$2,fence=o.fence+1,"
            "lease_until_unix_ms=c.now_ms+$3::bigint,attempts=o.attempts+1 FROM candidates AS c "
            "WHERE o.intent_id=c.intent_id "
            "RETURNING encode(o.record,'hex'),o.fence,o.attempts,o.lease_until_unix_ms",
            {std::to_string(limit), std::string {owner}, std::to_string(lease_duration_ms)});
        if (!result) {
            return std::unexpected(result.error());
        }
        std::vector<OutboxLease> leases;
        leases.reserve(static_cast<std::size_t>(PQntuples(result->value)));
        for (int row = 0; row < PQntuples(result->value); ++row) {
            auto record =
                decode_from_postgres<OutboxRecord>("\\x" + field(*result, row, 0), serialization::decode_outbox);
            auto fence = parse_unsigned(field(*result, row, 1), "outbox fence");
            auto attempt = parse_unsigned(field(*result, row, 2), "outbox attempt");
            auto until = parse_unsigned(field(*result, row, 3), "outbox lease expiry");
            if (!record || !fence || !attempt || !until || *attempt > std::numeric_limits<std::uint32_t>::max()) {
                return std::unexpected(!record  ? record.error() :
                                       !fence   ? fence.error() :
                                       !attempt ? attempt.error() :
                                       !until   ? until.error() :
                                                  postgres_shape("outbox attempt overflow"));
            }
            leases.push_back(OutboxLease {.record = std::move(*record),
                                          .owner = std::string {owner},
                                          .fence = *fence,
                                          .lease_until_unix_ms = *until,
                                          .attempt = static_cast<std::uint32_t>(*attempt)});
        }
        return leases;
#else
        static_cast<void>(owner);
        static_cast<void>(now_unix_ms);
        static_cast<void>(lease_duration_ms);
        static_cast<void>(limit);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<void, StoreError> PostgreSqlRuntimeStore::settle_outbox(const OutboxSettlement &settlement) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        static_cast<void>(settlement.now_unix_ms);
        std::string sql;
        switch (settlement.kind) {
            case OutboxSettlementKind::delivered:
                sql = "WITH timing AS (SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint AS now_ms) "
                      "UPDATE re_outbox AS o SET state=2,terminal_detail=$1 FROM timing AS t WHERE intent_id=$2 "
                      "AND owner=$3 AND fence=$4::bigint AND state=1 AND lease_until_unix_ms>=t.now_ms "
                      "RETURNING intent_id";
                break;
            case OutboxSettlementKind::retry:
                sql = "WITH timing AS (SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint AS now_ms) "
                      "UPDATE re_outbox AS o SET state=0,owner='',lease_until_unix_ms=0,terminal_detail=$1,"
                      "not_before_unix_ms=$5::bigint FROM timing AS t WHERE intent_id=$2 AND owner=$3 "
                      "AND fence=$4::bigint AND state=1 AND lease_until_unix_ms>=t.now_ms "
                      "AND $5::bigint>t.now_ms RETURNING intent_id";
                break;
            case OutboxSettlementKind::dead_letter:
                sql = "WITH timing AS (SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint AS now_ms) "
                      "UPDATE re_outbox AS o SET state=3,terminal_detail=$1 FROM timing AS t WHERE intent_id=$2 "
                      "AND owner=$3 AND fence=$4::bigint AND state=1 AND lease_until_unix_ms>=t.now_ms "
                      "RETURNING intent_id";
                break;
            default: return std::unexpected(postgres_shape("outbox settlement kind is invalid"));
        }
        std::vector<std::string> parameters {settlement.detail, settlement.intent.value, settlement.owner,
                                             std::to_string(settlement.fence)};
        if (settlement.kind == OutboxSettlementKind::retry) {
            parameters.push_back(std::to_string(settlement.retry_not_before_unix_ms));
        }
        const std::scoped_lock lock {impl_->mutex};
        auto result = execute_params(impl_->connection, sql, parameters);
        if (!result) {
            return std::unexpected(result.error());
        }
        if (PQntuples(result->value) != 1) {
            return std::unexpected(StoreError {
                .code = StoreErrorCode::stale_fence, .message = "outbox lease is stale", .retryable = false});
        }
        return {};
#else
        static_cast<void>(settlement);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<FencedLease, StoreError> PostgreSqlRuntimeStore::claim_lease(const LeaseResource &resource,
                                                                               const std::string_view owner,
                                                                               const std::uint64_t now_unix_ms,
                                                                               const std::uint64_t lease_duration_ms) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        static_cast<void>(now_unix_ms);
        if (resource.scope.empty() || resource.key.empty() || owner.empty() || lease_duration_ms == 0 ||
            lease_duration_ms > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::unexpected(postgres_shape("lease claim arguments are invalid"));
        }
        const std::scoped_lock lock {impl_->mutex};
        if (auto started = begin(impl_->connection); !started) {
            return std::unexpected(started.error());
        }
        RollbackGuard guard {.connection = impl_->connection, .active = true};
        const auto database_now = database_now_unix_ms(impl_->connection);
        if (!database_now) {
            return std::unexpected(database_now.error());
        }
        if (*database_now > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) - lease_duration_ms) {
            return std::unexpected(postgres_shape("lease expiry exceeds the durable SQL integer range"));
        }
        const auto until = *database_now + lease_duration_ms;
        auto current = execute_params(impl_->connection,
                                      "SELECT owner,fence,lease_until_unix_ms,held FROM re_resource_leases "
                                      "WHERE scope=$1 AND resource_key=$2 FOR UPDATE",
                                      {resource.scope, resource.key});
        if (!current) {
            return std::unexpected(current.error());
        }
        std::uint64_t fence {};
        if (PQntuples(current->value) == 1) {
            auto parsed_fence = parse_unsigned(field(*current, 0, 1), "lease fence");
            auto current_until = parse_unsigned(field(*current, 0, 2), "lease expiry");
            if (!parsed_fence || !current_until) {
                return std::unexpected(!parsed_fence ? parsed_fence.error() : current_until.error());
            }
            fence = *parsed_fence;
            if (field(*current, 0, 3) == "t" && *current_until >= *database_now) {
                if (field(*current, 0, 0) == owner) {
                    return FencedLease {.resource = resource,
                                        .owner = std::string {owner},
                                        .fence = fence,
                                        .lease_until_unix_ms = *current_until};
                }
                return std::unexpected(StoreError {
                    .code = StoreErrorCode::conflict, .message = "lease is held by another owner", .retryable = true});
            }
        }
        if (fence >= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::unexpected(postgres_unavailable("lease fence space is exhausted"));
        }
        ++fence;
        auto updated = execute_params(
            impl_->connection,
            "INSERT INTO re_resource_leases(scope,resource_key,owner,fence,lease_until_unix_ms,held) "
            "VALUES($1,$2,$3,$4::bigint,$5::bigint,TRUE) ON CONFLICT(scope,resource_key) DO UPDATE SET "
            "owner=excluded.owner,fence=excluded.fence,lease_until_unix_ms=excluded.lease_until_unix_ms,held=TRUE",
            {resource.scope, resource.key, std::string {owner}, std::to_string(fence), std::to_string(until)});
        if (!updated) {
            return std::unexpected(updated.error());
        }
        if (auto committed = commit(impl_->connection); !committed) {
            return std::unexpected(committed.error());
        }
        guard.active = false;
        return FencedLease {
            .resource = resource, .owner = std::string {owner}, .fence = fence, .lease_until_unix_ms = until};
#else
        static_cast<void>(resource);
        static_cast<void>(owner);
        static_cast<void>(now_unix_ms);
        static_cast<void>(lease_duration_ms);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<FencedLease, StoreError> PostgreSqlRuntimeStore::renew_lease(const FencedLease &lease,
                                                                               const std::uint64_t now_unix_ms,
                                                                               const std::uint64_t lease_duration_ms) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        static_cast<void>(now_unix_ms);
        if (lease_duration_ms == 0 ||
            lease_duration_ms > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::unexpected(postgres_shape("lease renewal arguments are invalid"));
        }
        const std::scoped_lock lock {impl_->mutex};
        auto result = execute_params(
            impl_->connection,
            "WITH timing AS (SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint AS now_ms) "
            "UPDATE re_resource_leases AS l SET lease_until_unix_ms=t.now_ms+$1::bigint FROM timing AS t "
            "WHERE scope=$2 AND resource_key=$3 AND owner=$4 AND fence=$5::bigint AND held=TRUE "
            "AND lease_until_unix_ms>=t.now_ms RETURNING lease_until_unix_ms",
            {std::to_string(lease_duration_ms), lease.resource.scope, lease.resource.key, lease.owner,
             std::to_string(lease.fence)});
        if (!result) {
            return std::unexpected(result.error());
        }
        if (PQntuples(result->value) != 1) {
            return std::unexpected(StoreError {
                .code = StoreErrorCode::stale_fence, .message = "lease renewal is stale", .retryable = false});
        }
        const auto until = parse_unsigned(field(*result, 0, 0), "lease expiry");
        if (!until) {
            return std::unexpected(until.error());
        }
        return FencedLease {
            .resource = lease.resource, .owner = lease.owner, .fence = lease.fence, .lease_until_unix_ms = *until};
#else
        static_cast<void>(lease);
        static_cast<void>(now_unix_ms);
        static_cast<void>(lease_duration_ms);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<void, StoreError> PostgreSqlRuntimeStore::release_lease(const FencedLease &lease,
                                                                          const std::uint64_t now_unix_ms) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        static_cast<void>(now_unix_ms);
        const std::scoped_lock lock {impl_->mutex};
        auto result =
            execute_params(impl_->connection,
                           "WITH timing AS (SELECT (EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint AS now_ms) "
                           "UPDATE re_resource_leases AS l SET owner='',held=FALSE,lease_until_unix_ms=t.now_ms,"
                           "fence=CASE WHEN fence<9223372036854775807 THEN fence+1 ELSE fence END FROM timing AS t "
                           "WHERE l.scope=$1 AND l.resource_key=$2 AND l.owner=$3 AND l.fence=$4::bigint "
                           "AND l.held=TRUE AND l.lease_until_unix_ms>=t.now_ms RETURNING l.fence",
                           {lease.resource.scope, lease.resource.key, lease.owner, std::to_string(lease.fence)});
        if (!result) {
            return std::unexpected(result.error());
        }
        if (PQntuples(result->value) != 1) {
            return std::unexpected(StoreError {
                .code = StoreErrorCode::stale_fence, .message = "lease release is stale", .retryable = false});
        }
        return {};
#else
        static_cast<void>(lease);
        static_cast<void>(now_unix_ms);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<bool, StoreError> PostgreSqlRuntimeStore::lease_is_current(const FencedLease &lease,
                                                                             const std::uint64_t now_unix_ms) const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        static_cast<void>(now_unix_ms);
        const std::scoped_lock lock {impl_->mutex};
        auto result =
            execute_params(impl_->connection,
                           "SELECT 1 FROM re_resource_leases WHERE scope=$1 AND resource_key=$2 AND owner=$3 AND "
                           "fence=$4::bigint AND held=TRUE AND lease_until_unix_ms>="
                           "(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint",
                           {lease.resource.scope, lease.resource.key, lease.owner, std::to_string(lease.fence)});
        if (!result) {
            return std::unexpected(result.error());
        }
        return PQntuples(result->value) == 1;
#else
        static_cast<void>(lease);
        static_cast<void>(now_unix_ms);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<std::vector<LeaseSnapshot>, StoreError>
    PostgreSqlRuntimeStore::inspect_leases(const std::uint64_t now_unix_ms) const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        static_cast<void>(now_unix_ms);
        const std::scoped_lock lock {impl_->mutex};
        auto result = execute(impl_->connection, "SELECT scope,resource_key,owner,fence,lease_until_unix_ms,"
                                                 "held AND lease_until_unix_ms>="
                                                 "(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint "
                                                 "FROM re_resource_leases ORDER BY scope,resource_key");
        if (!result) {
            return std::unexpected(result.error());
        }
        std::vector<LeaseSnapshot> leases;
        leases.reserve(static_cast<std::size_t>(PQntuples(result->value)));
        for (int row = 0; row < PQntuples(result->value); ++row) {
            auto fence = parse_unsigned(field(*result, row, 3), "lease fence");
            auto until = parse_unsigned(field(*result, row, 4), "lease expiry");
            if (!fence || !until) {
                return std::unexpected(!fence ? fence.error() : until.error());
            }
            leases.push_back(
                LeaseSnapshot {.resource = {.scope = field(*result, row, 0), .key = field(*result, row, 1)},
                               .owner = field(*result, row, 2),
                               .fence = *fence,
                               .lease_until_unix_ms = *until,
                               .held = field(*result, row, 5) == "t"});
        }
        return leases;
#else
        static_cast<void>(now_unix_ms);
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    std::expected<RuntimeStoreSnapshot, StoreError> PostgreSqlRuntimeStore::inspect() const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        RuntimeStoreSnapshot snapshot;
        const std::scoped_lock lock {impl_->mutex};
        auto events = execute(impl_->connection, "SELECT encode(envelope,'hex') FROM re_events ORDER BY event_id");
        if (!events) {
            return std::unexpected(events.error());
        }
        for (int row = 0; row < PQntuples(events->value); ++row) {
            auto value =
                decode_from_postgres<EventEnvelope>("\\x" + field(*events, row, 0), serialization::decode_event);
            if (!value) {
                return std::unexpected(value.error());
            }
            snapshot.events.push_back(std::move(*value));
        }
        auto cursors = execute(impl_->connection, "SELECT consumer,position FROM re_cursors ORDER BY consumer");
        if (!cursors) {
            return std::unexpected(cursors.error());
        }
        for (int row = 0; row < PQntuples(cursors->value); ++row) {
            auto position = parse_unsigned(field(*cursors, row, 1), "cursor position");
            if (!position) {
                return std::unexpected(position.error());
            }
            snapshot.cursors.emplace_back(field(*cursors, row, 0), *position);
        }
        auto states = execute(impl_->connection,
                              "SELECT owner_id,namespace_name,state_key,version,"
                              "CASE WHEN value IS NULL THEN NULL ELSE encode(value,'hex') END FROM re_state_cells "
                              "ORDER BY owner_id,namespace_name,state_key");
        if (!states) {
            return std::unexpected(states.error());
        }
        for (int row = 0; row < PQntuples(states->value); ++row) {
            auto version = parse_unsigned(field(*states, row, 3), "state version");
            if (!version) {
                return std::unexpected(version.error());
            }
            StoredStateCell cell {.key = {.owner = ExecutableId {field(*states, row, 0)},
                                          .namespace_name = field(*states, row, 1),
                                          .key = field(*states, row, 2)},
                                  .version = *version,
                                  .value = std::nullopt};
            if (PQgetisnull(states->value, row, 4) == 0) {
                auto value =
                    decode_from_postgres<FrozenValue>("\\x" + field(*states, row, 4), serialization::decode_frozen);
                if (!value) {
                    return std::unexpected(value.error());
                }
                cell.value = std::move(*value);
            }
            snapshot.state.push_back(std::move(cell));
        }
        auto results =
            execute(impl_->connection,
                    "SELECT input_event_id,encode(evaluation,'hex') FROM re_results ORDER BY input_event_id");
        if (!results) {
            return std::unexpected(results.error());
        }
        for (int row = 0; row < PQntuples(results->value); ++row) {
            auto value = decode_from_postgres<EvaluationResult>("\\x" + field(*results, row, 1),
                                                                serialization::decode_evaluation);
            if (!value) {
                return std::unexpected(value.error());
            }
            snapshot.results.push_back(
                StoredResult {.input = EventId {field(*results, row, 0)}, .evaluation = std::move(*value)});
        }
        auto effects =
            execute(impl_->connection, "SELECT encode(effect,'hex') FROM re_effect_journal ORDER BY intent_id");
        if (!effects) {
            return std::unexpected(effects.error());
        }
        for (int row = 0; row < PQntuples(effects->value); ++row) {
            auto value =
                decode_from_postgres<EffectIntent>("\\x" + field(*effects, row, 0), serialization::decode_effect);
            if (!value) {
                return std::unexpected(value.error());
            }
            snapshot.journal.push_back(std::move(*value));
        }
        auto outbox =
            execute(impl_->connection, "SELECT encode(record,'hex'),state,owner,fence,lease_until_unix_ms,attempts,"
                                       "terminal_detail FROM re_outbox ORDER BY intent_id");
        if (!outbox) {
            return std::unexpected(outbox.error());
        }
        for (int row = 0; row < PQntuples(outbox->value); ++row) {
            auto record =
                decode_from_postgres<OutboxRecord>("\\x" + field(*outbox, row, 0), serialization::decode_outbox);
            auto state = parse_unsigned(field(*outbox, row, 1), "outbox state");
            auto fence = parse_unsigned(field(*outbox, row, 3), "outbox fence");
            auto until = parse_unsigned(field(*outbox, row, 4), "outbox lease expiry");
            auto attempts = parse_unsigned(field(*outbox, row, 5), "outbox attempts");
            if (!record || !state || !fence || !until || !attempts) {
                return std::unexpected(!record ? record.error() :
                                       !state  ? state.error() :
                                       !fence  ? fence.error() :
                                       !until  ? until.error() :
                                                 attempts.error());
            }
            snapshot.outbox.push_back(StoredOutboxRecord {
                .record = std::move(*record),
                .state = static_cast<StoredOutboxState>(*state),
                .owner = field(*outbox, row, 2),
                .fence = *fence,
                .lease_until_unix_ms = *until,
                .attempts = static_cast<std::uint32_t>(*attempts),
                .terminal_detail = field(*outbox, row, 6),
            });
        }
        auto receipts =
            execute(impl_->connection, "SELECT encode(receipt,'hex') FROM re_receipts ORDER BY input_event_id");
        if (!receipts) {
            return std::unexpected(receipts.error());
        }
        for (int row = 0; row < PQntuples(receipts->value); ++row) {
            auto value = decode_from_postgres<TransactionReceipt>("\\x" + field(*receipts, row, 0),
                                                                  serialization::decode_receipt);
            if (!value) {
                return std::unexpected(value.error());
            }
            snapshot.receipts.push_back(std::move(*value));
        }
        auto agent_messages =
            execute(impl_->connection,
                    "SELECT tenant_id,peer_id,agent_epoch,session_id,session_fence,sequence,received_at_unix_ms,"
                    "body_kind,encode(body,'hex') FROM re_agent_messages "
                    "ORDER BY tenant_id,peer_id,agent_epoch,sequence");
        if (!agent_messages) {
            return std::unexpected(agent_messages.error());
        }
        for (int row = 0; row < PQntuples(agent_messages->value); ++row) {
            auto session_fence = parse_unsigned(field(*agent_messages, row, 4), "agent session fence");
            auto sequence = parse_unsigned(field(*agent_messages, row, 5), "agent sequence");
            auto received_at = parse_unsigned(field(*agent_messages, row, 6), "agent received time");
            auto body_kind = parse_unsigned(field(*agent_messages, row, 7), "agent body kind");
            auto body = parse_bytea("\\x" + field(*agent_messages, row, 8));
            if (!session_fence || !sequence || !received_at || !body_kind || !body) {
                return std::unexpected(!session_fence ? session_fence.error() :
                                       !sequence       ? sequence.error() :
                                       !received_at    ? received_at.error() :
                                       !body_kind      ? body_kind.error() :
                                                         body.error());
            }
            snapshot.agent_messages.push_back(StoredAgentMessage {
                .commit = {
                    .stream = {.tenant = TenantId {field(*agent_messages, row, 0)},
                               .peer = PeerId {field(*agent_messages, row, 1)},
                               .agent_epoch = field(*agent_messages, row, 2)},
                    .session = SessionId {field(*agent_messages, row, 3)},
                    .session_fence = *session_fence,
                    .sequence = *sequence,
                    .received_at_unix_ms = *received_at,
                    .body_kind = static_cast<std::uint8_t>(*body_kind),
                    .body = std::move(*body),
                },
            });
        }
        return snapshot;
#else
        return std::unexpected(postgres_unavailable("PostgreSQL runtime store is not connected"));
#endif
    }

    RuntimeStoreHealth PostgreSqlRuntimeStore::health() const {
        if (!impl_) {
            return RuntimeStoreHealth {.backend = StoreBackendKind::postgresql17,
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
                                       .driver_available = true,
#else
                                       .driver_available = false,
#endif
                                       .connected = false,
                                       .migrations_compatible = false,
                                       .schema_version = 0,
                                       .server_version = {},
                                       .detail = "PostgreSQL runtime store is not connected"};
        }
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        const std::scoped_lock lock {impl_->mutex};
        auto result = impl_->status;
        result.connected = PQstatus(impl_->connection) == CONNECTION_OK;
        if (result.connected) {
            auto probe = execute(impl_->connection, "SELECT 1");
            result.connected = probe.has_value();
            if (!probe) {
                result.detail = probe.error().message;
            }
        }
        return result;
#else
        return impl_->status;
#endif
    }

} // namespace rule_engine::python::cluster
