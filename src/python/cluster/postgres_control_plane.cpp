#include "rule_engine/python/cluster/control_plane.hpp"

#include "control_serialization.hpp"

#if defined(RULE_ENGINE_HAS_POSTGRESQL)
#include <libpq-fe.h>
#endif

#include <charconv>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::cluster {
    namespace {

        StoreError postgres_control_unavailable(std::string detail) {
            return StoreError {.code = StoreErrorCode::unavailable, .message = std::move(detail), .retryable = true};
        }

#if defined(RULE_ENGINE_HAS_POSTGRESQL)

        constexpr std::uint32_t control_schema_version = 1;

        StoreError postgres_control_shape(std::string detail) {
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

        StoreError postgres_control_error(PGconn *connection, PGresult *result, std::string context) {
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
            const auto *message = result != nullptr     ? PQresultErrorMessage(result) :
                                  connection != nullptr ? PQerrorMessage(connection) :
                                                          nullptr;
            if (message != nullptr && *message != '\0') {
                context += ": ";
                context += message;
            }
            return StoreError {.code = code, .message = std::move(context), .retryable = retryable};
        }

        std::expected<PgResult, StoreError> execute(PGconn *connection, const std::string_view sql) {
            auto *raw = PQexec(connection, std::string {sql}.c_str());
            if (raw == nullptr) {
                return std::unexpected(
                    postgres_control_error(connection, nullptr, "PostgreSQL control command failed"));
            }
            PgResult result {raw};
            const auto status = PQresultStatus(raw);
            if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
                return std::unexpected(postgres_control_error(connection, raw, "PostgreSQL control command failed"));
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
                return std::unexpected(
                    postgres_control_error(connection, nullptr, "PostgreSQL parameterized control command failed"));
            }
            PgResult result {raw};
            const auto status = PQresultStatus(raw);
            if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
                return std::unexpected(
                    postgres_control_error(connection, raw, "PostgreSQL parameterized control command failed"));
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
                                                   .message = "PostgreSQL control bytea is not canonical hex",
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
                                                       .message = "PostgreSQL control bytea contains invalid hex",
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
                                                                const std::string_view name) {
            std::uint64_t result {};
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
            if (parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size()) {
                return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                                   .message = "PostgreSQL returned invalid " + std::string {name},
                                                   .retryable = false});
            }
            return result;
        }

        template<typename Value> std::expected<std::vector<std::byte>, StoreError> encode_control(const Value &value) {
            auto bytes = control_serialization::encode(value);
            if (!bytes) {
                return std::unexpected(
                    postgres_control_shape("control-plane serialization failed: " + bytes.error().message));
            }
            return std::move(*bytes);
        }

        template<typename Value, typename Decode>
        std::expected<Value, StoreError> decode_control(const std::string_view value, Decode decode) {
            auto bytes = parse_bytea(value);
            if (!bytes) {
                return std::unexpected(bytes.error());
            }
            auto decoded = decode(*bytes);
            if (!decoded) {
                return std::unexpected(
                    StoreError {.code = StoreErrorCode::incompatible_schema,
                                .message = "stored PostgreSQL control payload is invalid: " + decoded.error().message,
                                .retryable = false});
            }
            return std::move(*decoded);
        }

        std::expected<void, StoreError> begin(PGconn *connection, const bool serializable = false) {
            auto result = execute(connection, serializable ? "BEGIN ISOLATION LEVEL SERIALIZABLE" :
                                                             "BEGIN ISOLATION LEVEL READ COMMITTED");
            if (!result) {
                return std::unexpected(result.error());
            }
            return {};
        }

        void rollback(PGconn *connection) { static_cast<void>(execute(connection, "ROLLBACK")); }

        std::expected<void, StoreError> commit_transaction(PGconn *connection) {
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
            if (auto started = begin(connection, true); !started) {
                return std::unexpected(started.error());
            }
            RollbackGuard guard {.connection = connection, .active = true};
            auto locked = execute(connection, "SELECT pg_advisory_xact_lock(7275017013371666)");
            if (!locked) {
                return std::unexpected(locked.error());
            }
            auto migration_table =
                execute(connection, "CREATE TABLE IF NOT EXISTS re_control_schema_migrations("
                                    "version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_unix_ms BIGINT NOT NULL)");
            if (!migration_table) {
                return std::unexpected(migration_table.error());
            }
            auto current_query =
                execute(connection, "SELECT COALESCE(MAX(version),0) FROM re_control_schema_migrations");
            if (!current_query) {
                return std::unexpected(current_query.error());
            }
            auto current = parse_unsigned(field(*current_query, 0, 0), "control schema version");
            if (!current) {
                return std::unexpected(current.error());
            }
            if (*current > control_schema_version) {
                return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                                   .message = "control-plane schema is newer than this binary",
                                                   .retryable = false});
            }
            if (*current == 0) {
                constexpr std::string_view schema = R"sql(
CREATE TABLE IF NOT EXISTS re_control_meta(
    singleton SMALLINT PRIMARY KEY CHECK(singleton=1),
    storage_revision BIGINT NOT NULL CHECK(storage_revision>=0)
);
INSERT INTO re_control_meta(singleton,storage_revision) VALUES(1,0)
    ON CONFLICT(singleton) DO NOTHING;
CREATE TABLE IF NOT EXISTS re_control_generations(
    pack_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK(generation>0),
    phase SMALLINT NOT NULL,
    source_digest TEXT NOT NULL,
    semantic_hash TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    payload BYTEA NOT NULL,
    PRIMARY KEY(pack_id,generation)
);
CREATE TABLE IF NOT EXISTS re_control_packs(
    pack_id TEXT PRIMARY KEY,
    resource_version BIGINT NOT NULL CHECK(resource_version>=0),
    active_generation BIGINT CHECK(active_generation>0),
    assignment_fence BIGINT NOT NULL CHECK(assignment_fence>=0),
    accepting_assignments BOOLEAN NOT NULL,
    drain_boundary BIGINT CHECK(drain_boundary>=0),
    drain_target BIGINT CHECK(drain_target>0),
    payload BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS re_control_operations(
    operation_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    request_fingerprint BYTEA NOT NULL,
    kind SMALLINT NOT NULL,
    phase SMALLINT NOT NULL,
    pack_id TEXT NOT NULL,
    target_generation BIGINT NOT NULL,
    payload BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS re_control_operations_pack
    ON re_control_operations(pack_id,target_generation,operation_id);
CREATE TABLE IF NOT EXISTS re_audit(
    sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at_unix_ms BIGINT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT NOT NULL
);
)sql";
                auto applied = execute(connection, schema);
                if (!applied) {
                    return std::unexpected(applied.error());
                }
                auto recorded =
                    execute(connection, "INSERT INTO re_control_schema_migrations(version,name,applied_unix_ms) "
                                        "VALUES(1,'activation-control-foundation',"
                                        "(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint)");
                if (!recorded) {
                    return std::unexpected(recorded.error());
                }
            }
            if (auto committed = commit_transaction(connection); !committed) {
                return std::unexpected(committed.error());
            }
            guard.active = false;
            return {};
        }

        std::expected<DurableControlState, StoreError> load_state_unlocked(PGconn *connection) {
            DurableControlState state;
            auto meta = execute(connection, "SELECT storage_revision FROM re_control_meta WHERE singleton=1");
            if (!meta) {
                return std::unexpected(meta.error());
            }
            if (PQntuples(meta->value) != 1) {
                return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                                   .message = "control-plane metadata row is missing",
                                                   .retryable = false});
            }
            auto revision = parse_unsigned(field(*meta, 0, 0), "control storage revision");
            if (!revision) {
                return std::unexpected(revision.error());
            }
            state.storage_revision = *revision;
            auto generations = execute(connection, "SELECT encode(payload,'hex') FROM re_control_generations "
                                                   "ORDER BY pack_id,generation");
            if (!generations) {
                return std::unexpected(generations.error());
            }
            for (int row = 0; row < PQntuples(generations->value); ++row) {
                auto decoded = decode_control<GenerationSnapshot>("\\x" + field(*generations, row, 0),
                                                                  control_serialization::decode_generation);
                if (!decoded) {
                    return std::unexpected(decoded.error());
                }
                state.generations.push_back(std::move(*decoded));
            }
            auto packs = execute(connection, "SELECT encode(payload,'hex') FROM re_control_packs ORDER BY pack_id");
            if (!packs) {
                return std::unexpected(packs.error());
            }
            for (int row = 0; row < PQntuples(packs->value); ++row) {
                auto decoded = decode_control<DurablePackControlSnapshot>("\\x" + field(*packs, row, 0),
                                                                          control_serialization::decode_pack);
                if (!decoded) {
                    return std::unexpected(decoded.error());
                }
                state.packs.push_back(std::move(*decoded));
            }
            return state;
        }

        std::expected<std::optional<AdminOperationRecord>, StoreError>
        find_operation_unlocked(PGconn *connection, const bool by_id, const std::string_view value) {
            auto result = execute_params(connection,
                                         by_id ? "SELECT encode(payload,'hex') FROM re_control_operations "
                                                 "WHERE operation_id=$1" :
                                                 "SELECT encode(payload,'hex') FROM re_control_operations "
                                                 "WHERE idempotency_key=$1",
                                         {std::string {value}});
            if (!result) {
                return std::unexpected(result.error());
            }
            if (PQntuples(result->value) == 0) {
                return std::optional<AdminOperationRecord> {};
            }
            auto decoded = decode_control<AdminOperationRecord>("\\x" + field(*result, 0, 0),
                                                                control_serialization::decode_operation);
            if (!decoded) {
                return std::unexpected(decoded.error());
            }
            return std::optional<AdminOperationRecord> {std::move(*decoded)};
        }

#endif

    } // namespace

    struct PostgreSqlActivationControlStore::Impl {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        PGconn *connection {};
        mutable std::mutex mutex;
#endif
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
                                   .detail = "PostgreSQL activation control plane is not connected"};

        ~Impl() {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
            if (connection != nullptr) {
                PQfinish(connection);
            }
#endif
        }
    };

    PostgreSqlActivationControlStore::PostgreSqlActivationControlStore(std::unique_ptr<Impl> impl):
        impl_ {std::move(impl)} {}

    std::expected<std::unique_ptr<PostgreSqlActivationControlStore>, StoreError>
    PostgreSqlActivationControlStore::open(const PostgreSql17Config &config) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        if (config.connection_reference.starts_with("secret://")) {
            return std::unexpected(postgres_control_unavailable(
                "PostgreSQL connection reference requires secret resolution before opening the control plane"));
        }
        return open_resolved(config, config.connection_reference);
#else
        static_cast<void>(config);
        return std::unexpected(
            postgres_control_unavailable("libpq/PostgreSQL 17 driver was not discovered at build time"));
#endif
    }

    std::expected<std::unique_ptr<PostgreSqlActivationControlStore>, StoreError>
    PostgreSqlActivationControlStore::open_resolved(const PostgreSql17Config &config,
                                                    const std::string_view connection_string) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        if (config.deployment_mode != DeploymentMode::production_cluster || config.server_major < 17 ||
            connection_string.empty() || !config.verify_tls_peer ||
            (config.server_processes > 1 && !config.external_ha_configured)) {
            return std::unexpected(postgres_control_shape("PostgreSQL 17 control-plane configuration is invalid"));
        }
        const std::string connection {connection_string};
        const char *keywords[] {"dbname", "sslmode", "connect_timeout", nullptr};
        const char *values[] {connection.c_str(), "verify-full", "10", nullptr};
        auto *database = PQconnectdbParams(keywords, values, 1);
        if (database == nullptr || PQstatus(database) != CONNECTION_OK) {
            auto failure = postgres_control_error(database, nullptr, "failed to connect to PostgreSQL control plane");
            if (database != nullptr) {
                PQfinish(database);
            }
            return std::unexpected(std::move(failure));
        }
        const auto server_version = PQserverVersion(database);
        if (server_version < 170000) {
            PQfinish(database);
            return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                               .message = "PostgreSQL control plane requires version 17 or newer",
                                               .retryable = false});
        }
        if (PQsslInUse(database) == 0) {
            PQfinish(database);
            return std::unexpected(
                postgres_control_unavailable("PostgreSQL control-plane connection is not protected by verified TLS"));
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
        impl->status = RuntimeStoreHealth {.backend = StoreBackendKind::postgresql17,
                                           .driver_available = true,
                                           .connected = true,
                                           .migrations_compatible = true,
                                           .schema_version = control_schema_version,
                                           .server_version = std::to_string(server_version),
                                           .detail = "PostgreSQL durable activation control plane"};
        return std::unique_ptr<PostgreSqlActivationControlStore>(
            new PostgreSqlActivationControlStore {std::move(impl)});
#else
        static_cast<void>(config);
        static_cast<void>(connection_string);
        return std::unexpected(
            postgres_control_unavailable("libpq/PostgreSQL 17 driver was not discovered at build time"));
#endif
    }

    PostgreSqlActivationControlStore::~PostgreSqlActivationControlStore() = default;

    std::expected<DurableControlState, StoreError> PostgreSqlActivationControlStore::load_state() const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        const std::scoped_lock lock {impl_->mutex};
        return load_state_unlocked(impl_->connection);
#else
        return std::unexpected(postgres_control_unavailable("PostgreSQL control plane is not connected"));
#endif
    }

    std::expected<std::optional<AdminOperationRecord>, StoreError>
    PostgreSqlActivationControlStore::find_operation(const std::string_view operation_id) const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        const std::scoped_lock lock {impl_->mutex};
        return find_operation_unlocked(impl_->connection, true, operation_id);
#else
        static_cast<void>(operation_id);
        return std::unexpected(postgres_control_unavailable("PostgreSQL control plane is not connected"));
#endif
    }

    std::expected<std::optional<AdminOperationRecord>, StoreError>
    PostgreSqlActivationControlStore::find_operation_by_idempotency(const std::string_view idempotency_key) const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        const std::scoped_lock lock {impl_->mutex};
        return find_operation_unlocked(impl_->connection, false, idempotency_key);
#else
        static_cast<void>(idempotency_key);
        return std::unexpected(postgres_control_unavailable("PostgreSQL control plane is not connected"));
#endif
    }

    std::expected<void, StoreError> PostgreSqlActivationControlStore::commit(const ControlPlaneCommit &commit) {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        if (commit.expected_storage_revision == std::numeric_limits<std::uint64_t>::max() ||
            commit.state.storage_revision != commit.expected_storage_revision + 1U ||
            commit.operation.operation_id.empty() || commit.operation.idempotency_key.empty() ||
            commit.operation.request_fingerprint.empty() || commit.audit.actor.empty() || commit.audit.action.empty()) {
            return std::unexpected(postgres_control_shape("control-plane commit shape is invalid"));
        }
        std::vector<std::vector<std::byte>> generations;
        generations.reserve(commit.state.generations.size());
        for (const auto &generation : commit.state.generations) {
            auto encoded = encode_control(generation);
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            generations.push_back(std::move(*encoded));
        }
        std::vector<std::vector<std::byte>> packs;
        packs.reserve(commit.state.packs.size());
        for (const auto &pack : commit.state.packs) {
            auto encoded = encode_control(pack);
            if (!encoded) {
                return std::unexpected(encoded.error());
            }
            packs.push_back(std::move(*encoded));
        }
        auto encoded_operation = encode_control(commit.operation);
        if (!encoded_operation) {
            return std::unexpected(encoded_operation.error());
        }
        const std::scoped_lock lock {impl_->mutex};
        if (auto started = begin(impl_->connection); !started) {
            return std::unexpected(started.error());
        }
        RollbackGuard guard {.connection = impl_->connection, .active = true};
        auto revision = execute_params(
            impl_->connection,
            "UPDATE re_control_meta SET storage_revision=$1::bigint "
            "WHERE singleton=1 AND storage_revision=$2::bigint RETURNING storage_revision",
            {std::to_string(commit.state.storage_revision), std::to_string(commit.expected_storage_revision)});
        if (!revision) {
            return std::unexpected(revision.error());
        }
        if (PQntuples(revision->value) != 1) {
            return std::unexpected(StoreError {.code = StoreErrorCode::conflict,
                                               .message = "control-plane storage revision changed",
                                               .retryable = true});
        }
        for (std::size_t index = 0; index < commit.state.generations.size(); ++index) {
            const auto &generation = commit.state.generations[index];
            auto updated = execute_params(
                impl_->connection,
                "INSERT INTO re_control_generations(pack_id,generation,phase,source_digest,semantic_hash,"
                "binding_hash,payload) VALUES($1,$2::bigint,$3::smallint,$4,$5,$6,$7::bytea) "
                "ON CONFLICT(pack_id,generation) DO UPDATE SET phase=excluded.phase,"
                "source_digest=excluded.source_digest,semantic_hash=excluded.semantic_hash,"
                "binding_hash=excluded.binding_hash,payload=excluded.payload",
                {generation.request.pack.value, std::to_string(generation.request.generation),
                 std::to_string(static_cast<std::uint8_t>(generation.phase)), generation.request.source_digest.value,
                 generation.semantic_hash, generation.binding_hash, bytea_text(generations[index])});
            if (!updated) {
                return std::unexpected(updated.error());
            }
        }
        for (std::size_t index = 0; index < commit.state.packs.size(); ++index) {
            const auto &pack = commit.state.packs[index];
            auto updated = execute_params(
                impl_->connection,
                "INSERT INTO re_control_packs(pack_id,resource_version,active_generation,assignment_fence,"
                "accepting_assignments,drain_boundary,drain_target,payload) "
                "VALUES($1,$2::bigint,NULLIF($3::text,'')::bigint,$4::bigint,$5::boolean,"
                "NULLIF($6::text,'')::bigint,NULLIF($7::text,'')::bigint,$8::bytea) "
                "ON CONFLICT(pack_id) DO UPDATE SET resource_version=excluded.resource_version,"
                "active_generation=excluded.active_generation,assignment_fence=excluded.assignment_fence,"
                "accepting_assignments=excluded.accepting_assignments,drain_boundary=excluded.drain_boundary,"
                "drain_target=excluded.drain_target,payload=excluded.payload",
                {pack.pack.value, std::to_string(pack.resource_version),
                 pack.active_generation ? std::to_string(*pack.active_generation) : std::string {},
                 std::to_string(pack.assignment_fence), pack.accepting_assignments ? "true" : "false",
                 pack.drain_boundary ? std::to_string(*pack.drain_boundary) : std::string {},
                 pack.drain_target ? std::to_string(*pack.drain_target) : std::string {}, bytea_text(packs[index])});
            if (!updated) {
                return std::unexpected(updated.error());
            }
        }
        auto existing_id = find_operation_unlocked(impl_->connection, true, commit.operation.operation_id);
        auto existing_key = find_operation_unlocked(impl_->connection, false, commit.operation.idempotency_key);
        if (!existing_id || !existing_key) {
            return std::unexpected(!existing_id ? existing_id.error() : existing_key.error());
        }
        const auto conflicts = [&](const std::optional<AdminOperationRecord> &existing) {
            return existing && (existing->operation_id != commit.operation.operation_id ||
                                existing->idempotency_key != commit.operation.idempotency_key ||
                                existing->request_fingerprint != commit.operation.request_fingerprint);
        };
        if (conflicts(*existing_id) || conflicts(*existing_key)) {
            return std::unexpected(
                postgres_control_shape("operation or idempotency identity conflicts with durable control-plane state"));
        }
        auto operation = execute_params(
            impl_->connection,
            "INSERT INTO re_control_operations(operation_id,idempotency_key,request_fingerprint,kind,phase,pack_id,"
            "target_generation,payload) VALUES($1,$2,$3::bytea,$4::smallint,$5::smallint,$6,$7::bigint,$8::bytea) "
            "ON CONFLICT(operation_id) DO UPDATE SET phase=excluded.phase,payload=excluded.payload",
            {commit.operation.operation_id, commit.operation.idempotency_key,
             bytea_text(commit.operation.request_fingerprint),
             std::to_string(static_cast<std::uint8_t>(commit.operation.kind)),
             std::to_string(static_cast<std::uint8_t>(commit.operation.phase)), commit.operation.pack.value,
             std::to_string(commit.operation.target_generation), bytea_text(*encoded_operation)});
        if (!operation) {
            return std::unexpected(operation.error());
        }
        auto audit = execute_params(impl_->connection,
                                    "INSERT INTO re_audit(at_unix_ms,actor,action,resource,outcome,detail) "
                                    "VALUES($1::bigint,$2,$3,$4,$5,$6)",
                                    {std::to_string(commit.audit.at_unix_ms), commit.audit.actor, commit.audit.action,
                                     commit.audit.resource, commit.audit.outcome, commit.audit.detail});
        if (!audit) {
            return std::unexpected(audit.error());
        }
        if (auto committed = commit_transaction(impl_->connection); !committed) {
            return std::unexpected(committed.error());
        }
        guard.active = false;
        return {};
#else
        static_cast<void>(commit);
        return std::unexpected(postgres_control_unavailable("PostgreSQL control plane is not connected"));
#endif
    }

    std::expected<ControlPlaneInspection, StoreError> PostgreSqlActivationControlStore::inspect() const {
#if defined(RULE_ENGINE_HAS_POSTGRESQL)
        const std::scoped_lock lock {impl_->mutex};
        auto state = load_state_unlocked(impl_->connection);
        if (!state) {
            return std::unexpected(state.error());
        }
        ControlPlaneInspection inspection {.state = std::move(*state), .operations = {}, .audit = {}};
        auto operations =
            execute(impl_->connection, "SELECT encode(payload,'hex') FROM re_control_operations ORDER BY operation_id");
        if (!operations) {
            return std::unexpected(operations.error());
        }
        for (int row = 0; row < PQntuples(operations->value); ++row) {
            auto decoded = decode_control<AdminOperationRecord>("\\x" + field(*operations, row, 0),
                                                                control_serialization::decode_operation);
            if (!decoded) {
                return std::unexpected(decoded.error());
            }
            inspection.operations.push_back(std::move(*decoded));
        }
        auto audit =
            execute(impl_->connection, "SELECT sequence,at_unix_ms,actor,action,resource,outcome,detail FROM re_audit "
                                       "WHERE action LIKE 'admin.%' ORDER BY sequence");
        if (!audit) {
            return std::unexpected(audit.error());
        }
        for (int row = 0; row < PQntuples(audit->value); ++row) {
            auto sequence = parse_unsigned(field(*audit, row, 0), "audit sequence");
            auto at = parse_unsigned(field(*audit, row, 1), "audit timestamp");
            if (!sequence || !at) {
                return std::unexpected(!sequence ? sequence.error() : at.error());
            }
            inspection.audit.push_back(AuditRecord {.sequence = *sequence,
                                                    .at_unix_ms = *at,
                                                    .actor = field(*audit, row, 2),
                                                    .action = field(*audit, row, 3),
                                                    .resource = field(*audit, row, 4),
                                                    .outcome = field(*audit, row, 5),
                                                    .detail = field(*audit, row, 6)});
        }
        return inspection;
#else
        return std::unexpected(postgres_control_unavailable("PostgreSQL control plane is not connected"));
#endif
    }

    RuntimeStoreHealth PostgreSqlActivationControlStore::health() const {
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
                                       .detail = "PostgreSQL activation control plane is not connected"};
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
