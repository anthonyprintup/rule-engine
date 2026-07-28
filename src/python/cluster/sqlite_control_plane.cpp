#include "rule_engine/python/cluster/control_plane.hpp"

#include "control_serialization.hpp"

#if defined(RULE_ENGINE_USE_WINSQLITE3)
#include <winsqlite/winsqlite3.h>
#else
#include <sqlite3.h>
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <mutex>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace rule_engine::python::cluster {
    namespace {

        constexpr std::uint32_t control_schema_version = 2;

        StoreError sqlite_control_error(sqlite3 *database, const int result, std::string context) {
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

        StoreError control_shape(std::string message) {
            return StoreError {
                .code = StoreErrorCode::constraint_violation, .message = std::move(message), .retryable = false};
        }

        std::expected<std::int64_t, StoreError> sqlite_integer(const std::uint64_t value, const std::string_view name) {
            if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                return std::unexpected(control_shape(std::string {name} + " exceeds the durable SQL integer range"));
            }
            return static_cast<std::int64_t>(value);
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
                return std::unexpected(sqlite_control_error(database, result, "failed to prepare control-plane SQL"));
            }
            return Statement {statement};
        }

        std::expected<void, StoreError> bind_text(sqlite3 *database, Statement &statement, const int index,
                                                  const std::string_view value) {
            const auto result = sqlite3_bind_text(statement.value, index, value.data(), static_cast<int>(value.size()),
                                                  SQLITE_TRANSIENT);
            if (result != SQLITE_OK) {
                return std::unexpected(sqlite_control_error(database, result, "failed to bind control-plane text"));
            }
            return {};
        }

        std::expected<void, StoreError> bind_blob(sqlite3 *database, Statement &statement, const int index,
                                                  const std::span<const std::byte> value) {
            const auto result = sqlite3_bind_blob(statement.value, index, value.data(), static_cast<int>(value.size()),
                                                  SQLITE_TRANSIENT);
            if (result != SQLITE_OK) {
                return std::unexpected(sqlite_control_error(database, result, "failed to bind control-plane blob"));
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
                return std::unexpected(sqlite_control_error(database, result, "failed to bind control-plane integer"));
            }
            return {};
        }

        std::expected<void, StoreError> expect_done(sqlite3 *database, Statement &statement) {
            const auto result = sqlite3_step(statement.value);
            if (result != SQLITE_DONE) {
                return std::unexpected(sqlite_control_error(database, result, "control-plane SQL mutation failed"));
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
            return std::unexpected(sqlite_control_error(database, result, "control-plane SQL query failed"));
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
            std::string detail = "control-plane SQL batch failed";
            if (message != nullptr) {
                detail += ": ";
                detail += message;
                sqlite3_free(message);
            }
            return std::unexpected(sqlite_control_error(database, result, std::move(detail)));
        }

        struct SqlTransaction {
            sqlite3 *database {};
            bool active {true};
            explicit SqlTransaction(sqlite3 *selected): database {selected} {}
            ~SqlTransaction() {
                if (active) {
                    static_cast<void>(execute(database, "ROLLBACK"));
                }
            }
            SqlTransaction(const SqlTransaction &) = delete;
            SqlTransaction &operator=(const SqlTransaction &) = delete;

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

        template<typename Value, typename Decode>
        std::expected<Value, StoreError> decode_control(const std::span<const std::byte> bytes, Decode decode) {
            auto value = decode(bytes);
            if (!value) {
                return std::unexpected(
                    StoreError {.code = StoreErrorCode::incompatible_schema,
                                .message = "stored control-plane payload is invalid: " + value.error().message,
                                .retryable = false});
            }
            return std::move(*value);
        }

        template<typename Value> std::expected<std::vector<std::byte>, StoreError> encode_control(const Value &value) {
            auto bytes = control_serialization::encode(value);
            if (!bytes) {
                return std::unexpected(control_shape("control-plane serialization failed: " + bytes.error().message));
            }
            return std::move(*bytes);
        }

        std::expected<void, StoreError> migrate(sqlite3 *database) {
            auto transaction = SqlTransaction::begin(database);
            if (!transaction) {
                return std::unexpected(transaction.error());
            }
            if (auto created = execute(
                    database, "CREATE TABLE IF NOT EXISTS re_control_schema_migrations("
                              "version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_unix_ms INTEGER NOT NULL)");
                !created) {
                return std::unexpected(created.error());
            }
            auto query = prepare(database, "SELECT COALESCE(MAX(version),0) FROM re_control_schema_migrations");
            if (!query) {
                return std::unexpected(query.error());
            }
            auto row = step_row(database, *query);
            if (!row) {
                return std::unexpected(row.error());
            }
            const auto current = static_cast<std::uint32_t>(sqlite3_column_int(query->value, 0));
            if (current > control_schema_version) {
                return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                                   .message = "control-plane schema is newer than this binary",
                                                   .retryable = false});
            }
            if (current == 0) {
                constexpr std::string_view schema = R"sql(
CREATE TABLE IF NOT EXISTS re_control_meta(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    storage_revision INTEGER NOT NULL CHECK(storage_revision>=0)
);
INSERT INTO re_control_meta(singleton,storage_revision) VALUES(1,0)
    ON CONFLICT(singleton) DO NOTHING;
CREATE TABLE IF NOT EXISTS re_control_generations(
    pack_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation>0),
    phase INTEGER NOT NULL,
    source_digest TEXT NOT NULL,
    semantic_hash TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    payload BLOB NOT NULL,
    PRIMARY KEY(pack_id,generation)
);
CREATE TABLE IF NOT EXISTS re_control_packs(
    pack_id TEXT PRIMARY KEY,
    resource_version INTEGER NOT NULL CHECK(resource_version>=0),
    active_generation INTEGER,
    assignment_fence INTEGER NOT NULL CHECK(assignment_fence>=0),
    accepting_assignments INTEGER NOT NULL CHECK(accepting_assignments IN (0,1)),
    drain_boundary INTEGER,
    drain_target INTEGER,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS re_control_operations(
    operation_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    request_fingerprint BLOB NOT NULL,
    kind INTEGER NOT NULL,
    phase INTEGER NOT NULL,
    pack_id TEXT NOT NULL,
    target_generation INTEGER NOT NULL,
    payload BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS re_control_operations_pack
    ON re_control_operations(pack_id,target_generation,operation_id);
CREATE TABLE IF NOT EXISTS re_audit(
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    at_unix_ms INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT NOT NULL
);
)sql";
                if (auto applied = execute(database, schema); !applied) {
                    return std::unexpected(applied.error());
                }
                auto record =
                    prepare(database, "INSERT INTO re_control_schema_migrations(version,name,applied_unix_ms) "
                                      "VALUES(1,'activation-control-foundation',"
                                      "CAST(strftime('%s','now') AS INTEGER)*1000)");
                if (!record) {
                    return std::unexpected(record.error());
                }
                if (auto inserted = expect_done(database, *record); !inserted) {
                    return std::unexpected(inserted.error());
                }
            }
            if (current < 2) {
                constexpr std::string_view node_schema = R"sql(
CREATE TABLE IF NOT EXISTS re_control_nodes(
    node_id TEXT PRIMARY KEY,
    platform_abi TEXT NOT NULL,
    lease_fence INTEGER NOT NULL CHECK(lease_fence>0),
    lease_until_unix_ms INTEGER NOT NULL CHECK(lease_until_unix_ms>0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms>0),
    serving INTEGER NOT NULL CHECK(serving IN (0,1)),
    payload BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS re_control_nodes_lease
    ON re_control_nodes(lease_until_unix_ms,node_id);
)sql";
                if (auto applied = execute(database, node_schema); !applied) {
                    return std::unexpected(applied.error());
                }
                auto record =
                    prepare(database, "INSERT INTO re_control_schema_migrations(version,name,applied_unix_ms) "
                                      "VALUES(2,'durable-resident-node-evidence',"
                                      "CAST(strftime('%s','now') AS INTEGER)*1000)");
                if (!record) {
                    return std::unexpected(record.error());
                }
                if (auto inserted = expect_done(database, *record); !inserted) {
                    return std::unexpected(inserted.error());
                }
            }
            return (*transaction)->commit();
        }

        std::expected<DurableControlState, StoreError> load_state_unlocked(sqlite3 *database) {
            DurableControlState state;
            auto meta = prepare(database, "SELECT storage_revision FROM re_control_meta WHERE singleton=1");
            if (!meta) {
                return std::unexpected(meta.error());
            }
            auto meta_row = step_row(database, *meta);
            if (!meta_row) {
                return std::unexpected(meta_row.error());
            }
            if (!*meta_row) {
                return std::unexpected(StoreError {.code = StoreErrorCode::incompatible_schema,
                                                   .message = "control-plane metadata row is missing",
                                                   .retryable = false});
            }
            state.storage_revision = static_cast<std::uint64_t>(sqlite3_column_int64(meta->value, 0));
            auto generations =
                prepare(database, "SELECT payload FROM re_control_generations ORDER BY pack_id,generation");
            if (!generations) {
                return std::unexpected(generations.error());
            }
            while (true) {
                auto row = step_row(database, *generations);
                if (!row) {
                    return std::unexpected(row.error());
                }
                if (!*row) {
                    break;
                }
                auto decoded = decode_control<GenerationSnapshot>(column_blob(*generations, 0),
                                                                  control_serialization::decode_generation);
                if (!decoded) {
                    return std::unexpected(decoded.error());
                }
                state.generations.push_back(std::move(*decoded));
            }
            auto packs = prepare(database, "SELECT payload FROM re_control_packs ORDER BY pack_id");
            if (!packs) {
                return std::unexpected(packs.error());
            }
            while (true) {
                auto row = step_row(database, *packs);
                if (!row) {
                    return std::unexpected(row.error());
                }
                if (!*row) {
                    break;
                }
                auto decoded = decode_control<DurablePackControlSnapshot>(column_blob(*packs, 0),
                                                                          control_serialization::decode_pack);
                if (!decoded) {
                    return std::unexpected(decoded.error());
                }
                state.packs.push_back(std::move(*decoded));
            }
            return state;
        }

        std::expected<std::optional<AdminOperationRecord>, StoreError>
        find_operation_unlocked(sqlite3 *database, const std::string_view column, const std::string_view value) {
            const auto sql = column == "operation_id" ?
                                 "SELECT payload FROM re_control_operations WHERE operation_id=?1" :
                                 "SELECT payload FROM re_control_operations WHERE idempotency_key=?1";
            auto statement = prepare(database, sql);
            if (!statement) {
                return std::unexpected(statement.error());
            }
            if (auto bound = bind_text(database, *statement, 1, value); !bound) {
                return std::unexpected(bound.error());
            }
            auto row = step_row(database, *statement);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                return std::optional<AdminOperationRecord> {};
            }
            auto decoded = decode_control<AdminOperationRecord>(column_blob(*statement, 0),
                                                                control_serialization::decode_operation);
            if (!decoded) {
                return std::unexpected(decoded.error());
            }
            return std::optional<AdminOperationRecord> {std::move(*decoded)};
        }

        std::expected<void, StoreError> bind_audit(sqlite3 *database, const AuditRecord &audit) {
            auto statement = prepare(database, "INSERT INTO re_audit(at_unix_ms,actor,action,resource,outcome,detail) "
                                               "VALUES(?1,?2,?3,?4,?5,?6)");
            if (!statement) {
                return std::unexpected(statement.error());
            }
            if (auto bound = bind_i64(database, *statement, 1, audit.at_unix_ms, "audit timestamp"); !bound) {
                return std::unexpected(bound.error());
            }
            const std::array values {std::string_view {audit.actor}, std::string_view {audit.action},
                                     std::string_view {audit.resource}, std::string_view {audit.outcome},
                                     std::string_view {audit.detail}};
            for (std::size_t index = 0; index < values.size(); ++index) {
                if (auto bound = bind_text(database, *statement, static_cast<int>(index + 2U), values[index]); !bound) {
                    return std::unexpected(bound.error());
                }
            }
            return expect_done(database, *statement);
        }

    } // namespace

    struct SqliteActivationControlStore::Impl {
        sqlite3 *database {};
        mutable std::mutex mutex;
        RuntimeStoreHealth status;
        ~Impl() {
            if (database != nullptr) {
                sqlite3_close_v2(database);
            }
        }
    };

    SqliteActivationControlStore::SqliteActivationControlStore(std::unique_ptr<Impl> impl): impl_ {std::move(impl)} {}

    std::expected<std::unique_ptr<SqliteActivationControlStore>, StoreError>
    SqliteActivationControlStore::open(const SqliteDevConfig &config) {
        if (config.deployment_mode != DeploymentMode::single_node_dev || config.server_processes != 1 ||
            config.remote_cluster || config.high_availability) {
            return std::unexpected(control_shape("SQLite control plane is restricted to one development process"));
        }
        if (config.database_path.empty() || !config.wal || !config.foreign_keys || config.busy_timeout.count() <= 0) {
            return std::unexpected(control_shape("SQLite path, WAL, foreign keys, and busy timeout are required"));
        }
        sqlite3 *database {};
        const auto opened =
            sqlite3_open_v2(config.database_path.c_str(), &database,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (opened != SQLITE_OK) {
            auto failure = sqlite_control_error(database, opened, "failed to open SQLite control-plane store");
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
        if (auto migrated = migrate(database); !migrated) {
            sqlite3_close_v2(database);
            return std::unexpected(migrated.error());
        }
        auto impl = std::make_unique<Impl>();
        impl->database = database;
        impl->status = RuntimeStoreHealth {.backend = StoreBackendKind::sqlite_dev,
                                           .driver_available = true,
                                           .connected = true,
                                           .migrations_compatible = true,
                                           .schema_version = control_schema_version,
                                           .server_version = sqlite3_libversion(),
                                           .detail = "SQLite durable activation control plane"};
        return std::unique_ptr<SqliteActivationControlStore>(new SqliteActivationControlStore {std::move(impl)});
    }

    SqliteActivationControlStore::~SqliteActivationControlStore() = default;

    std::expected<DurableControlState, StoreError> SqliteActivationControlStore::load_state() const {
        const std::scoped_lock lock {impl_->mutex};
        return load_state_unlocked(impl_->database);
    }

    std::expected<std::optional<AdminOperationRecord>, StoreError>
    SqliteActivationControlStore::find_operation(const std::string_view operation_id) const {
        const std::scoped_lock lock {impl_->mutex};
        return find_operation_unlocked(impl_->database, "operation_id", operation_id);
    }

    std::expected<std::optional<AdminOperationRecord>, StoreError>
    SqliteActivationControlStore::find_operation_by_idempotency(const std::string_view idempotency_key) const {
        const std::scoped_lock lock {impl_->mutex};
        return find_operation_unlocked(impl_->database, "idempotency_key", idempotency_key);
    }

    std::expected<void, StoreError> SqliteActivationControlStore::upsert_node(const DurableResidentNode &node) {
        if (node.node_id.empty() || node.platform_abi.empty() || node.lease_fence == 0 ||
            node.updated_at_unix_ms == 0 || node.lease_until_unix_ms <= node.updated_at_unix_ms ||
            !std::ranges::is_sorted(node.capability_hashes) ||
            std::ranges::adjacent_find(node.capability_hashes) != node.capability_hashes.end() ||
            std::ranges::any_of(node.capability_hashes, [](const auto &hash) { return hash.empty(); })) {
            return std::unexpected(control_shape("durable resident node shape is invalid"));
        }
        auto encoded = encode_control(node);
        if (!encoded) {
            return std::unexpected(encoded.error());
        }

        const std::scoped_lock lock {impl_->mutex};
        auto transaction = SqlTransaction::begin(impl_->database);
        if (!transaction) {
            return std::unexpected(transaction.error());
        }
        auto existing = prepare(impl_->database, "SELECT payload FROM re_control_nodes WHERE node_id=?1");
        if (!existing) {
            return std::unexpected(existing.error());
        }
        if (auto bound = bind_text(impl_->database, *existing, 1, node.node_id); !bound) {
            return std::unexpected(bound.error());
        }
        auto row = step_row(impl_->database, *existing);
        if (!row) {
            return std::unexpected(row.error());
        }
        if (*row) {
            auto previous =
                decode_control<DurableResidentNode>(column_blob(*existing, 0), control_serialization::decode_node);
            if (!previous) {
                return std::unexpected(previous.error());
            }
            if (node.lease_fence < previous->lease_fence || node.updated_at_unix_ms < previous->updated_at_unix_ms ||
                (node.lease_fence == previous->lease_fence &&
                 (node.platform_abi != previous->platform_abi ||
                  node.capability_hashes != previous->capability_hashes ||
                  node.lease_until_unix_ms < previous->lease_until_unix_ms))) {
                return std::unexpected(StoreError {.code = StoreErrorCode::stale_fence,
                                                   .message = "durable resident node evidence is stale or changed "
                                                              "within one lease fence",
                                                   .retryable = false});
            }
        }

        auto statement = prepare(
            impl_->database,
            "INSERT INTO re_control_nodes(node_id,platform_abi,lease_fence,lease_until_unix_ms,updated_at_unix_ms,"
            "serving,payload) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(node_id) DO UPDATE SET "
            "platform_abi=excluded.platform_abi,lease_fence=excluded.lease_fence,"
            "lease_until_unix_ms=excluded.lease_until_unix_ms,updated_at_unix_ms=excluded.updated_at_unix_ms,"
            "serving=excluded.serving,payload=excluded.payload");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 1, node.node_id); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_text(impl_->database, *statement, 2, node.platform_abi); !bound) {
            return std::unexpected(bound.error());
        }
        const std::array numbers {node.lease_fence, node.lease_until_unix_ms, node.updated_at_unix_ms};
        for (std::size_t index = 0; index < numbers.size(); ++index) {
            if (auto bound = bind_i64(impl_->database, *statement, static_cast<int>(index + 3U), numbers[index],
                                      "resident node value");
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        sqlite3_bind_int(statement->value, 6, node.serving ? 1 : 0);
        if (auto bound = bind_blob(impl_->database, *statement, 7, *encoded); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto updated = expect_done(impl_->database, *statement); !updated) {
            return std::unexpected(updated.error());
        }
        return (*transaction)->commit();
    }

    std::expected<std::vector<DurableResidentNode>, StoreError> SqliteActivationControlStore::node_snapshot() const {
        const std::scoped_lock lock {impl_->mutex};
        auto statement = prepare(impl_->database, "SELECT payload FROM re_control_nodes ORDER BY node_id");
        if (!statement) {
            return std::unexpected(statement.error());
        }
        std::vector<DurableResidentNode> nodes;
        while (true) {
            auto row = step_row(impl_->database, *statement);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                return nodes;
            }
            auto node =
                decode_control<DurableResidentNode>(column_blob(*statement, 0), control_serialization::decode_node);
            if (!node) {
                return std::unexpected(node.error());
            }
            nodes.push_back(std::move(*node));
        }
    }

    std::expected<void, StoreError> SqliteActivationControlStore::commit(const ControlPlaneCommit &commit) {
        if (commit.expected_storage_revision == std::numeric_limits<std::uint64_t>::max() ||
            commit.state.storage_revision != commit.expected_storage_revision + 1U ||
            commit.operation.operation_id.empty() || commit.operation.idempotency_key.empty() ||
            commit.operation.request_fingerprint.empty() || commit.audit.actor.empty() || commit.audit.action.empty()) {
            return std::unexpected(control_shape("control-plane commit shape is invalid"));
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
        auto transaction = SqlTransaction::begin(impl_->database);
        if (!transaction) {
            return std::unexpected(transaction.error());
        }
        auto revision = prepare(impl_->database, "UPDATE re_control_meta SET storage_revision=?1 "
                                                 "WHERE singleton=1 AND storage_revision=?2");
        if (!revision) {
            return std::unexpected(revision.error());
        }
        if (auto bound = bind_i64(impl_->database, *revision, 1, commit.state.storage_revision, "storage revision");
            !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound =
                bind_i64(impl_->database, *revision, 2, commit.expected_storage_revision, "expected storage revision");
            !bound) {
            return std::unexpected(bound.error());
        }
        if (auto updated = expect_done(impl_->database, *revision); !updated) {
            return std::unexpected(updated.error());
        }
        if (sqlite3_changes(impl_->database) != 1) {
            return std::unexpected(StoreError {.code = StoreErrorCode::conflict,
                                               .message = "control-plane storage revision changed",
                                               .retryable = true});
        }

        auto generation_statement = prepare(
            impl_->database,
            "INSERT INTO re_control_generations(pack_id,generation,phase,source_digest,semantic_hash,binding_hash,"
            "payload) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(pack_id,generation) DO UPDATE SET "
            "phase=excluded.phase,source_digest=excluded.source_digest,semantic_hash=excluded.semantic_hash,"
            "binding_hash=excluded.binding_hash,payload=excluded.payload");
        if (!generation_statement) {
            return std::unexpected(generation_statement.error());
        }
        for (std::size_t index = 0; index < commit.state.generations.size(); ++index) {
            const auto &generation = commit.state.generations[index];
            sqlite3_reset(generation_statement->value);
            sqlite3_clear_bindings(generation_statement->value);
            if (auto bound = bind_text(impl_->database, *generation_statement, 1, generation.request.pack.value);
                !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound =
                    bind_i64(impl_->database, *generation_statement, 2, generation.request.generation, "generation");
                !bound) {
                return std::unexpected(bound.error());
            }
            sqlite3_bind_int(generation_statement->value, 3, static_cast<int>(generation.phase));
            const std::array values {std::string_view {generation.request.source_digest.value},
                                     std::string_view {generation.semantic_hash},
                                     std::string_view {generation.binding_hash}};
            for (std::size_t value_index = 0; value_index < values.size(); ++value_index) {
                if (auto bound = bind_text(impl_->database, *generation_statement, static_cast<int>(value_index + 4U),
                                           values[value_index]);
                    !bound) {
                    return std::unexpected(bound.error());
                }
            }
            if (auto bound = bind_blob(impl_->database, *generation_statement, 7, generations[index]); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto updated = expect_done(impl_->database, *generation_statement); !updated) {
                return std::unexpected(updated.error());
            }
        }

        auto pack_statement =
            prepare(impl_->database,
                    "INSERT INTO re_control_packs(pack_id,resource_version,active_generation,assignment_fence,"
                    "accepting_assignments,drain_boundary,drain_target,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) "
                    "ON CONFLICT(pack_id) DO UPDATE SET resource_version=excluded.resource_version,"
                    "active_generation=excluded.active_generation,assignment_fence=excluded.assignment_fence,"
                    "accepting_assignments=excluded.accepting_assignments,drain_boundary=excluded.drain_boundary,"
                    "drain_target=excluded.drain_target,payload=excluded.payload");
        if (!pack_statement) {
            return std::unexpected(pack_statement.error());
        }
        for (std::size_t index = 0; index < commit.state.packs.size(); ++index) {
            const auto &pack = commit.state.packs[index];
            sqlite3_reset(pack_statement->value);
            sqlite3_clear_bindings(pack_statement->value);
            if (auto bound = bind_text(impl_->database, *pack_statement, 1, pack.pack.value); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_i64(impl_->database, *pack_statement, 2, pack.resource_version, "pack version");
                !bound) {
                return std::unexpected(bound.error());
            }
            if (pack.active_generation) {
                if (auto bound =
                        bind_i64(impl_->database, *pack_statement, 3, *pack.active_generation, "active generation");
                    !bound) {
                    return std::unexpected(bound.error());
                }
            } else {
                sqlite3_bind_null(pack_statement->value, 3);
            }
            if (auto bound = bind_i64(impl_->database, *pack_statement, 4, pack.assignment_fence, "assignment fence");
                !bound) {
                return std::unexpected(bound.error());
            }
            sqlite3_bind_int(pack_statement->value, 5, pack.accepting_assignments ? 1 : 0);
            const auto bind_optional =
                [&](const int parameter, const std::optional<std::uint64_t> value) -> std::expected<void, StoreError> {
                if (!value) {
                    sqlite3_bind_null(pack_statement->value, parameter);
                    return {};
                }
                return bind_i64(impl_->database, *pack_statement, parameter, *value, "pack control value");
            };
            if (auto bound = bind_optional(6, pack.drain_boundary); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_optional(7, pack.drain_target); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto bound = bind_blob(impl_->database, *pack_statement, 8, packs[index]); !bound) {
                return std::unexpected(bound.error());
            }
            if (auto updated = expect_done(impl_->database, *pack_statement); !updated) {
                return std::unexpected(updated.error());
            }
        }

        auto existing_id = find_operation_unlocked(impl_->database, "operation_id", commit.operation.operation_id);
        auto existing_key =
            find_operation_unlocked(impl_->database, "idempotency_key", commit.operation.idempotency_key);
        if (!existing_id || !existing_key) {
            return std::unexpected(!existing_id ? existing_id.error() : existing_key.error());
        }
        const auto conflicts = [&](const std::optional<AdminOperationRecord> &existing) {
            return existing && (existing->operation_id != commit.operation.operation_id ||
                                existing->idempotency_key != commit.operation.idempotency_key ||
                                existing->request_fingerprint != commit.operation.request_fingerprint);
        };
        if (conflicts(*existing_id) || conflicts(*existing_key)) {
            return std::unexpected(control_shape("operation or idempotency identity conflicts with durable state"));
        }
        auto operation_statement = prepare(
            impl_->database,
            "INSERT INTO re_control_operations(operation_id,idempotency_key,request_fingerprint,kind,phase,pack_id,"
            "target_generation,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) "
            "ON CONFLICT(operation_id) DO UPDATE SET phase=excluded.phase,payload=excluded.payload");
        if (!operation_statement) {
            return std::unexpected(operation_statement.error());
        }
        const std::array operation_values {std::string_view {commit.operation.operation_id},
                                           std::string_view {commit.operation.idempotency_key}};
        for (std::size_t index = 0; index < operation_values.size(); ++index) {
            if (auto bound = bind_text(impl_->database, *operation_statement, static_cast<int>(index + 1U),
                                       operation_values[index]);
                !bound) {
                return std::unexpected(bound.error());
            }
        }
        if (auto bound = bind_blob(impl_->database, *operation_statement, 3, commit.operation.request_fingerprint);
            !bound) {
            return std::unexpected(bound.error());
        }
        sqlite3_bind_int(operation_statement->value, 4, static_cast<int>(commit.operation.kind));
        sqlite3_bind_int(operation_statement->value, 5, static_cast<int>(commit.operation.phase));
        if (auto bound = bind_text(impl_->database, *operation_statement, 6, commit.operation.pack.value); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_i64(impl_->database, *operation_statement, 7, commit.operation.target_generation,
                                  "operation generation");
            !bound) {
            return std::unexpected(bound.error());
        }
        if (auto bound = bind_blob(impl_->database, *operation_statement, 8, *encoded_operation); !bound) {
            return std::unexpected(bound.error());
        }
        if (auto updated = expect_done(impl_->database, *operation_statement); !updated) {
            return std::unexpected(updated.error());
        }
        if (auto audited = bind_audit(impl_->database, commit.audit); !audited) {
            return std::unexpected(audited.error());
        }
        return (*transaction)->commit();
    }

    std::expected<ControlPlaneInspection, StoreError> SqliteActivationControlStore::inspect() const {
        const std::scoped_lock lock {impl_->mutex};
        auto state = load_state_unlocked(impl_->database);
        if (!state) {
            return std::unexpected(state.error());
        }
        ControlPlaneInspection result {.state = std::move(*state), .operations = {}, .audit = {}};
        auto operations = prepare(impl_->database, "SELECT payload FROM re_control_operations ORDER BY operation_id");
        if (!operations) {
            return std::unexpected(operations.error());
        }
        while (true) {
            auto row = step_row(impl_->database, *operations);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                break;
            }
            auto decoded = decode_control<AdminOperationRecord>(column_blob(*operations, 0),
                                                                control_serialization::decode_operation);
            if (!decoded) {
                return std::unexpected(decoded.error());
            }
            result.operations.push_back(std::move(*decoded));
        }
        auto audit =
            prepare(impl_->database, "SELECT sequence,at_unix_ms,actor,action,resource,outcome,detail FROM re_audit "
                                     "WHERE action LIKE 'admin.%' ORDER BY sequence");
        if (!audit) {
            return std::unexpected(audit.error());
        }
        while (true) {
            auto row = step_row(impl_->database, *audit);
            if (!row) {
                return std::unexpected(row.error());
            }
            if (!*row) {
                break;
            }
            result.audit.push_back(AuditRecord {
                .sequence = static_cast<std::uint64_t>(sqlite3_column_int64(audit->value, 0)),
                .at_unix_ms = static_cast<std::uint64_t>(sqlite3_column_int64(audit->value, 1)),
                .actor = column_text(*audit, 2),
                .action = column_text(*audit, 3),
                .resource = column_text(*audit, 4),
                .outcome = column_text(*audit, 5),
                .detail = column_text(*audit, 6),
            });
        }
        return result;
    }

    RuntimeStoreHealth SqliteActivationControlStore::health() const {
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
