#include "rule_engine/python/protocol/spool.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <mutex>
#include <string_view>
#include <type_traits>
#include <utility>

#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
#if RULE_ENGINE_PROTOCOL_USE_WINSQLITE
#include <winsqlite/winsqlite3.h>
#else
#include <sqlite3.h>
#endif
#endif

namespace rule_engine::python::protocol_v2 {
    namespace {

        [[nodiscard]] ProtocolError spool_error(const ProtocolErrorCode code, std::string message) {
            return ProtocolError {.code = code, .message = std::move(message), .byte_offset = 0};
        }

        [[nodiscard]] MessageKind durable_kind(const DurableAgentBody &body) noexcept {
            return std::visit(
                [](const auto &value) {
                    using Type = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::same_as<Type, WorkResultMessage>) {
                        return MessageKind::work_result;
                    } else if constexpr (std::same_as<Type, AuthoritativeSnapshotBegin>) {
                        return MessageKind::snapshot_begin;
                    } else if constexpr (std::same_as<Type, AuthoritativeSnapshotChunk>) {
                        return MessageKind::snapshot_chunk;
                    } else {
                        return MessageKind::snapshot_commit;
                    }
                },
                body);
        }

#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        struct Statement {
            sqlite3_stmt *value {};

            Statement() = default;
            Statement(const Statement &) = delete;
            Statement &operator=(const Statement &) = delete;
            Statement(Statement &&other) noexcept: value {std::exchange(other.value, nullptr)} {}
            Statement &operator=(Statement &&) = delete;
            ~Statement() {
                if (value != nullptr) {
                    sqlite3_finalize(value);
                }
            }
        };

        [[nodiscard]] std::expected<Statement, ProtocolError> prepare(sqlite3 *database, const char *sql) {
            Statement statement;
            if (sqlite3_prepare_v2(database, sql, -1, &statement.value, nullptr) != SQLITE_OK) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite statement preparation failed"));
            }
            return statement;
        }

        [[nodiscard]] std::expected<void, ProtocolError> execute(sqlite3 *database, const char *sql) {
            char *diagnostic {};
            const auto result = sqlite3_exec(database, sql, nullptr, nullptr, &diagnostic);
            if (diagnostic != nullptr) {
                sqlite3_free(diagnostic);
            }
            if (result != SQLITE_OK) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite transaction or schema operation failed"));
            }
            return {};
        }

        [[nodiscard]] std::expected<std::string, ProtocolError> meta_value(sqlite3 *database, const char *key) {
            auto statement = prepare(database, "SELECT value FROM spool_meta WHERE key = ?1");
            if (!statement) {
                return std::unexpected(std::move(statement.error()));
            }
            if (sqlite3_bind_text(statement->value, 1, key, -1, SQLITE_STATIC) != SQLITE_OK ||
                sqlite3_step(statement->value) != SQLITE_ROW) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite spool metadata is missing"));
            }
            const auto *text = sqlite3_column_text(statement->value, 0);
            const auto size = sqlite3_column_bytes(statement->value, 0);
            if (text == nullptr || size < 0) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite spool metadata is invalid"));
            }
            return std::string {reinterpret_cast<const char *>(text), static_cast<std::size_t>(size)};
        }

        [[nodiscard]] std::expected<std::uint64_t, ProtocolError> parse_u64(const std::string_view value) {
            std::uint64_t result {};
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
            if (parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size()) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite spool numeric metadata is invalid"));
            }
            return result;
        }

        [[nodiscard]] std::expected<void, ProtocolError> set_meta_u64(sqlite3 *database, const char *key,
                                                                      const std::uint64_t value) {
            auto statement = prepare(database, "UPDATE spool_meta SET value = ?2 WHERE key = ?1");
            if (!statement) {
                return std::unexpected(std::move(statement.error()));
            }
            std::array<char, 32> encoded {};
            const auto result = std::to_chars(encoded.data(), encoded.data() + encoded.size(), value);
            if (result.ec != std::errc {} ||
                sqlite3_bind_text(statement->value, 1, key, -1, SQLITE_STATIC) != SQLITE_OK ||
                sqlite3_bind_text(statement->value, 2, encoded.data(), static_cast<int>(result.ptr - encoded.data()),
                                  SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_step(statement->value) != SQLITE_DONE || sqlite3_changes(database) != 1) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite spool metadata update failed"));
            }
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError> begin(sqlite3 *database) {
            return execute(database, "BEGIN IMMEDIATE");
        }

        [[nodiscard]] std::expected<void, ProtocolError> commit(sqlite3 *database) {
            return execute(database, "COMMIT");
        }

        void rollback(sqlite3 *database) noexcept { sqlite3_exec(database, "ROLLBACK", nullptr, nullptr, nullptr); }
#endif

    } // namespace

    struct SqliteAgentSpool::Impl {
        std::string database_path;
        AgentSpoolLimits limits;
        ProtocolLimits protocol_limits;
        std::string epoch;
        std::uint64_t next_sequence {1};
        std::uint64_t acknowledged_through {};
        std::size_t records {};
        std::size_t bytes {};
        bool backpressured {};
        mutable std::mutex writer;
#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        sqlite3 *database {};

        ~Impl() {
            if (database != nullptr) {
                sqlite3_close_v2(database);
            }
        }

        [[nodiscard]] std::expected<void, ProtocolError> refresh_locked() {
            auto loaded_epoch = meta_value(database, "agent_epoch");
            auto loaded_next = meta_value(database, "next_sequence");
            auto loaded_ack = meta_value(database, "acknowledged_through");
            auto loaded_backpressure = meta_value(database, "backpressured");
            if (!loaded_epoch || !loaded_next || !loaded_ack || !loaded_backpressure) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite spool metadata cannot be loaded"));
            }
            auto parsed_next = parse_u64(*loaded_next);
            auto parsed_ack = parse_u64(*loaded_ack);
            auto parsed_backpressure = parse_u64(*loaded_backpressure);
            if (!parsed_next || !parsed_ack || !parsed_backpressure || loaded_epoch->size() != 32 ||
                *parsed_next == 0 || *parsed_ack >= *parsed_next || *parsed_backpressure > 1) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite spool metadata is inconsistent"));
            }

            auto totals = prepare(
                database, "SELECT count(*), coalesce(sum(encoded_bytes), 0) FROM spool_outbound WHERE epoch = ?1");
            if (!totals ||
                sqlite3_bind_text(totals->value, 1, loaded_epoch->c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_step(totals->value) != SQLITE_ROW) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite spool totals cannot be loaded"));
            }
            const auto row_count = sqlite3_column_int64(totals->value, 0);
            const auto byte_count = sqlite3_column_int64(totals->value, 1);
            if (row_count < 0 || byte_count < 0) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite spool totals exceed local bounds"));
            }
            epoch = std::move(*loaded_epoch);
            next_sequence = *parsed_next;
            acknowledged_through = *parsed_ack;
            backpressured = *parsed_backpressure != 0;
            records = static_cast<std::size_t>(row_count);
            bytes = static_cast<std::size_t>(byte_count);
            return {};
        }

        [[nodiscard]] std::expected<void, ProtocolError> update_backpressure_locked() {
            auto desired = backpressured;
            if (desired) {
                desired = bytes > limits.low_water_bytes;
            } else {
                desired = bytes >= limits.high_water_bytes || records >= limits.maximum_records;
            }
            if (desired == backpressured) {
                return {};
            }
            if (auto updated = set_meta_u64(database, "backpressured", desired ? 1 : 0); !updated) {
                return updated;
            }
            backpressured = desired;
            return {};
        }
#endif
    };

    SpoolBackendStatus spool_backend_status() noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        return SpoolBackendStatus {.available = true,
                                   .implementation = sqlite3_libversion(),
                                   .diagnostic = "SQLite WAL durable spool backend is linked"};
#else
        return SpoolBackendStatus {.available = false,
                                   .implementation = {},
                                   .diagnostic = "SQLite was not found when the protocol component was configured"};
#endif
    }

    SqliteAgentSpool::SqliteAgentSpool(std::unique_ptr<Impl> impl) noexcept: impl_ {std::move(impl)} {}
    SqliteAgentSpool::SqliteAgentSpool(SqliteAgentSpool &&) noexcept = default;
    SqliteAgentSpool &SqliteAgentSpool::operator=(SqliteAgentSpool &&) noexcept = default;
    SqliteAgentSpool::~SqliteAgentSpool() = default;

    std::expected<SqliteAgentSpool, ProtocolError>
    SqliteAgentSpool::open(std::string database_path, const AgentSpoolLimits limits,
                           const ProtocolLimits protocol_limits) noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        if (database_path.empty() || limits.maximum_records == 0 || limits.maximum_bytes == 0 ||
            limits.low_water_bytes > limits.high_water_bytes || limits.high_water_bytes > limits.maximum_bytes) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::malformed, "SQLite spool path or limits are invalid"));
        }
        auto impl = std::make_unique<Impl>();
        impl->database_path = std::move(database_path);
        impl->limits = limits;
        impl->protocol_limits = protocol_limits;
        if (sqlite3_open_v2(impl->database_path.c_str(), &impl->database,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK ||
            impl->database == nullptr) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::persistence_error, "SQLite spool database cannot be opened"));
        }
        sqlite3_extended_result_codes(impl->database, 1);
        sqlite3_busy_timeout(impl->database, 5'000);

        auto journal = prepare(impl->database, "PRAGMA journal_mode=WAL");
        if (!journal || sqlite3_step(journal->value) != SQLITE_ROW) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::persistence_error, "SQLite WAL mode cannot be enabled"));
        }
        const auto *mode = sqlite3_column_text(journal->value, 0);
        if (mode == nullptr || std::string_view {reinterpret_cast<const char *>(mode)} != "wal") {
            return std::unexpected(
                spool_error(ProtocolErrorCode::persistence_error, "SQLite spool requires a file-backed WAL database"));
        }
        if (auto configured = execute(
                impl->database, "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=1000;");
            !configured) {
            return std::unexpected(std::move(configured.error()));
        }
        if (auto created =
                execute(impl->database,
                        "CREATE TABLE IF NOT EXISTS spool_meta ("
                        " key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL"
                        ") WITHOUT ROWID;"
                        "CREATE TABLE IF NOT EXISTS spool_outbound ("
                        " sequence INTEGER PRIMARY KEY CHECK(sequence > 0),"
                        " epoch TEXT NOT NULL, kind INTEGER NOT NULL CHECK(kind BETWEEN 4 AND 8),"
                        " payload BLOB NOT NULL, encoded_bytes INTEGER NOT NULL CHECK(encoded_bytes > 0),"
                        " created_unix_seconds INTEGER NOT NULL, transmit_attempts INTEGER NOT NULL DEFAULT 0"
                        ");"
                        "CREATE INDEX IF NOT EXISTS spool_outbound_epoch_sequence ON spool_outbound(epoch, sequence);"
                        "CREATE TABLE IF NOT EXISTS spool_quarantine ("
                        " epoch TEXT NOT NULL, sequence INTEGER NOT NULL, kind INTEGER NOT NULL, payload BLOB NOT NULL,"
                        " encoded_bytes INTEGER NOT NULL, transmit_attempts INTEGER NOT NULL, reason INTEGER NOT NULL,"
                        " diagnostic TEXT NOT NULL, quarantined_unix_seconds INTEGER NOT NULL,"
                        " PRIMARY KEY(epoch, sequence)"
                        ") WITHOUT ROWID;"
                        "INSERT OR IGNORE INTO spool_meta(key, value) VALUES"
                        " ('agent_epoch', lower(hex(randomblob(16)))), ('next_sequence', '1'),"
                        " ('acknowledged_through', '0'), ('backpressured', '0');");
            !created) {
            return std::unexpected(std::move(created.error()));
        }
        if (auto refreshed = impl->refresh_locked(); !refreshed) {
            return std::unexpected(std::move(refreshed.error()));
        }
        return SqliteAgentSpool {std::move(impl)};
#else
        static_cast<void>(database_path);
        static_cast<void>(limits);
        static_cast<void>(protocol_limits);
        return std::unexpected(spool_error(ProtocolErrorCode::dependency_unavailable,
                                           "durable agent spooling is unavailable because SQLite was not linked"));
#endif
    }

    const std::string &SqliteAgentSpool::agent_epoch() const noexcept { return impl_->epoch; }
    std::uint64_t SqliteAgentSpool::next_sequence() const noexcept {
        return impl_ == nullptr ? 0 : impl_->next_sequence;
    }
    std::uint64_t SqliteAgentSpool::acknowledged_through() const noexcept {
        return impl_ == nullptr ? 0 : impl_->acknowledged_through;
    }
    std::size_t SqliteAgentSpool::pending_records() const noexcept { return impl_ == nullptr ? 0 : impl_->records; }
    std::size_t SqliteAgentSpool::pending_bytes() const noexcept { return impl_ == nullptr ? 0 : impl_->bytes; }
    bool SqliteAgentSpool::backpressured() const noexcept { return impl_ != nullptr && impl_->backpressured; }

    std::expected<std::uint64_t, ProtocolError> SqliteAgentSpool::enqueue(const DurableAgentBody &body) noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        if (impl_ == nullptr) {
            return std::unexpected(spool_error(ProtocolErrorCode::persistence_error, "SQLite spool is not open"));
        }
        auto encoded = encode_durable_body(body, impl_->protocol_limits);
        if (!encoded) {
            return std::unexpected(std::move(encoded.error()));
        }
        std::scoped_lock lock {impl_->writer};
        if (auto refreshed = impl_->refresh_locked(); !refreshed) {
            return std::unexpected(std::move(refreshed.error()));
        }
        if (encoded->size() > impl_->limits.maximum_bytes || impl_->records >= impl_->limits.maximum_records ||
            encoded->size() > impl_->limits.maximum_bytes - impl_->bytes ||
            impl_->next_sequence > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            impl_->backpressured = true;
            static_cast<void>(set_meta_u64(impl_->database, "backpressured", 1));
            return std::unexpected(spool_error(ProtocolErrorCode::backpressured, "SQLite spool hard limit is reached"));
        }
        if (auto started = begin(impl_->database); !started) {
            return std::unexpected(std::move(started.error()));
        }
        const auto sequence = impl_->next_sequence;
        auto insert =
            prepare(impl_->database, "INSERT INTO spool_outbound(sequence, epoch, kind, payload, encoded_bytes, "
                                     "created_unix_seconds, transmit_attempts) "
                                     "VALUES(?1, ?2, ?3, ?4, ?5, cast(strftime('%s','now') AS INTEGER), 0)");
        const auto bound =
            insert && sqlite3_bind_int64(insert->value, 1, static_cast<sqlite3_int64>(sequence)) == SQLITE_OK &&
            sqlite3_bind_text(insert->value, 2, impl_->epoch.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_bind_int(insert->value, 3, static_cast<int>(durable_kind(body))) == SQLITE_OK &&
            sqlite3_bind_blob(insert->value, 4, encoded->data(), static_cast<int>(encoded->size()), SQLITE_TRANSIENT) ==
                SQLITE_OK &&
            sqlite3_bind_int64(insert->value, 5, static_cast<sqlite3_int64>(encoded->size())) == SQLITE_OK &&
            sqlite3_step(insert->value) == SQLITE_DONE;
        if (!bound || !set_meta_u64(impl_->database, "next_sequence", sequence + 1)) {
            rollback(impl_->database);
            return std::unexpected(
                spool_error(ProtocolErrorCode::persistence_error, "SQLite spool enqueue transaction failed"));
        }
        if (auto committed = commit(impl_->database); !committed) {
            rollback(impl_->database);
            return std::unexpected(std::move(committed.error()));
        }
        if (auto refreshed = impl_->refresh_locked(); !refreshed) {
            return std::unexpected(std::move(refreshed.error()));
        }
        if (auto pressure = impl_->update_backpressure_locked(); !pressure) {
            return std::unexpected(std::move(pressure.error()));
        }
        return sequence;
#else
        static_cast<void>(body);
        return std::unexpected(spool_error(ProtocolErrorCode::dependency_unavailable,
                                           "durable agent spooling is unavailable because SQLite was not linked"));
#endif
    }

    std::expected<std::vector<std::uint64_t>, ProtocolError>
    SqliteAgentSpool::enqueue_batch(const std::span<const DurableAgentBody> bodies) noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        if (impl_ == nullptr) {
            return std::unexpected(spool_error(ProtocolErrorCode::persistence_error, "SQLite spool is not open"));
        }
        if (bodies.empty()) {
            return std::vector<std::uint64_t> {};
        }
        std::vector<std::vector<std::byte>> encoded;
        encoded.reserve(bodies.size());
        std::size_t total_bytes {};
        for (const auto &body : bodies) {
            auto value = encode_durable_body(body, impl_->protocol_limits);
            if (!value) {
                return std::unexpected(std::move(value.error()));
            }
            if (value->size() > impl_->limits.maximum_bytes - (std::min) (total_bytes, impl_->limits.maximum_bytes)) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::backpressured, "SQLite spool batch exceeds the byte limit"));
            }
            total_bytes += value->size();
            encoded.push_back(std::move(*value));
        }

        std::scoped_lock lock {impl_->writer};
        if (auto refreshed = impl_->refresh_locked(); !refreshed) {
            return std::unexpected(std::move(refreshed.error()));
        }
        if (bodies.size() >
                impl_->limits.maximum_records - (std::min) (impl_->records, impl_->limits.maximum_records) ||
            total_bytes > impl_->limits.maximum_bytes - (std::min) (impl_->bytes, impl_->limits.maximum_bytes) ||
            impl_->next_sequence > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) -
                                       static_cast<std::uint64_t>(bodies.size() - 1U)) {
            impl_->backpressured = true;
            static_cast<void>(set_meta_u64(impl_->database, "backpressured", 1));
            return std::unexpected(spool_error(ProtocolErrorCode::backpressured, "SQLite spool hard limit is reached"));
        }
        if (auto started = begin(impl_->database); !started) {
            return std::unexpected(std::move(started.error()));
        }
        auto insert =
            prepare(impl_->database, "INSERT INTO spool_outbound(sequence, epoch, kind, payload, encoded_bytes, "
                                     "created_unix_seconds, transmit_attempts) "
                                     "VALUES(?1, ?2, ?3, ?4, ?5, cast(strftime('%s','now') AS INTEGER), 0)");
        if (!insert) {
            rollback(impl_->database);
            return std::unexpected(std::move(insert.error()));
        }
        std::vector<std::uint64_t> sequences;
        sequences.reserve(bodies.size());
        for (std::size_t index = 0U; index < bodies.size(); ++index) {
            const auto sequence = impl_->next_sequence + index;
            const auto &payload = encoded[index];
            const auto bound =
                sqlite3_reset(insert->value) == SQLITE_OK && sqlite3_clear_bindings(insert->value) == SQLITE_OK &&
                sqlite3_bind_int64(insert->value, 1, static_cast<sqlite3_int64>(sequence)) == SQLITE_OK &&
                sqlite3_bind_text(insert->value, 2, impl_->epoch.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK &&
                sqlite3_bind_int(insert->value, 3, static_cast<int>(durable_kind(bodies[index]))) == SQLITE_OK &&
                sqlite3_bind_blob(insert->value, 4, payload.data(), static_cast<int>(payload.size()),
                                  SQLITE_TRANSIENT) == SQLITE_OK &&
                sqlite3_bind_int64(insert->value, 5, static_cast<sqlite3_int64>(payload.size())) == SQLITE_OK &&
                sqlite3_step(insert->value) == SQLITE_DONE;
            if (!bound) {
                rollback(impl_->database);
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite spool batch insert failed"));
            }
            sequences.push_back(sequence);
        }
        if (!set_meta_u64(impl_->database, "next_sequence", impl_->next_sequence + bodies.size())) {
            rollback(impl_->database);
            return std::unexpected(
                spool_error(ProtocolErrorCode::persistence_error, "SQLite spool batch metadata update failed"));
        }
        if (auto committed = commit(impl_->database); !committed) {
            rollback(impl_->database);
            return std::unexpected(std::move(committed.error()));
        }
        if (auto refreshed = impl_->refresh_locked(); !refreshed) {
            return std::unexpected(std::move(refreshed.error()));
        }
        if (auto pressure = impl_->update_backpressure_locked(); !pressure) {
            return std::unexpected(std::move(pressure.error()));
        }
        return sequences;
#else
        static_cast<void>(bodies);
        return std::unexpected(spool_error(ProtocolErrorCode::dependency_unavailable,
                                           "durable agent spooling is unavailable because SQLite was not linked"));
#endif
    }

    std::expected<std::vector<StoredSpoolRecord>, ProtocolError>
    SqliteAgentSpool::pending(const std::size_t maximum_records, const std::size_t maximum_bytes) const noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        if (impl_ == nullptr || maximum_records == 0 || maximum_bytes == 0) {
            return std::vector<StoredSpoolRecord> {};
        }
        std::scoped_lock lock {impl_->writer};
        auto query =
            prepare(impl_->database, "SELECT sequence, payload, encoded_bytes, transmit_attempts FROM spool_outbound "
                                     "WHERE epoch = ?1 ORDER BY sequence LIMIT ?2");
        if (!query || sqlite3_bind_text(query->value, 1, impl_->epoch.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
            sqlite3_bind_int64(query->value, 2,
                               static_cast<sqlite3_int64>(std::min<std::size_t>(
                                   maximum_records, std::numeric_limits<std::int64_t>::max()))) != SQLITE_OK) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::persistence_error, "SQLite pending spool query failed"));
        }
        std::vector<StoredSpoolRecord> result;
        result.reserve(maximum_records);
        std::size_t total {};
        for (;;) {
            const auto stepped = sqlite3_step(query->value);
            if (stepped == SQLITE_DONE) {
                break;
            }
            if (stepped != SQLITE_ROW) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite pending spool read failed"));
            }
            const auto sequence = sqlite3_column_int64(query->value, 0);
            const auto *payload = static_cast<const std::byte *>(sqlite3_column_blob(query->value, 1));
            const auto payload_size = sqlite3_column_bytes(query->value, 1);
            const auto encoded_size = sqlite3_column_int64(query->value, 2);
            const auto attempts = sqlite3_column_int64(query->value, 3);
            if (sequence <= 0 || payload == nullptr || payload_size <= 0 || encoded_size != payload_size ||
                attempts < 0 || static_cast<std::uint64_t>(attempts) > std::numeric_limits<std::uint32_t>::max()) {
                return std::unexpected(
                    spool_error(ProtocolErrorCode::persistence_error, "SQLite pending spool row is corrupt"));
            }
            const auto row_size = static_cast<std::size_t>(payload_size);
            if (row_size > maximum_bytes - total) {
                break;
            }
            std::vector<std::byte> canonical(payload, payload + row_size);
            auto body = decode_durable_body(canonical, impl_->protocol_limits);
            if (!body) {
                return std::unexpected(spool_error(ProtocolErrorCode::persistence_error,
                                                   "SQLite pending spool payload is not canonical protocol data"));
            }
            total += row_size;
            result.push_back(StoredSpoolRecord {
                .sequence = static_cast<std::uint64_t>(sequence),
                .body = std::move(*body),
                .canonical_body = std::move(canonical),
                .encoded_bytes = row_size,
                .transmit_attempts = static_cast<std::uint32_t>(attempts),
            });
        }
        return result;
#else
        static_cast<void>(maximum_records);
        static_cast<void>(maximum_bytes);
        return std::unexpected(spool_error(ProtocolErrorCode::dependency_unavailable,
                                           "durable agent spooling is unavailable because SQLite was not linked"));
#endif
    }

    std::expected<void, ProtocolError> SqliteAgentSpool::mark_transmitted(const std::uint64_t sequence) noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        if (impl_ == nullptr || sequence == 0 || sequence >= impl_->next_sequence) {
            return std::unexpected(spool_error(ProtocolErrorCode::sequence_gap, "spool transmit sequence is invalid"));
        }
        std::scoped_lock lock {impl_->writer};
        auto update = prepare(impl_->database, "UPDATE spool_outbound SET transmit_attempts = transmit_attempts + 1 "
                                               "WHERE epoch = ?1 AND sequence = ?2");
        if (!update || sqlite3_bind_text(update->value, 1, impl_->epoch.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
            sqlite3_bind_int64(update->value, 2, static_cast<sqlite3_int64>(sequence)) != SQLITE_OK ||
            sqlite3_step(update->value) != SQLITE_DONE || sqlite3_changes(impl_->database) != 1) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::sequence_gap, "spool transmit sequence is not pending"));
        }
        return {};
#else
        static_cast<void>(sequence);
        return std::unexpected(spool_error(ProtocolErrorCode::dependency_unavailable,
                                           "durable agent spooling is unavailable because SQLite was not linked"));
#endif
    }

    std::expected<void, ProtocolError> SqliteAgentSpool::acknowledge(const std::string_view agent_epoch,
                                                                     const std::uint64_t through) noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        if (impl_ == nullptr || agent_epoch != impl_->epoch) {
            return std::unexpected(spool_error(ProtocolErrorCode::stale_session, "spool ACK epoch is stale"));
        }
        std::scoped_lock lock {impl_->writer};
        if (through >= impl_->next_sequence) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::sequence_gap, "spool ACK exceeds the allocated sequence"));
        }
        if (through <= impl_->acknowledged_through) {
            return {};
        }
        if (auto started = begin(impl_->database); !started) {
            return std::unexpected(std::move(started.error()));
        }
        auto remove = prepare(impl_->database, "DELETE FROM spool_outbound WHERE epoch = ?1 AND sequence <= ?2");
        const auto deleted =
            remove && sqlite3_bind_text(remove->value, 1, impl_->epoch.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_bind_int64(remove->value, 2, static_cast<sqlite3_int64>(through)) == SQLITE_OK &&
            sqlite3_step(remove->value) == SQLITE_DONE;
        if (!deleted || !set_meta_u64(impl_->database, "acknowledged_through", through)) {
            rollback(impl_->database);
            return std::unexpected(
                spool_error(ProtocolErrorCode::persistence_error, "SQLite spool ACK transaction failed"));
        }
        if (auto committed = commit(impl_->database); !committed) {
            rollback(impl_->database);
            return std::unexpected(std::move(committed.error()));
        }
        if (auto refreshed = impl_->refresh_locked(); !refreshed) {
            return std::unexpected(std::move(refreshed.error()));
        }
        return impl_->update_backpressure_locked();
#else
        static_cast<void>(agent_epoch);
        static_cast<void>(through);
        return std::unexpected(spool_error(ProtocolErrorCode::dependency_unavailable,
                                           "durable agent spooling is unavailable because SQLite was not linked"));
#endif
    }

    std::expected<void, ProtocolError> SqliteAgentSpool::reject(const NackMessage &nack) noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        if (impl_ == nullptr || nack.agent_epoch != impl_->epoch || nack.sequence == 0 ||
            nack.sequence >= impl_->next_sequence) {
            return std::unexpected(spool_error(ProtocolErrorCode::sequence_gap, "spool NACK identity is invalid"));
        }
        if (!nack.permanent) {
            return {};
        }
        if (nack.diagnostic.size() > impl_->protocol_limits.maximum_string_bytes) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::limit_exceeded, "spool NACK diagnostic exceeds the limit"));
        }
        std::scoped_lock lock {impl_->writer};
        if (auto started = begin(impl_->database); !started) {
            return std::unexpected(std::move(started.error()));
        }
        auto quarantine =
            prepare(impl_->database,
                    "INSERT OR IGNORE INTO spool_quarantine(epoch, sequence, kind, payload, encoded_bytes, "
                    "transmit_attempts, reason, diagnostic, quarantined_unix_seconds) "
                    "SELECT epoch, sequence, kind, payload, encoded_bytes, transmit_attempts, ?3, ?4, "
                    "cast(strftime('%s','now') AS INTEGER) FROM spool_outbound WHERE epoch = ?1 AND sequence = ?2");
        const auto inserted =
            quarantine &&
            sqlite3_bind_text(quarantine->value, 1, impl_->epoch.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_bind_int64(quarantine->value, 2, static_cast<sqlite3_int64>(nack.sequence)) == SQLITE_OK &&
            sqlite3_bind_int(quarantine->value, 3, static_cast<int>(nack.reason)) == SQLITE_OK &&
            sqlite3_bind_text(quarantine->value, 4, nack.diagnostic.c_str(), static_cast<int>(nack.diagnostic.size()),
                              SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_step(quarantine->value) == SQLITE_DONE;
        auto remove = prepare(impl_->database, "DELETE FROM spool_outbound WHERE epoch = ?1 AND sequence = ?2");
        const auto removed =
            remove && sqlite3_bind_text(remove->value, 1, impl_->epoch.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_bind_int64(remove->value, 2, static_cast<sqlite3_int64>(nack.sequence)) == SQLITE_OK &&
            sqlite3_step(remove->value) == SQLITE_DONE;
        if (!inserted || !removed) {
            rollback(impl_->database);
            return std::unexpected(
                spool_error(ProtocolErrorCode::persistence_error, "SQLite spool quarantine transaction failed"));
        }
        if (sqlite3_changes(impl_->database) == 0 && nack.sequence > impl_->acknowledged_through) {
            auto exists = prepare(impl_->database, "SELECT 1 FROM spool_quarantine WHERE epoch = ?1 AND sequence = ?2");
            if (!exists ||
                sqlite3_bind_text(exists->value, 1, impl_->epoch.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
                sqlite3_bind_int64(exists->value, 2, static_cast<sqlite3_int64>(nack.sequence)) != SQLITE_OK ||
                sqlite3_step(exists->value) != SQLITE_ROW) {
                rollback(impl_->database);
                return std::unexpected(
                    spool_error(ProtocolErrorCode::sequence_gap, "spool NACK targets an unknown sequence"));
            }
        }
        if (auto committed = commit(impl_->database); !committed) {
            rollback(impl_->database);
            return std::unexpected(std::move(committed.error()));
        }
        if (auto refreshed = impl_->refresh_locked(); !refreshed) {
            return std::unexpected(std::move(refreshed.error()));
        }
        return impl_->update_backpressure_locked();
#else
        static_cast<void>(nack);
        return std::unexpected(spool_error(ProtocolErrorCode::dependency_unavailable,
                                           "durable agent spooling is unavailable because SQLite was not linked"));
#endif
    }

    std::expected<void, ProtocolError> SqliteAgentSpool::reset_epoch() noexcept {
#if RULE_ENGINE_PROTOCOL_HAS_SQLITE
        if (impl_ == nullptr) {
            return std::unexpected(spool_error(ProtocolErrorCode::persistence_error, "SQLite spool is not open"));
        }
        std::scoped_lock lock {impl_->writer};
        if (auto refreshed = impl_->refresh_locked(); !refreshed) {
            return std::unexpected(std::move(refreshed.error()));
        }
        if (impl_->records != 0) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::backpressured, "spool epoch cannot reset with pending durable rows"));
        }
        if (auto updated = execute(impl_->database,
                                   "BEGIN IMMEDIATE;"
                                   "UPDATE spool_meta SET value = lower(hex(randomblob(16))) WHERE key='agent_epoch';"
                                   "UPDATE spool_meta SET value = '1' WHERE key='next_sequence';"
                                   "UPDATE spool_meta SET value = '0' WHERE key='acknowledged_through';"
                                   "UPDATE spool_meta SET value = '0' WHERE key='backpressured';"
                                   "COMMIT;");
            !updated) {
            rollback(impl_->database);
            return std::unexpected(std::move(updated.error()));
        }
        return impl_->refresh_locked();
#else
        return std::unexpected(spool_error(ProtocolErrorCode::dependency_unavailable,
                                           "durable agent spooling is unavailable because SQLite was not linked"));
#endif
    }

    PersistentAgentSession::PersistentAgentSession(PeerId peer, SqliteAgentSpool &spool):
        peer_ {peer}, spool_ {&spool}, control_ {std::move(peer), spool.agent_epoch()} {}

    std::expected<void, ProtocolError> PersistentAgentSession::establish(const ServerHelloMessage &hello) noexcept {
        if (spool_ == nullptr || hello.peer != peer_) {
            return std::unexpected(spool_error(ProtocolErrorCode::stale_session, "persistent session peer is stale"));
        }
        auto control_hello = hello;
        control_hello.acknowledged_sequence = 0;
        if (auto established = control_.establish(control_hello); !established) {
            return std::unexpected(std::move(established.error()));
        }
        if (auto acknowledged = spool_->acknowledge(spool_->agent_epoch(), hello.acknowledged_sequence);
            !acknowledged) {
            return std::unexpected(std::move(acknowledged.error()));
        }
        clear_in_flight();
        session_ = hello.session;
        credit_ = hello.credit;
        return {};
    }

    std::expected<WorkAcceptance, ProtocolError> PersistentAgentSession::accept_work(const WorkLeaseMessage &work) {
        return control_.accept_work(work);
    }

    std::expected<std::vector<RequestId>, ProtocolError>
    PersistentAgentSession::accept_cancel(const CancelWorkMessage &cancel) {
        return control_.accept_cancel(cancel);
    }

    std::expected<std::uint64_t, ProtocolError> PersistentAgentSession::enqueue(const DurableAgentBody &body) noexcept {
        if (spool_ == nullptr) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::persistence_error, "persistent session spool is missing"));
        }
        return spool_->enqueue(body);
    }

    std::expected<std::vector<PeerEnvelope>, ProtocolError>
    PersistentAgentSession::take_transmit_batch(const std::size_t maximum_records) noexcept {
        if (!session_.has_value() || spool_ == nullptr) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::stale_session, "persistent session is not established"));
        }
        const auto in_flight_bytes =
            std::ranges::fold_left(in_flight_, std::size_t {},
                                   [](const std::size_t total, const InFlight &item) { return total + item.bytes; });
        const auto in_flight_work = std::ranges::count_if(in_flight_, &InFlight::work);
        const auto in_flight_chunks = std::ranges::count_if(in_flight_, &InFlight::snapshot_chunk);
        if (in_flight_.size() >= credit_.messages || in_flight_bytes >= credit_.bytes || maximum_records == 0) {
            return std::vector<PeerEnvelope> {};
        }
        const auto available_bytes = static_cast<std::size_t>(
            std::min<std::uint64_t>(credit_.bytes - in_flight_bytes, std::numeric_limits<std::size_t>::max()));
        auto records = spool_->pending(maximum_records + in_flight_.size(), available_bytes);
        if (!records) {
            return std::unexpected(std::move(records.error()));
        }

        auto current_bytes = in_flight_bytes;
        auto current_work = static_cast<std::size_t>(in_flight_work);
        auto current_chunks = static_cast<std::size_t>(in_flight_chunks);
        std::vector<PeerEnvelope> result;
        for (auto &record : *records) {
            if (std::ranges::any_of(in_flight_,
                                    [&record](const InFlight &item) { return item.sequence == record.sequence; })) {
                continue;
            }
            const auto work = std::holds_alternative<WorkResultMessage>(record.body);
            const auto chunk = std::holds_alternative<AuthoritativeSnapshotChunk>(record.body);
            if (result.size() + in_flight_.size() >= credit_.messages ||
                record.encoded_bytes > credit_.bytes - current_bytes ||
                (work && current_work >= credit_.work_attempts) ||
                (chunk && current_chunks >= credit_.snapshot_chunks)) {
                break;
            }
            if (auto transmitted = spool_->mark_transmitted(record.sequence); !transmitted) {
                return std::unexpected(std::move(transmitted.error()));
            }
            MessageBody message = std::visit([](auto &&value) -> MessageBody { return std::move(value); }, record.body);
            result.push_back(PeerEnvelope {
                .protocol_major = major_version,
                .protocol_minor = initial_minor_version,
                .message_id = spool_->agent_epoch() + ":" + std::to_string(record.sequence) + ":" +
                              std::to_string(record.transmit_attempts + 1),
                .session = session_,
                .agent_epoch = spool_->agent_epoch(),
                .agent_sequence = record.sequence,
                .acknowledged_agent_sequence = spool_->acknowledged_through(),
                .body = std::move(message),
            });
            in_flight_.push_back(InFlight {
                .sequence = record.sequence, .bytes = record.encoded_bytes, .work = work, .snapshot_chunk = chunk});
            current_bytes += record.encoded_bytes;
            current_work += work ? 1 : 0;
            current_chunks += chunk ? 1 : 0;
        }
        return result;
    }

    std::expected<void, ProtocolError> PersistentAgentSession::acknowledge(const AckMessage &ack) noexcept {
        if (spool_ == nullptr || ack.agent_epoch != spool_->agent_epoch()) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::stale_session, "persistent session ACK epoch is stale"));
        }
        if (auto acknowledged = spool_->acknowledge(ack.agent_epoch, ack.acknowledged_through); !acknowledged) {
            return std::unexpected(std::move(acknowledged.error()));
        }
        std::erase_if(in_flight_, [&ack](const InFlight &item) { return item.sequence <= ack.acknowledged_through; });
        credit_ = ack.credit;
        return {};
    }

    std::expected<void, ProtocolError> PersistentAgentSession::reject(const NackMessage &nack) noexcept {
        if (spool_ == nullptr) {
            return std::unexpected(
                spool_error(ProtocolErrorCode::persistence_error, "persistent session spool is missing"));
        }
        if (auto rejected = spool_->reject(nack); !rejected) {
            return std::unexpected(std::move(rejected.error()));
        }
        release(nack.sequence);
        return {};
    }

    void PersistentAgentSession::update_credit(const CreditWindow credit) noexcept { credit_ = credit; }

    void PersistentAgentSession::disconnect() noexcept {
        clear_in_flight();
        control_.disconnect();
        session_.reset();
        credit_ = {};
    }

    void PersistentAgentSession::clear_in_flight() noexcept { in_flight_.clear(); }

    void PersistentAgentSession::release(const std::uint64_t sequence) noexcept {
        std::erase_if(in_flight_, [sequence](const InFlight &item) { return item.sequence == sequence; });
    }

} // namespace rule_engine::python::protocol_v2
