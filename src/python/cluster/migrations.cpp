#include "rule_engine/python/cluster/migrations.hpp"

#include <array>

namespace rule_engine::python::cluster {
    namespace {

        constexpr std::string_view sqlite_v1 = R"sql(
CREATE TABLE IF NOT EXISTS re_schema_migrations(
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_unix_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS re_consumer_fences(
    consumer TEXT PRIMARY KEY,
    fence INTEGER NOT NULL CHECK(fence > 0)
);
CREATE TABLE IF NOT EXISTS re_cursors(
    consumer TEXT PRIMARY KEY,
    position INTEGER NOT NULL CHECK(position >= 0)
);
CREATE TABLE IF NOT EXISTS re_events(
    event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    ingest_unix_ms INTEGER NOT NULL,
    envelope BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS re_events_history
    ON re_events(tenant_id, peer_id, schema_id, ingest_unix_ms, event_id);
CREATE TABLE IF NOT EXISTS re_state_cells(
    owner_id TEXT NOT NULL,
    namespace_name TEXT NOT NULL,
    state_key TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    value BLOB,
    PRIMARY KEY(owner_id, namespace_name, state_key)
);
CREATE TABLE IF NOT EXISTS re_results(
    input_event_id TEXT PRIMARY KEY,
    evaluation BLOB NOT NULL,
    FOREIGN KEY(input_event_id) REFERENCES re_events(event_id)
);
CREATE TABLE IF NOT EXISTS re_effect_journal(
    intent_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    effect BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS re_outbox(
    intent_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    not_before_unix_ms INTEGER NOT NULL,
    record BLOB NOT NULL,
    state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3),
    owner TEXT NOT NULL DEFAULT '',
    fence INTEGER NOT NULL DEFAULT 0 CHECK(fence >= 0),
    lease_until_unix_ms INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    terminal_detail TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(intent_id) REFERENCES re_effect_journal(intent_id)
);
CREATE INDEX IF NOT EXISTS re_outbox_claim
    ON re_outbox(state, not_before_unix_ms, lease_until_unix_ms, intent_id);
CREATE TABLE IF NOT EXISTS re_receipts(
    input_event_id TEXT PRIMARY KEY,
    transaction_signature BLOB NOT NULL,
    receipt BLOB NOT NULL,
    FOREIGN KEY(input_event_id) REFERENCES re_events(event_id)
);
CREATE TABLE IF NOT EXISTS re_resource_leases(
    scope TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    fence INTEGER NOT NULL CHECK(fence >= 0),
    lease_until_unix_ms INTEGER NOT NULL DEFAULT 0,
    held INTEGER NOT NULL DEFAULT 0 CHECK(held IN (0, 1)),
    PRIMARY KEY(scope, resource_key)
);
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

        constexpr std::string_view postgresql_v1 = R"sql(
CREATE TABLE IF NOT EXISTS re_schema_migrations(
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_unix_ms BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS re_consumer_fences(
    consumer TEXT PRIMARY KEY,
    fence BIGINT NOT NULL CHECK(fence > 0)
);
CREATE TABLE IF NOT EXISTS re_cursors(
    consumer TEXT PRIMARY KEY,
    position BIGINT NOT NULL CHECK(position >= 0)
);
CREATE TABLE IF NOT EXISTS re_events(
    event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    ingest_unix_ms BIGINT NOT NULL,
    envelope BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS re_events_history
    ON re_events(tenant_id, peer_id, schema_id, ingest_unix_ms, event_id);
CREATE TABLE IF NOT EXISTS re_state_cells(
    owner_id TEXT NOT NULL,
    namespace_name TEXT NOT NULL,
    state_key TEXT NOT NULL,
    version BIGINT NOT NULL CHECK(version > 0),
    value BYTEA,
    PRIMARY KEY(owner_id, namespace_name, state_key)
);
CREATE TABLE IF NOT EXISTS re_results(
    input_event_id TEXT PRIMARY KEY REFERENCES re_events(event_id),
    evaluation BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS re_effect_journal(
    intent_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    effect BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS re_outbox(
    intent_id TEXT PRIMARY KEY REFERENCES re_effect_journal(intent_id),
    idempotency_key TEXT NOT NULL UNIQUE,
    not_before_unix_ms BIGINT NOT NULL,
    record BYTEA NOT NULL,
    state SMALLINT NOT NULL CHECK(state BETWEEN 0 AND 3),
    owner TEXT NOT NULL DEFAULT '',
    fence BIGINT NOT NULL DEFAULT 0 CHECK(fence >= 0),
    lease_until_unix_ms BIGINT NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    terminal_detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS re_outbox_claim
    ON re_outbox(state, not_before_unix_ms, lease_until_unix_ms, intent_id);
CREATE TABLE IF NOT EXISTS re_receipts(
    input_event_id TEXT PRIMARY KEY REFERENCES re_events(event_id),
    transaction_signature BYTEA NOT NULL,
    receipt BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS re_resource_leases(
    scope TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    fence BIGINT NOT NULL CHECK(fence >= 0),
    lease_until_unix_ms BIGINT NOT NULL DEFAULT 0,
    held BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY(scope, resource_key)
);
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

        constexpr std::string_view sqlite_v2 = R"sql(
CREATE TABLE IF NOT EXISTS re_agent_receipts(
    tenant_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    agent_epoch TEXT NOT NULL,
    acknowledged_through INTEGER NOT NULL CHECK(acknowledged_through >= 0),
    PRIMARY KEY(tenant_id, peer_id, agent_epoch)
);
CREATE TABLE IF NOT EXISTS re_agent_messages(
    tenant_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    agent_epoch TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    session_id TEXT NOT NULL,
    session_fence INTEGER NOT NULL CHECK(session_fence > 0),
    received_at_unix_ms INTEGER NOT NULL CHECK(received_at_unix_ms >= 0),
    body_kind INTEGER NOT NULL CHECK(body_kind > 0),
    body BLOB NOT NULL,
    PRIMARY KEY(tenant_id, peer_id, agent_epoch, sequence),
    FOREIGN KEY(tenant_id, peer_id, agent_epoch)
        REFERENCES re_agent_receipts(tenant_id, peer_id, agent_epoch)
);
)sql";

        constexpr std::string_view postgresql_v2 = R"sql(
CREATE TABLE IF NOT EXISTS re_agent_receipts(
    tenant_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    agent_epoch TEXT NOT NULL,
    acknowledged_through BIGINT NOT NULL CHECK(acknowledged_through >= 0),
    PRIMARY KEY(tenant_id, peer_id, agent_epoch)
);
CREATE TABLE IF NOT EXISTS re_agent_messages(
    tenant_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    agent_epoch TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK(sequence > 0),
    session_id TEXT NOT NULL,
    session_fence BIGINT NOT NULL CHECK(session_fence > 0),
    received_at_unix_ms BIGINT NOT NULL CHECK(received_at_unix_ms >= 0),
    body_kind SMALLINT NOT NULL CHECK(body_kind > 0),
    body BYTEA NOT NULL,
    PRIMARY KEY(tenant_id, peer_id, agent_epoch, sequence),
    FOREIGN KEY(tenant_id, peer_id, agent_epoch)
        REFERENCES re_agent_receipts(tenant_id, peer_id, agent_epoch)
);
)sql";

        constexpr std::array migrations {
            SchemaMigration {.version = 1,
                             .name = "runtime-store-foundation",
                             .sqlite_sql = sqlite_v1,
                             .postgresql_sql = postgresql_v1},
            SchemaMigration {.version = 2,
                             .name = "durable-agent-ingress",
                             .sqlite_sql = sqlite_v2,
                             .postgresql_sql = postgresql_v2},
        };

    } // namespace

    std::span<const SchemaMigration> runtime_store_migrations() { return migrations; }

} // namespace rule_engine::python::cluster
