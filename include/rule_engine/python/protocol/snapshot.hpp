#pragma once

#include "rule_engine/python/protocol/types.hpp"

#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rule_engine::python::protocol_v2 {

    struct SnapshotDelta {
        std::uint64_t generation {};
        std::string canonical_digest;
        std::vector<SubjectKey> added;
        std::vector<SubjectKey> removed;
        std::vector<SubjectKey> current;
    };

    [[nodiscard]] std::expected<std::string, ProtocolError>
    authoritative_snapshot_digest(std::span<const SubjectKey> subjects, const ProtocolLimits &limits = {});

    struct AuthoritativeSnapshotAssembler {
        AuthoritativeSnapshotAssembler(PeerId peer, SessionId session, std::uint64_t session_fence,
                                       SchemaId subject_schema, std::optional<SubjectKey> parent,
                                       ProtocolLimits limits = {});

        [[nodiscard]] std::expected<void, ProtocolError> begin(const AuthoritativeSnapshotBegin &message);
        [[nodiscard]] std::expected<void, ProtocolError> append(const AuthoritativeSnapshotChunk &message);
        [[nodiscard]] std::expected<SnapshotDelta, ProtocolError> commit(const AuthoritativeSnapshotCommit &message);
        void abort() noexcept;

        [[nodiscard]] bool staging() const noexcept { return stage_.has_value(); }
        [[nodiscard]] std::uint64_t last_good_generation() const noexcept { return last_good_generation_; }
        [[nodiscard]] const std::vector<SubjectKey> &visible() const noexcept { return visible_; }

    private:
        struct Stage {
            std::string snapshot_id;
            std::uint64_t generation {};
            std::uint64_t expected_count {};
            std::string expected_digest;
            std::uint32_t next_chunk {};
            std::size_t canonical_bytes {};
            std::vector<SubjectKey> subjects;
            std::vector<std::string> canonical_keys;
        };

        [[nodiscard]] std::expected<void, ProtocolError> validate_session(const SessionId &session, const PeerId &peer,
                                                                          std::uint64_t fence) const;
        [[nodiscard]] bool has_expected_parent(const SubjectKey &subject) const;
        void reject_stage() noexcept;

        PeerId peer_;
        SessionId session_;
        std::uint64_t session_fence_ {};
        SchemaId subject_schema_;
        std::optional<SubjectKey> parent_;
        ProtocolLimits limits_;
        std::uint64_t last_good_generation_ {};
        std::vector<SubjectKey> visible_;
        std::optional<Stage> stage_;
    };

} // namespace rule_engine::python::protocol_v2
