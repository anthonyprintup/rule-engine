#include "rule_engine/python/protocol/types.hpp"

#include <type_traits>

namespace rule_engine::python::protocol_v2 {

    MessageKind message_kind(const MessageBody &body) noexcept {
        return std::visit(
            [](const auto &message) noexcept {
                using Message = std::remove_cvref_t<decltype(message)>;
                if constexpr (std::is_same_v<Message, AgentHelloMessage>) {
                    return MessageKind::agent_hello;
                } else if constexpr (std::is_same_v<Message, ServerHelloMessage>) {
                    return MessageKind::server_hello;
                } else if constexpr (std::is_same_v<Message, WorkLeaseMessage>) {
                    return MessageKind::work_lease;
                } else if constexpr (std::is_same_v<Message, WorkResultMessage>) {
                    return MessageKind::work_result;
                } else if constexpr (std::is_same_v<Message, CancelWorkMessage>) {
                    return MessageKind::cancel_work;
                } else if constexpr (std::is_same_v<Message, AuthoritativeSnapshotBegin>) {
                    return MessageKind::snapshot_begin;
                } else if constexpr (std::is_same_v<Message, AuthoritativeSnapshotChunk>) {
                    return MessageKind::snapshot_chunk;
                } else if constexpr (std::is_same_v<Message, AuthoritativeSnapshotCommit>) {
                    return MessageKind::snapshot_commit;
                } else if constexpr (std::is_same_v<Message, AckMessage>) {
                    return MessageKind::ack;
                } else if constexpr (std::is_same_v<Message, NackMessage>) {
                    return MessageKind::nack;
                } else {
                    return MessageKind::credit_update;
                }
            },
            body);
    }

} // namespace rule_engine::python::protocol_v2
