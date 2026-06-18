#pragma once

#include <rule_engine/client_protocol.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace rule_engine::server_output {
    [[nodiscard]] std::string evaluation_session_json(std::string_view host,
                                                      std::uint16_t port,
                                                      const client_protocol::ClientMultiEvaluationSession &session,
                                                      const client_protocol::ClientEvaluationInstrumentation
                                                          *instrumentation = nullptr);
    [[nodiscard]] std::string client_session_json(std::string_view host,
                                                  std::uint16_t port,
                                                  const client_protocol::ClientSession &session);
} // namespace rule_engine::server_output
