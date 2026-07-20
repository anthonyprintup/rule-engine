#pragma once

#include "rule_engine/python/contract.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace rule_engine::python::compiler {

    inline constexpr std::string_view ast_envelope_media_type = "rule-engine.ast/1";
    inline constexpr std::uint16_t ast_envelope_protocol_major = 1;
    inline constexpr std::uint16_t ast_envelope_protocol_minor = 0;
    inline constexpr std::uint16_t python_grammar_major = 3;
    inline constexpr std::uint16_t python_grammar_minor = 14;
    inline constexpr std::size_t maximum_ast_payload_bytes = 64 * mebibyte;
    inline constexpr std::uint32_t maximum_ast_depth = 512;

    using AstNodeId = std::uint32_t;

    struct AstNodeReference {
        AstNodeId id {};
        auto operator<=>(const AstNodeReference &) const = default;
    };

    struct AstFloatBits {
        std::uint64_t bits {};
        auto operator<=>(const AstFloatBits &) const = default;
    };

    struct AstSequence;

    struct AstValue {
        using Sequence = std::shared_ptr<const AstSequence>;
        using Data = std::variant<std::monostate, bool, IntegerValue, AstFloatBits, UnicodeValue, BytesValue,
                                  AstNodeReference, Sequence>;

        Data data;
    };

    struct AstSequence {
        std::vector<AstValue> values;
    };

    struct AstField {
        std::string name;
        AstValue value;
    };

    struct AstNode {
        AstNodeId id {};
        std::string kind;
        SourceSpan span;
        std::vector<AstField> fields;
    };

    struct AstModule {
        std::string name;
        SourceId source;
        AstNodeId root {};
    };

    struct AstEnvelope {
        std::uint16_t protocol_major {ast_envelope_protocol_major};
        std::uint16_t protocol_minor {ast_envelope_protocol_minor};
        std::uint16_t grammar_major {python_grammar_major};
        std::uint16_t grammar_minor {python_grammar_minor};
        std::string worker_runtime;
        SourceDigest source_digest;
        std::vector<AstModule> modules;
        std::vector<AstNode> nodes;
    };

    [[nodiscard]] AstValue ast_none();
    [[nodiscard]] AstValue ast_bool(bool value);
    [[nodiscard]] AstValue ast_integer(std::string decimal);
    [[nodiscard]] AstValue ast_float_bits(std::uint64_t bits);
    [[nodiscard]] AstValue ast_string(std::string utf8);
    [[nodiscard]] AstValue ast_bytes(std::vector<std::byte> bytes);
    [[nodiscard]] AstValue ast_reference(AstNodeId id);
    [[nodiscard]] AstValue ast_sequence(std::vector<AstValue> values);

    [[nodiscard]] std::expected<std::vector<std::byte>, DiagnosticSet> encode_ast_envelope(const AstEnvelope &input);

    [[nodiscard]] std::expected<AstEnvelope, DiagnosticSet> decode_ast_envelope(std::span<const std::byte> payload,
                                                                                const VerifiedRulePack &pack);

} // namespace rule_engine::python::compiler
