#include "rule_engine/python/contract.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <set>
#include <string>
#include <type_traits>
#include <utility>

namespace rule_engine::python {
    namespace {

        void append_token(std::string &output, const std::string_view token) {
            std::array<char, 32> length {};
            const auto [end, error] = std::to_chars(length.data(), length.data() + length.size(), token.size());
            if (error == std::errc {}) {
                output.append(length.data(), end);
            }
            output.push_back(':');
            output.append(token);
            output.push_back(';');
        }

        std::string bytes_as_hex(const std::vector<std::byte> &bytes) {
            constexpr std::string_view digits = "0123456789abcdef";
            std::string result;
            result.reserve(bytes.size() * 2U);
            for (const auto value : bytes) {
                const auto number = std::to_integer<unsigned int>(value);
                result.push_back(digits[(number >> 4U) & 0xFU]);
                result.push_back(digits[number & 0xFU]);
            }
            return result;
        }

        void append_identity(std::string &output, const IdentityScalar &scalar) {
            std::visit(
                [&output](const auto &value) {
                    using ValueType = std::remove_cvref_t<decltype(value)>;
                    if constexpr (std::is_same_v<ValueType, bool>) {
                        append_token(output, value ? "b1" : "b0");
                    } else if constexpr (std::is_same_v<ValueType, std::int64_t>) {
                        append_token(output, "i" + std::to_string(value));
                    } else if constexpr (std::is_same_v<ValueType, std::uint64_t>) {
                        append_token(output, "u" + std::to_string(value));
                    } else if constexpr (std::is_same_v<ValueType, IntegerValue>) {
                        append_token(output, "n" + value.decimal);
                    } else if constexpr (std::is_same_v<ValueType, UnicodeValue>) {
                        append_token(output, "s" + value.utf8);
                    } else if constexpr (std::is_same_v<ValueType, BytesValue>) {
                        append_token(output, "x" + bytes_as_hex(value.bytes));
                    }
                },
                scalar);
        }

        Diagnostic bytecode_error(std::string code, std::string message,
                                  std::optional<SourceSpan> span = std::nullopt) {
            return Diagnostic {.code = std::move(code),
                               .severity = DiagnosticSeverity::error,
                               .message = std::move(message),
                               .span = std::move(span),
                               .related = {}};
        }

    } // namespace

    DataLabel join_labels(const DataLabel &left, const DataLabel &right) {
        DataLabel result {
            .classification = std::max(left.classification, right.classification),
            .categories = left.categories,
        };
        result.categories.insert(result.categories.end(), right.categories.begin(), right.categories.end());
        std::ranges::sort(result.categories);
        const auto unique_end = std::ranges::unique(result.categories).begin();
        result.categories.erase(unique_end, result.categories.end());
        return result;
    }

    bool may_flow_to(const DataLabel &value, const DataLabel &ceiling) noexcept {
        if (value.classification > ceiling.classification) {
            return false;
        }
        return std::ranges::all_of(value.categories, [&ceiling](const std::string &category) {
            return std::ranges::find(ceiling.categories, category) != ceiling.categories.end();
        });
    }

    FactValue make_fact(FactData data) {
        return FactValue {.node = std::make_shared<const FactNode>(FactNode {.data = std::move(data)})};
    }

    bool SubjectKey::valid() const noexcept {
        if (peer.empty() || descriptor.empty() || identity.empty()) {
            return false;
        }
        std::uint32_t previous {};
        for (const auto &field : identity) {
            if (field.field_id == 0 || field.field_id <= previous) {
                return false;
            }
            previous = field.field_id;
        }

        std::set<const SubjectKey *> seen;
        auto current = this;
        while (current != nullptr) {
            if (!seen.insert(current).second || current->peer != peer) {
                return false;
            }
            current = current->parent.get();
        }
        return true;
    }

    std::string canonical_subject_key(const SubjectKey &subject) {
        if (!subject.valid()) {
            return {};
        }

        std::vector<const SubjectKey *> lineage;
        for (auto current = &subject; current != nullptr; current = current->parent.get()) {
            lineage.push_back(current);
        }
        std::ranges::reverse(lineage);

        std::string output;
        append_token(output, "subject-key-v1");
        append_token(output, subject.peer.value);
        for (const auto *part : lineage) {
            append_token(output, part->descriptor.value);
            for (const auto &field : part->identity) {
                append_token(output, std::to_string(field.field_id));
                append_identity(output, field.value);
            }
            append_token(output, "/");
        }
        return output;
    }

    std::expected<void, DiagnosticSet> verify_bytecode(const CompiledPack &pack) {
        DiagnosticSet diagnostics;
        if (pack.pack.empty() || pack.version.empty() || pack.source_digest.empty()) {
            diagnostics.push_back(bytecode_error("PYC0001", "compiled pack identity is incomplete"));
        }
        if (pack.compiler_abi.empty() || pack.semantic_hash.empty()) {
            diagnostics.push_back(bytecode_error("PYC0002", "compiled pack semantic identity is incomplete"));
        }

        std::set<std::string> function_ids;
        for (const auto &function : pack.functions) {
            if (function.id.empty() || !function_ids.insert(function.id.value).second) {
                diagnostics.push_back(bytecode_error("PYC0100", "bytecode function IDs must be non-empty and unique"));
            }
            if (function.register_count < function.parameter_count) {
                diagnostics.push_back(bytecode_error("PYC0101", "parameter count exceeds register count"));
            }
            for (std::size_t index = 0; index < function.instructions.size(); ++index) {
                const auto &instruction = function.instructions[index];
                if (std::to_underlying(instruction.opcode) > std::to_underlying(Opcode::delete_state)) {
                    diagnostics.push_back(bytecode_error("PYC0109", "instruction opcode is unknown", instruction.span));
                    continue;
                }
                if (!instruction.span.valid()) {
                    diagnostics.push_back(bytecode_error("PYC0102", "instruction has an invalid UTF-8 byte span"));
                }
                const auto has_no_destination =
                    instruction.opcode == Opcode::jump || instruction.opcode == Opcode::enter_try ||
                    instruction.opcode == Opcode::leave_try || instruction.opcode == Opcode::begin_transaction ||
                    instruction.opcode == Opcode::commit_transaction ||
                    instruction.opcode == Opcode::rollback_transaction || instruction.opcode == Opcode::delete_state;
                if (instruction.destination >= function.register_count && !has_no_destination) {
                    diagnostics.push_back(bytecode_error("PYC0103", "instruction destination register is out of range",
                                                         instruction.span));
                }
                if ((instruction.opcode == Opcode::jump || instruction.opcode == Opcode::jump_if_false ||
                     instruction.opcode == Opcode::iter_next) &&
                    instruction.immediate >= function.instructions.size()) {
                    diagnostics.push_back(bytecode_error("PYC0104", "jump target is out of range", instruction.span));
                }
                const auto register_valid = [&](const std::uint32_t reg) { return reg < function.register_count; };
                const auto register_window_valid = [&](const std::uint32_t first, const std::uint32_t count) {
                    return first <= function.register_count && count <= function.register_count - first;
                };
                const auto malformed_register = [&] {
                    diagnostics.push_back(
                        bytecode_error("PYC0106", "instruction register operand is out of range", instruction.span));
                };
                const auto malformed_reserved = [&] {
                    diagnostics.push_back(
                        bytecode_error("PYC0107", "instruction reserved operand must be zero", instruction.span));
                };
                switch (instruction.opcode) {
                    case Opcode::build_list:
                    case Opcode::build_tuple:
                        if (!register_window_valid(instruction.operand_a, instruction.operand_b)) {
                            malformed_register();
                        }
                        if (instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::build_dict:
                        if (instruction.operand_a > function.register_count ||
                            instruction.operand_b > (function.register_count - instruction.operand_a) / 2U) {
                            malformed_register();
                        }
                        if (instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::get_iter:
                        if (!register_valid(instruction.operand_a)) {
                            malformed_register();
                        }
                        if (instruction.operand_b != 0U || instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::iter_next:
                        if (!register_valid(instruction.operand_a)) {
                            malformed_register();
                        }
                        if (instruction.operand_b != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::load_subscript:
                    case Opcode::store_subscript:
                        if (!register_valid(instruction.operand_a) || !register_valid(instruction.operand_b)) {
                            malformed_register();
                        }
                        if (instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::delete_state:
                        if (instruction.immediate >= pack.constants.size()) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0108", "delete_state constant index is out of range", instruction.span));
                        }
                        if (instruction.destination != 0U || instruction.operand_a != 0U ||
                            instruction.operand_b != 0U) {
                            malformed_reserved();
                        }
                        break;
                    default: break;
                }
            }
            for (const auto &region : function.exception_regions) {
                const auto instruction_count = function.instructions.size();
                if (region.begin_instruction >= region.end_instruction || region.end_instruction > instruction_count ||
                    region.handler_instruction >= instruction_count ||
                    region.cleanup_instruction >= instruction_count) {
                    diagnostics.push_back(bytecode_error("PYC0105", "exception region is out of range"));
                }
            }
        }

        for (const auto &certificate : pack.optimization_certificates) {
            if (!function_ids.contains(certificate.executable.value)) {
                diagnostics.push_back(
                    bytecode_error("PYC0200", "optimizer certificate references an unknown executable"));
            }
            if (certificate.transitively_pure &&
                (certificate.emits_effects || certificate.reads_state || certificate.reads_history ||
                 certificate.calls_services || certificate.may_fault || certificate.recorder_observable)) {
                diagnostics.push_back(
                    bytecode_error("PYC0201", "pure optimizer certificate contradicts its effect summary"));
            }
        }

        if (!diagnostics.empty()) {
            return std::unexpected(std::move(diagnostics));
        }
        return {};
    }

} // namespace rule_engine::python
