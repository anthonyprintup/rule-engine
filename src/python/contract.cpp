#include "rule_engine/python/contract.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <deque>
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
                if (std::to_underlying(instruction.opcode) > std::to_underlying(Opcode::leave_except)) {
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
                    instruction.opcode == Opcode::rollback_transaction || instruction.opcode == Opcode::delete_state ||
                    instruction.opcode == Opcode::reraise || instruction.opcode == Opcode::unwind_jump ||
                    instruction.opcode == Opcode::leave_except;
                if (instruction.destination >= function.register_count && !has_no_destination) {
                    diagnostics.push_back(bytecode_error("PYC0103", "instruction destination register is out of range",
                                                         instruction.span));
                }
                if ((instruction.opcode == Opcode::jump || instruction.opcode == Opcode::jump_if_false ||
                     instruction.opcode == Opcode::iter_next || instruction.opcode == Opcode::unwind_jump) &&
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
                    case Opcode::load_current_exception:
                        if (instruction.operand_a != 0U || instruction.operand_b != 0U || instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::match_exception:
                        if (instruction.operand_a >= function.instructions.size() ||
                            instruction.operand_b >= function.instructions.size()) {
                            diagnostics.push_back(
                                bytecode_error("PYC0104", "exception filter target is out of range", instruction.span));
                        }
                        if (instruction.immediate > std::to_underlying(PythonFaultKind::exception)) {
                            diagnostics.push_back(
                                bytecode_error("PYC0112", "exception filter kind is outside the closed fault table",
                                               instruction.span));
                        }
                        break;
                    case Opcode::reraise:
                    case Opcode::leave_except:
                        if (instruction.destination != 0U || instruction.operand_a != 0U ||
                            instruction.operand_b != 0U || instruction.immediate != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::unwind_jump:
                        if (instruction.destination != 0U || instruction.operand_a != 0U ||
                            instruction.operand_b != 0U) {
                            malformed_reserved();
                        }
                        break;
                    case Opcode::raise_fault:
                        if (instruction.immediate > std::to_underlying(PythonFaultKind::arithmetic_error)) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0112", "raise kind is not a concrete engine-owned fault kind", instruction.span));
                        }
                        break;
                    case Opcode::load_const:
                    case Opcode::move:
                    case Opcode::unary_op:
                    case Opcode::binary_op:
                    case Opcode::compare:
                    case Opcode::jump:
                    case Opcode::jump_if_false:
                    case Opcode::call:
                    case Opcode::return_value:
                    case Opcode::enter_try:
                    case Opcode::leave_try:
                    case Opcode::yield_value:
                    case Opcode::await_fact:
                    case Opcode::await_capability:
                    case Opcode::read_state:
                    case Opcode::write_state:
                    case Opcode::append_effect:
                    case Opcode::begin_transaction:
                    case Opcode::commit_transaction:
                    case Opcode::rollback_transaction: break;
                    default: std::unreachable();
                }
            }
            const auto instruction_count = function.instructions.size();
            std::set<std::uint32_t> cleanup_entries;
            std::set<std::uint32_t> filter_nodes;
            std::vector<std::pair<std::uint32_t, std::set<std::uint32_t>>> filter_handler_targets;
            for (const auto &region : function.exception_regions) {
                if (region.begin_instruction >= region.end_instruction || region.end_instruction > instruction_count ||
                    region.handler_instruction >= instruction_count ||
                    region.cleanup_instruction >= instruction_count) {
                    diagnostics.push_back(bytecode_error("PYC0105", "exception region is out of range"));
                    continue;
                }
                if ((region.handler_instruction >= region.begin_instruction &&
                     region.handler_instruction < region.end_instruction) ||
                    (region.cleanup_instruction >= region.begin_instruction &&
                     region.cleanup_instruction < region.end_instruction)) {
                    diagnostics.push_back(
                        bytecode_error("PYC0110", "exception region target lies inside its protected interval"));
                }
                if (std::to_underlying(region.kind) > std::to_underlying(ExceptionRegionKind::cleanup)) {
                    diagnostics.push_back(bytecode_error("PYC0110", "exception region kind is unknown"));
                    continue;
                }
                switch (region.kind) {
                    case ExceptionRegionKind::handler:
                        if (region.cleanup_instruction != region.handler_instruction) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0110", "handler region must use its handler as the compatibility cleanup target"));
                        }
                        break;
                    case ExceptionRegionKind::cleanup:
                        if (region.cleanup_instruction == region.handler_instruction ||
                            function.instructions[region.handler_instruction].opcode != Opcode::reraise) {
                            diagnostics.push_back(bytecode_error(
                                "PYC0110", "cleanup region must resume exceptions at a distinct reraise instruction"));
                        }
                        if (!cleanup_entries.insert(region.cleanup_instruction).second) {
                            diagnostics.push_back(
                                bytecode_error("PYC0110", "cleanup regions must have distinct entry instructions"));
                        }
                        break;
                    default: std::unreachable();
                }

                if (function.instructions[region.handler_instruction].opcode != Opcode::match_exception) {
                    continue;
                }
                std::set<std::uint32_t> chain;
                std::set<PythonFaultKind> kinds;
                std::set<std::uint32_t> handler_targets;
                auto cursor = region.handler_instruction;
                while (cursor < instruction_count && function.instructions[cursor].opcode == Opcode::match_exception) {
                    if (!chain.insert(cursor).second) {
                        diagnostics.push_back(bytecode_error("PYC0112", "exception filter chain contains a cycle",
                                                             function.instructions[cursor].span));
                        break;
                    }
                    filter_nodes.insert(cursor);
                    const auto &filter = function.instructions[cursor];
                    const auto kind = static_cast<PythonFaultKind>(filter.immediate);
                    if (filter.immediate <= std::to_underlying(PythonFaultKind::exception) &&
                        !kinds.insert(kind).second) {
                        diagnostics.push_back(
                            bytecode_error("PYC0112", "exception filter kind is duplicated", filter.span));
                    }
                    handler_targets.insert(filter.operand_a);
                    if (filter.operand_a >= region.begin_instruction && filter.operand_a < region.end_instruction) {
                        diagnostics.push_back(bytecode_error(
                            "PYC0112", "exception handler target lies inside its protected interval", filter.span));
                    }
                    if (filter.immediate == std::to_underlying(PythonFaultKind::exception) &&
                        (filter.operand_b >= instruction_count ||
                         function.instructions[filter.operand_b].opcode != Opcode::reraise)) {
                        diagnostics.push_back(bytecode_error(
                            "PYC0112", "catch-all exception filter must terminate the ordered filter chain",
                            filter.span));
                    }
                    cursor = filter.operand_b;
                }
                if (cursor >= instruction_count || function.instructions[cursor].opcode != Opcode::reraise) {
                    diagnostics.push_back(
                        bytecode_error("PYC0112", "exception filter chain must terminate at a reraise instruction"));
                }
                filter_handler_targets.emplace_back(region.handler_instruction, std::move(handler_targets));
                for (const auto target : filter_handler_targets.back().second) {
                    if (chain.contains(target)) {
                        diagnostics.push_back(
                            bytecode_error("PYC0112", "exception filter matching edge targets another filter node"));
                    }
                }
            }

            for (std::size_t left = 0U; left < function.exception_regions.size(); ++left) {
                const auto &a = function.exception_regions[left];
                if (a.begin_instruction >= a.end_instruction || a.end_instruction > instruction_count) {
                    continue;
                }
                for (std::size_t right = left + 1U; right < function.exception_regions.size(); ++right) {
                    const auto &b = function.exception_regions[right];
                    if (b.begin_instruction >= b.end_instruction || b.end_instruction > instruction_count) {
                        continue;
                    }
                    const auto overlap = std::max(a.begin_instruction, b.begin_instruction) <
                                         std::min(a.end_instruction, b.end_instruction);
                    const auto a_contains_b =
                        a.begin_instruction <= b.begin_instruction && a.end_instruction >= b.end_instruction;
                    const auto b_contains_a =
                        b.begin_instruction <= a.begin_instruction && b.end_instruction >= a.end_instruction;
                    const auto identical =
                        a.begin_instruction == b.begin_instruction && a.end_instruction == b.end_instruction;
                    if (overlap && (identical || (!a_contains_b && !b_contains_a))) {
                        diagnostics.push_back(
                            bytecode_error("PYC0111", "exception regions overlap without strict lexical nesting"));
                    }
                }
            }

            for (std::uint32_t pc = 0U; pc < instruction_count; ++pc) {
                if (function.instructions[pc].opcode == Opcode::match_exception && !filter_nodes.contains(pc)) {
                    diagnostics.push_back(
                        bytecode_error("PYC0112", "exception filter instruction is not owned by a handler region",
                                       function.instructions[pc].span));
                }
            }

            const auto add_normal_successors = [&](const std::uint32_t pc, auto &&add) {
                const auto &instruction = function.instructions[pc];
                switch (instruction.opcode) {
                    case Opcode::jump:
                    case Opcode::unwind_jump: add(instruction.immediate); break;
                    case Opcode::jump_if_false:
                    case Opcode::iter_next:
                        add(instruction.immediate);
                        add(pc + 1U);
                        break;
                    case Opcode::match_exception:
                        add(instruction.operand_a);
                        add(instruction.operand_b);
                        break;
                    case Opcode::return_value:
                    case Opcode::raise_fault:
                    case Opcode::reraise: break;
                    case Opcode::load_const:
                    case Opcode::move:
                    case Opcode::unary_op:
                    case Opcode::binary_op:
                    case Opcode::compare:
                    case Opcode::call:
                    case Opcode::enter_try:
                    case Opcode::leave_try:
                    case Opcode::yield_value:
                    case Opcode::await_fact:
                    case Opcode::await_capability:
                    case Opcode::read_state:
                    case Opcode::write_state:
                    case Opcode::append_effect:
                    case Opcode::begin_transaction:
                    case Opcode::commit_transaction:
                    case Opcode::rollback_transaction:
                    case Opcode::build_list:
                    case Opcode::build_tuple:
                    case Opcode::build_dict:
                    case Opcode::get_iter:
                    case Opcode::load_subscript:
                    case Opcode::store_subscript:
                    case Opcode::delete_state:
                    case Opcode::load_current_exception: add(pc + 1U); break;
                    case Opcode::leave_except: add(pc + 1U); break;
                    default: break;
                }
            };
            for (std::uint32_t pc = 0U; pc < instruction_count; ++pc) {
                add_normal_successors(pc, [&](const std::uint32_t successor) {
                    for (const auto &region : function.exception_regions) {
                        const auto source_inside = pc >= region.begin_instruction && pc < region.end_instruction;
                        const auto successor_inside =
                            successor >= region.begin_instruction && successor < region.end_instruction;
                        if (successor >= instruction_count || source_inside || !successor_inside ||
                            successor == region.begin_instruction) {
                            continue;
                        }
                        diagnostics.push_back(
                            bytecode_error("PYC0110", "ordinary control flow enters the middle of an exception region",
                                           function.instructions[pc].span));
                    }
                });
            }
            for (const auto &region : function.exception_regions) {
                if (region.kind != ExceptionRegionKind::cleanup || region.cleanup_instruction >= instruction_count) {
                    continue;
                }
                std::vector<bool> visited(instruction_count, false);
                std::deque<std::uint32_t> work {region.cleanup_instruction};
                visited[region.cleanup_instruction] = true;
                while (!work.empty()) {
                    const auto pc = work.front();
                    work.pop_front();
                    const auto opcode = function.instructions[pc].opcode;
                    if (opcode == Opcode::leave_try || opcode == Opcode::return_value ||
                        opcode == Opcode::raise_fault || opcode == Opcode::reraise || opcode == Opcode::unwind_jump) {
                        continue;
                    }
                    add_normal_successors(pc, [&](const std::uint32_t successor) {
                        if (successor >= instruction_count) {
                            diagnostics.push_back(bytecode_error("PYC0110",
                                                                 "cleanup path reaches the end without a continuation",
                                                                 function.instructions[pc].span));
                            return;
                        }
                        if (successor >= region.begin_instruction && successor < region.end_instruction) {
                            diagnostics.push_back(bytecode_error("PYC0114",
                                                                 "cleanup path re-enters its protected interval",
                                                                 function.instructions[pc].span));
                            return;
                        }
                        if (!visited[successor]) {
                            visited[successor] = true;
                            work.push_back(successor);
                        }
                    });
                }
            }
            for (const auto &[root, targets] : filter_handler_targets) {
                for (const auto target : targets) {
                    std::vector<bool> visited(instruction_count, false);
                    std::deque<std::uint32_t> work;
                    if (target < instruction_count) {
                        visited[target] = true;
                        work.push_back(target);
                    }
                    while (!work.empty()) {
                        const auto pc = work.front();
                        work.pop_front();
                        if (filter_nodes.contains(pc)) {
                            diagnostics.push_back(
                                bytecode_error("PYC0112", "exception handler control flow re-enters a filter chain",
                                               function.instructions[root].span));
                            break;
                        }
                        add_normal_successors(pc, [&](const std::uint32_t successor) {
                            if (successor < instruction_count && !visited[successor]) {
                                visited[successor] = true;
                                work.push_back(successor);
                            }
                        });
                    }
                }
            }
            std::vector<bool> normal_reachable(instruction_count, false);
            std::deque<std::uint32_t> normal_work;
            if (instruction_count != 0U) {
                normal_reachable.front() = true;
                normal_work.push_back(0U);
            }
            while (!normal_work.empty()) {
                const auto pc = normal_work.front();
                normal_work.pop_front();
                add_normal_successors(pc, [&](const std::uint32_t successor) {
                    if (successor < instruction_count && !normal_reachable[successor]) {
                        normal_reachable[successor] = true;
                        normal_work.push_back(successor);
                    }
                });
            }
            for (std::uint32_t pc = 0U; pc < instruction_count; ++pc) {
                if (!normal_reachable[pc]) {
                    continue;
                }
                const auto opcode = function.instructions[pc].opcode;
                if (opcode == Opcode::load_current_exception || opcode == Opcode::match_exception ||
                    opcode == Opcode::reraise || opcode == Opcode::leave_except) {
                    diagnostics.push_back(bytecode_error(
                        "PYC0113", "current-exception instruction is reachable without an exception edge",
                        function.instructions[pc].span));
                }
            }
            for (const auto &region : function.exception_regions) {
                if (region.handler_instruction < instruction_count && normal_reachable[region.handler_instruction]) {
                    diagnostics.push_back(
                        bytecode_error("PYC0113", "exception handler is reachable by ordinary control flow"));
                }
                if (region.kind == ExceptionRegionKind::cleanup && region.cleanup_instruction < instruction_count &&
                    normal_reachable[region.cleanup_instruction]) {
                    diagnostics.push_back(
                        bytecode_error("PYC0113", "cleanup entry is reachable by ordinary control flow"));
                }
                if (region.kind != ExceptionRegionKind::cleanup || region.begin_instruction >= region.end_instruction ||
                    region.end_instruction > instruction_count) {
                    continue;
                }
                for (auto pc = region.begin_instruction; pc < region.end_instruction; ++pc) {
                    const auto &instruction = function.instructions[pc];
                    if (instruction.opcode == Opcode::return_value || instruction.opcode == Opcode::raise_fault ||
                        instruction.opcode == Opcode::reraise || instruction.opcode == Opcode::unwind_jump) {
                        continue;
                    }
                    add_normal_successors(pc, [&](const std::uint32_t successor) {
                        if (successor < region.begin_instruction || successor >= region.end_instruction) {
                            diagnostics.push_back(
                                bytecode_error("PYC0114", "ordinary control-flow edge bypasses a cleanup continuation",
                                               instruction.span));
                        }
                    });
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
