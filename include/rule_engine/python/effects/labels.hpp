#pragma once

#include "rule_engine/python/effects/common.hpp"

#include <cstddef>
#include <expected>
#include <string>
#include <vector>

namespace rule_engine::python::effects {

    enum struct LabelErrorCode : std::uint8_t {
        invalid_control_token,
        caller_not_authorized,
        input_label_rejected,
        transform_mismatch,
    };

    struct LabelError {
        LabelErrorCode code {};
        std::string message;
    };

    struct ControlLabelToken {
        std::size_t depth {};
        auto operator<=>(const ControlLabelToken &) const = default;
    };

    struct ControlLabelStack {
        ControlLabelStack();

        [[nodiscard]] const DataLabel &current() const noexcept;
        [[nodiscard]] ControlLabelToken push(const DataLabel &condition_label);
        [[nodiscard]] std::expected<void, LabelError> pop(ControlLabelToken token);

    private:
        std::vector<DataLabel> labels_;
    };

    [[nodiscard]] FrozenValue apply_control_label(const FrozenValue &value, const DataLabel &control_label);

    struct DeclassifierPermit {
        std::string transform_id;
        std::string transform_version;
        BindingId authorized_binding;
        DataLabel accepted_input;
        DataLabel output_label;
    };

    struct DeclassificationAudit {
        std::string transform_id;
        std::string transform_version;
        BindingId caller;
        DataLabel input_label;
        DataLabel output_label;
        std::string input_digest;
        std::string output_digest;
        SourceSpan span;
    };

    struct DeclassificationResult {
        FrozenValue value;
        DeclassificationAudit audit;
    };

    [[nodiscard]] std::expected<DeclassificationResult, LabelError>
    apply_declassification(const FrozenValue &source, FrozenValue transformed, const BindingId &caller,
                           const DeclassifierPermit &permit, const SourceSpan &span);

} // namespace rule_engine::python::effects
