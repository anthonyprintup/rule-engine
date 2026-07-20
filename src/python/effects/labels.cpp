#include "rule_engine/python/effects/labels.hpp"

#include <utility>

namespace rule_engine::python::effects {

    ControlLabelStack::ControlLabelStack(): labels_ {DataLabel {}} {}

    const DataLabel &ControlLabelStack::current() const noexcept { return labels_.back(); }

    ControlLabelToken ControlLabelStack::push(const DataLabel &condition_label) {
        labels_.push_back(join_labels(labels_.back(), condition_label));
        return ControlLabelToken {.depth = labels_.size() - 1U};
    }

    std::expected<void, LabelError> ControlLabelStack::pop(const ControlLabelToken token) {
        if (token.depth == 0 || labels_.size() != token.depth + 1U) {
            return std::unexpected(LabelError {
                .code = LabelErrorCode::invalid_control_token,
                .message = "control-label regions must close in strict LIFO order",
            });
        }
        labels_.pop_back();
        return {};
    }

    FrozenValue apply_control_label(const FrozenValue &value, const DataLabel &control_label) {
        auto result = value;
        result.label = join_labels(result.label, control_label);
        return result;
    }

    std::expected<DeclassificationResult, LabelError>
    apply_declassification(const FrozenValue &source, FrozenValue transformed, const BindingId &caller,
                           const DeclassifierPermit &permit, const SourceSpan &span) {
        if (permit.transform_id.empty() || permit.transform_version.empty() || permit.authorized_binding.empty() ||
            !span.valid() || !transformed.value.valid() || transformed.canonical_digest.empty()) {
            return std::unexpected(LabelError {
                .code = LabelErrorCode::transform_mismatch,
                .message = "declassification requires a complete named transform, valid output, and source span",
            });
        }
        if (caller != permit.authorized_binding) {
            return std::unexpected(LabelError {
                .code = LabelErrorCode::caller_not_authorized,
                .message = "the caller binding is not authorized for this declassification transform",
            });
        }
        if (!may_flow_to(source.label, permit.accepted_input)) {
            return std::unexpected(LabelError {
                .code = LabelErrorCode::input_label_rejected,
                .message = "the source label exceeds the declassification transform input policy",
            });
        }

        transformed.label = permit.output_label;
        const auto output_digest = transformed.canonical_digest;
        return DeclassificationResult {
            .value = std::move(transformed),
            .audit = {.transform_id = permit.transform_id,
                      .transform_version = permit.transform_version,
                      .caller = caller,
                      .input_label = source.label,
                      .output_label = permit.output_label,
                      .input_digest = source.canonical_digest,
                      .output_digest = output_digest,
                      .span = span},
        };
    }

} // namespace rule_engine::python::effects
