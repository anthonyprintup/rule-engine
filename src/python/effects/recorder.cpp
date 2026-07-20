#include "rule_engine/python/effects/recorder.hpp"

#include <algorithm>
#include <deque>
#include <limits>
#include <utility>

namespace rule_engine::python::effects {
    namespace {

        inline constexpr std::size_t dropped_marker_bytes = 64U;

        std::size_t saturating_add(const std::size_t left, const std::size_t right) noexcept {
            if (right > std::numeric_limits<std::size_t>::max() - left) {
                return std::numeric_limits<std::size_t>::max();
            }
            return left + right;
        }

        std::size_t recorder_event_size(const RecorderEvent &event) noexcept {
            auto size = sizeof(event.sequence) + sizeof(event.label.classification) + event.kind.size() +
                        event.span.source.value.size() + event.summary.size();
            for (const auto &category : event.label.categories) { size = saturating_add(size, category.size()); }
            return size;
        }

    } // namespace

    struct FlightRecorder::Implementation {
        FlightRecorderConfig config;
        bool publication_requested {};
        bool truncated {};
        std::optional<std::uint64_t> last_sequence;
        std::uint64_t redacted_events {};
        std::vector<RecorderEvent> full;
        std::size_t full_bytes {};
        std::vector<RecorderEvent> head;
        std::size_t head_bytes {};
        std::deque<RecorderEvent> tail;
        std::size_t tail_bytes {};
        DroppedRecorderEvents dropped;

        [[nodiscard]] std::uint32_t head_capacity() const noexcept { return (config.maximum_entries - 1U) / 2U; }

        [[nodiscard]] std::uint32_t tail_capacity() const noexcept {
            return config.maximum_entries - 1U - head_capacity();
        }

        [[nodiscard]] std::size_t data_byte_capacity() const noexcept {
            return config.maximum_bytes - dropped_marker_bytes;
        }

        [[nodiscard]] std::size_t head_byte_capacity() const noexcept { return data_byte_capacity() / 2U; }

        [[nodiscard]] std::size_t tail_byte_capacity() const noexcept {
            return data_byte_capacity() - head_byte_capacity();
        }

        void add_dropped(const RecorderEvent &event) noexcept {
            const auto bytes = recorder_event_size(event);
            if (dropped.event_count == 0) {
                dropped.first_sequence = event.sequence;
            }
            dropped.last_sequence = event.sequence;
            ++dropped.event_count;
            dropped.estimated_bytes = saturating_add(dropped.estimated_bytes, bytes);
        }

        void begin_truncation(RecorderEvent latest) {
            std::vector<RecorderEvent> combined = std::move(full);
            combined.push_back(std::move(latest));
            full.clear();
            full_bytes = 0;

            std::size_t head_count {};
            while (head_count < combined.size() && head_count < head_capacity()) {
                const auto event_bytes = recorder_event_size(combined[head_count]);
                if (event_bytes > head_byte_capacity() - std::min(head_byte_capacity(), head_bytes)) {
                    break;
                }
                head_bytes += event_bytes;
                head.push_back(combined[head_count]);
                ++head_count;
            }

            std::size_t tail_begin = combined.size();
            std::size_t tail_count {};
            while (tail_begin > head_count && tail_count < tail_capacity()) {
                const auto candidate = tail_begin - 1U;
                const auto event_bytes = recorder_event_size(combined[candidate]);
                if (event_bytes > tail_byte_capacity() - std::min(tail_byte_capacity(), tail_bytes)) {
                    break;
                }
                tail_bytes += event_bytes;
                --tail_begin;
                ++tail_count;
            }

            for (std::size_t index = head_count; index < tail_begin; ++index) { add_dropped(combined[index]); }
            for (std::size_t index = tail_begin; index < combined.size(); ++index) {
                tail.push_back(std::move(combined[index]));
            }
            truncated = true;
        }

        void append_truncated(RecorderEvent event) {
            const auto event_bytes = recorder_event_size(event);
            if (event_bytes > tail_byte_capacity()) {
                while (!tail.empty()) {
                    add_dropped(tail.front());
                    tail.pop_front();
                }
                tail_bytes = 0;
                add_dropped(event);
                return;
            }

            tail_bytes += event_bytes;
            tail.push_back(std::move(event));
            while (tail.size() > tail_capacity() || tail_bytes > tail_byte_capacity()) {
                const auto bytes = recorder_event_size(tail.front());
                add_dropped(tail.front());
                tail.pop_front();
                tail_bytes -= bytes;
            }
        }
    };

    std::expected<FlightRecorder, RecorderError> FlightRecorder::create(const FlightRecorderConfig config) {
        if (config.maximum_entries < 3U || config.maximum_bytes < dropped_marker_bytes + 2U) {
            return std::unexpected(RecorderError {
                .code = RecorderErrorCode::invalid_limits,
                .message = "flight recorder limits must reserve one head event, one tail event, and a dropped marker",
            });
        }
        auto implementation = std::make_unique<Implementation>();
        implementation->config = config;
        implementation->publication_requested = config.armed && config.publish_initially;
        return FlightRecorder {std::move(implementation)};
    }

    FlightRecorder::FlightRecorder(std::unique_ptr<Implementation> implementation) noexcept:
        implementation_ {std::move(implementation)} {}

    FlightRecorder::FlightRecorder(FlightRecorder &&other) noexcept = default;
    FlightRecorder &FlightRecorder::operator=(FlightRecorder &&other) noexcept = default;
    FlightRecorder::~FlightRecorder() = default;

    bool FlightRecorder::armed() const noexcept { return implementation_->config.armed; }

    bool FlightRecorder::publication_requested() const noexcept { return implementation_->publication_requested; }

    bool FlightRecorder::request_publication() noexcept {
        if (!armed()) {
            return false;
        }
        implementation_->publication_requested = true;
        return true;
    }

    void FlightRecorder::disable_publication() noexcept { implementation_->publication_requested = false; }

    std::expected<void, RecorderError> FlightRecorder::record(RecorderEvent event) {
        if (!armed()) {
            return {};
        }
        if (implementation_->last_sequence.has_value() && event.sequence <= *implementation_->last_sequence) {
            return std::unexpected(RecorderError {
                .code = RecorderErrorCode::non_monotonic_sequence,
                .message = "flight recorder sequence numbers must increase monotonically",
            });
        }
        implementation_->last_sequence = event.sequence;
        if (!may_flow_to(event.label, implementation_->config.retention_ceiling)) {
            event.summary = "<redacted>";
            ++implementation_->redacted_events;
        }

        if (implementation_->truncated) {
            implementation_->append_truncated(std::move(event));
            return {};
        }

        const auto bytes = recorder_event_size(event);
        const auto fits_count = implementation_->full.size() < implementation_->config.maximum_entries;
        const auto fits_bytes =
            bytes <= implementation_->config.maximum_bytes -
                         std::min(implementation_->config.maximum_bytes, implementation_->full_bytes);
        if (fits_count && fits_bytes) {
            implementation_->full_bytes += bytes;
            implementation_->full.push_back(std::move(event));
            return {};
        }

        implementation_->begin_truncation(std::move(event));
        return {};
    }

    RecorderSnapshot FlightRecorder::snapshot() const {
        RecorderSnapshot result {
            .armed = armed(),
            .publication_requested = publication_requested(),
            .truncated = implementation_->truncated,
            .entries = {},
            .estimated_bytes = 0,
            .redacted_events = implementation_->redacted_events,
        };
        if (!armed()) {
            return result;
        }
        if (!implementation_->truncated) {
            result.entries.reserve(implementation_->full.size());
            for (const auto &event : implementation_->full) { result.entries.emplace_back(event); }
            result.estimated_bytes = implementation_->full_bytes;
            return result;
        }

        result.entries.reserve(implementation_->head.size() + implementation_->tail.size() + 1U);
        for (const auto &event : implementation_->head) { result.entries.emplace_back(event); }
        result.entries.emplace_back(implementation_->dropped);
        for (const auto &event : implementation_->tail) { result.entries.emplace_back(event); }
        result.estimated_bytes = implementation_->head_bytes + dropped_marker_bytes + implementation_->tail_bytes;
        return result;
    }

    RecorderSnapshot FlightRecorder::published_snapshot() const {
        auto result = snapshot();
        if (!result.publication_requested) {
            result.entries.clear();
            result.estimated_bytes = 0;
        }
        return result;
    }

} // namespace rule_engine::python::effects
