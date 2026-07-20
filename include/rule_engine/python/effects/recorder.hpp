#pragma once

#include "rule_engine/python/effects/common.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

namespace rule_engine::python::effects {

    enum struct RecorderErrorCode : std::uint8_t { invalid_limits, non_monotonic_sequence };

    struct RecorderError {
        RecorderErrorCode code {};
        std::string message;
    };

    struct FlightRecorderConfig {
        bool armed {};
        bool publish_initially {};
        std::uint32_t maximum_entries {balanced_v1.normal.recorder_events};
        std::size_t maximum_bytes {balanced_v1.normal.recorder_bytes};
        DataLabel retention_ceiling {.classification = Classification::secret, .categories = {}};
    };

    struct DroppedRecorderEvents {
        std::uint64_t first_sequence {};
        std::uint64_t last_sequence {};
        std::uint64_t event_count {};
        std::size_t estimated_bytes {};
    };

    using RecorderEntry = std::variant<RecorderEvent, DroppedRecorderEvents>;

    struct RecorderSnapshot {
        bool armed {};
        bool publication_requested {};
        bool truncated {};
        std::vector<RecorderEntry> entries;
        std::size_t estimated_bytes {};
        std::uint64_t redacted_events {};
    };

    struct FlightRecorder {
        struct Implementation;

        [[nodiscard]] static std::expected<FlightRecorder, RecorderError> create(FlightRecorderConfig config);

        FlightRecorder(FlightRecorder &&other) noexcept;
        FlightRecorder &operator=(FlightRecorder &&other) noexcept;
        FlightRecorder(const FlightRecorder &) = delete;
        FlightRecorder &operator=(const FlightRecorder &) = delete;
        ~FlightRecorder();

        [[nodiscard]] bool armed() const noexcept;
        [[nodiscard]] bool publication_requested() const noexcept;
        [[nodiscard]] bool request_publication() noexcept;
        void disable_publication() noexcept;
        [[nodiscard]] std::expected<void, RecorderError> record(RecorderEvent event);
        [[nodiscard]] RecorderSnapshot snapshot() const;
        [[nodiscard]] RecorderSnapshot published_snapshot() const;

    private:
        explicit FlightRecorder(std::unique_ptr<Implementation> implementation) noexcept;

        std::unique_ptr<Implementation> implementation_;
    };

} // namespace rule_engine::python::effects
