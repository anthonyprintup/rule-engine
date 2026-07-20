#include "rule_engine/python/tools/authoring.hpp"

#include <utility>

namespace rule_engine::python::tools {

    WatchTicket CheckWatchCoordinator::begin_generation() {
        std::scoped_lock lock {mutex_};
        cancellation_.request_stop();
        cancellation_ = std::stop_source {};
        ++generation_;
        return WatchTicket {
            .generation = generation_,
            .cancellation = cancellation_.get_token(),
        };
    }

    WatchCompletion CheckWatchCoordinator::complete(const WatchTicket &ticket, CheckToolResult result) {
        std::scoped_lock lock {mutex_};
        if (ticket.generation != generation_) {
            return WatchCompletion::stale;
        }
        if (ticket.cancellation.stop_requested()) {
            return WatchCompletion::cancelled;
        }
        if (!result.success || has_errors(result.diagnostics)) {
            return WatchCompletion::failed;
        }
        published_ = std::move(result);
        return WatchCompletion::published;
    }

    void CheckWatchCoordinator::cancel_current() {
        std::scoped_lock lock {mutex_};
        cancellation_.request_stop();
    }

    std::uint64_t CheckWatchCoordinator::current_generation() const {
        std::scoped_lock lock {mutex_};
        return generation_;
    }

    std::optional<CheckToolResult> CheckWatchCoordinator::last_published() const {
        std::scoped_lock lock {mutex_};
        return published_;
    }

} // namespace rule_engine::python::tools
