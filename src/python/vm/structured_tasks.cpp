#include "rule_engine/python/vm/register_vm.hpp"

#include <algorithm>

namespace rule_engine::python::vm {
    namespace {

        [[nodiscard]] VmError task_error(std::string message) {
            return VmError {.code = VmErrorCode::engine_fault, .message = std::move(message), .span = std::nullopt};
        }

        [[nodiscard]] bool live(const TaskState state) noexcept {
            return state == TaskState::cold || state == TaskState::ready || state == TaskState::running ||
                   state == TaskState::waiting;
        }

    } // namespace

    TaskGroupId StructuredTasks::open_group(const std::optional<TaskGroupId> parent) {
        if (parent.has_value()) {
            const auto found = std::ranges::find(groups_, *parent, &StructuredTaskGroup::id);
            if (found == groups_.end() || !found->open) {
                return 0U;
            }
        }
        const auto id = next_group_id_++;
        groups_.push_back(StructuredTaskGroup {.id = id, .parent = parent, .open = true});
        return id;
    }

    std::expected<TaskId, VmError> StructuredTasks::start(const TaskGroupId owner,
                                                          const std::optional<PyValue> coroutine) {
        const auto group = std::ranges::find(groups_, owner, &StructuredTaskGroup::id);
        if (group == groups_.end() || !group->open) {
            return std::unexpected(task_error("task must be started in an open lexical task group"));
        }
        const auto id = next_task_id_++;
        tasks_.push_back(StructuredTask {
            .id = id,
            .owner = owner,
            .state = TaskState::ready,
            .coroutine = coroutine,
        });
        return id;
    }

    std::expected<void, VmError> StructuredTasks::set_state(const TaskId task, const TaskState state) {
        const auto found = std::ranges::find(tasks_, task, &StructuredTask::id);
        if (found == tasks_.end()) {
            return std::unexpected(task_error("unknown structured task"));
        }
        if (!live(found->state)) {
            return std::unexpected(task_error("completed structured task cannot transition"));
        }
        found->state = state;
        return {};
    }

    std::optional<TaskId> StructuredTasks::next_ready() const noexcept {
        const auto ready = std::ranges::find(tasks_, TaskState::ready, &StructuredTask::state);
        if (ready == tasks_.end()) {
            return std::nullopt;
        }
        return ready->id;
    }

    std::expected<void, VmError> StructuredTasks::close(const TaskGroupId group, const TaskGroupExitMode mode) {
        const auto found = std::ranges::find(groups_, group, &StructuredTaskGroup::id);
        if (found == groups_.end() || !found->open) {
            return std::unexpected(task_error("task group is unknown or already closed"));
        }
        const auto open_child = std::ranges::find_if(
            groups_, [group](const auto &candidate) { return candidate.open && candidate.parent == group; });
        if (open_child != groups_.end()) {
            return std::unexpected(task_error("nested task group must close before its parent"));
        }
        if (mode == TaskGroupExitMode::wait_pending && has_live_tasks(group)) {
            return std::unexpected(task_error("WAIT_PENDING group still owns live tasks"));
        }
        if (mode == TaskGroupExitMode::cancel_pending) {
            for (auto &task : tasks_) {
                if (task.owner == group && live(task.state)) {
                    task.state = TaskState::canceled;
                }
            }
        }
        found->open = false;
        return {};
    }

    bool StructuredTasks::owns(const TaskGroupId group, const TaskId task) const noexcept {
        const auto found = std::ranges::find(tasks_, task, &StructuredTask::id);
        return found != tasks_.end() && found->owner == group;
    }

    bool StructuredTasks::has_live_tasks(const TaskGroupId group) const noexcept {
        return std::ranges::any_of(tasks_,
                                   [group](const auto &task) { return task.owner == group && live(task.state); });
    }

    std::span<const StructuredTask> StructuredTasks::tasks() const noexcept { return tasks_; }

} // namespace rule_engine::python::vm
