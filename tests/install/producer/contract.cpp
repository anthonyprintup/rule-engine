#include "rule_engine/python/contract/core.hpp"

namespace rule_engine::python {
    bool may_flow_to(const DataLabel &value, const DataLabel &ceiling) noexcept {
        return value.classification <= ceiling.classification && value.categories == ceiling.categories;
    }
}
