#include "rule_engine/python/contract/core.hpp"

int main() {
    const rule_engine::python::DataLabel value {
        .classification = rule_engine::python::Classification::internal,
        .categories = {"install-smoke"},
    };
    const rule_engine::python::DataLabel ceiling {
        .classification = rule_engine::python::Classification::sensitive,
        .categories = {"install-smoke"},
    };
    return rule_engine::python::may_flow_to(value, ceiling) ? 0 : 1;
}
