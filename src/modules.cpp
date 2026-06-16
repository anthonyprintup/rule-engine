#include <rule_engine/modules.hpp>

#include <algorithm>

namespace rule_engine {
    const ModuleDescriptor *ModuleRegistry::find_module(const std::string_view name) const noexcept {
        const auto found = std::ranges::find_if(modules, [&](const auto &module) { return module.name == name; });
        if (found == modules.end()) {
            return nullptr;
        }
        return &*found;
    }

    const FieldDescriptor *ModuleRegistry::find_field(const std::string_view key) const noexcept {
        for (const auto &module : modules) {
            const auto found = std::ranges::find_if(module.fields, [&](const auto &field) { return field.key == key; });
            if (found != module.fields.end()) {
                return &*found;
            }
        }
        return nullptr;
    }

    const FunctionDescriptor *ModuleRegistry::find_function(const std::string_view key) const noexcept {
        for (const auto &module : modules) {
            const auto found = std::ranges::find_if(module.functions, [&](const auto &function) {
                if (!key.starts_with(module.name)) {
                    return false;
                }
                if (key.size() != module.name.size() + 1u + function.name.size()) {
                    return false;
                }
                if (key[module.name.size()] != '.') {
                    return false;
                }
                return key.substr(module.name.size() + 1u) == function.name;
            });
            if (found != module.functions.end()) {
                return &*found;
            }
        }
        return nullptr;
    }

    const GlobalDescriptor *ModuleRegistry::find_global(const std::string_view name) const noexcept {
        const auto found = std::ranges::find_if(globals, [&](const auto &global) { return global.name == name; });
        if (found == globals.end()) {
            return nullptr;
        }
        return &*found;
    }

    ModuleRegistry default_module_registry() {
        using namespace std::chrono_literals;
        return ModuleRegistry {
            .modules = {
                ModuleDescriptor {
                    .name = "process",
                    .fields = {
                        FieldDescriptor {.key = "process.pid",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true},
                        FieldDescriptor {.key = "process.parent.pid",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true},
                        FieldDescriptor {.key = "process.name",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true},
                        FieldDescriptor {.key = "process.path",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true},
                        FieldDescriptor {.key = "process.command_line",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = false},
                        FieldDescriptor {.key = "process.session_id",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true},
                        FieldDescriptor {.key = "process.handles.count",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.handles",
                                         .ttl = 0s,
                                         .cheap_prefetch = false},
                        FieldDescriptor {.key = "process.signer.status",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.signer",
                                         .ttl = 30s,
                                         .cheap_prefetch = false},
                    },
                    .functions = {},
                },
                ModuleDescriptor {
                    .name = "pe",
                    .fields = {
                        FieldDescriptor {.key = "pe.is_valid",
                                         .type = ValueType::boolean,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true},
                        FieldDescriptor {.key = "pe.machine",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true},
                        FieldDescriptor {.key = "pe.number_of_sections",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true},
                        FieldDescriptor {.key = "pe.entry_point",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true},
                        FieldDescriptor {.key = "pe.size_of_image",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true},
                    },
                    .functions = {},
                },
            },
            .globals = {},
        };
    }
} // namespace rule_engine
