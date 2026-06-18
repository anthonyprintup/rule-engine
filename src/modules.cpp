#include <rule_engine/modules.hpp>

#include <algorithm>

namespace rule_engine {
    std::string_view fact_cost_class_name(const FactCostClass cost_class) noexcept {
        switch (cost_class) {
            case FactCostClass::inventory: return "inventory";
            case FactCostClass::cheap_process_snapshot: return "cheap_process_snapshot";
            case FactCostClass::static_image_header: return "static_image_header";
            case FactCostClass::process_array: return "process_array";
            case FactCostClass::broad_image_array: return "broad_image_array";
            case FactCostClass::handle_signer: return "handle_signer";
            case FactCostClass::memory_region: return "memory_region";
            case FactCostClass::pattern_scan: return "pattern_scan";
            case FactCostClass::custom: return "custom";
            default: return "custom";
        }
    }

    std::string_view provider_retry_policy_name(const ProviderRetryPolicy retry_policy) noexcept {
        switch (retry_policy) {
            case ProviderRetryPolicy::none: return "none";
            case ProviderRetryPolicy::timed_out: return "timed_out";
            default: return "none";
        }
    }

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
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::inventory},
                        FieldDescriptor {.key = "process.parent.pid",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::cheap_process_snapshot},
                        FieldDescriptor {.key = "process.thread_count",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::cheap_process_snapshot},
                        FieldDescriptor {.key = "process.architecture",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::inventory},
                        FieldDescriptor {.key = "process.integrity_level",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::cheap_process_snapshot},
                        FieldDescriptor {.key = "process.user.sid",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::cheap_process_snapshot},
                        FieldDescriptor {.key = "process.user.name",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::cheap_process_snapshot},
                        FieldDescriptor {.key = "process.token.elevated",
                                         .type = ValueType::boolean,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::cheap_process_snapshot},
                        FieldDescriptor {.key = "process.token.type",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::cheap_process_snapshot},
                        FieldDescriptor {.key = "process.modules.count",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::process_array},
                        FieldDescriptor {.key = "process.modules.names",
                                         .type = ValueType::array,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::process_array},
                        FieldDescriptor {.key = "process.memory.regions.count",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::memory_region},
                        FieldDescriptor {.key = "process.memory.regions.readable_count",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::memory_region},
                        FieldDescriptor {.key = "process.memory.regions",
                                         .type = ValueType::array,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::memory_region},
                        FieldDescriptor {.key = "process.name",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::inventory},
                        FieldDescriptor {.key = "process.path",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::inventory},
                        FieldDescriptor {.key = "process.command_line",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::cheap_process_snapshot},
                        FieldDescriptor {.key = "process.session_id",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.snapshot",
                                         .ttl = 0s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::inventory},
                        FieldDescriptor {.key = "process.handles.count",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.handles",
                                         .ttl = 0s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::handle_signer},
                        FieldDescriptor {.key = "process.signer.status",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.signer",
                                         .ttl = 30s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::handle_signer},
                        FieldDescriptor {.key = "process.signer.is_signed",
                                         .type = ValueType::boolean,
                                         .route = "endpoint.process.signer",
                                         .ttl = 30s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::handle_signer},
                    },
                    .functions = {},
                },
                ModuleDescriptor {
                    .name = "pe",
                    .fields = {
                        FieldDescriptor {.key = "pe.identity.path",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.identity.file_id",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.identity.file_size",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.identity.last_write_time",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.identity.scan_space_name",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.identity.scan_space_version",
                                         .type = ValueType::string,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.is_valid",
                                         .type = ValueType::boolean,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.machine",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.number_of_sections",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.entry_point",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.size_of_image",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.subsystem",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.characteristics",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.dll_characteristics",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.timestamp",
                                         .type = ValueType::integer,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = true,
                                         .cost_class = FactCostClass::static_image_header},
                        FieldDescriptor {.key = "pe.sections",
                                         .type = ValueType::array,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::broad_image_array},
                        FieldDescriptor {.key = "pe.imports",
                                         .type = ValueType::array,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::broad_image_array},
                        FieldDescriptor {.key = "pe.exports",
                                         .type = ValueType::array,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::broad_image_array},
                        FieldDescriptor {.key = "pe.debug_entries",
                                         .type = ValueType::array,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::broad_image_array},
                        FieldDescriptor {.key = "pe.resources",
                                         .type = ValueType::array,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::broad_image_array},
                        FieldDescriptor {.key = "pe.certificates",
                                         .type = ValueType::array,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::broad_image_array},
                        FieldDescriptor {.key = "pe.tls_callbacks",
                                         .type = ValueType::array,
                                         .route = "endpoint.process.image.pe",
                                         .ttl = 30s,
                                         .cheap_prefetch = false,
                                         .cost_class = FactCostClass::broad_image_array},
                    },
                    .functions = {},
                },
            },
            .globals = {},
        };
    }
} // namespace rule_engine
