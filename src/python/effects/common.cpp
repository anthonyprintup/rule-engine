#include "rule_engine/python/effects/common.hpp"

#include <algorithm>
#include <charconv>
#include <type_traits>

namespace rule_engine::python::effects {
    namespace {

        void append_component(std::string &output, const std::string_view component) {
            char length[32] {};
            const auto [end, error] = std::to_chars(std::begin(length), std::end(length), component.size());
            if (error == std::errc {}) {
                output.append(std::begin(length), end);
            }
            output.push_back(':');
            output.append(component);
            output.push_back(';');
        }

        std::size_t fact_value_size(const FactValue &value) noexcept;

        std::size_t fact_data_size(const FactData &data) noexcept {
            return std::visit(
                [](const auto &item) -> std::size_t {
                    using Item = std::remove_cvref_t<decltype(item)>;
                    if constexpr (std::is_same_v<Item, std::monostate>) {
                        return 1U;
                    } else if constexpr (std::is_same_v<Item, bool> || std::is_same_v<Item, double>) {
                        return sizeof(Item);
                    } else if constexpr (std::is_same_v<Item, IntegerValue>) {
                        return item.decimal.size();
                    } else if constexpr (std::is_same_v<Item, UnicodeValue>) {
                        return item.utf8.size();
                    } else if constexpr (std::is_same_v<Item, BytesValue>) {
                        return item.bytes.size();
                    } else if constexpr (std::is_same_v<Item, EnumValue>) {
                        return item.schema.value.size() + item.member.size();
                    } else if constexpr (std::is_same_v<Item, FactList>) {
                        std::size_t size = sizeof(std::uint64_t);
                        for (const auto &child : item.items) { size += fact_value_size(child); }
                        return size;
                    } else if constexpr (std::is_same_v<Item, FactMap>) {
                        std::size_t size = sizeof(std::uint64_t);
                        for (const auto &entry : item.entries) {
                            size += fact_value_size(entry.key) + fact_value_size(entry.value);
                        }
                        return size;
                    } else {
                        std::size_t size = item.schema.value.size() + sizeof(std::uint64_t);
                        for (const auto &field : item.fields) {
                            size += sizeof(field.field_id) + fact_value_size(field.value);
                        }
                        return size;
                    }
                },
                data);
        }

        std::size_t fact_value_size(const FactValue &value) noexcept {
            if (!value.valid()) {
                return 0;
            }
            return fact_data_size(value.node->data);
        }

    } // namespace

    std::string stable_domain_key(const std::string_view domain,
                                  const std::initializer_list<std::string_view> components) {
        std::string output;
        output.reserve(domain.size() + components.size() * 24U);
        append_component(output, domain);
        for (const auto component : components) { append_component(output, component); }
        return output;
    }

    std::size_t frozen_value_size(const FrozenValue &value) noexcept {
        auto size = fact_value_size(value.value) + value.canonical_digest.size() + sizeof(value.label.classification);
        for (const auto &category : value.label.categories) { size += category.size(); }
        return size;
    }

    bool same_frozen_value(const FrozenValue &left, const FrozenValue &right) noexcept {
        return left.canonical_digest == right.canonical_digest && left.label == right.label &&
               left.value.valid() == right.value.valid();
    }

} // namespace rule_engine::python::effects
