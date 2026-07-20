#pragma once

#include "rule_engine/python/contract.hpp"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rule_engine::python::vm {

    enum struct VmErrorCode : std::uint8_t {
        invalid_handle,
        stale_handle,
        type_error,
        value_error,
        arithmetic_error,
        heap_budget_exhausted,
        instruction_budget_exhausted,
        frame_budget_exhausted,
        loop_budget_exhausted,
        elapsed_budget_exhausted,
        fact_budget_exhausted,
        capability_budget_exhausted,
        state_budget_exhausted,
        effect_budget_exhausted,
        invalid_bytecode,
        invalid_host_response,
        canceled,
        engine_fault,
    };

    struct VmError {
        VmErrorCode code {VmErrorCode::engine_fault};
        std::string message;
        std::optional<SourceSpan> span;
    };

    struct BigInteger {
        bool negative {};
        std::string magnitude {"0"};

        [[nodiscard]] static std::expected<BigInteger, VmError> parse(std::string_view decimal);
        [[nodiscard]] std::string decimal() const;
        [[nodiscard]] bool is_zero() const noexcept;
        [[nodiscard]] std::size_t digits() const noexcept;

        auto operator<=>(const BigInteger &) const = delete;
    };

    [[nodiscard]] int compare(const BigInteger &left, const BigInteger &right) noexcept;
    [[nodiscard]] BigInteger add(const BigInteger &left, const BigInteger &right);
    [[nodiscard]] BigInteger subtract(const BigInteger &left, const BigInteger &right);
    [[nodiscard]] BigInteger multiply(const BigInteger &left, const BigInteger &right);

    enum struct ValueKind : std::uint8_t {
        none,
        boolean,
        integer,
        floating,
        unicode,
        bytes,
        list,
        map,
        record,
    };

    // These ordinals are part of the compiler/VM ABI. Keep them synchronized with
    // the Python AST operator lowering in the compiler lane.
    enum struct UnaryOperation : std::uint32_t { logical_not, positive, negative, invert };
    enum struct BinaryOperation : std::uint32_t {
        add,
        subtract,
        multiply,
        true_divide,
        floor_divide,
        modulo,
        power,
        left_shift,
        right_shift,
        bit_or,
        bit_xor,
        bit_and,
    };
    enum struct CompareOperation : std::uint32_t {
        equal,
        not_equal,
        less,
        less_equal,
        greater,
        greater_equal,
        identity,
        not_identity,
        contains,
        not_contains,
    };

    struct RecordFieldValue {
        std::uint32_t field_id {};
        PyValue value;
    };

    struct FreezeLimits {
        std::size_t maximum_bytes {balanced_v1.normal.effect_bytes};
        std::uint32_t maximum_items {100'000};
        std::uint32_t maximum_depth {128};
    };

    struct HeapStats {
        std::size_t live_bytes {};
        std::size_t peak_live_bytes {};
        std::size_t logical_allocated_bytes {};
        std::uint64_t collections {};
        std::uint64_t live_objects {};
    };

    struct ValueHeap {
        explicit ValueHeap(std::size_t maximum_live_bytes = balanced_v1.normal.heap_bytes);
        ValueHeap(ValueHeap &&) noexcept;
        ValueHeap &operator=(ValueHeap &&) noexcept;
        ValueHeap(const ValueHeap &) = delete;
        ValueHeap &operator=(const ValueHeap &) = delete;
        ~ValueHeap();

        [[nodiscard]] std::expected<PyValue, VmError> allocate_none();
        [[nodiscard]] std::expected<PyValue, VmError> allocate_bool(bool value);
        [[nodiscard]] std::expected<PyValue, VmError> allocate_integer(std::string_view decimal);
        [[nodiscard]] std::expected<PyValue, VmError> allocate_float(double value);
        [[nodiscard]] std::expected<PyValue, VmError> allocate_unicode(std::string_view utf8);
        [[nodiscard]] std::expected<PyValue, VmError> allocate_unicode_codepoints(std::u32string value);
        [[nodiscard]] std::expected<PyValue, VmError> allocate_bytes(std::span<const std::byte> value);
        [[nodiscard]] std::expected<PyValue, VmError> allocate_list(std::span<const PyValue> values = {});
        [[nodiscard]] std::expected<PyValue, VmError>
        allocate_map(std::span<const std::pair<PyValue, PyValue>> entries = {});
        [[nodiscard]] std::expected<PyValue, VmError> allocate_record(SchemaId schema,
                                                                      std::span<const RecordFieldValue> fields = {});

        [[nodiscard]] std::expected<void, VmError> list_append(PyValue list, PyValue value);
        [[nodiscard]] std::expected<void, VmError> map_insert(PyValue map, PyValue key, PyValue value);

        [[nodiscard]] std::expected<ValueKind, VmError> kind(PyValue value) const;
        [[nodiscard]] std::expected<bool, VmError> truthy(PyValue value) const;
        [[nodiscard]] std::expected<bool, VmError> equal(PyValue left, PyValue right) const;
        [[nodiscard]] std::expected<int, VmError> compare_values(PyValue left, PyValue right) const;
        [[nodiscard]] std::expected<PyValue, VmError> unary(UnaryOperation operation, PyValue value);
        [[nodiscard]] std::expected<PyValue, VmError> binary(BinaryOperation operation, PyValue left, PyValue right,
                                                             std::uint64_t *work_charge = nullptr);
        [[nodiscard]] std::expected<bool, VmError> compare_operation(CompareOperation operation, PyValue left,
                                                                     PyValue right) const;

        [[nodiscard]] std::expected<std::string, VmError> integer_decimal(PyValue value) const;
        [[nodiscard]] std::expected<std::string, VmError> unicode_utf8(PyValue value) const;
        [[nodiscard]] std::expected<std::vector<PyValue>, VmError> list_items(PyValue value) const;
        [[nodiscard]] std::expected<SchemaId, VmError> record_schema(PyValue value) const;
        [[nodiscard]] std::expected<std::vector<RecordFieldValue>, VmError> record_fields(PyValue value) const;

        [[nodiscard]] std::expected<FrozenValue, FreezeError> freeze(PyValue value, DataLabel label = {},
                                                                     FreezeLimits limits = {}) const;
        [[nodiscard]] std::expected<PyValue, VmError> thaw(const FactValue &value);
        [[nodiscard]] std::expected<PyValue, FreezeError>
        validate_frozen(const FrozenValue &value, std::optional<SchemaId> expected_schema = std::nullopt,
                        const SchemaCatalog *schemas = nullptr, FreezeLimits limits = {});

        [[nodiscard]] static std::expected<void, FreezeError> validate_schema(const FactValue &value,
                                                                              const SchemaId &expected_schema,
                                                                              const SchemaCatalog *schemas = nullptr);

        [[nodiscard]] std::expected<std::size_t, VmError> collect(std::span<const PyValue> roots);
        [[nodiscard]] bool valid(PyValue value) const noexcept;
        [[nodiscard]] HeapStats stats() const noexcept;
        [[nodiscard]] std::size_t maximum_live_bytes() const noexcept;

    private:
        struct Impl;
        Impl *impl_ {};
    };

} // namespace rule_engine::python::vm
