#include "rule_engine/python/vm/value.hpp"

#include <algorithm>
#include <bit>
#include <charconv>
#include <cmath>
#include <iomanip>
#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <variant>

namespace rule_engine::python::vm {
    namespace {

        [[nodiscard]] VmError error(const VmErrorCode code, std::string message) {
            return VmError {.code = code, .message = std::move(message), .span = std::nullopt};
        }

        [[nodiscard]] int compare_magnitude(const std::string_view left, const std::string_view right) noexcept {
            if (left.size() != right.size()) {
                return left.size() < right.size() ? -1 : 1;
            }
            if (left == right) {
                return 0;
            }
            return left < right ? -1 : 1;
        }

        [[nodiscard]] std::string add_magnitude(const std::string_view left, const std::string_view right) {
            std::string result;
            result.reserve(std::max(left.size(), right.size()) + 1U);
            std::size_t left_index = left.size();
            std::size_t right_index = right.size();
            unsigned carry {};
            while (left_index != 0U || right_index != 0U || carry != 0U) {
                unsigned digit = carry;
                if (left_index != 0U) {
                    --left_index;
                    digit += static_cast<unsigned>(left[left_index] - '0');
                }
                if (right_index != 0U) {
                    --right_index;
                    digit += static_cast<unsigned>(right[right_index] - '0');
                }
                result.push_back(static_cast<char>('0' + (digit % 10U)));
                carry = digit / 10U;
            }
            std::ranges::reverse(result);
            return result;
        }

        [[nodiscard]] std::string subtract_magnitude(const std::string_view larger, const std::string_view smaller) {
            std::string result;
            result.reserve(larger.size());
            std::size_t larger_index = larger.size();
            std::size_t smaller_index = smaller.size();
            int borrow {};
            while (larger_index != 0U) {
                --larger_index;
                int digit = static_cast<int>(larger[larger_index] - '0') - borrow;
                if (smaller_index != 0U) {
                    --smaller_index;
                    digit -= static_cast<int>(smaller[smaller_index] - '0');
                }
                if (digit < 0) {
                    digit += 10;
                    borrow = 1;
                } else {
                    borrow = 0;
                }
                result.push_back(static_cast<char>('0' + digit));
            }
            while (result.size() > 1U && result.back() == '0') { result.pop_back(); }
            std::ranges::reverse(result);
            return result;
        }

        [[nodiscard]] std::string multiply_magnitude(const std::string_view left, const std::string_view right) {
            if (left == "0" || right == "0") {
                return "0";
            }
            std::vector<unsigned> digits(left.size() + right.size(), 0U);
            for (std::size_t left_index = left.size(); left_index != 0U; --left_index) {
                for (std::size_t right_index = right.size(); right_index != 0U; --right_index) {
                    const auto product = static_cast<unsigned>(left[left_index - 1U] - '0') *
                                             static_cast<unsigned>(right[right_index - 1U] - '0') +
                                         digits[left_index + right_index - 1U];
                    digits[left_index + right_index - 1U] = product % 10U;
                    digits[left_index + right_index - 2U] += product / 10U;
                }
            }
            std::string result;
            result.reserve(digits.size());
            bool leading = true;
            for (const auto digit : digits) {
                if (leading && digit == 0U) {
                    continue;
                }
                leading = false;
                result.push_back(static_cast<char>('0' + digit));
            }
            return result.empty() ? std::string {"0"} : result;
        }

        [[nodiscard]] std::expected<std::u32string, VmError> decode_utf8(const std::string_view input) {
            std::u32string output;
            output.reserve(input.size());
            std::size_t index {};
            while (index < input.size()) {
                const auto first = static_cast<unsigned char>(input[index]);
                char32_t point {};
                std::size_t count {};
                if (first <= 0x7FU) {
                    point = first;
                    count = 1U;
                } else if ((first & 0xE0U) == 0xC0U) {
                    point = first & 0x1FU;
                    count = 2U;
                } else if ((first & 0xF0U) == 0xE0U) {
                    point = first & 0x0FU;
                    count = 3U;
                } else if ((first & 0xF8U) == 0xF0U) {
                    point = first & 0x07U;
                    count = 4U;
                } else {
                    return std::unexpected(error(VmErrorCode::value_error, "invalid UTF-8 leading byte"));
                }
                if (index + count > input.size()) {
                    return std::unexpected(error(VmErrorCode::value_error, "truncated UTF-8 sequence"));
                }
                for (std::size_t continuation = 1U; continuation < count; ++continuation) {
                    const auto byte = static_cast<unsigned char>(input[index + continuation]);
                    if ((byte & 0xC0U) != 0x80U) {
                        return std::unexpected(error(VmErrorCode::value_error, "invalid UTF-8 continuation byte"));
                    }
                    point = static_cast<char32_t>((point << 6U) | (byte & 0x3FU));
                }
                const bool overlong = (count == 2U && point < 0x80U) || (count == 3U && point < 0x800U) ||
                                      (count == 4U && point < 0x10000U);
                if (overlong || point > 0x10FFFFU || (point >= 0xD800U && point <= 0xDFFFU)) {
                    return std::unexpected(error(VmErrorCode::value_error, "non-scalar UTF-8 sequence"));
                }
                output.push_back(point);
                index += count;
            }
            return output;
        }

        [[nodiscard]] std::expected<std::string, VmError> encode_utf8(const std::u32string &input) {
            std::string output;
            output.reserve(input.size());
            for (const auto point : input) {
                if (point > 0x10FFFFU || (point >= 0xD800U && point <= 0xDFFFU)) {
                    return std::unexpected(
                        error(VmErrorCode::value_error, "Unicode value contains a surrogate code point"));
                }
                if (point <= 0x7FU) {
                    output.push_back(static_cast<char>(point));
                    continue;
                }
                if (point <= 0x7FFU) {
                    output.push_back(static_cast<char>(0xC0U | (point >> 6U)));
                    output.push_back(static_cast<char>(0x80U | (point & 0x3FU)));
                    continue;
                }
                if (point <= 0xFFFFU) {
                    output.push_back(static_cast<char>(0xE0U | (point >> 12U)));
                    output.push_back(static_cast<char>(0x80U | ((point >> 6U) & 0x3FU)));
                    output.push_back(static_cast<char>(0x80U | (point & 0x3FU)));
                    continue;
                }
                output.push_back(static_cast<char>(0xF0U | (point >> 18U)));
                output.push_back(static_cast<char>(0x80U | ((point >> 12U) & 0x3FU)));
                output.push_back(static_cast<char>(0x80U | ((point >> 6U) & 0x3FU)));
                output.push_back(static_cast<char>(0x80U | (point & 0x3FU)));
            }
            return output;
        }

        [[nodiscard]] std::string digest(const std::string_view canonical) {
            std::uint64_t value {14695981039346656037ULL};
            for (const auto byte : canonical) {
                value ^= static_cast<unsigned char>(byte);
                value *= 1099511628211ULL;
            }
            std::ostringstream output;
            output << "fnv1a64:" << std::hex << std::setfill('0') << std::setw(16) << value;
            return output.str();
        }

        void append_token(std::string &output, const std::string_view value) {
            output.append(std::to_string(value.size()));
            output.push_back(':');
            output.append(value);
            output.push_back(';');
        }

    } // namespace

    std::expected<BigInteger, VmError> BigInteger::parse(const std::string_view decimal) {
        if (decimal.empty()) {
            return std::unexpected(error(VmErrorCode::value_error, "integer spelling is empty"));
        }
        BigInteger result;
        std::size_t offset {};
        if (decimal.front() == '-') {
            result.negative = true;
            offset = 1U;
        }
        if (offset == decimal.size()) {
            return std::unexpected(error(VmErrorCode::value_error, "integer spelling has no digits"));
        }
        for (std::size_t index = offset; index < decimal.size(); ++index) {
            if (decimal[index] < '0' || decimal[index] > '9') {
                return std::unexpected(error(VmErrorCode::value_error, "integer spelling is not canonical decimal"));
            }
        }
        result.magnitude = std::string {decimal.substr(offset)};
        const auto non_zero = result.magnitude.find_first_not_of('0');
        if (non_zero == std::string::npos) {
            result.magnitude = "0";
            result.negative = false;
            return result;
        }
        if (non_zero != 0U) {
            return std::unexpected(error(VmErrorCode::value_error, "integer spelling contains leading zeroes"));
        }
        return result;
    }

    std::string BigInteger::decimal() const { return negative && !is_zero() ? "-" + magnitude : magnitude; }

    bool BigInteger::is_zero() const noexcept { return magnitude == "0"; }

    std::size_t BigInteger::digits() const noexcept { return magnitude.size(); }

    int compare(const BigInteger &left, const BigInteger &right) noexcept {
        if (left.negative != right.negative) {
            return left.negative ? -1 : 1;
        }
        const auto magnitude = compare_magnitude(left.magnitude, right.magnitude);
        return left.negative ? -magnitude : magnitude;
    }

    BigInteger add(const BigInteger &left, const BigInteger &right) {
        if (left.negative == right.negative) {
            return BigInteger {.negative = left.negative, .magnitude = add_magnitude(left.magnitude, right.magnitude)};
        }
        const auto order = compare_magnitude(left.magnitude, right.magnitude);
        if (order == 0) {
            return {};
        }
        if (order > 0) {
            return BigInteger {.negative = left.negative,
                               .magnitude = subtract_magnitude(left.magnitude, right.magnitude)};
        }
        return BigInteger {.negative = right.negative,
                           .magnitude = subtract_magnitude(right.magnitude, left.magnitude)};
    }

    BigInteger subtract(const BigInteger &left, const BigInteger &right) {
        auto negated = right;
        if (!negated.is_zero()) {
            negated.negative = !negated.negative;
        }
        return add(left, negated);
    }

    BigInteger multiply(const BigInteger &left, const BigInteger &right) {
        BigInteger result {.negative = left.negative != right.negative,
                           .magnitude = multiply_magnitude(left.magnitude, right.magnitude)};
        if (result.is_zero()) {
            result.negative = false;
        }
        return result;
    }

    struct ValueHeap::Impl {
        struct UnicodeStorage {
            std::u32string codepoints;
        };
        struct BytesStorage {
            std::vector<std::byte> bytes;
        };
        struct ListStorage {
            std::vector<PyValue> values;
        };
        struct MapStorage {
            std::vector<std::pair<PyValue, PyValue>> entries;
        };
        using Payload = std::variant<std::monostate, bool, BigInteger, double, UnicodeStorage, BytesStorage,
                                     ListStorage, MapStorage>;

        struct Object {
            ValueKind kind {ValueKind::none};
            Payload payload;
        };

        struct Slot {
            std::uint32_t generation {1U};
            bool marked {};
            std::size_t bytes {};
            std::optional<Object> object;
        };

        std::size_t maximum_live_bytes {};
        HeapStats stats;
        std::vector<Slot> slots;
        std::vector<std::uint32_t> free_slots;

        [[nodiscard]] static std::size_t object_bytes(const Object &object) {
            auto bytes = sizeof(Object);
            switch (object.kind) {
                case ValueKind::integer: bytes += std::get<BigInteger>(object.payload).magnitude.size(); break;
                case ValueKind::unicode:
                    bytes += std::get<UnicodeStorage>(object.payload).codepoints.size() * sizeof(char32_t);
                    break;
                case ValueKind::bytes: bytes += std::get<BytesStorage>(object.payload).bytes.size(); break;
                case ValueKind::list:
                    bytes += std::get<ListStorage>(object.payload).values.size() * sizeof(PyValue);
                    break;
                case ValueKind::map:
                    bytes += std::get<MapStorage>(object.payload).entries.size() * sizeof(std::pair<PyValue, PyValue>);
                    break;
                default: break;
            }
            return bytes;
        }

        [[nodiscard]] std::expected<PyValue, VmError> allocate(Object object) {
            const auto bytes = object_bytes(object);
            if (bytes > maximum_live_bytes || stats.live_bytes > maximum_live_bytes - bytes) {
                return std::unexpected(
                    error(VmErrorCode::heap_budget_exhausted, "allocation would exceed the live VM heap budget"));
            }

            std::uint32_t index {};
            if (free_slots.empty()) {
                if (slots.size() >= std::numeric_limits<std::uint32_t>::max()) {
                    return std::unexpected(error(VmErrorCode::heap_budget_exhausted, "heap handle space exhausted"));
                }
                index = static_cast<std::uint32_t>(slots.size());
                slots.emplace_back();
            } else {
                index = free_slots.back();
                free_slots.pop_back();
            }
            auto &slot = slots[index];
            slot.bytes = bytes;
            slot.marked = false;
            slot.object = std::move(object);
            stats.live_bytes += bytes;
            stats.logical_allocated_bytes += bytes;
            stats.peak_live_bytes = std::max(stats.peak_live_bytes, stats.live_bytes);
            ++stats.live_objects;
            return PyValue {.slot = index, .generation = slot.generation};
        }

        [[nodiscard]] const Slot *find(const PyValue value) const noexcept {
            if (value.generation == 0U || value.slot >= slots.size()) {
                return nullptr;
            }
            const auto &slot = slots[value.slot];
            if (!slot.object.has_value() || slot.generation != value.generation) {
                return nullptr;
            }
            return &slot;
        }

        [[nodiscard]] Slot *find(const PyValue value) noexcept {
            return const_cast<Slot *>(std::as_const(*this).find(value));
        }

        [[nodiscard]] std::expected<const Object *, VmError> object(const PyValue value) const {
            const auto *slot = find(value);
            if (slot == nullptr) {
                return std::unexpected(error(VmErrorCode::stale_handle, "VM value handle is invalid or stale"));
            }
            return &*slot->object;
        }

        [[nodiscard]] std::optional<BigInteger> integer_like(const Object &object) const {
            if (object.kind == ValueKind::integer) {
                return std::get<BigInteger>(object.payload);
            }
            if (object.kind == ValueKind::boolean) {
                return BigInteger {.negative = false, .magnitude = std::get<bool>(object.payload) ? "1" : "0"};
            }
            return std::nullopt;
        }

        [[nodiscard]] std::expected<bool, VmError>
        equal_recursive(const PyValue left, const PyValue right,
                        std::set<std::pair<std::uint64_t, std::uint64_t>> &active, const std::uint32_t depth) const {
            if (left == right) {
                return true;
            }
            if (depth > 128U) {
                return std::unexpected(error(VmErrorCode::value_error, "equality recursion limit exceeded"));
            }
            const auto left_object = object(left);
            const auto right_object = object(right);
            if (!left_object) {
                return std::unexpected(left_object.error());
            }
            if (!right_object) {
                return std::unexpected(right_object.error());
            }
            const auto left_integer = integer_like(**left_object);
            const auto right_integer = integer_like(**right_object);
            if (left_integer.has_value() && right_integer.has_value()) {
                return compare(*left_integer, *right_integer) == 0;
            }
            if ((*left_object)->kind != (*right_object)->kind) {
                return false;
            }
            switch ((*left_object)->kind) {
                case ValueKind::none: return true;
                case ValueKind::floating:
                    return std::get<double>((*left_object)->payload) == std::get<double>((*right_object)->payload);
                case ValueKind::unicode:
                    return std::get<UnicodeStorage>((*left_object)->payload).codepoints ==
                           std::get<UnicodeStorage>((*right_object)->payload).codepoints;
                case ValueKind::bytes:
                    return std::get<BytesStorage>((*left_object)->payload).bytes ==
                           std::get<BytesStorage>((*right_object)->payload).bytes;
                case ValueKind::list: {
                    const auto pair = std::pair {
                        (static_cast<std::uint64_t>(left.slot) << 32U) | left.generation,
                        (static_cast<std::uint64_t>(right.slot) << 32U) | right.generation,
                    };
                    if (!active.insert(pair).second) {
                        return true;
                    }
                    const auto &left_values = std::get<ListStorage>((*left_object)->payload).values;
                    const auto &right_values = std::get<ListStorage>((*right_object)->payload).values;
                    if (left_values.size() != right_values.size()) {
                        active.erase(pair);
                        return false;
                    }
                    for (std::size_t index = 0; index < left_values.size(); ++index) {
                        auto item_equal = equal_recursive(left_values[index], right_values[index], active, depth + 1U);
                        if (!item_equal || !*item_equal) {
                            active.erase(pair);
                            return item_equal;
                        }
                    }
                    active.erase(pair);
                    return true;
                }
                case ValueKind::map: {
                    const auto pair = std::pair {
                        (static_cast<std::uint64_t>(left.slot) << 32U) | left.generation,
                        (static_cast<std::uint64_t>(right.slot) << 32U) | right.generation,
                    };
                    if (!active.insert(pair).second) {
                        return true;
                    }
                    const auto &left_entries = std::get<MapStorage>((*left_object)->payload).entries;
                    const auto &right_entries = std::get<MapStorage>((*right_object)->payload).entries;
                    if (left_entries.size() != right_entries.size()) {
                        active.erase(pair);
                        return false;
                    }
                    for (const auto &[left_key, left_value] : left_entries) {
                        bool found {};
                        for (const auto &[right_key, right_value] : right_entries) {
                            auto keys_equal = equal_recursive(left_key, right_key, active, depth + 1U);
                            if (!keys_equal) {
                                active.erase(pair);
                                return std::unexpected(keys_equal.error());
                            }
                            if (!*keys_equal) {
                                continue;
                            }
                            auto values_equal = equal_recursive(left_value, right_value, active, depth + 1U);
                            if (!values_equal) {
                                active.erase(pair);
                                return std::unexpected(values_equal.error());
                            }
                            found = *values_equal;
                            break;
                        }
                        if (!found) {
                            active.erase(pair);
                            return false;
                        }
                    }
                    active.erase(pair);
                    return true;
                }
                case ValueKind::boolean:
                case ValueKind::integer: break;
            }
            return false;
        }

        struct FreezeState {
            FreezeLimits limits;
            std::uint32_t items {};
            std::size_t bytes {};
            std::unordered_set<std::uint64_t> path;
            std::string canonical;
        };

        [[nodiscard]] static FreezeError freeze_error(const FreezeErrorCode code, std::string message) {
            return FreezeError {.code = code, .message = std::move(message), .span = std::nullopt};
        }

        [[nodiscard]] static bool add_freeze_bytes(FreezeState &state, const std::size_t amount) noexcept {
            if (amount > state.limits.maximum_bytes || state.bytes > state.limits.maximum_bytes - amount) {
                return false;
            }
            state.bytes += amount;
            return true;
        }

        [[nodiscard]] std::expected<FactValue, FreezeError> freeze_value(const PyValue value, FreezeState &state,
                                                                         const std::uint32_t depth) const {
            if (depth > state.limits.maximum_depth) {
                return std::unexpected(
                    freeze_error(FreezeErrorCode::budget_exhausted, "boundary value exceeds maximum depth"));
            }
            if (state.items == state.limits.maximum_items) {
                return std::unexpected(
                    freeze_error(FreezeErrorCode::budget_exhausted, "boundary value exceeds maximum item count"));
            }
            ++state.items;
            const auto object_value = object(value);
            if (!object_value) {
                return std::unexpected(freeze_error(FreezeErrorCode::invalid_handle, object_value.error().message));
            }
            const auto &current = **object_value;
            switch (current.kind) {
                case ValueKind::none:
                    if (!add_freeze_bytes(state, 1U)) {
                        return std::unexpected(
                            freeze_error(FreezeErrorCode::budget_exhausted, "boundary byte budget exhausted"));
                    }
                    append_token(state.canonical, "none");
                    return make_fact(std::monostate {});
                case ValueKind::boolean: {
                    const auto boolean = std::get<bool>(current.payload);
                    if (!add_freeze_bytes(state, 1U)) {
                        return std::unexpected(
                            freeze_error(FreezeErrorCode::budget_exhausted, "boundary byte budget exhausted"));
                    }
                    append_token(state.canonical, boolean ? "true" : "false");
                    return make_fact(boolean);
                }
                case ValueKind::integer: {
                    const auto &integer = std::get<BigInteger>(current.payload);
                    const auto decimal_size = integer.digits() + (integer.negative && !integer.is_zero() ? 1U : 0U);
                    if (!add_freeze_bytes(state, decimal_size)) {
                        return std::unexpected(
                            freeze_error(FreezeErrorCode::budget_exhausted, "boundary byte budget exhausted"));
                    }
                    const auto decimal = integer.decimal();
                    append_token(state.canonical, "int");
                    append_token(state.canonical, decimal);
                    return make_fact(IntegerValue {.decimal = decimal});
                }
                case ValueKind::floating: {
                    if (!add_freeze_bytes(state, sizeof(double))) {
                        return std::unexpected(
                            freeze_error(FreezeErrorCode::budget_exhausted, "boundary byte budget exhausted"));
                    }
                    auto floating = std::get<double>(current.payload);
                    if (std::isnan(floating)) {
                        floating = std::numeric_limits<double>::quiet_NaN();
                    }
                    const auto bits = std::bit_cast<std::uint64_t>(floating);
                    append_token(state.canonical, "float");
                    append_token(state.canonical, std::to_string(bits));
                    return make_fact(floating);
                }
                case ValueKind::unicode: {
                    const auto &codepoints = std::get<UnicodeStorage>(current.payload).codepoints;
                    const auto remaining = state.limits.maximum_bytes - state.bytes;
                    if (codepoints.size() > remaining) {
                        return std::unexpected(
                            freeze_error(FreezeErrorCode::budget_exhausted, "boundary byte budget exhausted"));
                    }
                    auto encoded = encode_utf8(codepoints);
                    if (!encoded) {
                        return std::unexpected(
                            freeze_error(FreezeErrorCode::unsupported_type, std::move(encoded.error().message)));
                    }
                    if (!add_freeze_bytes(state, encoded->size())) {
                        return std::unexpected(
                            freeze_error(FreezeErrorCode::budget_exhausted, "boundary byte budget exhausted"));
                    }
                    append_token(state.canonical, "unicode");
                    append_token(state.canonical, *encoded);
                    return make_fact(UnicodeValue {.utf8 = std::move(*encoded)});
                }
                case ValueKind::bytes: {
                    const auto &bytes = std::get<BytesStorage>(current.payload).bytes;
                    if (!add_freeze_bytes(state, bytes.size())) {
                        return std::unexpected(
                            freeze_error(FreezeErrorCode::budget_exhausted, "boundary byte budget exhausted"));
                    }
                    append_token(state.canonical, "bytes");
                    state.canonical.append(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                    return make_fact(BytesValue {.bytes = bytes});
                }
                case ValueKind::list:
                case ValueKind::map: break;
            }

            const auto key = (static_cast<std::uint64_t>(value.slot) << 32U) | value.generation;
            if (!state.path.insert(key).second) {
                return std::unexpected(
                    freeze_error(FreezeErrorCode::cycle, "cyclic VM values cannot cross a canonical boundary"));
            }
            if (current.kind == ValueKind::list) {
                append_token(state.canonical, "list");
                FactList list;
                const auto &items = std::get<ListStorage>(current.payload).values;
                list.items.reserve(items.size());
                for (const auto item : items) {
                    auto frozen = freeze_value(item, state, depth + 1U);
                    if (!frozen) {
                        state.path.erase(key);
                        return std::unexpected(std::move(frozen.error()));
                    }
                    list.items.push_back(std::move(*frozen));
                }
                state.path.erase(key);
                return make_fact(std::move(list));
            }

            append_token(state.canonical, "map");
            FactMap map;
            const auto &entries = std::get<MapStorage>(current.payload).entries;
            map.entries.reserve(entries.size());
            for (const auto &[entry_key, entry_value] : entries) {
                auto frozen_key = freeze_value(entry_key, state, depth + 1U);
                if (!frozen_key) {
                    state.path.erase(key);
                    return std::unexpected(std::move(frozen_key.error()));
                }
                auto frozen_value = freeze_value(entry_value, state, depth + 1U);
                if (!frozen_value) {
                    state.path.erase(key);
                    return std::unexpected(std::move(frozen_value.error()));
                }
                map.entries.push_back(FactMapEntry {.key = std::move(*frozen_key), .value = std::move(*frozen_value)});
            }
            state.path.erase(key);
            return make_fact(std::move(map));
        }

        [[nodiscard]] std::expected<PyValue, VmError>
        thaw_value(const FactValue &value, std::unordered_set<const FactNode *> &path, const std::uint32_t depth) {
            if (!value.valid()) {
                return std::unexpected(error(VmErrorCode::value_error, "fact value is empty"));
            }
            if (depth > 128U) {
                return std::unexpected(error(VmErrorCode::value_error, "fact value exceeds thaw depth"));
            }
            if (!path.insert(value.node.get()).second) {
                return std::unexpected(error(VmErrorCode::value_error, "fact value contains a cycle"));
            }
            const auto &data = value.node->data;
            std::expected<PyValue, VmError> result =
                std::unexpected(error(VmErrorCode::type_error, "fact value type is not supported by this VM"));
            if (std::holds_alternative<std::monostate>(data)) {
                result = allocate(Object {.kind = ValueKind::none, .payload = std::monostate {}});
            } else if (const auto *boolean = std::get_if<bool>(&data); boolean != nullptr) {
                result = allocate(Object {.kind = ValueKind::boolean, .payload = *boolean});
            } else if (const auto *integer = std::get_if<IntegerValue>(&data); integer != nullptr) {
                auto parsed = BigInteger::parse(integer->decimal);
                if (!parsed) {
                    result = std::unexpected(parsed.error());
                } else {
                    result = allocate(Object {.kind = ValueKind::integer, .payload = std::move(*parsed)});
                }
            } else if (const auto *floating = std::get_if<double>(&data); floating != nullptr) {
                result = allocate(Object {.kind = ValueKind::floating, .payload = *floating});
            } else if (const auto *unicode = std::get_if<UnicodeValue>(&data); unicode != nullptr) {
                auto decoded = decode_utf8(unicode->utf8);
                if (!decoded) {
                    result = std::unexpected(decoded.error());
                } else {
                    result = allocate(Object {.kind = ValueKind::unicode,
                                              .payload = UnicodeStorage {.codepoints = std::move(*decoded)}});
                }
            } else if (const auto *bytes = std::get_if<BytesValue>(&data); bytes != nullptr) {
                result = allocate(Object {.kind = ValueKind::bytes, .payload = BytesStorage {.bytes = bytes->bytes}});
            } else if (const auto *list = std::get_if<FactList>(&data); list != nullptr) {
                std::vector<PyValue> items;
                items.reserve(list->items.size());
                for (const auto &item : list->items) {
                    auto thawed = thaw_value(item, path, depth + 1U);
                    if (!thawed) {
                        result = std::unexpected(thawed.error());
                        break;
                    }
                    items.push_back(*thawed);
                }
                if (items.size() == list->items.size()) {
                    result =
                        allocate(Object {.kind = ValueKind::list, .payload = ListStorage {.values = std::move(items)}});
                }
            } else if (const auto *map = std::get_if<FactMap>(&data); map != nullptr) {
                std::vector<std::pair<PyValue, PyValue>> entries;
                entries.reserve(map->entries.size());
                for (const auto &entry : map->entries) {
                    auto key = thaw_value(entry.key, path, depth + 1U);
                    if (!key) {
                        result = std::unexpected(key.error());
                        break;
                    }
                    auto entry_value = thaw_value(entry.value, path, depth + 1U);
                    if (!entry_value) {
                        result = std::unexpected(entry_value.error());
                        break;
                    }
                    entries.emplace_back(*key, *entry_value);
                }
                if (entries.size() == map->entries.size()) {
                    result = allocate(
                        Object {.kind = ValueKind::map, .payload = MapStorage {.entries = std::move(entries)}});
                }
            }
            path.erase(value.node.get());
            return result;
        }
    };

    ValueHeap::ValueHeap(const std::size_t maximum_live_bytes): impl_ {new Impl {}} {
        impl_->maximum_live_bytes = maximum_live_bytes;
    }

    ValueHeap::ValueHeap(ValueHeap &&other) noexcept: impl_ {std::exchange(other.impl_, nullptr)} {}

    ValueHeap &ValueHeap::operator=(ValueHeap &&other) noexcept {
        if (this == &other) {
            return *this;
        }
        delete impl_;
        impl_ = std::exchange(other.impl_, nullptr);
        return *this;
    }

    ValueHeap::~ValueHeap() { delete impl_; }

    std::expected<PyValue, VmError> ValueHeap::allocate_none() {
        return impl_->allocate(Impl::Object {.kind = ValueKind::none, .payload = std::monostate {}});
    }

    std::expected<PyValue, VmError> ValueHeap::allocate_bool(const bool value) {
        return impl_->allocate(Impl::Object {.kind = ValueKind::boolean, .payload = value});
    }

    std::expected<PyValue, VmError> ValueHeap::allocate_integer(const std::string_view decimal) {
        const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
        if (remaining < sizeof(Impl::Object) || decimal.size() > remaining - sizeof(Impl::Object)) {
            return std::unexpected(
                error(VmErrorCode::heap_budget_exhausted, "integer allocation would exceed the live VM heap budget"));
        }
        auto parsed = BigInteger::parse(decimal);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        return impl_->allocate(Impl::Object {.kind = ValueKind::integer, .payload = std::move(*parsed)});
    }

    std::expected<PyValue, VmError> ValueHeap::allocate_float(const double value) {
        return impl_->allocate(Impl::Object {.kind = ValueKind::floating, .payload = value});
    }

    std::expected<PyValue, VmError> ValueHeap::allocate_unicode(const std::string_view utf8) {
        const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
        if (remaining < sizeof(Impl::Object) || utf8.size() > (remaining - sizeof(Impl::Object)) / sizeof(char32_t)) {
            return std::unexpected(
                error(VmErrorCode::heap_budget_exhausted, "Unicode allocation would exceed the live VM heap budget"));
        }
        auto decoded = decode_utf8(utf8);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        return allocate_unicode_codepoints(std::move(*decoded));
    }

    std::expected<PyValue, VmError> ValueHeap::allocate_unicode_codepoints(std::u32string value) {
        const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
        if (remaining < sizeof(Impl::Object) || value.size() > (remaining - sizeof(Impl::Object)) / sizeof(char32_t)) {
            return std::unexpected(
                error(VmErrorCode::heap_budget_exhausted, "Unicode allocation would exceed the live VM heap budget"));
        }
        for (const auto point : value) {
            if (point > 0x10FFFFU) {
                return std::unexpected(error(VmErrorCode::value_error, "Unicode code point is out of range"));
            }
        }
        return impl_->allocate(Impl::Object {
            .kind = ValueKind::unicode,
            .payload = Impl::UnicodeStorage {.codepoints = std::move(value)},
        });
    }

    std::expected<PyValue, VmError> ValueHeap::allocate_bytes(const std::span<const std::byte> value) {
        const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
        if (remaining < sizeof(Impl::Object) || value.size() > remaining - sizeof(Impl::Object)) {
            return std::unexpected(
                error(VmErrorCode::heap_budget_exhausted, "bytes allocation would exceed the live VM heap budget"));
        }
        return impl_->allocate(Impl::Object {
            .kind = ValueKind::bytes,
            .payload = Impl::BytesStorage {.bytes = std::vector<std::byte> {value.begin(), value.end()}},
        });
    }

    std::expected<PyValue, VmError> ValueHeap::allocate_list(const std::span<const PyValue> values) {
        const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
        if (remaining < sizeof(Impl::Object) || values.size() > (remaining - sizeof(Impl::Object)) / sizeof(PyValue)) {
            return std::unexpected(
                error(VmErrorCode::heap_budget_exhausted, "list allocation would exceed the live VM heap budget"));
        }
        if (!std::ranges::all_of(values, [this](const auto value) { return valid(value); })) {
            return std::unexpected(error(VmErrorCode::invalid_handle, "list contains an invalid VM handle"));
        }
        return impl_->allocate(Impl::Object {
            .kind = ValueKind::list,
            .payload = Impl::ListStorage {.values = std::vector<PyValue> {values.begin(), values.end()}},
        });
    }

    std::expected<PyValue, VmError>
    ValueHeap::allocate_map(const std::span<const std::pair<PyValue, PyValue>> entries) {
        const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
        if (remaining < sizeof(Impl::Object) ||
            entries.size() > (remaining - sizeof(Impl::Object)) / sizeof(std::pair<PyValue, PyValue>)) {
            return std::unexpected(
                error(VmErrorCode::heap_budget_exhausted, "map allocation would exceed the live VM heap budget"));
        }
        for (const auto &[key, value] : entries) {
            if (!valid(key) || !valid(value)) {
                return std::unexpected(error(VmErrorCode::invalid_handle, "map contains an invalid VM handle"));
            }
            const auto key_kind = kind(key);
            if (!key_kind || *key_kind == ValueKind::list || *key_kind == ValueKind::map) {
                return std::unexpected(error(VmErrorCode::type_error, "unhashable map key"));
            }
        }
        return impl_->allocate(Impl::Object {
            .kind = ValueKind::map,
            .payload =
                Impl::MapStorage {.entries = std::vector<std::pair<PyValue, PyValue>> {entries.begin(), entries.end()}},
        });
    }

    std::expected<void, VmError> ValueHeap::list_append(const PyValue list, const PyValue value) {
        auto *slot = impl_->find(list);
        if (slot == nullptr || !valid(value)) {
            return std::unexpected(error(VmErrorCode::invalid_handle, "list append uses an invalid VM handle"));
        }
        if (slot->object->kind != ValueKind::list) {
            return std::unexpected(error(VmErrorCode::type_error, "list append target is not a list"));
        }
        constexpr auto charge = sizeof(PyValue);
        if (charge > impl_->maximum_live_bytes || impl_->stats.live_bytes > impl_->maximum_live_bytes - charge) {
            return std::unexpected(
                error(VmErrorCode::heap_budget_exhausted, "list growth would exceed the live VM heap budget"));
        }
        std::get<Impl::ListStorage>(slot->object->payload).values.push_back(value);
        slot->bytes += charge;
        impl_->stats.live_bytes += charge;
        impl_->stats.logical_allocated_bytes += charge;
        impl_->stats.peak_live_bytes = std::max(impl_->stats.peak_live_bytes, impl_->stats.live_bytes);
        return {};
    }

    std::expected<void, VmError> ValueHeap::map_insert(const PyValue map, const PyValue key, const PyValue value) {
        auto *slot = impl_->find(map);
        if (slot == nullptr || !valid(key) || !valid(value)) {
            return std::unexpected(error(VmErrorCode::invalid_handle, "map insert uses an invalid VM handle"));
        }
        if (slot->object->kind != ValueKind::map) {
            return std::unexpected(error(VmErrorCode::type_error, "map insert target is not a map"));
        }
        const auto key_kind = kind(key);
        if (!key_kind || *key_kind == ValueKind::list || *key_kind == ValueKind::map) {
            return std::unexpected(error(VmErrorCode::type_error, "unhashable map key"));
        }
        auto &entries = std::get<Impl::MapStorage>(slot->object->payload).entries;
        for (auto &[existing_key, existing_value] : entries) {
            auto same = equal(existing_key, key);
            if (!same) {
                return std::unexpected(same.error());
            }
            if (*same) {
                existing_value = value;
                return {};
            }
        }
        constexpr auto charge = sizeof(std::pair<PyValue, PyValue>);
        if (charge > impl_->maximum_live_bytes || impl_->stats.live_bytes > impl_->maximum_live_bytes - charge) {
            return std::unexpected(
                error(VmErrorCode::heap_budget_exhausted, "map growth would exceed the live VM heap budget"));
        }
        entries.emplace_back(key, value);
        slot->bytes += charge;
        impl_->stats.live_bytes += charge;
        impl_->stats.logical_allocated_bytes += charge;
        impl_->stats.peak_live_bytes = std::max(impl_->stats.peak_live_bytes, impl_->stats.live_bytes);
        return {};
    }

    std::expected<ValueKind, VmError> ValueHeap::kind(const PyValue value) const {
        auto object = impl_->object(value);
        if (!object) {
            return std::unexpected(object.error());
        }
        return (*object)->kind;
    }

    std::expected<bool, VmError> ValueHeap::truthy(const PyValue value) const {
        auto object = impl_->object(value);
        if (!object) {
            return std::unexpected(object.error());
        }
        switch ((*object)->kind) {
            case ValueKind::none: return false;
            case ValueKind::boolean: return std::get<bool>((*object)->payload);
            case ValueKind::integer: return !std::get<BigInteger>((*object)->payload).is_zero();
            case ValueKind::floating: return std::get<double>((*object)->payload) != 0.0;
            case ValueKind::unicode: return !std::get<Impl::UnicodeStorage>((*object)->payload).codepoints.empty();
            case ValueKind::bytes: return !std::get<Impl::BytesStorage>((*object)->payload).bytes.empty();
            case ValueKind::list: return !std::get<Impl::ListStorage>((*object)->payload).values.empty();
            case ValueKind::map: return !std::get<Impl::MapStorage>((*object)->payload).entries.empty();
        }
        return false;
    }

    std::expected<bool, VmError> ValueHeap::equal(const PyValue left, const PyValue right) const {
        std::set<std::pair<std::uint64_t, std::uint64_t>> active;
        return impl_->equal_recursive(left, right, active, 0U);
    }

    std::expected<int, VmError> ValueHeap::compare_values(const PyValue left, const PyValue right) const {
        auto left_object = impl_->object(left);
        auto right_object = impl_->object(right);
        if (!left_object) {
            return std::unexpected(left_object.error());
        }
        if (!right_object) {
            return std::unexpected(right_object.error());
        }
        const auto left_integer = impl_->integer_like(**left_object);
        const auto right_integer = impl_->integer_like(**right_object);
        if (left_integer.has_value() && right_integer.has_value()) {
            return compare(*left_integer, *right_integer);
        }
        if ((*left_object)->kind == ValueKind::floating && (*right_object)->kind == ValueKind::floating) {
            const auto lhs = std::get<double>((*left_object)->payload);
            const auto rhs = std::get<double>((*right_object)->payload);
            if (std::isnan(lhs) || std::isnan(rhs)) {
                return std::unexpected(error(VmErrorCode::value_error, "NaN values are unordered"));
            }
            return lhs < rhs ? -1 : (lhs > rhs ? 1 : 0);
        }
        if ((*left_object)->kind == ValueKind::unicode && (*right_object)->kind == ValueKind::unicode) {
            const auto &lhs = std::get<Impl::UnicodeStorage>((*left_object)->payload).codepoints;
            const auto &rhs = std::get<Impl::UnicodeStorage>((*right_object)->payload).codepoints;
            return lhs < rhs ? -1 : (lhs > rhs ? 1 : 0);
        }
        if ((*left_object)->kind == ValueKind::bytes && (*right_object)->kind == ValueKind::bytes) {
            const auto &lhs = std::get<Impl::BytesStorage>((*left_object)->payload).bytes;
            const auto &rhs = std::get<Impl::BytesStorage>((*right_object)->payload).bytes;
            return lhs < rhs ? -1 : (lhs > rhs ? 1 : 0);
        }
        return std::unexpected(error(VmErrorCode::type_error, "values do not support ordered comparison"));
    }

    std::expected<PyValue, VmError> ValueHeap::unary(const UnaryOperation operation, const PyValue value) {
        if (operation == UnaryOperation::logical_not) {
            auto boolean = truthy(value);
            if (!boolean) {
                return std::unexpected(boolean.error());
            }
            return allocate_bool(!*boolean);
        }
        auto object = impl_->object(value);
        if (!object) {
            return std::unexpected(object.error());
        }
        auto integer = impl_->integer_like(**object);
        if (integer.has_value()) {
            if (operation == UnaryOperation::negative && !integer->is_zero()) {
                integer->negative = !integer->negative;
            }
            return allocate_integer(integer->decimal());
        }
        if ((*object)->kind == ValueKind::floating) {
            const auto floating = std::get<double>((*object)->payload);
            return allocate_float(operation == UnaryOperation::negative ? -floating : floating);
        }
        return std::unexpected(error(VmErrorCode::type_error, "unary numeric operation requires a number"));
    }

    std::expected<PyValue, VmError> ValueHeap::binary(const BinaryOperation operation, const PyValue left,
                                                      const PyValue right, std::uint64_t *const work_charge) {
        auto left_object = impl_->object(left);
        auto right_object = impl_->object(right);
        if (!left_object) {
            return std::unexpected(left_object.error());
        }
        if (!right_object) {
            return std::unexpected(right_object.error());
        }
        const auto left_integer = impl_->integer_like(**left_object);
        const auto right_integer = impl_->integer_like(**right_object);
        if (left_integer.has_value() && right_integer.has_value()) {
            const auto left_digits = left_integer->digits();
            const auto right_digits = right_integer->digits();
            const auto maximum_result_digits = operation == BinaryOperation::multiply ?
                                                   left_digits + right_digits :
                                                   std::max(left_digits, right_digits) + 1U;
            const auto scratch_multiplier = operation == BinaryOperation::multiply ? sizeof(unsigned) : 1U;
            const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
            if (remaining < sizeof(Impl::Object) ||
                maximum_result_digits > (remaining - sizeof(Impl::Object)) / scratch_multiplier) {
                return std::unexpected(error(VmErrorCode::heap_budget_exhausted,
                                             "integer operation would exceed the live VM heap budget"));
            }
            if (work_charge != nullptr) {
                const auto left_work = static_cast<std::uint64_t>(left_digits);
                const auto right_work = static_cast<std::uint64_t>(right_digits);
                *work_charge =
                    operation == BinaryOperation::multiply ? left_work * right_work : std::max(left_work, right_work);
            }
            BigInteger result;
            switch (operation) {
                case BinaryOperation::add: result = add(*left_integer, *right_integer); break;
                case BinaryOperation::subtract: result = subtract(*left_integer, *right_integer); break;
                case BinaryOperation::multiply: result = multiply(*left_integer, *right_integer); break;
            }
            return allocate_integer(result.decimal());
        }
        if ((*left_object)->kind == ValueKind::floating && (*right_object)->kind == ValueKind::floating) {
            const auto lhs = std::get<double>((*left_object)->payload);
            const auto rhs = std::get<double>((*right_object)->payload);
            switch (operation) {
                case BinaryOperation::add: return allocate_float(lhs + rhs);
                case BinaryOperation::subtract: return allocate_float(lhs - rhs);
                case BinaryOperation::multiply: return allocate_float(lhs * rhs);
            }
        }
        if (operation == BinaryOperation::add && (*left_object)->kind == ValueKind::unicode &&
            (*right_object)->kind == ValueKind::unicode) {
            const auto &prefix = std::get<Impl::UnicodeStorage>((*left_object)->payload).codepoints;
            const auto &suffix = std::get<Impl::UnicodeStorage>((*right_object)->payload).codepoints;
            const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
            if (remaining < sizeof(Impl::Object)) {
                return std::unexpected(error(VmErrorCode::heap_budget_exhausted,
                                             "Unicode operation would exceed the live VM heap budget"));
            }
            const auto capacity = (remaining - sizeof(Impl::Object)) / sizeof(char32_t);
            if (prefix.size() > capacity || suffix.size() > capacity - prefix.size()) {
                return std::unexpected(error(VmErrorCode::heap_budget_exhausted,
                                             "Unicode operation would exceed the live VM heap budget"));
            }
            auto result = prefix;
            result.insert(result.end(), suffix.begin(), suffix.end());
            if (work_charge != nullptr) {
                *work_charge = static_cast<std::uint64_t>(result.size());
            }
            return allocate_unicode_codepoints(std::move(result));
        }
        return std::unexpected(error(VmErrorCode::type_error, "binary operands have incompatible types"));
    }

    std::expected<bool, VmError> ValueHeap::compare_operation(const CompareOperation operation, const PyValue left,
                                                              const PyValue right) const {
        if (operation == CompareOperation::equal || operation == CompareOperation::not_equal) {
            auto same = equal(left, right);
            if (!same) {
                return std::unexpected(same.error());
            }
            return operation == CompareOperation::equal ? *same : !*same;
        }
        auto order = compare_values(left, right);
        if (!order) {
            return std::unexpected(order.error());
        }
        switch (operation) {
            case CompareOperation::less: return *order < 0;
            case CompareOperation::less_equal: return *order <= 0;
            case CompareOperation::greater: return *order > 0;
            case CompareOperation::greater_equal: return *order >= 0;
            case CompareOperation::equal:
            case CompareOperation::not_equal: break;
        }
        return false;
    }

    std::expected<std::string, VmError> ValueHeap::integer_decimal(const PyValue value) const {
        auto object = impl_->object(value);
        if (!object) {
            return std::unexpected(object.error());
        }
        if ((*object)->kind != ValueKind::integer) {
            return std::unexpected(error(VmErrorCode::type_error, "VM value is not an integer"));
        }
        return std::get<BigInteger>((*object)->payload).decimal();
    }

    std::expected<std::string, VmError> ValueHeap::unicode_utf8(const PyValue value) const {
        auto object = impl_->object(value);
        if (!object) {
            return std::unexpected(object.error());
        }
        if ((*object)->kind != ValueKind::unicode) {
            return std::unexpected(error(VmErrorCode::type_error, "VM value is not Unicode"));
        }
        return encode_utf8(std::get<Impl::UnicodeStorage>((*object)->payload).codepoints);
    }

    std::expected<std::vector<PyValue>, VmError> ValueHeap::list_items(const PyValue value) const {
        auto object = impl_->object(value);
        if (!object) {
            return std::unexpected(object.error());
        }
        if ((*object)->kind != ValueKind::list) {
            return std::unexpected(error(VmErrorCode::type_error, "VM value is not a list"));
        }
        return std::get<Impl::ListStorage>((*object)->payload).values;
    }

    std::expected<FrozenValue, FreezeError> ValueHeap::freeze(const PyValue value, DataLabel label,
                                                              const FreezeLimits limits) const {
        Impl::FreezeState state {
            .limits = limits,
            .items = 0U,
            .bytes = 0U,
            .path = {},
            .canonical = {},
        };
        auto frozen = impl_->freeze_value(value, state, 0U);
        if (!frozen) {
            return std::unexpected(std::move(frozen.error()));
        }
        return FrozenValue {
            .value = std::move(*frozen),
            .label = std::move(label),
            .canonical_digest = digest(state.canonical),
        };
    }

    std::expected<PyValue, VmError> ValueHeap::thaw(const FactValue &value) {
        std::unordered_set<const FactNode *> path;
        return impl_->thaw_value(value, path, 0U);
    }

    std::expected<std::size_t, VmError> ValueHeap::collect(const std::span<const PyValue> roots) {
        std::vector<PyValue> worklist;
        worklist.reserve(roots.size());
        for (const auto root : roots) {
            if (!valid(root)) {
                return std::unexpected(error(VmErrorCode::invalid_handle, "garbage collection root is invalid"));
            }
            worklist.push_back(root);
        }
        while (!worklist.empty()) {
            const auto value = worklist.back();
            worklist.pop_back();
            auto *slot = impl_->find(value);
            if (slot == nullptr || slot->marked) {
                continue;
            }
            slot->marked = true;
            if (slot->object->kind == ValueKind::list) {
                const auto &items = std::get<Impl::ListStorage>(slot->object->payload).values;
                worklist.insert(worklist.end(), items.begin(), items.end());
            } else if (slot->object->kind == ValueKind::map) {
                for (const auto &[key, item] : std::get<Impl::MapStorage>(slot->object->payload).entries) {
                    worklist.push_back(key);
                    worklist.push_back(item);
                }
            }
        }

        std::size_t reclaimed {};
        for (std::uint32_t index = 0; index < impl_->slots.size(); ++index) {
            auto &slot = impl_->slots[index];
            if (!slot.object.has_value()) {
                continue;
            }
            if (slot.marked) {
                slot.marked = false;
                continue;
            }
            reclaimed += slot.bytes;
            impl_->stats.live_bytes -= slot.bytes;
            --impl_->stats.live_objects;
            slot.object.reset();
            slot.bytes = 0U;
            ++slot.generation;
            if (slot.generation == 0U) {
                slot.generation = 1U;
            }
            impl_->free_slots.push_back(index);
        }
        ++impl_->stats.collections;
        return reclaimed;
    }

    bool ValueHeap::valid(const PyValue value) const noexcept {
        return impl_ != nullptr && impl_->find(value) != nullptr;
    }

    HeapStats ValueHeap::stats() const noexcept { return impl_->stats; }

    std::size_t ValueHeap::maximum_live_bytes() const noexcept { return impl_->maximum_live_bytes; }

} // namespace rule_engine::python::vm
