#include "rule_engine/python/vm/value.hpp"

#include <algorithm>
#include <bit>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdlib>
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

        [[nodiscard]] std::string normalize_magnitude(std::string value) {
            const auto non_zero = value.find_first_not_of('0');
            if (non_zero == std::string::npos) {
                return "0";
            }
            value.erase(0U, non_zero);
            return value;
        }

        struct MagnitudeDivision {
            std::string quotient;
            std::string remainder;
        };

        [[nodiscard]] std::expected<MagnitudeDivision, VmError> divide_magnitude(const std::string_view dividend,
                                                                                 const std::string_view divisor) {
            if (divisor == "0") {
                return std::unexpected(error(VmErrorCode::arithmetic_error, "integer division or modulo by zero"));
            }
            if (compare_magnitude(dividend, divisor) < 0) {
                return MagnitudeDivision {.quotient = "0", .remainder = std::string {dividend}};
            }
            std::string quotient;
            quotient.reserve(dividend.size());
            std::string remainder {"0"};
            for (const auto digit : dividend) {
                if (remainder == "0") {
                    remainder.assign(1U, digit);
                } else {
                    remainder.push_back(digit);
                }
                remainder = normalize_magnitude(std::move(remainder));
                unsigned quotient_digit {};
                while (compare_magnitude(remainder, divisor) >= 0) {
                    remainder = subtract_magnitude(remainder, divisor);
                    ++quotient_digit;
                }
                quotient.push_back(static_cast<char>('0' + quotient_digit));
            }
            return MagnitudeDivision {.quotient = normalize_magnitude(std::move(quotient)),
                                      .remainder = normalize_magnitude(std::move(remainder))};
        }

        struct IntegerDivision {
            BigInteger quotient;
            BigInteger remainder;
        };

        [[nodiscard]] std::expected<IntegerDivision, VmError> floor_divide(const BigInteger &left,
                                                                           const BigInteger &right) {
            auto divided = divide_magnitude(left.magnitude, right.magnitude);
            if (!divided) {
                return std::unexpected(divided.error());
            }
            const auto different_sign = left.negative != right.negative;
            if (different_sign && divided->remainder != "0") {
                divided->quotient = add_magnitude(divided->quotient, "1");
                divided->remainder = subtract_magnitude(right.magnitude, divided->remainder);
            }
            return IntegerDivision {
                .quotient = BigInteger {.negative = different_sign && divided->quotient != "0",
                                        .magnitude = std::move(divided->quotient)},
                .remainder = BigInteger {.negative = right.negative && divided->remainder != "0",
                                         .magnitude = std::move(divided->remainder)},
            };
        }

        [[nodiscard]] std::expected<std::uint64_t, VmError>
        bounded_unsigned(const BigInteger &value, const std::uint64_t maximum, const std::string_view operation) {
            if (value.negative) {
                return std::unexpected(
                    error(VmErrorCode::value_error, std::string {operation} + " count cannot be negative"));
            }
            std::uint64_t result {};
            for (const auto digit : value.magnitude) {
                const auto next = static_cast<std::uint64_t>(digit - '0');
                if (result > (maximum - next) / 10U) {
                    return std::unexpected(error(VmErrorCode::instruction_budget_exhausted,
                                                 std::string {operation} + " count exceeds the bounded VM limit"));
                }
                result = result * 10U + next;
            }
            return result;
        }

        [[nodiscard]] std::pair<std::string, unsigned> divide_magnitude_by_two(const std::string_view magnitude) {
            std::string quotient;
            quotient.reserve(magnitude.size());
            unsigned remainder {};
            for (const auto digit : magnitude) {
                const auto current = remainder * 10U + static_cast<unsigned>(digit - '0');
                if (!quotient.empty() || current / 2U != 0U) {
                    quotient.push_back(static_cast<char>('0' + current / 2U));
                }
                remainder = current % 2U;
            }
            return {quotient.empty() ? std::string {"0"} : std::move(quotient), remainder};
        }

        [[nodiscard]] std::vector<bool> magnitude_bits(std::string magnitude) {
            std::vector<bool> bits;
            while (magnitude != "0") {
                auto [quotient, remainder] = divide_magnitude_by_two(magnitude);
                bits.push_back(remainder != 0U);
                magnitude = std::move(quotient);
            }
            if (bits.empty()) {
                bits.push_back(false);
            }
            return bits;
        }

        [[nodiscard]] std::string bits_magnitude(const std::vector<bool> &bits) {
            std::string magnitude {"0"};
            for (auto index = bits.size(); index != 0U; --index) {
                magnitude = multiply_magnitude(magnitude, "2");
                if (bits[index - 1U]) {
                    magnitude = add_magnitude(magnitude, "1");
                }
            }
            return magnitude;
        }

        void twos_complement(std::vector<bool> &bits) {
            for (std::size_t index = 0; index < bits.size(); ++index) { bits[index] = !bits[index]; }
            bool carry = true;
            for (std::size_t index = 0; index < bits.size() && carry; ++index) {
                const bool old = bits[index];
                bits[index] = !old;
                carry = old;
            }
        }

        [[nodiscard]] BigInteger bitwise(const BigInteger &left, const BigInteger &right,
                                         const BinaryOperation operation) {
            auto left_bits = magnitude_bits(left.magnitude);
            auto right_bits = magnitude_bits(right.magnitude);
            const auto width = std::max(left_bits.size(), right_bits.size()) + 1U;
            left_bits.resize(width, false);
            right_bits.resize(width, false);
            if (left.negative) {
                twos_complement(left_bits);
            }
            if (right.negative) {
                twos_complement(right_bits);
            }
            std::vector<bool> result(width);
            for (std::size_t index = 0; index < width; ++index) {
                if (operation == BinaryOperation::bit_or) {
                    result[index] = left_bits[index] || right_bits[index];
                } else if (operation == BinaryOperation::bit_xor) {
                    result[index] = left_bits[index] != right_bits[index];
                } else if (operation == BinaryOperation::bit_and) {
                    result[index] = left_bits[index] && right_bits[index];
                } else {
                    std::unreachable();
                }
            }
            const auto negative = result.back();
            if (negative) {
                twos_complement(result);
            }
            return BigInteger {.negative = negative, .magnitude = bits_magnitude(result)};
        }

        [[nodiscard]] std::expected<double, VmError> as_double(const BigInteger &integer) {
            const auto decimal = integer.decimal();
            errno = 0;
            char *end {};
            const auto result = std::strtod(decimal.c_str(), &end);
            if (end != decimal.data() + decimal.size() || errno == ERANGE || !std::isfinite(result)) {
                return std::unexpected(
                    error(VmErrorCode::arithmetic_error, "integer is too large to convert to a finite float"));
            }
            return result;
        }

        [[nodiscard]] bool python_float_equal(const double left, const double right) noexcept {
            return !std::isnan(left) && !std::isnan(right) && !(left < right) && !(right < left);
        }

        [[nodiscard]] std::expected<int, VmError> compare_integer_float(const BigInteger &integer,
                                                                        const double floating) {
            if (std::isnan(floating)) {
                return std::unexpected(error(VmErrorCode::value_error, "NaN values are unordered"));
            }
            if (std::isinf(floating)) {
                return std::signbit(floating) ? 1 : -1;
            }

            const auto bits = std::bit_cast<std::uint64_t>(floating);
            const auto negative = (bits >> 63U) != 0U;
            const auto exponent_bits = static_cast<unsigned>((bits >> 52U) & 0x7FFU);
            constexpr std::uint64_t fraction_mask {(std::uint64_t {1U} << 52U) - 1U};
            const auto fraction = bits & fraction_mask;
            const auto significand = exponent_bits == 0U ? fraction : fraction | (std::uint64_t {1U} << 52U);
            const auto exponent = exponent_bits == 0U ? -1074 : static_cast<int>(exponent_bits) - 1023 - 52;

            BigInteger whole;
            bool fractional {};
            if (exponent >= 0) {
                whole = *BigInteger::parse(std::to_string(significand));
                for (auto shift = 0; shift < exponent; ++shift) {
                    whole = multiply(whole, BigInteger {.negative = false, .magnitude = "2"});
                }
            } else {
                const auto shift = static_cast<unsigned>(-exponent);
                const auto whole_magnitude = shift >= 64U ? 0U : significand >> shift;
                if (shift >= 64U) {
                    fractional = significand != 0U;
                } else if (shift != 0U) {
                    fractional = (significand & ((std::uint64_t {1U} << shift) - 1U)) != 0U;
                }
                whole = *BigInteger::parse(std::to_string(whole_magnitude));
            }
            whole.negative = negative && !whole.is_zero();
            const auto order = compare(integer, whole);
            if (order != 0 || !fractional) {
                return order;
            }
            return negative ? 1 : -1;
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
        struct RecordStorage {
            SchemaId schema;
            std::vector<RecordFieldValue> fields;
        };
        using Payload = std::variant<std::monostate, bool, BigInteger, double, UnicodeStorage, BytesStorage,
                                     ListStorage, MapStorage, RecordStorage>;

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
                case ValueKind::record: {
                    const auto &record = std::get<RecordStorage>(object.payload);
                    bytes += record.schema.value.size() + record.fields.size() * sizeof(RecordFieldValue);
                    break;
                }
                case ValueKind::none:
                case ValueKind::boolean:
                case ValueKind::floating: break;
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
            if (left == right) {
                if ((*left_object)->kind == ValueKind::floating) {
                    const auto floating = std::get<double>((*left_object)->payload);
                    return python_float_equal(floating, floating);
                }
                return true;
            }
            const auto left_integer = integer_like(**left_object);
            const auto right_integer = integer_like(**right_object);
            if (left_integer.has_value() && right_integer.has_value()) {
                return compare(*left_integer, *right_integer) == 0;
            }
            if (left_integer.has_value() && (*right_object)->kind == ValueKind::floating) {
                const auto floating = std::get<double>((*right_object)->payload);
                if (std::isnan(floating)) {
                    return false;
                }
                auto order = compare_integer_float(*left_integer, floating);
                return order && *order == 0;
            }
            if (right_integer.has_value() && (*left_object)->kind == ValueKind::floating) {
                const auto floating = std::get<double>((*left_object)->payload);
                if (std::isnan(floating)) {
                    return false;
                }
                auto order = compare_integer_float(*right_integer, floating);
                return order && *order == 0;
            }
            if ((*left_object)->kind != (*right_object)->kind) {
                return false;
            }
            switch ((*left_object)->kind) {
                case ValueKind::none: return true;
                case ValueKind::floating: {
                    const auto left_float = std::get<double>((*left_object)->payload);
                    const auto right_float = std::get<double>((*right_object)->payload);
                    return python_float_equal(left_float, right_float);
                }
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
                case ValueKind::record: {
                    const auto pair = std::pair {
                        (static_cast<std::uint64_t>(left.slot) << 32U) | left.generation,
                        (static_cast<std::uint64_t>(right.slot) << 32U) | right.generation,
                    };
                    if (!active.insert(pair).second) {
                        return true;
                    }
                    const auto &left_record = std::get<RecordStorage>((*left_object)->payload);
                    const auto &right_record = std::get<RecordStorage>((*right_object)->payload);
                    if (left_record.schema != right_record.schema ||
                        left_record.fields.size() != right_record.fields.size()) {
                        active.erase(pair);
                        return false;
                    }
                    for (std::size_t index = 0; index < left_record.fields.size(); ++index) {
                        if (left_record.fields[index].field_id != right_record.fields[index].field_id) {
                            active.erase(pair);
                            return false;
                        }
                        auto field_equal = equal_recursive(left_record.fields[index].value,
                                                           right_record.fields[index].value, active, depth + 1U);
                        if (!field_equal || !*field_equal) {
                            active.erase(pair);
                            return field_equal;
                        }
                    }
                    active.erase(pair);
                    return true;
                }
                case ValueKind::boolean:
                case ValueKind::integer: break;
                default: return std::unexpected(error(VmErrorCode::engine_fault, "VM value has an invalid kind"));
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

        [[nodiscard]] std::expected<std::string, FreezeError> canonical_map_key(const PyValue value) const {
            const auto object_value = object(value);
            if (!object_value) {
                return std::unexpected(freeze_error(FreezeErrorCode::invalid_handle, object_value.error().message));
            }
            std::string result;
            const auto &current = **object_value;
            switch (current.kind) {
                case ValueKind::none: append_token(result, "none"); break;
                case ValueKind::boolean:
                    append_token(result, std::get<bool>(current.payload) ? "true" : "false");
                    break;
                case ValueKind::integer:
                    append_token(result, "int");
                    append_token(result, std::get<BigInteger>(current.payload).decimal());
                    break;
                case ValueKind::floating: {
                    auto floating = std::get<double>(current.payload);
                    if (std::isnan(floating)) {
                        floating = std::numeric_limits<double>::quiet_NaN();
                    }
                    append_token(result, "float");
                    append_token(result, std::to_string(std::bit_cast<std::uint64_t>(floating)));
                    break;
                }
                case ValueKind::unicode: {
                    auto encoded = encode_utf8(std::get<UnicodeStorage>(current.payload).codepoints);
                    if (!encoded) {
                        return std::unexpected(
                            freeze_error(FreezeErrorCode::unsupported_type, std::move(encoded.error().message)));
                    }
                    append_token(result, "unicode");
                    append_token(result, *encoded);
                    break;
                }
                case ValueKind::bytes: {
                    append_token(result, "bytes");
                    const auto &bytes = std::get<BytesStorage>(current.payload).bytes;
                    result.append(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                    break;
                }
                case ValueKind::list:
                case ValueKind::map:
                case ValueKind::record:
                    return std::unexpected(freeze_error(FreezeErrorCode::unsupported_type,
                                                        "container or record is not a canonical map key"));
                default:
                    return std::unexpected(
                        freeze_error(FreezeErrorCode::unsupported_type, "VM value has an invalid kind"));
            }
            return result;
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
                case ValueKind::map:
                case ValueKind::record: break;
                default:
                    return std::unexpected(
                        freeze_error(FreezeErrorCode::unsupported_type, "VM value has an invalid kind"));
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

            if (current.kind == ValueKind::record) {
                const auto &record = std::get<RecordStorage>(current.payload);
                append_token(state.canonical, "record");
                append_token(state.canonical, record.schema.value);
                FactRecord frozen_record {.schema = record.schema, .fields = {}};
                frozen_record.fields.reserve(record.fields.size());
                for (const auto &field : record.fields) {
                    append_token(state.canonical, std::to_string(field.field_id));
                    auto frozen = freeze_value(field.value, state, depth + 1U);
                    if (!frozen) {
                        state.path.erase(key);
                        return std::unexpected(std::move(frozen.error()));
                    }
                    frozen_record.fields.push_back(
                        FactRecordField {.field_id = field.field_id, .value = std::move(*frozen)});
                }
                state.path.erase(key);
                return make_fact(std::move(frozen_record));
            }

            append_token(state.canonical, "map");
            FactMap map;
            const auto &entries = std::get<MapStorage>(current.payload).entries;
            map.entries.reserve(entries.size());
            std::vector<std::pair<std::string, std::size_t>> order;
            order.reserve(entries.size());
            for (std::size_t index = 0; index < entries.size(); ++index) {
                auto encoded_key = canonical_map_key(entries[index].first);
                if (!encoded_key) {
                    state.path.erase(key);
                    return std::unexpected(std::move(encoded_key.error()));
                }
                order.emplace_back(std::move(*encoded_key), index);
            }
            std::ranges::sort(order, [](const auto &left, const auto &right) {
                return left.first < right.first || (left.first == right.first && left.second < right.second);
            });
            for (const auto &[canonical_key, index] : order) {
                static_cast<void>(canonical_key);
                const auto &[entry_key, entry_value] = entries[index];
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
            } else if (const auto *record = std::get_if<FactRecord>(&data); record != nullptr) {
                if (record->schema.empty()) {
                    result = std::unexpected(error(VmErrorCode::value_error, "record schema is empty"));
                } else {
                    std::vector<RecordFieldValue> fields;
                    fields.reserve(record->fields.size());
                    for (const auto &field : record->fields) {
                        auto thawed = thaw_value(field.value, path, depth + 1U);
                        if (!thawed) {
                            result = std::unexpected(thawed.error());
                            break;
                        }
                        fields.push_back(RecordFieldValue {.field_id = field.field_id, .value = *thawed});
                    }
                    if (fields.size() == record->fields.size()) {
                        std::ranges::sort(fields, {}, &RecordFieldValue::field_id);
                        const auto duplicate =
                            std::ranges::adjacent_find(fields, [](const auto &left, const auto &right) {
                                return left.field_id == right.field_id;
                            });
                        if (duplicate != fields.end()) {
                            result =
                                std::unexpected(error(VmErrorCode::value_error, "record contains duplicate field IDs"));
                        } else {
                            result = allocate(Object {
                                .kind = ValueKind::record,
                                .payload = RecordStorage {.schema = record->schema, .fields = std::move(fields)}});
                        }
                    }
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
            if (!key_kind || *key_kind == ValueKind::list || *key_kind == ValueKind::map ||
                *key_kind == ValueKind::record) {
                return std::unexpected(error(VmErrorCode::type_error, "unhashable map key"));
            }
        }
        return impl_->allocate(Impl::Object {
            .kind = ValueKind::map,
            .payload =
                Impl::MapStorage {.entries = std::vector<std::pair<PyValue, PyValue>> {entries.begin(), entries.end()}},
        });
    }

    std::expected<PyValue, VmError> ValueHeap::allocate_record(SchemaId schema,
                                                               const std::span<const RecordFieldValue> fields) {
        if (schema.empty()) {
            return std::unexpected(error(VmErrorCode::value_error, "record schema is empty"));
        }
        const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
        if (remaining < sizeof(Impl::Object) || schema.value.size() > remaining - sizeof(Impl::Object)) {
            return std::unexpected(
                error(VmErrorCode::heap_budget_exhausted, "record allocation would exceed the live VM heap budget"));
        }
        const auto field_capacity = (remaining - sizeof(Impl::Object) - schema.value.size()) / sizeof(RecordFieldValue);
        if (fields.size() > field_capacity) {
            return std::unexpected(
                error(VmErrorCode::heap_budget_exhausted, "record allocation would exceed the live VM heap budget"));
        }
        std::vector<RecordFieldValue> sorted {fields.begin(), fields.end()};
        if (!std::ranges::all_of(sorted, [this](const auto &field) { return valid(field.value); })) {
            return std::unexpected(error(VmErrorCode::invalid_handle, "record contains an invalid VM handle"));
        }
        std::ranges::sort(sorted, {}, &RecordFieldValue::field_id);
        if (std::ranges::adjacent_find(sorted, [](const auto &left, const auto &right) {
                return left.field_id == right.field_id;
            }) != sorted.end()) {
            return std::unexpected(error(VmErrorCode::value_error, "record contains duplicate field IDs"));
        }
        return impl_->allocate(Impl::Object {
            .kind = ValueKind::record,
            .payload = Impl::RecordStorage {.schema = std::move(schema), .fields = std::move(sorted)},
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
        if (!key_kind || *key_kind == ValueKind::list || *key_kind == ValueKind::map ||
            *key_kind == ValueKind::record) {
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
            case ValueKind::record: return true;
            default: return std::unexpected(error(VmErrorCode::engine_fault, "VM value has an invalid kind"));
        }
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
        if (left_integer.has_value() && (*right_object)->kind == ValueKind::floating) {
            return compare_integer_float(*left_integer, std::get<double>((*right_object)->payload));
        }
        if (right_integer.has_value() && (*left_object)->kind == ValueKind::floating) {
            auto order = compare_integer_float(*right_integer, std::get<double>((*left_object)->payload));
            if (!order) {
                return std::unexpected(order.error());
            }
            return -*order;
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
            } else if (operation == UnaryOperation::invert) {
                *integer = subtract(BigInteger {.negative = true, .magnitude = "1"}, *integer);
            }
            return allocate_integer(integer->decimal());
        }
        if ((*object)->kind == ValueKind::floating) {
            if (operation == UnaryOperation::invert) {
                return std::unexpected(error(VmErrorCode::type_error, "bitwise inversion requires an integer"));
            }
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
            std::uint64_t operand_count {};
            if (operation == BinaryOperation::power && right_integer->negative) {
                operand_count = 0U;
            } else if (operation == BinaryOperation::power || operation == BinaryOperation::left_shift ||
                       operation == BinaryOperation::right_shift) {
                auto count = bounded_unsigned(*right_integer, 1'000'000U,
                                              operation == BinaryOperation::power ? "exponent" : "shift");
                if (!count) {
                    return std::unexpected(count.error());
                }
                operand_count = *count;
            }

            auto maximum_result_digits = std::max(left_digits, right_digits) + 1U;
            if (operation == BinaryOperation::multiply) {
                maximum_result_digits = left_digits + right_digits;
            } else if (operation == BinaryOperation::power && !right_integer->negative) {
                if (operand_count != 0U &&
                    left_digits > (std::numeric_limits<std::size_t>::max() - 1U) / operand_count) {
                    return std::unexpected(
                        error(VmErrorCode::heap_budget_exhausted, "power result exceeds VM size accounting"));
                }
                maximum_result_digits = left_digits * static_cast<std::size_t>(operand_count) + 1U;
            } else if (operation == BinaryOperation::left_shift) {
                maximum_result_digits = left_digits + static_cast<std::size_t>(operand_count / 3U) + 2U;
            }
            const auto scratch_multiplier =
                operation == BinaryOperation::multiply || operation == BinaryOperation::power ||
                        operation == BinaryOperation::bit_or || operation == BinaryOperation::bit_xor ||
                        operation == BinaryOperation::bit_and ?
                    sizeof(unsigned) :
                    1U;
            const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
            const auto produces_float = operation == BinaryOperation::true_divide ||
                                        (operation == BinaryOperation::power && right_integer->negative);
            if (remaining < sizeof(Impl::Object) ||
                (!produces_float && maximum_result_digits > (remaining - sizeof(Impl::Object)) / scratch_multiplier)) {
                return std::unexpected(error(VmErrorCode::heap_budget_exhausted,
                                             "integer operation would exceed the live VM heap budget"));
            }
            if (work_charge != nullptr) {
                const auto left_work = static_cast<std::uint64_t>(left_digits);
                const auto right_work = static_cast<std::uint64_t>(right_digits);
                switch (operation) {
                    case BinaryOperation::multiply:
                    case BinaryOperation::floor_divide:
                    case BinaryOperation::modulo: *work_charge = left_work * right_work; break;
                    case BinaryOperation::power:
                    case BinaryOperation::left_shift:
                    case BinaryOperation::right_shift:
                        *work_charge = left_work * std::max<std::uint64_t>(1U, operand_count);
                        break;
                    case BinaryOperation::add:
                    case BinaryOperation::subtract:
                    case BinaryOperation::true_divide:
                    case BinaryOperation::bit_or:
                    case BinaryOperation::bit_xor:
                    case BinaryOperation::bit_and: *work_charge = std::max(left_work, right_work); break;
                    default: return std::unexpected(error(VmErrorCode::engine_fault, "invalid binary operation"));
                }
            }
            BigInteger result;
            switch (operation) {
                case BinaryOperation::add: result = add(*left_integer, *right_integer); break;
                case BinaryOperation::subtract: result = subtract(*left_integer, *right_integer); break;
                case BinaryOperation::multiply: result = multiply(*left_integer, *right_integer); break;
                case BinaryOperation::true_divide: {
                    if (right_integer->is_zero()) {
                        return std::unexpected(error(VmErrorCode::arithmetic_error, "division by zero"));
                    }
                    auto lhs = as_double(*left_integer);
                    auto rhs = as_double(*right_integer);
                    if (!lhs) {
                        return std::unexpected(lhs.error());
                    }
                    if (!rhs) {
                        return std::unexpected(rhs.error());
                    }
                    return allocate_float(*lhs / *rhs);
                }
                case BinaryOperation::floor_divide:
                case BinaryOperation::modulo: {
                    auto divided = floor_divide(*left_integer, *right_integer);
                    if (!divided) {
                        return std::unexpected(divided.error());
                    }
                    result = operation == BinaryOperation::floor_divide ? std::move(divided->quotient) :
                                                                          std::move(divided->remainder);
                    break;
                }
                case BinaryOperation::power: {
                    if (right_integer->negative) {
                        auto lhs = as_double(*left_integer);
                        auto rhs = as_double(*right_integer);
                        if (!lhs) {
                            return std::unexpected(lhs.error());
                        }
                        if (!rhs) {
                            return std::unexpected(rhs.error());
                        }
                        if (*lhs == 0.0) {
                            return std::unexpected(
                                error(VmErrorCode::arithmetic_error, "zero cannot be raised to a negative power"));
                        }
                        return allocate_float(std::pow(*lhs, *rhs));
                    }
                    auto exponent = operand_count;
                    result = BigInteger {.negative = false, .magnitude = "1"};
                    auto factor = *left_integer;
                    while (exponent != 0U) {
                        if ((exponent & 1U) != 0U) {
                            result = multiply(result, factor);
                        }
                        exponent >>= 1U;
                        if (exponent != 0U) {
                            factor = multiply(factor, factor);
                        }
                    }
                    break;
                }
                case BinaryOperation::left_shift:
                    result = *left_integer;
                    for (std::uint64_t count = 0U; count < operand_count; ++count) {
                        result = multiply(result, BigInteger {.negative = false, .magnitude = "2"});
                    }
                    break;
                case BinaryOperation::right_shift:
                    result = *left_integer;
                    for (std::uint64_t count = 0U; count < operand_count; ++count) {
                        auto divided = floor_divide(result, BigInteger {.negative = false, .magnitude = "2"});
                        if (!divided) {
                            return std::unexpected(divided.error());
                        }
                        result = std::move(divided->quotient);
                    }
                    break;
                case BinaryOperation::bit_or:
                case BinaryOperation::bit_xor:
                case BinaryOperation::bit_and: result = bitwise(*left_integer, *right_integer, operation); break;
                default: return std::unexpected(error(VmErrorCode::engine_fault, "invalid binary operation"));
            }
            return allocate_integer(result.decimal());
        }

        const auto numeric_value = [](const Impl::Object &object) -> std::expected<double, VmError> {
            if (object.kind == ValueKind::floating) {
                return std::get<double>(object.payload);
            }
            if (object.kind == ValueKind::integer) {
                return as_double(std::get<BigInteger>(object.payload));
            }
            if (object.kind == ValueKind::boolean) {
                return std::get<bool>(object.payload) ? 1.0 : 0.0;
            }
            return std::unexpected(error(VmErrorCode::type_error, "value is not numeric"));
        };
        if ((*left_object)->kind == ValueKind::floating || (*right_object)->kind == ValueKind::floating) {
            auto lhs_value = numeric_value(**left_object);
            auto rhs_value = numeric_value(**right_object);
            if (!lhs_value) {
                return std::unexpected(lhs_value.error());
            }
            if (!rhs_value) {
                return std::unexpected(rhs_value.error());
            }
            const auto lhs = *lhs_value;
            const auto rhs = *rhs_value;
            switch (operation) {
                case BinaryOperation::add: return allocate_float(lhs + rhs);
                case BinaryOperation::subtract: return allocate_float(lhs - rhs);
                case BinaryOperation::multiply: return allocate_float(lhs * rhs);
                case BinaryOperation::true_divide:
                    if (rhs == 0.0) {
                        return std::unexpected(error(VmErrorCode::arithmetic_error, "division by zero"));
                    }
                    return allocate_float(lhs / rhs);
                case BinaryOperation::floor_divide:
                    if (rhs == 0.0) {
                        return std::unexpected(error(VmErrorCode::arithmetic_error, "division by zero"));
                    }
                    return allocate_float(std::floor(lhs / rhs));
                case BinaryOperation::modulo: {
                    if (rhs == 0.0) {
                        return std::unexpected(error(VmErrorCode::arithmetic_error, "modulo by zero"));
                    }
                    auto remainder = std::fmod(lhs, rhs);
                    if (remainder != 0.0 && std::signbit(remainder) != std::signbit(rhs)) {
                        remainder += rhs;
                    }
                    return allocate_float(remainder);
                }
                case BinaryOperation::power: return allocate_float(std::pow(lhs, rhs));
                case BinaryOperation::left_shift:
                case BinaryOperation::right_shift:
                case BinaryOperation::bit_or:
                case BinaryOperation::bit_xor:
                case BinaryOperation::bit_and:
                    return std::unexpected(error(VmErrorCode::type_error, "bitwise operation requires integers"));
                default: return std::unexpected(error(VmErrorCode::engine_fault, "invalid binary operation"));
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
        if (operation == BinaryOperation::add && (*left_object)->kind == ValueKind::bytes &&
            (*right_object)->kind == ValueKind::bytes) {
            const auto &prefix = std::get<Impl::BytesStorage>((*left_object)->payload).bytes;
            const auto &suffix = std::get<Impl::BytesStorage>((*right_object)->payload).bytes;
            const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
            if (remaining < sizeof(Impl::Object) || prefix.size() > remaining - sizeof(Impl::Object) ||
                suffix.size() > remaining - sizeof(Impl::Object) - prefix.size()) {
                return std::unexpected(
                    error(VmErrorCode::heap_budget_exhausted, "bytes operation would exceed the live VM heap budget"));
            }
            std::vector<std::byte> result = prefix;
            result.insert(result.end(), suffix.begin(), suffix.end());
            if (work_charge != nullptr) {
                *work_charge = static_cast<std::uint64_t>(result.size());
            }
            return allocate_bytes(result);
        }
        if (operation == BinaryOperation::add && (*left_object)->kind == ValueKind::list &&
            (*right_object)->kind == ValueKind::list) {
            const auto &prefix = std::get<Impl::ListStorage>((*left_object)->payload).values;
            const auto &suffix = std::get<Impl::ListStorage>((*right_object)->payload).values;
            const auto remaining = impl_->maximum_live_bytes - impl_->stats.live_bytes;
            if (remaining < sizeof(Impl::Object)) {
                return std::unexpected(
                    error(VmErrorCode::heap_budget_exhausted, "list operation would exceed the live VM heap budget"));
            }
            const auto capacity = (remaining - sizeof(Impl::Object)) / sizeof(PyValue);
            if (prefix.size() > capacity || suffix.size() > capacity - prefix.size()) {
                return std::unexpected(
                    error(VmErrorCode::heap_budget_exhausted, "list operation would exceed the live VM heap budget"));
            }
            std::vector<PyValue> result = prefix;
            result.insert(result.end(), suffix.begin(), suffix.end());
            if (work_charge != nullptr) {
                *work_charge = static_cast<std::uint64_t>(result.size());
            }
            return allocate_list(result);
        }
        return std::unexpected(error(VmErrorCode::type_error, "binary operands have incompatible types"));
    }

    std::expected<bool, VmError> ValueHeap::compare_operation(const CompareOperation operation, const PyValue left,
                                                              const PyValue right) const {
        if (operation == CompareOperation::identity || operation == CompareOperation::not_identity) {
            const auto identical = left == right;
            return operation == CompareOperation::identity ? identical : !identical;
        }
        if (operation == CompareOperation::equal || operation == CompareOperation::not_equal) {
            auto same = equal(left, right);
            if (!same) {
                return std::unexpected(same.error());
            }
            return operation == CompareOperation::equal ? *same : !*same;
        }
        if (operation == CompareOperation::contains || operation == CompareOperation::not_contains) {
            auto container = impl_->object(right);
            if (!container) {
                return std::unexpected(container.error());
            }
            bool found {};
            switch ((*container)->kind) {
                case ValueKind::list:
                    for (const auto item : std::get<Impl::ListStorage>((*container)->payload).values) {
                        auto same = equal(left, item);
                        if (!same) {
                            return std::unexpected(same.error());
                        }
                        if (*same) {
                            found = true;
                            break;
                        }
                    }
                    break;
                case ValueKind::map:
                    for (const auto &[key, value] : std::get<Impl::MapStorage>((*container)->payload).entries) {
                        static_cast<void>(value);
                        auto same = equal(left, key);
                        if (!same) {
                            return std::unexpected(same.error());
                        }
                        if (*same) {
                            found = true;
                            break;
                        }
                    }
                    break;
                case ValueKind::unicode: {
                    auto needle = impl_->object(left);
                    if (!needle) {
                        return std::unexpected(needle.error());
                    }
                    if ((*needle)->kind != ValueKind::unicode) {
                        return std::unexpected(
                            error(VmErrorCode::type_error, "Unicode containment requires a Unicode needle"));
                    }
                    const auto &needle_points = std::get<Impl::UnicodeStorage>((*needle)->payload).codepoints;
                    const auto &haystack = std::get<Impl::UnicodeStorage>((*container)->payload).codepoints;
                    found = std::ranges::search(haystack, needle_points).begin() != haystack.end();
                    break;
                }
                case ValueKind::bytes: {
                    auto needle = impl_->object(left);
                    if (!needle) {
                        return std::unexpected(needle.error());
                    }
                    const auto &haystack = std::get<Impl::BytesStorage>((*container)->payload).bytes;
                    if (const auto integer = impl_->integer_like(**needle); integer.has_value()) {
                        auto byte = bounded_unsigned(*integer, 255U, "byte membership");
                        if (!byte) {
                            return std::unexpected(byte.error());
                        }
                        found = std::ranges::find(haystack, static_cast<std::byte>(*byte)) != haystack.end();
                    } else if ((*needle)->kind == ValueKind::bytes) {
                        const auto &needle_bytes = std::get<Impl::BytesStorage>((*needle)->payload).bytes;
                        found = std::ranges::search(haystack, needle_bytes).begin() != haystack.end();
                    } else {
                        return std::unexpected(
                            error(VmErrorCode::type_error, "bytes containment requires an integer or bytes needle"));
                    }
                    break;
                }
                case ValueKind::none:
                case ValueKind::boolean:
                case ValueKind::integer:
                case ValueKind::floating:
                case ValueKind::record:
                    return std::unexpected(error(VmErrorCode::type_error, "right operand is not a container"));
                default: return std::unexpected(error(VmErrorCode::engine_fault, "VM value has an invalid kind"));
            }
            return operation == CompareOperation::contains ? found : !found;
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
            case CompareOperation::not_equal:
            case CompareOperation::identity:
            case CompareOperation::not_identity:
            case CompareOperation::contains:
            case CompareOperation::not_contains: break;
            default: return std::unexpected(error(VmErrorCode::engine_fault, "invalid comparison operation"));
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

    std::expected<SchemaId, VmError> ValueHeap::record_schema(const PyValue value) const {
        auto object = impl_->object(value);
        if (!object) {
            return std::unexpected(object.error());
        }
        if ((*object)->kind != ValueKind::record) {
            return std::unexpected(error(VmErrorCode::type_error, "VM value is not a record"));
        }
        return std::get<Impl::RecordStorage>((*object)->payload).schema;
    }

    std::expected<std::vector<RecordFieldValue>, VmError> ValueHeap::record_fields(const PyValue value) const {
        auto object = impl_->object(value);
        if (!object) {
            return std::unexpected(object.error());
        }
        if ((*object)->kind != ValueKind::record) {
            return std::unexpected(error(VmErrorCode::type_error, "VM value is not a record"));
        }
        return std::get<Impl::RecordStorage>((*object)->payload).fields;
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

    std::expected<void, FreezeError> ValueHeap::validate_schema(const FactValue &value, const SchemaId &expected_schema,
                                                                const SchemaCatalog *const schemas) {
        const auto mismatch = [](std::string message) {
            return std::unexpected(FreezeError {
                .code = FreezeErrorCode::schema_mismatch, .message = std::move(message), .span = std::nullopt});
        };
        if (!value.valid() || expected_schema.empty()) {
            return mismatch("boundary value or expected schema is empty");
        }
        const auto &data = value.node->data;
        const auto &id = expected_schema.value;
        const auto primitive_matches = [&]() {
            if (id == "any") {
                return true;
            }
            if (id == "none" || id == "null") {
                return std::holds_alternative<std::monostate>(data);
            }
            if (id == "bool" || id == "boolean") {
                return std::holds_alternative<bool>(data);
            }
            if (id == "int" || id == "integer") {
                return std::holds_alternative<IntegerValue>(data);
            }
            if (id == "float") {
                return std::holds_alternative<double>(data);
            }
            if (id == "str" || id == "string" || id == "text" || id == "unicode") {
                return std::holds_alternative<UnicodeValue>(data);
            }
            if (id == "bytes") {
                return std::holds_alternative<BytesValue>(data);
            }
            if (id == "list") {
                return std::holds_alternative<FactList>(data);
            }
            if (id == "map") {
                return std::holds_alternative<FactMap>(data);
            }
            return false;
        };
        if (primitive_matches()) {
            return {};
        }

        if (const auto *enumeration = std::get_if<EnumValue>(&data); enumeration != nullptr) {
            return enumeration->schema == expected_schema ? std::expected<void, FreezeError> {} :
                                                            mismatch("enum schema does not match boundary schema");
        }
        const auto *record = std::get_if<FactRecord>(&data);
        if (record == nullptr || record->schema != expected_schema) {
            return mismatch("record schema does not match boundary schema");
        }
        if (schemas == nullptr) {
            return {};
        }
        const auto descriptor = std::ranges::find(schemas->descriptors, expected_schema, &SchemaDescriptor::id);
        if (descriptor == schemas->descriptors.end()) {
            return mismatch("expected schema is absent from the active catalog");
        }
        for (const auto &schema_field : descriptor->fields) {
            const auto field = std::ranges::find(record->fields, schema_field.field_id, &FactRecordField::field_id);
            if (field == record->fields.end()) {
                if (!schema_field.optional) {
                    return mismatch("record is missing required schema field " + std::to_string(schema_field.field_id));
                }
                continue;
            }
            if (auto valid = validate_schema(field->value, schema_field.type, schemas); !valid) {
                return valid;
            }
        }
        for (const auto &field : record->fields) {
            if (std::ranges::find(descriptor->fields, field.field_id, &SchemaField::field_id) ==
                descriptor->fields.end()) {
                return mismatch("record contains unknown schema field " + std::to_string(field.field_id));
            }
        }
        return {};
    }

    std::expected<PyValue, FreezeError> ValueHeap::validate_frozen(const FrozenValue &value,
                                                                   const std::optional<SchemaId> expected_schema,
                                                                   const SchemaCatalog *const schemas,
                                                                   const FreezeLimits limits) {
        if (!value.value.valid() || value.canonical_digest.empty()) {
            return std::unexpected(FreezeError {.code = FreezeErrorCode::invalid_handle,
                                                .message = "frozen boundary value is incomplete",
                                                .span = std::nullopt});
        }
        if (expected_schema.has_value()) {
            if (auto valid = validate_schema(value.value, *expected_schema, schemas); !valid) {
                return std::unexpected(std::move(valid.error()));
            }
        }
        auto thawed = thaw(value.value);
        if (!thawed) {
            return std::unexpected(FreezeError {.code = FreezeErrorCode::unsupported_type,
                                                .message = std::move(thawed.error().message),
                                                .span = thawed.error().span});
        }
        auto canonical = freeze(*thawed, value.label, limits);
        if (!canonical) {
            return std::unexpected(std::move(canonical.error()));
        }
        if (canonical->canonical_digest != value.canonical_digest) {
            return std::unexpected(FreezeError {.code = FreezeErrorCode::schema_mismatch,
                                                .message = "frozen boundary digest is not canonical",
                                                .span = std::nullopt});
        }
        return *thawed;
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
            } else if (slot->object->kind == ValueKind::record) {
                for (const auto &field : std::get<Impl::RecordStorage>(slot->object->payload).fields) {
                    worklist.push_back(field.value);
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
