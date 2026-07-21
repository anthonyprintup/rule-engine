#include "rule_engine/python/packaging/source_pack.hpp"

#include "rule_engine/python/packaging/signing.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>

namespace rule_engine::python::packaging {
    namespace {

        PackagingError error(const PackagingErrorCode code, std::string message,
                             std::optional<std::string> subject = std::nullopt) {
            return PackagingError {.code = code, .message = std::move(message), .subject = std::move(subject)};
        }

        constexpr std::array<std::uint32_t, 64> sha256_constants {
            0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
            0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
            0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
            0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
            0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
            0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
            0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
            0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
        };

        struct Sha256State {
            std::array<std::uint32_t, 8> hash {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                                               0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
            std::array<std::byte, 64> block {};
            std::size_t block_size {};
            std::uint64_t total_bytes {};

            void transform() noexcept {
                std::array<std::uint32_t, 64> words {};
                for (std::size_t index = 0; index < 16; ++index) {
                    const auto offset = index * 4U;
                    words[index] = (std::to_integer<std::uint32_t>(block[offset]) << 24U) |
                                   (std::to_integer<std::uint32_t>(block[offset + 1U]) << 16U) |
                                   (std::to_integer<std::uint32_t>(block[offset + 2U]) << 8U) |
                                   std::to_integer<std::uint32_t>(block[offset + 3U]);
                }
                for (std::size_t index = 16; index < words.size(); ++index) {
                    const auto left = words[index - 15U];
                    const auto right = words[index - 2U];
                    const auto sigma0 = std::rotr(left, 7) ^ std::rotr(left, 18) ^ (left >> 3U);
                    const auto sigma1 = std::rotr(right, 17) ^ std::rotr(right, 19) ^ (right >> 10U);
                    words[index] = words[index - 16U] + sigma0 + words[index - 7U] + sigma1;
                }

                auto a = hash[0];
                auto b = hash[1];
                auto c = hash[2];
                auto d = hash[3];
                auto e = hash[4];
                auto f = hash[5];
                auto g = hash[6];
                auto h = hash[7];
                for (std::size_t index = 0; index < words.size(); ++index) {
                    const auto sum1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
                    const auto choose = (e & f) ^ (~e & g);
                    const auto temporary1 = h + sum1 + choose + sha256_constants[index] + words[index];
                    const auto sum0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
                    const auto majority = (a & b) ^ (a & c) ^ (b & c);
                    const auto temporary2 = sum0 + majority;
                    h = g;
                    g = f;
                    f = e;
                    e = d + temporary1;
                    d = c;
                    c = b;
                    b = a;
                    a = temporary1 + temporary2;
                }
                hash[0] += a;
                hash[1] += b;
                hash[2] += c;
                hash[3] += d;
                hash[4] += e;
                hash[5] += f;
                hash[6] += g;
                hash[7] += h;
            }

            void update(const std::span<const std::byte> bytes) noexcept {
                total_bytes += static_cast<std::uint64_t>(bytes.size());
                for (const auto value : bytes) {
                    block[block_size++] = value;
                    if (block_size == block.size()) {
                        transform();
                        block_size = 0;
                    }
                }
            }

            std::array<std::byte, 32> finish() noexcept {
                const auto bit_count = total_bytes * 8U;
                block[block_size++] = std::byte {0x80};
                if (block_size > 56U) {
                    while (block_size < block.size()) { block[block_size++] = std::byte {}; }
                    transform();
                    block_size = 0;
                }
                while (block_size < 56U) { block[block_size++] = std::byte {}; }
                for (std::size_t index = 0; index < 8U; ++index) {
                    block[63U - index] = static_cast<std::byte>((bit_count >> (index * 8U)) & 0xffU);
                }
                transform();

                std::array<std::byte, 32> result {};
                for (std::size_t index = 0; index < hash.size(); ++index) {
                    const auto value = hash[index];
                    result[index * 4U] = static_cast<std::byte>((value >> 24U) & 0xffU);
                    result[index * 4U + 1U] = static_cast<std::byte>((value >> 16U) & 0xffU);
                    result[index * 4U + 2U] = static_cast<std::byte>((value >> 8U) & 0xffU);
                    result[index * 4U + 3U] = static_cast<std::byte>(value & 0xffU);
                }
                return result;
            }
        };

        std::span<const std::byte> as_bytes(const std::string_view text) noexcept {
            return {reinterpret_cast<const std::byte *>(text.data()), text.size()};
        }

        std::string bytes_to_text(const std::span<const std::byte> bytes) {
            return {reinterpret_cast<const char *>(bytes.data()), bytes.size()};
        }

        std::string hex(const std::span<const std::byte> bytes) {
            constexpr std::string_view digits = "0123456789abcdef";
            std::string output;
            output.reserve(bytes.size() * 2U);
            for (const auto value : bytes) {
                const auto number = std::to_integer<unsigned int>(value);
                output.push_back(digits[number >> 4U]);
                output.push_back(digits[number & 0x0fU]);
            }
            return output;
        }

        bool is_lower_hex_digest(const std::string_view value) noexcept {
            if (value.size() != 64U) {
                return false;
            }
            return std::ranges::all_of(value, [](const char character) {
                return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
            });
        }

        bool is_safe_atom(const std::string_view value, const bool allow_dot = true) noexcept {
            if (value.empty()) {
                return false;
            }
            return std::ranges::all_of(value, [allow_dot](const char character) {
                return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                       (character >= '0' && character <= '9') || character == '_' || character == '-' ||
                       (allow_dot && character == '.');
            });
        }

        bool is_media_type(const std::string_view value) noexcept {
            if (value.empty() || value.find('/') == std::string_view::npos) {
                return false;
            }
            return std::ranges::all_of(value, [](const char character) {
                return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
                       character == '-' || character == '+' || character == '.' || character == '/';
            });
        }

        bool is_reverse_dns_id(const std::string_view value) noexcept {
            return value.size() <= 128U && is_safe_atom(value) && value.front() != '.' && value.back() != '.' &&
                   value.find("..") == std::string_view::npos;
        }

        bool is_semver(const std::string_view value) noexcept {
            std::size_t dots {};
            bool digit_in_component {};
            for (const auto character : value) {
                if (character == '.') {
                    if (!digit_in_component || dots == 2U) {
                        return false;
                    }
                    ++dots;
                    digit_in_component = false;
                    continue;
                }
                if (character < '0' || character > '9') {
                    return false;
                }
                digit_in_component = true;
            }
            return dots == 2U && digit_in_component;
        }

        bool is_safe_path(const std::string_view path) noexcept {
            if (path.empty() || path.front() == '/' || path.back() == '/' ||
                path.find('\\') != std::string_view::npos || path.find(':') != std::string_view::npos) {
                return false;
            }
            std::size_t segment_begin {};
            while (segment_begin < path.size()) {
                const auto separator = path.find('/', segment_begin);
                const auto segment_end = separator == std::string_view::npos ? path.size() : separator;
                const auto segment = path.substr(segment_begin, segment_end - segment_begin);
                if (segment.empty() || segment == "." || segment == "..") {
                    return false;
                }
                if (!std::ranges::all_of(segment, [](const char character) {
                        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                               (character >= '0' && character <= '9') || character == '_' || character == '-' ||
                               character == '.';
                    })) {
                    return false;
                }
                if (separator == std::string_view::npos) {
                    break;
                }
                segment_begin = separator + 1U;
            }
            return true;
        }

        std::string folded_path(std::string_view path) {
            std::string folded {path};
            std::ranges::transform(folded, folded.begin(), [](const char character) {
                if (character >= 'A' && character <= 'Z') {
                    return static_cast<char>(character - 'A' + 'a');
                }
                return character;
            });
            return folded;
        }

        bool valid_utf8(const std::span<const std::byte> bytes) noexcept {
            std::size_t index {};
            while (index < bytes.size()) {
                const auto first = std::to_integer<unsigned int>(bytes[index]);
                if (first <= 0x7fU) {
                    ++index;
                    continue;
                }
                std::size_t count {};
                std::uint32_t codepoint {};
                if (first >= 0xc2U && first <= 0xdfU) {
                    count = 1;
                    codepoint = first & 0x1fU;
                } else if (first >= 0xe0U && first <= 0xefU) {
                    count = 2;
                    codepoint = first & 0x0fU;
                } else if (first >= 0xf0U && first <= 0xf4U) {
                    count = 3;
                    codepoint = first & 0x07U;
                } else {
                    return false;
                }
                if (index + count >= bytes.size()) {
                    return false;
                }
                for (std::size_t offset = 1; offset <= count; ++offset) {
                    const auto continuation = std::to_integer<unsigned int>(bytes[index + offset]);
                    if ((continuation & 0xc0U) != 0x80U) {
                        return false;
                    }
                    codepoint = (codepoint << 6U) | (continuation & 0x3fU);
                }
                if ((count == 2U && codepoint < 0x800U) || (count == 3U && codepoint < 0x10000U) ||
                    codepoint > 0x10ffffU || (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
                    return false;
                }
                index += count + 1U;
            }
            return true;
        }

        bool canonical_text(const ArchiveEntry &entry) noexcept {
            if (!valid_utf8(entry.bytes)) {
                return false;
            }
            if (entry.bytes.size() >= 3U && entry.bytes[0] == std::byte {0xef} && entry.bytes[1] == std::byte {0xbb} &&
                entry.bytes[2] == std::byte {0xbf}) {
                return false;
            }
            return std::ranges::find(entry.bytes, std::byte {0x0d}) == entry.bytes.end();
        }

        std::string quoted_array(const std::vector<std::string> &values) {
            std::string output {"["};
            for (std::size_t index = 0; index < values.size(); ++index) {
                if (index != 0U) {
                    output += ", ";
                }
                output += '"';
                output += values[index];
                output += '"';
            }
            output += ']';
            return output;
        }

        std::vector<std::string> capability_values(const std::vector<CapabilityId> &values) {
            std::vector<std::string> output;
            output.reserve(values.size());
            for (const auto &value : values) { output.push_back(value.value); }
            return output;
        }

        std::expected<std::vector<std::string_view>, PackagingError>
        split_canonical_lines(const std::string_view text) {
            if (text.empty() || text.back() != '\n' || text.find('\r') != std::string_view::npos) {
                return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                             "canonical manifest must use LF and end with a newline"));
            }
            std::vector<std::string_view> lines;
            std::size_t begin {};
            while (begin < text.size()) {
                const auto end = text.find('\n', begin);
                lines.push_back(text.substr(begin, end - begin));
                begin = end + 1U;
            }
            return lines;
        }

        std::expected<std::string, PackagingError> parse_quoted(const std::string_view line,
                                                                const std::string_view key) {
            const std::string prefix = std::string {key} + " = \"";
            if (!line.starts_with(prefix) || line.size() <= prefix.size() || line.back() != '"') {
                return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                             "expected canonical quoted assignment", std::string {key}));
            }
            const auto value = line.substr(prefix.size(), line.size() - prefix.size() - 1U);
            if (!std::ranges::all_of(value, [](const char character) {
                    return character >= 0x20 && character <= 0x7e && character != '"' && character != '\\';
                })) {
                return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                             "manifest value uses unsupported characters", std::string {key}));
            }
            return std::string {value};
        }

        std::expected<std::uint32_t, PackagingError> parse_unsigned(const std::string_view line,
                                                                    const std::string_view key) {
            const std::string prefix = std::string {key} + " = ";
            if (!line.starts_with(prefix)) {
                return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                             "expected canonical integer assignment", std::string {key}));
            }
            std::uint32_t value {};
            const auto text = line.substr(prefix.size());
            const auto [end, parse_error] = std::from_chars(text.data(), text.data() + text.size(), value);
            if (parse_error != std::errc {} || end != text.data() + text.size()) {
                return std::unexpected(
                    error(PackagingErrorCode::invalid_manifest, "invalid unsigned manifest value", std::string {key}));
            }
            return value;
        }

        std::expected<std::vector<std::string>, PackagingError> parse_quoted_array(const std::string_view line,
                                                                                   const std::string_view key) {
            const std::string prefix = std::string {key} + " = [";
            if (!line.starts_with(prefix) || line.back() != ']') {
                return std::unexpected(
                    error(PackagingErrorCode::invalid_manifest, "expected canonical string array", std::string {key}));
            }
            auto body = line.substr(prefix.size(), line.size() - prefix.size() - 1U);
            std::vector<std::string> values;
            if (body.empty()) {
                return values;
            }
            while (!body.empty()) {
                if (body.front() != '"') {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest, "invalid canonical string array",
                                                 std::string {key}));
                }
                const auto quote = body.find('"', 1U);
                if (quote == std::string_view::npos) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                                 "unterminated manifest array string", std::string {key}));
                }
                const auto value = body.substr(1U, quote - 1U);
                if (!is_safe_atom(value)) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                                 "manifest array value uses unsupported characters",
                                                 std::string {key}));
                }
                values.emplace_back(value);
                body.remove_prefix(quote + 1U);
                if (body.empty()) {
                    break;
                }
                if (!body.starts_with(", ")) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                                 "manifest array separator is not canonical", std::string {key}));
                }
                body.remove_prefix(2U);
            }
            return values;
        }

        std::expected<void, PackagingError> validate_manifest(const SourcePackManifest &manifest) {
            if (manifest.format != 1U || manifest.engine_api != 1U || manifest.python_version != "3.14.6") {
                return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                             "pack requires format 1, engine API 1, and Python 3.14.6"));
            }
            if (!is_reverse_dns_id(manifest.pack.value) || !is_semver(manifest.version.value) ||
                manifest.entry_modules.empty() || !is_reverse_dns_id(manifest.budget_profile) ||
                !is_reverse_dns_id(manifest.policy_profile)) {
                return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                             "pack identity, version, entries, or profiles are invalid"));
            }
            if (manifest.kind == PackKind::library && manifest.generator.has_value()) {
                return std::unexpected(
                    error(PackagingErrorCode::invalid_manifest, "library packs cannot contain a generator"));
            }
            std::set<std::string> unique;
            if (!std::ranges::is_sorted(manifest.entry_modules)) {
                return std::unexpected(
                    error(PackagingErrorCode::invalid_manifest, "entry modules must be in canonical sorted order"));
            }
            for (const auto &module : manifest.entry_modules) {
                if (!is_reverse_dns_id(module) || !unique.insert(module).second) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                                 "entry modules must be unique dotted identifiers", module));
                }
            }
            unique.clear();
            if (!std::ranges::is_sorted(manifest.dependencies, {}, &PackDependency::alias)) {
                return std::unexpected(
                    error(PackagingErrorCode::invalid_manifest, "dependencies must be in canonical alias order"));
            }
            for (const auto &dependency : manifest.dependencies) {
                if (!is_safe_atom(dependency.alias, false) || !is_reverse_dns_id(dependency.pack.value) ||
                    !dependency.digest.value.starts_with("sha256:") ||
                    !is_lower_hex_digest(std::string_view {dependency.digest.value}.substr(7U)) ||
                    !unique.insert(dependency.alias).second) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                                 "dependency alias, pack, or digest is invalid", dependency.alias));
                }
            }
            if (manifest.generator) {
                if (!is_reverse_dns_id(manifest.generator->module) ||
                    !is_safe_atom(manifest.generator->callable, false) ||
                    manifest.generator->lock_path != "generator.lock") {
                    return std::unexpected(
                        error(PackagingErrorCode::invalid_manifest, "generator declaration is invalid"));
                }
                unique.clear();
                if (!std::ranges::is_sorted(manifest.generator->inputs, {}, &GeneratorInput::name)) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                                 "generator inputs must be in canonical name order"));
                }
                for (const auto &input : manifest.generator->inputs) {
                    if (!is_safe_atom(input.name, false) || !is_safe_path(input.path) ||
                        !input.path.starts_with("inputs/") || !unique.insert(input.name).second) {
                        return std::unexpected(
                            error(PackagingErrorCode::invalid_manifest, "generator input is invalid", input.name));
                    }
                }
            }
            if (!std::ranges::is_sorted(
                    manifest.required_capabilities, {},
                    [](const CapabilityId &capability) -> const std::string & { return capability.value; }) ||
                !std::ranges::is_sorted(
                    manifest.optional_capabilities, {},
                    [](const CapabilityId &capability) -> const std::string & { return capability.value; })) {
                return std::unexpected(
                    error(PackagingErrorCode::invalid_manifest, "capabilities must be in canonical sorted order"));
            }
            unique.clear();
            for (const auto &capability : manifest.required_capabilities) {
                if (!is_reverse_dns_id(capability.value) || !unique.insert(capability.value).second) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                                 "required capability is invalid or duplicated", capability.value));
                }
            }
            for (const auto &capability : manifest.optional_capabilities) {
                if (!is_reverse_dns_id(capability.value) || !unique.insert(capability.value).second) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                                 "optional capability is invalid or duplicated", capability.value));
                }
            }
            return {};
        }

        struct IndexCursor {
            std::string_view input;
            std::size_t offset {};

            bool consume(const std::string_view expected) noexcept {
                if (!input.substr(offset).starts_with(expected)) {
                    return false;
                }
                offset += expected.size();
                return true;
            }

            std::expected<std::string, PackagingError> string_until_quote(const std::string_view field) {
                const auto end = input.find('"', offset);
                if (end == std::string_view::npos) {
                    return std::unexpected(error(PackagingErrorCode::invalid_index,
                                                 "unterminated canonical index string", std::string {field}));
                }
                const auto value = input.substr(offset, end - offset);
                if (value.find('\\') != std::string_view::npos || !std::ranges::all_of(value, [](const char character) {
                        return character >= 0x20 && character <= 0x7e && character != '"';
                    })) {
                    return std::unexpected(error(PackagingErrorCode::invalid_index,
                                                 "index strings must be canonical printable ASCII",
                                                 std::string {field}));
                }
                offset = end;
                return std::string {value};
            }

            std::expected<std::size_t, PackagingError> unsigned_number(const std::string_view field) {
                const auto begin = input.data() + offset;
                std::size_t value {};
                const auto [end, parse_error] = std::from_chars(begin, input.data() + input.size(), value);
                if (parse_error != std::errc {} || end == begin) {
                    return std::unexpected(error(PackagingErrorCode::invalid_index, "invalid canonical index number",
                                                 std::string {field}));
                }
                offset = static_cast<std::size_t>(end - input.data());
                return value;
            }
        };

        std::string base64url_encode(const std::span<const std::byte> bytes) {
            constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            std::string output;
            output.reserve((bytes.size() * 4U + 2U) / 3U);
            std::size_t index {};
            while (index + 3U <= bytes.size()) {
                const auto value = (std::to_integer<std::uint32_t>(bytes[index]) << 16U) |
                                   (std::to_integer<std::uint32_t>(bytes[index + 1U]) << 8U) |
                                   std::to_integer<std::uint32_t>(bytes[index + 2U]);
                output.push_back(alphabet[(value >> 18U) & 0x3fU]);
                output.push_back(alphabet[(value >> 12U) & 0x3fU]);
                output.push_back(alphabet[(value >> 6U) & 0x3fU]);
                output.push_back(alphabet[value & 0x3fU]);
                index += 3U;
            }
            const auto remaining = bytes.size() - index;
            if (remaining == 1U) {
                const auto value = std::to_integer<std::uint32_t>(bytes[index]) << 16U;
                output.push_back(alphabet[(value >> 18U) & 0x3fU]);
                output.push_back(alphabet[(value >> 12U) & 0x3fU]);
            } else if (remaining == 2U) {
                const auto value = (std::to_integer<std::uint32_t>(bytes[index]) << 16U) |
                                   (std::to_integer<std::uint32_t>(bytes[index + 1U]) << 8U);
                output.push_back(alphabet[(value >> 18U) & 0x3fU]);
                output.push_back(alphabet[(value >> 12U) & 0x3fU]);
                output.push_back(alphabet[(value >> 6U) & 0x3fU]);
            }
            return output;
        }

        std::expected<std::vector<std::byte>, PackagingError> base64url_decode(const std::string_view text) {
            if (text.find('=') != std::string_view::npos || text.size() % 4U == 1U) {
                return std::unexpected(
                    error(PackagingErrorCode::invalid_signature_envelope, "signature is not unpadded base64url"));
            }
            auto decode = [](const char character) -> int {
                if (character >= 'A' && character <= 'Z') {
                    return character - 'A';
                }
                if (character >= 'a' && character <= 'z') {
                    return character - 'a' + 26;
                }
                if (character >= '0' && character <= '9') {
                    return character - '0' + 52;
                }
                if (character == '-') {
                    return 62;
                }
                if (character == '_') {
                    return 63;
                }
                return -1;
            };
            std::vector<std::byte> output;
            output.reserve(text.size() * 3U / 4U);
            std::uint32_t accumulator {};
            unsigned bits {};
            for (const auto character : text) {
                const auto value = decode(character);
                if (value < 0) {
                    return std::unexpected(
                        error(PackagingErrorCode::invalid_signature_envelope, "signature contains invalid base64url"));
                }
                accumulator = (accumulator << 6U) | static_cast<std::uint32_t>(value);
                bits += 6U;
                if (bits >= 8U) {
                    bits -= 8U;
                    output.push_back(static_cast<std::byte>((accumulator >> bits) & 0xffU));
                }
            }
            if (bits != 0U && (accumulator & ((1U << bits) - 1U)) != 0U) {
                return std::unexpected(error(PackagingErrorCode::invalid_signature_envelope,
                                             "signature base64url has nonzero trailing bits"));
            }
            return output;
        }

        std::string source_module(const std::string_view path) {
            auto module = std::string {path.substr(4U, path.size() - 7U)};
            if (module.ends_with("/__init__")) {
                module.resize(module.size() - 9U);
            }
            std::ranges::replace(module, '/', '.');
            return module;
        }

        void append_sized(std::string &output, const std::string_view value) {
            output += std::to_string(value.size());
            output += ':';
            output += value;
            output += ';';
        }

        std::vector<std::byte> source_pack_signature_message(const std::string_view canonical_index_bytes) {
            constexpr char signature_domain_bytes[] = "rule-engine-rpack-signature-v1\0";
            const std::string_view signature_domain {signature_domain_bytes, sizeof(signature_domain_bytes) - 1U};
            std::vector<std::byte> message;
            message.reserve(signature_domain.size() + canonical_index_bytes.size());
            message.insert(message.end(), as_bytes(signature_domain).begin(), as_bytes(signature_domain).end());
            message.insert(message.end(), as_bytes(canonical_index_bytes).begin(),
                           as_bytes(canonical_index_bytes).end());
            return message;
        }

    } // namespace

    std::string sha256_hex(const std::span<const std::byte> bytes) {
        Sha256State state;
        state.update(bytes);
        const auto digest = state.finish();
        return hex(digest);
    }

    std::string canonical_manifest(const SourcePackManifest &manifest) {
        std::string output;
        output += "format = " + std::to_string(manifest.format) + "\n\n[pack]\n";
        output += "id = \"" + manifest.pack.value + "\"\n";
        output += "version = \"" + manifest.version.value + "\"\n";
        output += std::string {"kind = \""} + (manifest.kind == PackKind::rules ? "rules" : "library") + "\"\n";
        output += "engine_api = " + std::to_string(manifest.engine_api) + "\n";
        output += "python = \"" + manifest.python_version + "\"\n";
        output += "entry_modules = " + quoted_array(manifest.entry_modules) + "\n";
        output += "budget_profile = \"" + manifest.budget_profile + "\"\n";
        output += "policy_profile = \"" + manifest.policy_profile + "\"\n";
        if (manifest.generator) {
            output += "\n[generator]\n";
            output += "module = \"" + manifest.generator->module + "\"\n";
            output += "callable = \"" + manifest.generator->callable + "\"\n";
            output += "lock = \"" + manifest.generator->lock_path + "\"\n";
            for (const auto &input : manifest.generator->inputs) {
                output += "\n[generator.inputs." + input.name + "]\n";
                output += "path = \"" + input.path + "\"\n";
                const auto format = input.format == GeneratorInputFormat::json ? "json" :
                                    input.format == GeneratorInputFormat::utf8 ? "utf8" :
                                                                                 "bytes";
                output += std::string {"format = \""} + format + "\"\n";
            }
        }
        for (const auto &dependency : manifest.dependencies) {
            output += "\n[dependencies." + dependency.alias + "]\n";
            output += "pack = \"" + dependency.pack.value + "\"\n";
            output += "digest = \"" + dependency.digest.value + "\"\n";
        }
        output += "\n[capabilities]\n";
        output += "required = " + quoted_array(capability_values(manifest.required_capabilities)) + "\n";
        output += "optional = " + quoted_array(capability_values(manifest.optional_capabilities)) + "\n";
        return output;
    }

    std::expected<SourcePackManifest, PackagingError> parse_canonical_manifest(const std::string_view text) {
        const auto parsed_lines = split_canonical_lines(text);
        if (!parsed_lines) {
            return std::unexpected(parsed_lines.error());
        }
        const auto &lines = *parsed_lines;
        std::size_t position {};
        auto next = [&lines, &position](const std::string_view expected) -> std::expected<void, PackagingError> {
            if (position >= lines.size() || lines[position] != expected) {
                return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                             "manifest is missing or reorders a canonical field",
                                             std::string {expected}));
            }
            ++position;
            return {};
        };
        if (lines.size() < 13U) {
            return std::unexpected(error(PackagingErrorCode::invalid_manifest, "manifest is incomplete"));
        }

        SourcePackManifest manifest;
        auto format = parse_unsigned(lines[position++], "format");
        if (!format || !next("") || !next("[pack]")) {
            return std::unexpected(format ? error(PackagingErrorCode::invalid_manifest, "invalid pack header") :
                                            format.error());
        }
        manifest.format = *format;
        auto pack = parse_quoted(lines[position++], "id");
        auto version = parse_quoted(lines[position++], "version");
        auto kind = parse_quoted(lines[position++], "kind");
        auto engine_api = parse_unsigned(lines[position++], "engine_api");
        auto python = parse_quoted(lines[position++], "python");
        auto entries = parse_quoted_array(lines[position++], "entry_modules");
        auto budget = parse_quoted(lines[position++], "budget_profile");
        auto policy = parse_quoted(lines[position++], "policy_profile");
        if (!pack || !version || !kind || !engine_api || !python || !entries || !budget || !policy) {
            return std::unexpected(error(PackagingErrorCode::invalid_manifest, "pack section is invalid"));
        }
        if (*kind != "rules" && *kind != "library") {
            return std::unexpected(error(PackagingErrorCode::invalid_manifest, "pack kind is invalid"));
        }
        manifest.pack = PackId {*pack};
        manifest.version = PackVersion {*version};
        manifest.kind = *kind == "rules" ? PackKind::rules : PackKind::library;
        manifest.engine_api = *engine_api;
        manifest.python_version = *python;
        manifest.entry_modules = std::move(*entries);
        manifest.budget_profile = *budget;
        manifest.policy_profile = *policy;

        while (position < lines.size()) {
            if (!next("")) {
                return std::unexpected(
                    error(PackagingErrorCode::invalid_manifest, "manifest section separator is not canonical"));
            }
            if (position >= lines.size()) {
                return std::unexpected(
                    error(PackagingErrorCode::invalid_manifest, "manifest has a trailing blank section"));
            }
            const auto section = lines[position++];
            if (section == "[generator]") {
                if (manifest.generator || position + 3U > lines.size()) {
                    return std::unexpected(
                        error(PackagingErrorCode::invalid_manifest, "generator section is duplicated or incomplete"));
                }
                auto module = parse_quoted(lines[position++], "module");
                auto callable = parse_quoted(lines[position++], "callable");
                auto lock = parse_quoted(lines[position++], "lock");
                if (!module || !callable || !lock) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest, "generator section is invalid"));
                }
                manifest.generator =
                    GeneratorDeclaration {.module = *module, .callable = *callable, .lock_path = *lock, .inputs = {}};
                continue;
            }
            constexpr std::string_view input_prefix = "[generator.inputs.";
            if (section.starts_with(input_prefix) && section.ends_with(']')) {
                if (!manifest.generator || position + 2U > lines.size()) {
                    return std::unexpected(
                        error(PackagingErrorCode::invalid_manifest, "generator input appears before generator"));
                }
                const auto name = section.substr(input_prefix.size(), section.size() - input_prefix.size() - 1U);
                auto path = parse_quoted(lines[position++], "path");
                auto input_format = parse_quoted(lines[position++], "format");
                if (!path || !input_format ||
                    (*input_format != "json" && *input_format != "utf8" && *input_format != "bytes")) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                                 "generator input section is invalid", std::string {name}));
                }
                manifest.generator->inputs.push_back(GeneratorInput {
                    .name = std::string {name},
                    .path = *path,
                    .format = *input_format == "json" ? GeneratorInputFormat::json :
                              *input_format == "utf8" ? GeneratorInputFormat::utf8 :
                                                        GeneratorInputFormat::bytes,
                });
                continue;
            }
            constexpr std::string_view dependency_prefix = "[dependencies.";
            if (section.starts_with(dependency_prefix) && section.ends_with(']')) {
                if (position + 2U > lines.size()) {
                    return std::unexpected(
                        error(PackagingErrorCode::invalid_manifest, "dependency section is incomplete"));
                }
                const auto alias =
                    section.substr(dependency_prefix.size(), section.size() - dependency_prefix.size() - 1U);
                auto dependency_pack = parse_quoted(lines[position++], "pack");
                auto digest = parse_quoted(lines[position++], "digest");
                if (!dependency_pack || !digest) {
                    return std::unexpected(error(PackagingErrorCode::invalid_manifest, "dependency section is invalid",
                                                 std::string {alias}));
                }
                manifest.dependencies.push_back(PackDependency {
                    .alias = std::string {alias},
                    .pack = PackId {*dependency_pack},
                    .digest = SourceDigest {*digest},
                });
                continue;
            }
            if (section == "[capabilities]") {
                if (position + 2U != lines.size()) {
                    return std::unexpected(
                        error(PackagingErrorCode::invalid_manifest, "capabilities must be the final manifest section"));
                }
                auto required = parse_quoted_array(lines[position++], "required");
                auto optional = parse_quoted_array(lines[position++], "optional");
                if (!required || !optional) {
                    return std::unexpected(
                        error(PackagingErrorCode::invalid_manifest, "capabilities section is invalid"));
                }
                for (auto &value : *required) {
                    manifest.required_capabilities.push_back(CapabilityId {std::move(value)});
                }
                for (auto &value : *optional) {
                    manifest.optional_capabilities.push_back(CapabilityId {std::move(value)});
                }
                continue;
            }
            return std::unexpected(
                error(PackagingErrorCode::invalid_manifest, "unknown manifest section", std::string {section}));
        }
        const auto validated = validate_manifest(manifest);
        if (!validated) {
            return std::unexpected(validated.error());
        }
        if (canonical_manifest(manifest) != text) {
            return std::unexpected(error(PackagingErrorCode::invalid_manifest, "manifest bytes are not canonical"));
        }
        return manifest;
    }

    std::string canonical_index(const SourceIndex &index) {
        std::string output {"{\"entries\":["};
        for (std::size_t position = 0; position < index.entries.size(); ++position) {
            if (position != 0U) {
                output += ',';
            }
            const auto &entry = index.entries[position];
            output += "{\"media_type\":\"" + entry.media_type + "\",\"path\":\"" + entry.path + "\",\"sha256\":\"" +
                      entry.sha256 + "\",\"size\":" + std::to_string(entry.size) + '}';
        }
        output += "],\"format\":" + std::to_string(index.format) + '}';
        return output;
    }

    std::expected<SourceIndex, PackagingError> parse_canonical_index(const std::string_view text) {
        IndexCursor cursor {.input = text};
        if (!cursor.consume("{\"entries\":[")) {
            return std::unexpected(
                error(PackagingErrorCode::invalid_index, "index does not begin with the canonical entries field"));
        }
        SourceIndex index;
        if (!cursor.consume("]")) {
            while (true) {
                if (!cursor.consume("{\"media_type\":\"")) {
                    return std::unexpected(error(PackagingErrorCode::invalid_index, "invalid canonical index entry"));
                }
                auto media_type = cursor.string_until_quote("media_type");
                if (!media_type || !cursor.consume("\",\"path\":\"")) {
                    return std::unexpected(
                        media_type ? error(PackagingErrorCode::invalid_index, "index entry path field is missing") :
                                     media_type.error());
                }
                auto path = cursor.string_until_quote("path");
                if (!path || !cursor.consume("\",\"sha256\":\"")) {
                    return std::unexpected(
                        path ? error(PackagingErrorCode::invalid_index, "index entry digest field is missing") :
                               path.error());
                }
                auto digest = cursor.string_until_quote("sha256");
                if (!digest || !cursor.consume("\",\"size\":")) {
                    return std::unexpected(
                        digest ? error(PackagingErrorCode::invalid_index, "index entry size field is missing") :
                                 digest.error());
                }
                auto size = cursor.unsigned_number("size");
                if (!size || !cursor.consume("}")) {
                    return std::unexpected(
                        size ? error(PackagingErrorCode::invalid_index, "index entry object is malformed") :
                               size.error());
                }
                index.entries.push_back(SourceIndexEntry {
                    .media_type = std::move(*media_type),
                    .path = std::move(*path),
                    .sha256 = std::move(*digest),
                    .size = *size,
                });
                if (cursor.consume("]")) {
                    break;
                }
                if (!cursor.consume(",")) {
                    return std::unexpected(
                        error(PackagingErrorCode::invalid_index, "index entry separator is malformed"));
                }
            }
        }
        if (!cursor.consume(",\"format\":")) {
            return std::unexpected(error(PackagingErrorCode::invalid_index, "index format field is missing"));
        }
        auto format = cursor.unsigned_number("format");
        if (!format || *format > std::numeric_limits<std::uint32_t>::max() || !cursor.consume("}") ||
            cursor.offset != text.size()) {
            return std::unexpected(
                format ? error(PackagingErrorCode::invalid_index, "index has invalid format or trailing bytes") :
                         format.error());
        }
        index.format = static_cast<std::uint32_t>(*format);
        if (index.format != 1U || canonical_index(index) != text) {
            return std::unexpected(error(PackagingErrorCode::invalid_index, "index is not canonical format 1"));
        }
        std::string previous;
        for (const auto &entry : index.entries) {
            if (!is_safe_path(entry.path) || entry.path <= previous || !is_media_type(entry.media_type) ||
                !is_lower_hex_digest(entry.sha256)) {
                return std::unexpected(error(PackagingErrorCode::invalid_index,
                                             "index paths, media types, order, or digests are invalid", entry.path));
            }
            previous = entry.path;
        }
        return index;
    }

    std::string canonical_signature_envelope(const SignatureEnvelope &envelope) {
        return "{\"algorithm\":\"" + envelope.algorithm + "\",\"key_id\":\"" + envelope.key_id + "\",\"signature\":\"" +
               base64url_encode(envelope.signature) + "\",\"version\":" + std::to_string(envelope.version) + '}';
    }

    std::expected<SignatureEnvelope, PackagingError> parse_canonical_signature_envelope(const std::string_view text) {
        constexpr std::string_view prefix = "{\"algorithm\":\"Ed25519\",\"key_id\":\"";
        constexpr std::string_view middle = "\",\"signature\":\"";
        constexpr std::string_view suffix = "\",\"version\":1}";
        if (!text.starts_with(prefix) || !text.ends_with(suffix)) {
            return std::unexpected(error(PackagingErrorCode::invalid_signature_envelope,
                                         "signature envelope is not canonical Ed25519 v1"));
        }
        const auto content = text.substr(prefix.size(), text.size() - prefix.size() - suffix.size());
        const auto separator = content.find(middle);
        if (separator == std::string_view::npos) {
            return std::unexpected(
                error(PackagingErrorCode::invalid_signature_envelope, "signature envelope fields are incomplete"));
        }
        const auto key_id = content.substr(0, separator);
        const auto encoded = content.substr(separator + middle.size());
        if (!key_id.starts_with("sha256:") || !is_lower_hex_digest(key_id.substr(7U))) {
            return std::unexpected(
                error(PackagingErrorCode::invalid_signature_envelope, "signature key ID is invalid"));
        }
        auto signature = base64url_decode(encoded);
        if (!signature || signature->size() != 64U) {
            return std::unexpected(signature ? error(PackagingErrorCode::invalid_signature_envelope,
                                                     "Ed25519 signature must contain 64 bytes") :
                                               signature.error());
        }
        SignatureEnvelope envelope {
            .version = 1,
            .algorithm = "Ed25519",
            .key_id = std::string {key_id},
            .signature = std::move(*signature),
        };
        if (canonical_signature_envelope(envelope) != text) {
            return std::unexpected(
                error(PackagingErrorCode::invalid_signature_envelope, "signature envelope is not canonical"));
        }
        return envelope;
    }

    namespace {

        struct VerifiedDependencyClosure {
            PackId pack;
            SourceDigest closure_digest;
        };

        struct DependencyVerificationState {
            std::size_t unique_packs {};
            std::size_t unique_bytes {};
            std::map<std::string, VerifiedDependencyClosure, std::less<>> verified_by_artifact_digest;
            std::map<std::string, std::string, std::less<>> artifact_digest_by_pack_id;
            std::set<std::string, std::less<>> active_pack_ids;
        };

        struct ActivePackGuard {
            std::set<std::string, std::less<>> &active_pack_ids;
            std::string pack_id;

            ~ActivePackGuard() { active_pack_ids.erase(pack_id); }
        };

        struct DependencyPayload {
            const PackDependency *declaration {};
            const ArchiveEntry *archive_entry {};
        };

        enum struct SignatureValidationMode { enforce_trust, structure_only };

    } // namespace

    static std::expected<LoadedSourcePack, PackagingError> verify_and_load_source_pack_recursive(
        const SourcePackArchive &archive, const TrustPolicy &policy, const SignatureVerifier *signature_verifier,
        const SourcePackLimits &limits, DependencyVerificationState &state, const std::size_t depth,
        const SignatureValidationMode signature_validation, const std::optional<PackId> &expected_pack = std::nullopt,
        const std::optional<SourceDigest> &artifact_digest = std::nullopt) {
        if (depth > limits.maximum_dependency_depth) {
            return std::unexpected(
                error(PackagingErrorCode::size_limit, "dependency depth exceeds the configured bound"));
        }
        if (archive.entries.empty() || archive.entries.size() > limits.maximum_entries) {
            return std::unexpected(
                error(PackagingErrorCode::size_limit, "archive entry count exceeds the configured bound"));
        }

        std::map<std::string, const ArchiveEntry *, std::less<>> entries;
        std::set<std::string> folded_paths;
        std::size_t aggregate_bytes {};
        std::string previous_path;
        for (const auto &entry : archive.entries) {
            if (entry.path.size() > limits.maximum_path_bytes || !is_safe_path(entry.path)) {
                return std::unexpected(error(PackagingErrorCode::invalid_path,
                                             "archive path is not a safe canonical ASCII path", entry.path));
            }
            if (entry.path <= previous_path) {
                return std::unexpected(error(PackagingErrorCode::noncanonical_archive,
                                             "archive entries must be strictly path-sorted", entry.path));
            }
            previous_path = entry.path;
            if (!folded_paths.insert(folded_path(entry.path)).second) {
                return std::unexpected(error(PackagingErrorCode::path_collision,
                                             "archive paths collide under Windows case folding", entry.path));
            }
            if (entry.kind != ArchiveEntryKind::regular_file || entry.compression != ArchiveCompression::stored ||
                entry.encrypted || !entry.canonical_metadata) {
                return std::unexpected(error(PackagingErrorCode::unsupported_entry,
                                             "archive entries must be unencrypted canonical stored files", entry.path));
            }
            if (entry.bytes.size() > limits.maximum_entry_bytes || entry.bytes.size() > limits.maximum_archive_bytes ||
                aggregate_bytes > limits.maximum_archive_bytes - entry.bytes.size()) {
                return std::unexpected(
                    error(PackagingErrorCode::size_limit, "archive byte bounds are exceeded", entry.path));
            }
            aggregate_bytes += entry.bytes.size();
            entries.emplace(entry.path, &entry);
        }

        const auto manifest_entry = entries.find("rulepack.toml");
        const auto index_entry = entries.find("META-INF/index.json");
        if (manifest_entry == entries.end() || index_entry == entries.end()) {
            return std::unexpected(
                error(PackagingErrorCode::entry_missing, "archive requires rulepack.toml and META-INF/index.json"));
        }
        if (!canonical_text(*manifest_entry->second) || !canonical_text(*index_entry->second)) {
            return std::unexpected(
                error(PackagingErrorCode::noncanonical_archive, "manifest and index must be canonical UTF-8/LF text"));
        }

        auto manifest = parse_canonical_manifest(bytes_to_text(manifest_entry->second->bytes));
        if (!manifest) {
            return std::unexpected(manifest.error());
        }
        if (expected_pack && manifest->pack != *expected_pack) {
            return std::unexpected(error(PackagingErrorCode::dependency_mismatch,
                                         "dependency payload pack ID differs from its declaration",
                                         expected_pack->value));
        }
        if (state.active_pack_ids.contains(manifest->pack.value)) {
            return std::unexpected(error(PackagingErrorCode::dependency_cycle,
                                         "dependency closure contains a pack-ID cycle", manifest->pack.value));
        }
        state.active_pack_ids.insert(manifest->pack.value);
        ActivePackGuard active_pack_guard {.active_pack_ids = state.active_pack_ids, .pack_id = manifest->pack.value};
        if (artifact_digest) {
            const auto [known_pack, inserted] =
                state.artifact_digest_by_pack_id.emplace(manifest->pack.value, artifact_digest->value);
            if (!inserted && known_pack->second != artifact_digest->value) {
                return std::unexpected(error(PackagingErrorCode::dependency_mismatch,
                                             "one pack ID resolves to multiple dependency artifacts",
                                             manifest->pack.value));
            }
        }
        if (manifest->dependencies.size() > limits.maximum_dependencies) {
            return std::unexpected(
                error(PackagingErrorCode::size_limit, "dependency count exceeds the configured bound"));
        }
        auto index = parse_canonical_index(bytes_to_text(index_entry->second->bytes));
        if (!index) {
            return std::unexpected(index.error());
        }

        std::set<std::string> indexed_paths;
        std::size_t source_bytes {};
        for (const auto &indexed : index->entries) {
            if (indexed.path == "META-INF/index.json" || indexed.path == "META-INF/signature.json") {
                return std::unexpected(error(PackagingErrorCode::invalid_index,
                                             "index cannot include index or signature envelopes", indexed.path));
            }
            const auto archived = entries.find(indexed.path);
            if (archived == entries.end()) {
                return std::unexpected(
                    error(PackagingErrorCode::entry_missing, "indexed payload is absent", indexed.path));
            }
            if (indexed.size != archived->second->bytes.size()) {
                return std::unexpected(error(PackagingErrorCode::entry_size_mismatch,
                                             "indexed payload size differs from archive", indexed.path));
            }
            if (indexed.sha256 != sha256_hex(archived->second->bytes)) {
                return std::unexpected(error(PackagingErrorCode::entry_digest_mismatch,
                                             "indexed payload digest differs from archive", indexed.path));
            }
            indexed_paths.insert(indexed.path);
            const bool python_source = indexed.path.starts_with("src/") || indexed.path.starts_with("generator/");
            const bool dependency_source = indexed.path.starts_with("deps/") && indexed.path.ends_with(".rpack");
            if (python_source || dependency_source) {
                if (python_source && (!indexed.path.ends_with(".py") || !canonical_text(*archived->second))) {
                    return std::unexpected(error(PackagingErrorCode::noncanonical_archive,
                                                 "Python source must be canonical UTF-8/LF text", indexed.path));
                }
                if (indexed.size > limits.maximum_source_bytes ||
                    source_bytes > limits.maximum_source_bytes - indexed.size) {
                    return std::unexpected(error(PackagingErrorCode::size_limit,
                                                 "source closure exceeds the configured bound", indexed.path));
                }
                source_bytes += indexed.size;
            }
        }
        for (const auto &[path, entry] : entries) {
            static_cast<void>(entry);
            if (path != "META-INF/index.json" && path != "META-INF/signature.json" && !indexed_paths.contains(path)) {
                return std::unexpected(
                    error(PackagingErrorCode::entry_unindexed, "archive contains an unindexed payload", path));
            }
        }

        std::vector<DependencyPayload> dependency_payloads;
        dependency_payloads.reserve(manifest->dependencies.size());
        std::set<std::string, std::less<>> declared_dependency_paths;
        for (const auto &dependency : manifest->dependencies) {
            const auto digest = std::string_view {dependency.digest.value}.substr(7U);
            const auto dependency_path = "deps/" + std::string {digest} + ".rpack";
            const auto dependency_entry = entries.find(dependency_path);
            if (dependency_entry == entries.end()) {
                return std::unexpected(error(PackagingErrorCode::dependency_mismatch,
                                             "manifest dependency payload is absent", dependency.alias));
            }
            const auto actual_digest = "sha256:" + sha256_hex(dependency_entry->second->bytes);
            if (actual_digest != dependency.digest.value) {
                return std::unexpected(error(PackagingErrorCode::dependency_mismatch,
                                             "dependency artifact digest differs from its declaration",
                                             dependency.alias));
            }
            declared_dependency_paths.insert(dependency_path);
            dependency_payloads.push_back(
                DependencyPayload {.declaration = &dependency, .archive_entry = dependency_entry->second});
        }
        for (const auto &[path, entry] : entries) {
            static_cast<void>(entry);
            if (path.starts_with("deps/") && !declared_dependency_paths.contains(path)) {
                return std::unexpected(error(PackagingErrorCode::dependency_mismatch,
                                             "dependency payload is not declared by the manifest", path));
            }
        }
        if (manifest->generator) {
            if (!entries.contains(manifest->generator->lock_path)) {
                return std::unexpected(error(PackagingErrorCode::entry_missing, "generator lock file is absent",
                                             manifest->generator->lock_path));
            }
            std::size_t generator_input_bytes {};
            for (const auto &input : manifest->generator->inputs) {
                const auto input_entry = entries.find(input.path);
                if (input_entry == entries.end()) {
                    return std::unexpected(
                        error(PackagingErrorCode::entry_missing, "declared generator input is absent", input.path));
                }
                if (input_entry->second->bytes.size() > limits.maximum_generator_input_bytes ||
                    generator_input_bytes > limits.maximum_generator_input_bytes - input_entry->second->bytes.size()) {
                    return std::unexpected(error(PackagingErrorCode::size_limit,
                                                 "declared generator inputs exceed their configured bound",
                                                 input.path));
                }
                generator_input_bytes += input_entry->second->bytes.size();
            }
        }

        const auto canonical_index_bytes = canonical_index(*index);
        constexpr char source_domain_bytes[] = "rule-engine-rpack-source-v1\0";
        const std::string_view source_domain {source_domain_bytes, sizeof(source_domain_bytes) - 1U};
        Sha256State source_hasher;
        source_hasher.update(as_bytes(source_domain));
        source_hasher.update(as_bytes(canonical_index_bytes));
        const auto source_hash = source_hasher.finish();
        const SourceDigest source_digest {"sha256:" + hex(source_hash)};

        PackTrust trust;
        std::string signature_algorithm;
        const auto signature_entry = entries.find("META-INF/signature.json");
        if (signature_entry == entries.end()) {
            if (signature_validation == SignatureValidationMode::enforce_trust &&
                (policy.mode != TrustMode::development || !policy.allow_unsigned_packs)) {
                return std::unexpected(error(PackagingErrorCode::signature_required,
                                             "production policy requires a trusted Ed25519 signature"));
            }
            trust = PackTrust {
                .kind = PackTrustKind::development_unsigned,
                .signer_key_id = {},
                .generator_execution_authorized = policy.allow_unsigned_generators,
            };
        } else {
            if (!canonical_text(*signature_entry->second)) {
                return std::unexpected(error(PackagingErrorCode::invalid_signature_envelope,
                                             "signature envelope must be canonical UTF-8"));
            }
            auto envelope = parse_canonical_signature_envelope(bytes_to_text(signature_entry->second->bytes));
            if (!envelope) {
                return std::unexpected(envelope.error());
            }
            if (signature_validation == SignatureValidationMode::structure_only) {
                trust = PackTrust {
                    .kind = PackTrustKind::development_unsigned,
                    .signer_key_id = {},
                    .generator_execution_authorized = false,
                };
            } else {
                const auto signer = std::ranges::find_if(policy.signers, [&envelope](const TrustedSigner &candidate) {
                    return candidate.key_id == envelope->key_id;
                });
                if (signer == policy.signers.end()) {
                    return std::unexpected(error(PackagingErrorCode::signer_unknown,
                                                 "signature key is not in the trust policy", envelope->key_id));
                }
                if (signer->revoked) {
                    return std::unexpected(
                        error(PackagingErrorCode::signer_revoked, "signature key is revoked", envelope->key_id));
                }
                if (signer->public_key.size() != 32U || "sha256:" + sha256_hex(signer->public_key) != signer->key_id) {
                    return std::unexpected(error(PackagingErrorCode::signer_unknown,
                                                 "trusted signer key ID does not match its public key",
                                                 signer->key_id));
                }
                if (!std::ranges::any_of(signer->allowed_pack_prefixes, [&manifest](const std::string &prefix) {
                        return !prefix.empty() && manifest->pack.value.starts_with(prefix);
                    })) {
                    return std::unexpected(error(PackagingErrorCode::signer_out_of_scope,
                                                 "signature key is not authorized for this pack ID",
                                                 manifest->pack.value));
                }
                if (signature_verifier == nullptr) {
                    return std::unexpected(
                        error(PackagingErrorCode::crypto_backend_unavailable, "signature verifier is unavailable"));
                }
                const auto message = source_pack_signature_message(canonical_index_bytes);
                auto verified = signature_verifier->verify_ed25519(signer->public_key, message, envelope->signature);
                if (!verified) {
                    return std::unexpected(verified.error());
                }
                if (!*verified) {
                    return std::unexpected(error(PackagingErrorCode::signature_invalid,
                                                 "Ed25519 verifier rejected the pack signature", envelope->key_id));
                }
                trust = PackTrust {
                    .kind = PackTrustKind::production_signed,
                    .signer_key_id = envelope->key_id,
                    .generator_execution_authorized = true,
                };
                signature_algorithm = "Ed25519";
            }
        }

        std::vector<VerifiedDependencyClosure> verified_dependencies;
        verified_dependencies.reserve(dependency_payloads.size());
        for (const auto &payload : dependency_payloads) {
            const auto &dependency = *payload.declaration;
            const auto known_pack = state.artifact_digest_by_pack_id.find(dependency.pack.value);
            if (known_pack != state.artifact_digest_by_pack_id.end() && known_pack->second != dependency.digest.value) {
                return std::unexpected(error(PackagingErrorCode::dependency_mismatch,
                                             "one pack ID resolves to multiple dependency artifacts",
                                             dependency.pack.value));
            }

            const auto cached = state.verified_by_artifact_digest.find(dependency.digest.value);
            if (cached != state.verified_by_artifact_digest.end()) {
                if (cached->second.pack != dependency.pack) {
                    return std::unexpected(error(PackagingErrorCode::dependency_mismatch,
                                                 "one dependency artifact is declared with multiple pack IDs",
                                                 dependency.alias));
                }
                verified_dependencies.push_back(cached->second);
                continue;
            }

            if (depth >= limits.maximum_dependency_depth) {
                return std::unexpected(error(PackagingErrorCode::size_limit,
                                             "dependency depth exceeds the configured bound", dependency.alias));
            }
            if (state.unique_packs >= limits.maximum_dependency_packs) {
                return std::unexpected(error(PackagingErrorCode::size_limit,
                                             "dependency pack count exceeds the configured bound", dependency.alias));
            }
            const auto artifact_bytes = payload.archive_entry->bytes.size();
            if (artifact_bytes > limits.maximum_dependency_bytes ||
                state.unique_bytes > limits.maximum_dependency_bytes - artifact_bytes) {
                return std::unexpected(error(PackagingErrorCode::size_limit,
                                             "dependency artifact bytes exceed the configured bound",
                                             dependency.alias));
            }
            ++state.unique_packs;
            state.unique_bytes += artifact_bytes;

            auto dependency_archive = decode_canonical_source_pack(payload.archive_entry->bytes, limits);
            if (!dependency_archive) {
                return std::unexpected(dependency_archive.error());
            }
            auto verified = verify_and_load_source_pack_recursive(*dependency_archive, policy, signature_verifier,
                                                                  limits, state, depth + 1U, signature_validation,
                                                                  dependency.pack, dependency.digest);
            if (!verified) {
                return std::unexpected(verified.error());
            }
            VerifiedDependencyClosure closure {.pack = dependency.pack, .closure_digest = verified->closure_digest};
            state.verified_by_artifact_digest.emplace(dependency.digest.value, closure);
            verified_dependencies.push_back(std::move(closure));
        }

        constexpr char closure_domain_bytes[] = "rule-engine-rpack-closure-v1\0";
        std::string closure_material {closure_domain_bytes, sizeof(closure_domain_bytes) - 1U};
        append_sized(closure_material, source_digest.value);
        for (std::size_t dependency_index = 0U; dependency_index < manifest->dependencies.size(); ++dependency_index) {
            const auto &dependency = manifest->dependencies[dependency_index];
            append_sized(closure_material, dependency.alias);
            append_sized(closure_material, dependency.pack.value);
            append_sized(closure_material, dependency.digest.value);
            append_sized(closure_material, verified_dependencies[dependency_index].closure_digest.value);
        }
        const SourceDigest closure_digest {"sha256:" + sha256_hex(as_bytes(closure_material))};

        PackManifest contract_manifest {
            .pack = manifest->pack,
            .version = manifest->version,
            .compiler_abi = std::string {python_static_compiler_abi_v1},
            .budget_profile = manifest->budget_profile,
            .entry_modules = manifest->entry_modules,
            .dependency_digests = {},
        };
        for (const auto &dependency : manifest->dependencies) {
            contract_manifest.dependency_digests.push_back(dependency.digest.value);
        }
        std::vector<SourceFile> sources;
        std::set<std::string> modules;
        for (const auto &indexed : index->entries) {
            if (!indexed.path.starts_with("src/") || !indexed.path.ends_with(".py")) {
                continue;
            }
            const auto module = source_module(indexed.path);
            if (!modules.insert(module).second) {
                return std::unexpected(error(PackagingErrorCode::invalid_manifest,
                                             "multiple source paths map to the same module", module));
            }
            const auto &entry = *entries.at(indexed.path);
            sources.push_back(SourceFile {
                .id = SourceId {indexed.path},
                .module = module,
                .utf8 = bytes_to_text(entry.bytes),
                .digest = SourceDigest {"sha256:" + indexed.sha256},
            });
        }
        VerifiedRulePack contract_pack {
            .manifest = std::move(contract_manifest),
            .sources = std::move(sources),
            .trust =
                TrustResult {
                    .signer_key_id = trust.signer_key_id,
                    .signature_algorithm = signature_algorithm,
                    .production_authorized = trust.kind == PackTrustKind::production_signed,
                },
            .closure_digest = closure_digest,
        };
        return LoadedSourcePack {
            .manifest = std::move(*manifest),
            .index = std::move(*index),
            .source_digest = source_digest,
            .closure_digest = closure_digest,
            .trust = std::move(trust),
            .contract_pack = std::move(contract_pack),
        };
    }

    std::expected<std::vector<std::byte>, PackagingError>
    canonical_source_pack_signature_message(const SourcePackArchive &unsigned_archive, const SourcePackLimits &limits) {
        if (std::ranges::any_of(unsigned_archive.entries,
                                [](const ArchiveEntry &entry) { return entry.path == "META-INF/signature.json"; })) {
            return std::unexpected(error(PackagingErrorCode::invalid_signature_envelope,
                                         "source pack already contains a signature envelope"));
        }
        const TrustPolicy structural_policy {
            .mode = TrustMode::development,
            .allow_unsigned_packs = true,
            .allow_unsigned_generators = false,
            .signers = {},
        };
        DependencyVerificationState state;
        const auto loaded = verify_and_load_source_pack_recursive(unsigned_archive, structural_policy, nullptr, limits,
                                                                  state, 0U, SignatureValidationMode::structure_only);
        if (!loaded) {
            return std::unexpected(loaded.error());
        }
        return source_pack_signature_message(canonical_index(loaded->index));
    }

    std::expected<LoadedSourcePack, PackagingError>
    verify_and_load_source_pack(const SourcePackArchive &archive, const TrustPolicy &policy,
                                const SignatureVerifier &signature_verifier, const SourcePackLimits &limits) {
        DependencyVerificationState state;
        return verify_and_load_source_pack_recursive(archive, policy, &signature_verifier, limits, state, 0U,
                                                     SignatureValidationMode::enforce_trust);
    }

} // namespace rule_engine::python::packaging
