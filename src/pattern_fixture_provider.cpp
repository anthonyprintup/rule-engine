#include <rule_engine/pattern_fixture_provider.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {
    using namespace std::chrono_literals;
    constexpr std::size_t pattern_context_bytes = 8u;

    [[nodiscard]] rule_engine::Fact make_fact(std::string subject_id,
                                              std::string key,
                                              rule_engine::Value value,
                                              const rule_engine::FactStatus status,
                                              std::string diagnostic = {}) {
        return rule_engine::Fact {
            .subject_id = std::move(subject_id),
            .key = std::move(key),
            .value = std::move(value),
            .status = status,
            .diagnostic = std::move(diagnostic),
            .ttl = 30s,
        };
    }

    [[nodiscard]] rule_engine::Fact unavailable_fact(const rule_engine::protocol::FactKey &key,
                                                     std::string diagnostic) {
        return make_fact(key.subject_id,
                         key.key,
                         rule_engine::Value::undefined(),
                         rule_engine::FactStatus::unavailable,
                         std::move(diagnostic));
    }

    [[nodiscard]] rule_engine::PatternValue fixture_pattern() {
        rule_engine::PatternValue pattern;
        pattern.matched = true;
        pattern.matches.push_back(rule_engine::PatternMatchContext {
            .offset = 4096u,
            .length = 6u,
            .bytes = {std::byte {'n'}, std::byte {'e'}, std::byte {'e'}, std::byte {'d'}, std::byte {'l'}, std::byte {'e'}},
            .before = {std::byte {0x90}, std::byte {0x90}},
            .after = {std::byte {0xcc}},
            .scan_space = "fixture.process.memory",
            .region_permissions = "rx",
        });
        return pattern;
    }

    [[nodiscard]] std::optional<std::uint8_t> hex_nibble(const char value) noexcept {
        if (value >= '0' && value <= '9') {
            return static_cast<std::uint8_t>(value - '0');
        }
        if (value >= 'a' && value <= 'f') {
            return static_cast<std::uint8_t>(value - 'a' + 10);
        }
        if (value >= 'A' && value <= 'F') {
            return static_cast<std::uint8_t>(value - 'A' + 10);
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::vector<std::byte>> parse_hex_bytes(const std::string_view text) {
        if ((text.size() % 2u) != 0u) {
            return std::nullopt;
        }
        std::vector<std::byte> out;
        out.reserve(text.size() / 2u);
        for (std::size_t index = 0; index < text.size(); index += 2u) {
            const auto high = hex_nibble(text[index]);
            const auto low = hex_nibble(text[index + 1u]);
            if (!high.has_value() || !low.has_value()) {
                return std::nullopt;
            }
            out.push_back(static_cast<std::byte>((*high << 4u) | *low));
        }
        return out;
    }

    [[nodiscard]] std::optional<std::vector<std::byte>> read_binary_file(const std::filesystem::path &path) {
        std::ifstream file {path, std::ios::binary};
        if (!file) {
            return std::nullopt;
        }

        std::vector<std::byte> out;
        char ch {};
        while (file.get(ch)) {
            out.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
        }
        if (!file.eof()) {
            return std::nullopt;
        }
        return out;
    }

    template <typename T>
    [[nodiscard]] bool parse_integer(const std::string_view text, T &out) noexcept {
        const auto *first = text.data();
        const auto *last = first + text.size();
        const auto [ptr, ec] = std::from_chars(first, last, out);
        return ec == std::errc {} && ptr == last;
    }

    [[nodiscard]] std::optional<bool> parse_bool(const std::string_view text) noexcept {
        if (text == "true" || text == "1") {
            return true;
        }
        if (text == "false" || text == "0") {
            return false;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<std::byte> byte_slice(const std::vector<std::byte> &bytes,
                                                    const std::size_t offset,
                                                    const std::size_t length) {
        if (offset >= bytes.size()) {
            return {};
        }
        const auto end = (std::min)(bytes.size(), offset + length);
        return std::vector<std::byte> {bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                       bytes.begin() + static_cast<std::ptrdiff_t>(end)};
    }

    [[nodiscard]] rule_engine::PatternValue scan_literal_pattern(const std::vector<std::byte> &haystack,
                                                                 const std::vector<std::byte> &needle,
                                                                 std::string scan_space,
                                                                 std::string permissions) {
        rule_engine::PatternValue pattern;
        if (needle.empty() || haystack.size() < needle.size()) {
            return pattern;
        }

        for (std::size_t offset = 0u; offset <= haystack.size() - needle.size(); ++offset) {
            const auto matches = std::equal(needle.begin(),
                                            needle.end(),
                                            haystack.begin() + static_cast<std::ptrdiff_t>(offset));
            if (!matches) {
                continue;
            }

            const auto before_size = (std::min)(offset, pattern_context_bytes);
            const auto before_offset = offset - before_size;
            const auto after_offset = offset + needle.size();
            pattern.matches.push_back(rule_engine::PatternMatchContext {
                .offset = offset,
                .length = needle.size(),
                .bytes = needle,
                .before = byte_slice(haystack, before_offset, before_size),
                .after = byte_slice(haystack, after_offset, pattern_context_bytes),
                .scan_space = scan_space,
                .region_permissions = permissions,
            });
        }

        pattern.matched = !pattern.matches.empty();
        return pattern;
    }

    void append_pattern_fixture(rule_engine::patterns::PatternFixtureSet &set,
                                std::string pattern_key,
                                rule_engine::PatternValue value) {
        const auto found = std::ranges::find_if(set.patterns, [&](const auto &fixture) {
            return fixture.pattern_key == pattern_key;
        });
        if (found == set.patterns.end()) {
            set.patterns.push_back(rule_engine::patterns::PatternFixture {
                .pattern_key = std::move(pattern_key),
                .value = std::move(value),
            });
            return;
        }

        found->value.matched = found->value.matched || value.matched;
        found->value.matches.insert(found->value.matches.end(),
                                    std::make_move_iterator(value.matches.begin()),
                                    std::make_move_iterator(value.matches.end()));
    }

    [[nodiscard]] bool is_pattern_metadata_key(const std::string_view key) noexcept {
        return key.starts_with('$') && key.ends_with(".pattern");
    }

    [[nodiscard]] bool is_pattern_match_key(const std::string_view key) noexcept {
        return key.starts_with('$') && key.ends_with(".matches");
    }
} // namespace

namespace rule_engine::patterns {
    PatternFixtureSet default_pattern_fixtures() {
        return PatternFixtureSet {
            .patterns = {
                PatternFixture {
                    .pattern_key = "$needle",
                    .value = fixture_pattern(),
                },
            },
        };
    }

    std::expected<PatternFixtureSet, ErrorSet> load_pattern_fixture_file(const std::filesystem::path &path) {
        std::ifstream file {path};
        if (!file) {
            return std::unexpected(single_error(path.string(), "failed to open pattern fixture file"));
        }

        PatternFixtureSet out;
        std::string line;
        std::uint64_t line_number {};
        while (std::getline(file, line)) {
            ++line_number;
            if (line.empty() || line.starts_with('#')) {
                continue;
            }

            std::istringstream stream {line};
            std::string directive_or_pattern;
            stream >> directive_or_pattern;

            if (directive_or_pattern == "scan") {
                std::string pattern_key;
                std::string scan_space;
                std::string permissions;
                std::string haystack_text;
                std::string needle_text;
                if (!(stream >> pattern_key >> scan_space >> permissions >> haystack_text >> needle_text)) {
                    return std::unexpected(single_error(path.string(),
                                                        "invalid pattern scan line " + std::to_string(line_number)));
                }

                auto haystack = parse_hex_bytes(haystack_text);
                auto needle = parse_hex_bytes(needle_text);
                if (pattern_key.empty() || !pattern_key.starts_with('$') || !haystack.has_value() ||
                    !needle.has_value() || needle->empty()) {
                    return std::unexpected(single_error(path.string(),
                                                        "invalid pattern scan value on line " +
                                                            std::to_string(line_number)));
                }

                append_pattern_fixture(out,
                                       std::move(pattern_key),
                                       scan_literal_pattern(*haystack,
                                                            *needle,
                                                            std::move(scan_space),
                                                            std::move(permissions)));
                continue;
            }

            if (directive_or_pattern == "scan_file") {
                std::string pattern_key;
                std::string scan_space;
                std::string permissions;
                std::string file_path_text;
                std::string needle_text;
                if (!(stream >> pattern_key >> scan_space >> permissions >> file_path_text >> needle_text)) {
                    return std::unexpected(single_error(path.string(),
                                                        "invalid pattern scan_file line " +
                                                            std::to_string(line_number)));
                }

                auto file_path = std::filesystem::path {file_path_text};
                if (file_path.is_relative()) {
                    file_path = path.parent_path() / file_path;
                }
                auto haystack = read_binary_file(file_path);
                auto needle = parse_hex_bytes(needle_text);
                if (pattern_key.empty() || !pattern_key.starts_with('$') || !haystack.has_value() ||
                    !needle.has_value() || needle->empty()) {
                    return std::unexpected(single_error(path.string(),
                                                        "invalid pattern scan_file value on line " +
                                                            std::to_string(line_number)));
                }

                append_pattern_fixture(out,
                                       std::move(pattern_key),
                                       scan_literal_pattern(*haystack,
                                                            *needle,
                                                            std::move(scan_space),
                                                            std::move(permissions)));
                continue;
            }

            std::string pattern_key;
            std::string matched_text;
            std::string offset_text;
            std::string length_text;
            std::string scan_space;
            std::string permissions;
            std::string bytes_text;
            pattern_key = std::move(directive_or_pattern);
            if (!(stream >> matched_text >> offset_text >> length_text >> scan_space >> permissions >>
                  bytes_text)) {
                return std::unexpected(single_error(path.string(),
                                                    "invalid pattern fixture line " + std::to_string(line_number)));
            }

            const auto matched = parse_bool(matched_text);
            std::uint64_t offset {};
            std::uint64_t length {};
            auto bytes = parse_hex_bytes(bytes_text);
            if (pattern_key.empty() || !pattern_key.starts_with('$') || !matched.has_value() ||
                !parse_integer(offset_text, offset) || !parse_integer(length_text, length) || !bytes.has_value()) {
                return std::unexpected(single_error(path.string(),
                                                    "invalid pattern fixture value on line " +
                                                        std::to_string(line_number)));
            }

            PatternValue pattern;
            pattern.matched = *matched;
            if (pattern.matched) {
                pattern.matches.push_back(PatternMatchContext {
                    .offset = offset,
                    .length = length,
                    .bytes = std::move(*bytes),
                    .before = {},
                    .after = {},
                    .scan_space = std::move(scan_space),
                    .region_permissions = std::move(permissions),
                });
            }
            append_pattern_fixture(out, std::move(pattern_key), std::move(pattern));
        }

        return out;
    }

    std::vector<Fact> read_fixture_pattern_facts(const std::span<const protocol::FactKey> keys,
                                                 const PatternFixtureSet &fixtures) {
        std::vector<Fact> out;
        out.reserve(keys.size());
        for (const auto &key : keys) {
            const auto pattern_key = key.key.substr(0, key.key.find('.'));
            const auto found = std::ranges::find_if(fixtures.patterns, [&](const auto &fixture) {
                return fixture.pattern_key == pattern_key;
            });
            if (is_pattern_match_key(key.key)) {
                const auto matched = found != fixtures.patterns.end() && found->value.matched;
                out.push_back(make_fact(key.subject_id, key.key, Value::boolean(matched), FactStatus::available));
                continue;
            }
            if (is_pattern_metadata_key(key.key)) {
                if (found == fixtures.patterns.end()) {
                    out.push_back(make_fact(key.subject_id,
                                            key.key,
                                            Value::pattern(PatternValue {}),
                                            FactStatus::available,
                                            "pattern fixture not found"));
                    continue;
                }
                out.push_back(make_fact(key.subject_id, key.key, Value::pattern(found->value), FactStatus::available));
                continue;
            }
            out.push_back(unavailable_fact(key, "unsupported fixture pattern fact"));
        }
        return out;
    }
} // namespace rule_engine::patterns
