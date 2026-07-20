#include "rule_engine/python/protocol/snapshot.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace rule_engine::python::protocol_v2 {
    namespace {

        [[nodiscard]] ProtocolError snapshot_error(const ProtocolErrorCode code, std::string message) {
            return ProtocolError {.code = code, .message = std::move(message), .byte_offset = 0};
        }

        constexpr std::array<std::uint32_t, 64> round_constants {
            0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
            0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
            0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
            0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
            0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
            0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
            0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
            0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
        };

        struct Sha256 {
            std::array<std::uint32_t, 8> state {
                0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
            };
            std::array<std::byte, 64> buffer {};
            std::size_t buffered {};
            std::uint64_t total_bytes {};

            void transform(const std::span<const std::byte, 64> block) noexcept {
                std::array<std::uint32_t, 64> words {};
                for (std::size_t index = 0; index < 16; ++index) {
                    const auto offset = index * 4;
                    words[index] = (std::to_integer<std::uint32_t>(block[offset]) << 24U) |
                                   (std::to_integer<std::uint32_t>(block[offset + 1]) << 16U) |
                                   (std::to_integer<std::uint32_t>(block[offset + 2]) << 8U) |
                                   std::to_integer<std::uint32_t>(block[offset + 3]);
                }
                for (std::size_t index = 16; index < words.size(); ++index) {
                    const auto s0 =
                        std::rotr(words[index - 15], 7) ^ std::rotr(words[index - 15], 18) ^ (words[index - 15] >> 3U);
                    const auto s1 =
                        std::rotr(words[index - 2], 17) ^ std::rotr(words[index - 2], 19) ^ (words[index - 2] >> 10U);
                    words[index] = words[index - 16] + s0 + words[index - 7] + s1;
                }

                auto a = state[0];
                auto b = state[1];
                auto c = state[2];
                auto d = state[3];
                auto e = state[4];
                auto f = state[5];
                auto g = state[6];
                auto h = state[7];
                for (std::size_t index = 0; index < words.size(); ++index) {
                    const auto sum1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
                    const auto choose = (e & f) ^ ((~e) & g);
                    const auto temp1 = h + sum1 + choose + round_constants[index] + words[index];
                    const auto sum0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
                    const auto majority = (a & b) ^ (a & c) ^ (b & c);
                    const auto temp2 = sum0 + majority;
                    h = g;
                    g = f;
                    f = e;
                    e = d + temp1;
                    d = c;
                    c = b;
                    b = a;
                    a = temp1 + temp2;
                }
                state[0] += a;
                state[1] += b;
                state[2] += c;
                state[3] += d;
                state[4] += e;
                state[5] += f;
                state[6] += g;
                state[7] += h;
            }

            void update(const std::span<const std::byte> input) noexcept {
                total_bytes += input.size();
                std::size_t offset {};
                while (offset < input.size()) {
                    const auto take = std::min(buffer.size() - buffered, input.size() - offset);
                    std::ranges::copy(input.subspan(offset, take),
                                      buffer.begin() + static_cast<std::ptrdiff_t>(buffered));
                    buffered += take;
                    offset += take;
                    if (buffered == buffer.size()) {
                        transform(std::span<const std::byte, 64> {buffer});
                        buffered = 0;
                    }
                }
            }

            void update(const std::string_view input) noexcept {
                update(std::as_bytes(std::span {input.data(), input.size()}));
            }

            [[nodiscard]] std::array<std::byte, 32> finish() noexcept {
                const auto bit_count = total_bytes * 8U;
                buffer[buffered++] = std::byte {0x80};
                if (buffered > 56) {
                    std::fill(buffer.begin() + static_cast<std::ptrdiff_t>(buffered), buffer.end(), std::byte {});
                    transform(std::span<const std::byte, 64> {buffer});
                    buffered = 0;
                }
                std::fill(buffer.begin() + static_cast<std::ptrdiff_t>(buffered), buffer.begin() + 56, std::byte {});
                for (std::size_t index = 0; index < 8; ++index) {
                    const auto shift = static_cast<unsigned int>((7 - index) * 8);
                    buffer[56 + index] = static_cast<std::byte>((bit_count >> shift) & 0xffU);
                }
                transform(std::span<const std::byte, 64> {buffer});

                std::array<std::byte, 32> digest {};
                for (std::size_t index = 0; index < state.size(); ++index) {
                    digest[index * 4] = static_cast<std::byte>((state[index] >> 24U) & 0xffU);
                    digest[index * 4 + 1] = static_cast<std::byte>((state[index] >> 16U) & 0xffU);
                    digest[index * 4 + 2] = static_cast<std::byte>((state[index] >> 8U) & 0xffU);
                    digest[index * 4 + 3] = static_cast<std::byte>(state[index] & 0xffU);
                }
                return digest;
            }
        };

        void update_u64(Sha256 &hash, const std::uint64_t value) noexcept {
            std::array<std::byte, 8> bytes {};
            for (std::size_t index = 0; index < bytes.size(); ++index) {
                const auto shift = static_cast<unsigned int>((7 - index) * 8);
                bytes[index] = static_cast<std::byte>((value >> shift) & 0xffU);
            }
            hash.update(bytes);
        }

        [[nodiscard]] std::string hex_digest(const std::array<std::byte, 32> &digest) {
            constexpr std::string_view digits = "0123456789abcdef";
            std::string result {"sha256:"};
            result.reserve(7 + digest.size() * 2);
            for (const auto value : digest) {
                const auto byte = std::to_integer<unsigned int>(value);
                result.push_back(digits[(byte >> 4U) & 0xfU]);
                result.push_back(digits[byte & 0xfU]);
            }
            return result;
        }

        [[nodiscard]] std::string parent_key(const std::optional<SubjectKey> &parent) {
            return parent.has_value() ? canonical_subject_key(*parent) : std::string {};
        }

    } // namespace

    std::expected<std::string, ProtocolError> authoritative_snapshot_digest(const std::span<const SubjectKey> subjects,
                                                                            const ProtocolLimits &limits) {
        if (subjects.size() > limits.maximum_snapshot_items) {
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::limit_exceeded, "snapshot item count exceeds the limit"));
        }

        std::vector<std::string> keys;
        keys.reserve(subjects.size());
        std::size_t bytes {};
        for (const auto &subject : subjects) {
            auto key = canonical_subject_key(subject);
            if (key.empty()) {
                return std::unexpected(
                    snapshot_error(ProtocolErrorCode::invalid_identity, "snapshot contains an invalid subject"));
            }
            if (key.size() > limits.maximum_snapshot_bytes - bytes) {
                return std::unexpected(
                    snapshot_error(ProtocolErrorCode::limit_exceeded, "snapshot canonical bytes exceed the limit"));
            }
            bytes += key.size();
            keys.push_back(std::move(key));
        }
        std::ranges::sort(keys);
        if (std::ranges::adjacent_find(keys) != keys.end()) {
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::duplicate_item, "snapshot contains duplicate subjects"));
        }

        Sha256 hash;
        hash.update(std::string_view {"rule-engine-authoritative-snapshot-v1\0", 38});
        update_u64(hash, keys.size());
        for (const auto &key : keys) {
            update_u64(hash, key.size());
            hash.update(key);
        }
        return hex_digest(hash.finish());
    }

    AuthoritativeSnapshotAssembler::AuthoritativeSnapshotAssembler(PeerId peer, SessionId session,
                                                                   const std::uint64_t session_fence,
                                                                   SchemaId subject_schema,
                                                                   std::optional<SubjectKey> parent,
                                                                   ProtocolLimits limits):
        peer_ {std::move(peer)},
        session_ {std::move(session)},
        session_fence_ {session_fence},
        subject_schema_ {std::move(subject_schema)},
        parent_ {std::move(parent)},
        limits_ {limits} {}

    std::expected<void, ProtocolError>
    AuthoritativeSnapshotAssembler::validate_session(const SessionId &session, const PeerId &peer,
                                                     const std::uint64_t fence) const {
        if (session != session_ || peer != peer_) {
            return std::unexpected(snapshot_error(ProtocolErrorCode::stale_session, "snapshot session is stale"));
        }
        if (fence != session_fence_) {
            return std::unexpected(snapshot_error(ProtocolErrorCode::stale_fence, "snapshot fence is stale"));
        }
        return {};
    }

    std::expected<void, ProtocolError>
    AuthoritativeSnapshotAssembler::begin(const AuthoritativeSnapshotBegin &message) {
        if (auto valid = validate_session(message.session, message.peer, message.session_fence); !valid) {
            return valid;
        }
        if (stage_.has_value()) {
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::malformed, "a snapshot is already staging for this scope"));
        }
        if (message.subject_schema != subject_schema_ || parent_key(message.parent) != parent_key(parent_)) {
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::schema_mismatch, "snapshot scope does not match the assembler"));
        }
        if (message.snapshot_id.empty() || message.expected_digest.empty() || message.generation == 0 ||
            message.generation <= last_good_generation_) {
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::stale_generation, "snapshot generation or identity is stale"));
        }
        if (message.expected_count > limits_.maximum_snapshot_items) {
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::limit_exceeded, "snapshot item count exceeds the limit"));
        }
        stage_ = Stage {
            .snapshot_id = message.snapshot_id,
            .generation = message.generation,
            .expected_count = message.expected_count,
            .expected_digest = message.expected_digest,
            .next_chunk = 0,
            .canonical_bytes = 0,
            .subjects = {},
            .canonical_keys = {},
        };
        stage_->subjects.reserve(static_cast<std::size_t>(message.expected_count));
        stage_->canonical_keys.reserve(static_cast<std::size_t>(message.expected_count));
        return {};
    }

    bool AuthoritativeSnapshotAssembler::has_expected_parent(const SubjectKey &subject) const {
        if (!parent_.has_value()) {
            return !subject.parent;
        }
        return subject.parent && canonical_subject_key(*subject.parent) == canonical_subject_key(*parent_);
    }

    std::expected<void, ProtocolError>
    AuthoritativeSnapshotAssembler::append(const AuthoritativeSnapshotChunk &message) {
        if (auto valid = validate_session(message.session, message.peer, message.session_fence); !valid) {
            reject_stage();
            return valid;
        }
        if (!stage_.has_value() || message.snapshot_id != stage_->snapshot_id ||
            message.generation != stage_->generation) {
            reject_stage();
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::stale_generation, "snapshot chunk does not match the active stage"));
        }
        if (message.chunk_index != stage_->next_chunk) {
            reject_stage();
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::sequence_gap, "snapshot chunk index is not contiguous"));
        }
        if (message.subjects.size() > limits_.maximum_collection_items ||
            message.subjects.size() > stage_->expected_count - stage_->subjects.size()) {
            reject_stage();
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::limit_exceeded, "snapshot chunk exceeds its declared count"));
        }

        std::unordered_set<std::string> existing(stage_->canonical_keys.begin(), stage_->canonical_keys.end());
        for (const auto &subject : message.subjects) {
            if (!subject.valid() || subject.peer != peer_ || subject.descriptor != subject_schema_ ||
                !has_expected_parent(subject)) {
                reject_stage();
                return std::unexpected(
                    snapshot_error(ProtocolErrorCode::invalid_identity, "snapshot subject is outside its scope"));
            }
            auto key = canonical_subject_key(subject);
            if (!existing.insert(key).second) {
                reject_stage();
                return std::unexpected(
                    snapshot_error(ProtocolErrorCode::duplicate_item, "snapshot subject identity is duplicated"));
            }
            if (key.size() > limits_.maximum_snapshot_bytes - stage_->canonical_bytes) {
                reject_stage();
                return std::unexpected(
                    snapshot_error(ProtocolErrorCode::limit_exceeded, "snapshot canonical bytes exceed the limit"));
            }
            stage_->canonical_bytes += key.size();
            stage_->canonical_keys.push_back(std::move(key));
            stage_->subjects.push_back(subject);
        }
        ++stage_->next_chunk;
        return {};
    }

    std::expected<SnapshotDelta, ProtocolError>
    AuthoritativeSnapshotAssembler::commit(const AuthoritativeSnapshotCommit &message) {
        if (auto valid = validate_session(message.session, message.peer, message.session_fence); !valid) {
            reject_stage();
            return std::unexpected(std::move(valid.error()));
        }
        if (!stage_.has_value() || message.snapshot_id != stage_->snapshot_id ||
            message.generation != stage_->generation) {
            reject_stage();
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::stale_generation, "snapshot commit does not match the stage"));
        }
        if (message.item_count != stage_->expected_count || message.item_count != stage_->subjects.size()) {
            reject_stage();
            return std::unexpected(snapshot_error(ProtocolErrorCode::malformed, "snapshot item count does not match"));
        }
        if (message.canonical_digest != stage_->expected_digest) {
            reject_stage();
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::digest_mismatch, "snapshot begin and commit digests differ"));
        }
        auto digest = authoritative_snapshot_digest(stage_->subjects, limits_);
        if (!digest || *digest != message.canonical_digest) {
            reject_stage();
            if (!digest) {
                return std::unexpected(std::move(digest.error()));
            }
            return std::unexpected(
                snapshot_error(ProtocolErrorCode::digest_mismatch, "snapshot content digest does not match"));
        }

        std::unordered_map<std::string, std::size_t> old_indexes;
        old_indexes.reserve(visible_.size());
        for (std::size_t index = 0; index < visible_.size(); ++index) {
            old_indexes.emplace(canonical_subject_key(visible_[index]), index);
        }
        std::unordered_map<std::string, std::size_t> new_indexes;
        new_indexes.reserve(stage_->subjects.size());
        for (std::size_t index = 0; index < stage_->subjects.size(); ++index) {
            new_indexes.emplace(canonical_subject_key(stage_->subjects[index]), index);
        }

        SnapshotDelta delta {
            .generation = stage_->generation,
            .canonical_digest = *digest,
            .added = {},
            .removed = {},
            .current = stage_->subjects,
        };
        for (const auto &[key, index] : new_indexes) {
            if (!old_indexes.contains(key)) {
                delta.added.push_back(stage_->subjects[index]);
            }
        }
        for (const auto &[key, index] : old_indexes) {
            if (!new_indexes.contains(key)) {
                delta.removed.push_back(visible_[index]);
            }
        }
        const auto by_key = [](const SubjectKey &left, const SubjectKey &right) {
            return canonical_subject_key(left) < canonical_subject_key(right);
        };
        std::ranges::sort(delta.added, by_key);
        std::ranges::sort(delta.removed, by_key);
        std::ranges::sort(delta.current, by_key);

        visible_ = delta.current;
        last_good_generation_ = delta.generation;
        stage_.reset();
        return delta;
    }

    void AuthoritativeSnapshotAssembler::abort() noexcept { stage_.reset(); }

    void AuthoritativeSnapshotAssembler::reject_stage() noexcept { stage_.reset(); }

} // namespace rule_engine::python::protocol_v2
