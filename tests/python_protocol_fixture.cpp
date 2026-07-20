#include "rule_engine/python/protocol.hpp"

#include <cstddef>
#include <fstream>
#include <span>
#include <string_view>
#include <vector>

namespace {
    using namespace rule_engine::python::protocol_v2;

    [[nodiscard]] bool read_file(const char *path, std::vector<std::byte> &bytes) {
        std::ifstream input {path, std::ios::binary | std::ios::ate};
        if (!input) {
            return false;
        }
        const auto size = input.tellg();
        if (size <= 0 || static_cast<std::uint64_t>(size) > ProtocolLimits {}.maximum_frame_bytes + 4) {
            return false;
        }
        bytes.resize(static_cast<std::size_t>(size));
        input.seekg(0);
        return static_cast<bool>(input.read(reinterpret_cast<char *>(bytes.data()), size));
    }

    [[nodiscard]] bool write_file(const char *path, const std::span<const std::byte> bytes) {
        std::ofstream output {path, std::ios::binary | std::ios::trunc};
        return output && static_cast<bool>(output.write(reinterpret_cast<const char *>(bytes.data()),
                                                        static_cast<std::streamsize>(bytes.size())));
    }
} // namespace

int main(const int argc, char **argv) {
    if (argc != 4 || std::string_view {argv[1]} != "roundtrip") {
        return 64;
    }
    std::vector<std::byte> input;
    if (!read_file(argv[2], input)) {
        return 65;
    }
    auto decoded = decode_frame(input);
    if (!decoded || decoded->bytes_consumed != input.size()) {
        return 66;
    }
    auto encoded = encode_frame(decoded->envelope);
    if (!encoded || !write_file(argv[3], *encoded)) {
        return 67;
    }
    return 0;
}
