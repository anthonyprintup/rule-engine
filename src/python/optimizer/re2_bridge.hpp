#pragma once

#include <stdint.h>

#define RULE_ENGINE_RE2_BRIDGE_ABI_VERSION UINT32_C(1)
#define RULE_ENGINE_RE2_BRIDGE_NO_PATTERN_OFFSET UINT64_MAX
#define RULE_ENGINE_RE2_BRIDGE_MAX_MEMORY_BYTES UINT64_C(8388608)

#define RULE_ENGINE_RE2_BRIDGE_STATUS_OK UINT32_C(0)
#define RULE_ENGINE_RE2_BRIDGE_STATUS_NO_MATCH UINT32_C(1)
#define RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_ARGUMENT UINT32_C(2)
#define RULE_ENGINE_RE2_BRIDGE_STATUS_INVALID_OPTIONS UINT32_C(3)
#define RULE_ENGINE_RE2_BRIDGE_STATUS_REGEX_SYNTAX UINT32_C(4)
#define RULE_ENGINE_RE2_BRIDGE_STATUS_RESOURCE_EXHAUSTED UINT32_C(5)

#define RULE_ENGINE_RE2_BRIDGE_ENCODING_UTF8 UINT8_C(1)
#define RULE_ENGINE_RE2_BRIDGE_ENCODING_LATIN1 UINT8_C(2)

#if defined(_WIN32)
#define RULE_ENGINE_RE2_BRIDGE_CALL __cdecl
#if defined(RULE_ENGINE_RE2_BRIDGE_BUILD)
#define RULE_ENGINE_RE2_BRIDGE_API __declspec(dllexport)
#elif defined(RULE_ENGINE_RE2_BRIDGE_STATIC)
#define RULE_ENGINE_RE2_BRIDGE_API
#else
#define RULE_ENGINE_RE2_BRIDGE_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define RULE_ENGINE_RE2_BRIDGE_CALL
#define RULE_ENGINE_RE2_BRIDGE_API __attribute__((visibility("default")))
#else
#define RULE_ENGINE_RE2_BRIDGE_CALL
#define RULE_ENGINE_RE2_BRIDGE_API
#endif

#if defined(__cplusplus)
#define RULE_ENGINE_RE2_BRIDGE_NOEXCEPT noexcept
extern "C" {
#else
#define RULE_ENGINE_RE2_BRIDGE_NOEXCEPT
#endif

    typedef uint32_t rule_engine_re2_bridge_status;

    // Fixed-layout options for ABI version 1. Every boolean byte must be 0 or 1,
    // and every reserved byte must be zero. `structure_size` must be initialized to
    // sizeof(rule_engine_re2_bridge_options). Compiled RE2 state is capped at
    // RULE_ENGINE_RE2_BRIDGE_MAX_MEMORY_BYTES per handle.
    typedef struct rule_engine_re2_bridge_options {
        uint32_t structure_size;
        uint32_t abi_version;
        uint8_t encoding;
        uint8_t case_sensitive;
        uint8_t dot_nl;
        uint8_t multiline;
        uint8_t reserved[4];
    } rule_engine_re2_bridge_options;

    // Caller-owned diagnostic storage. `message_capacity` includes room for the
    // trailing NUL. `message_size` reports the complete message size excluding the
    // NUL even when the buffer is truncated. `pattern_offset` is a byte offset or
    // RULE_ENGINE_RE2_BRIDGE_NO_PATTERN_OFFSET when RE2 cannot identify one.
    // The whole struct and its message buffer must not overlap any other argument.
    typedef struct rule_engine_re2_bridge_diagnostic {
        char *message_data;
        uint64_t message_capacity;
        uint64_t message_size;
        uint64_t pattern_offset;
        uint8_t message_truncated;
        uint8_t reserved[7];
    } rule_engine_re2_bridge_diagnostic;

    typedef struct rule_engine_re2_bridge_match {
        uint64_t offset;
        uint64_t length;
    } rule_engine_re2_bridge_match;

    // Opaque RE2 allocation. It is created and destroyed inside the bridge so
    // no C++ object or CRT-owned allocation crosses the DLL boundary.
    typedef struct rule_engine_re2_bridge_pattern rule_engine_re2_bridge_pattern;

    // Validates one exact byte span as an RE2 pattern. A null pattern pointer is
    // accepted only for a zero-length pattern. The optional diagnostic remains
    // caller-owned and is cleared on success.
    RULE_ENGINE_RE2_BRIDGE_API rule_engine_re2_bridge_status RULE_ENGINE_RE2_BRIDGE_CALL
    rule_engine_re2_bridge_validate_pattern(
        const uint8_t *pattern_data, uint64_t pattern_size, const rule_engine_re2_bridge_options *options,
        rule_engine_re2_bridge_diagnostic *diagnostic) RULE_ENGINE_RE2_BRIDGE_NOEXCEPT;

    RULE_ENGINE_RE2_BRIDGE_API rule_engine_re2_bridge_status RULE_ENGINE_RE2_BRIDGE_CALL
    rule_engine_re2_bridge_compile_pattern(
        const uint8_t *pattern_data, uint64_t pattern_size, const rule_engine_re2_bridge_options *options,
        rule_engine_re2_bridge_pattern **compiled_pattern,
        rule_engine_re2_bridge_diagnostic *diagnostic) RULE_ENGINE_RE2_BRIDGE_NOEXCEPT;

    RULE_ENGINE_RE2_BRIDGE_API void RULE_ENGINE_RE2_BRIDGE_CALL rule_engine_re2_bridge_destroy_pattern(
        rule_engine_re2_bridge_pattern *compiled_pattern) RULE_ENGINE_RE2_BRIDGE_NOEXCEPT;

    RULE_ENGINE_RE2_BRIDGE_API rule_engine_re2_bridge_status RULE_ENGINE_RE2_BRIDGE_CALL
    rule_engine_re2_bridge_find_next_compiled(
        const rule_engine_re2_bridge_pattern *compiled_pattern, const uint8_t *input_data, uint64_t input_size,
        uint64_t start_offset, rule_engine_re2_bridge_match *match,
        rule_engine_re2_bridge_diagnostic *diagnostic) RULE_ENGINE_RE2_BRIDGE_NOEXCEPT;

    // Convenience stateless form. Prefer compile/find_next_compiled/destroy for
    // repeated matching so compilation work is paid once.
    RULE_ENGINE_RE2_BRIDGE_API rule_engine_re2_bridge_status RULE_ENGINE_RE2_BRIDGE_CALL
    rule_engine_re2_bridge_find_next(const uint8_t *pattern_data, uint64_t pattern_size,
                                     const rule_engine_re2_bridge_options *options, const uint8_t *input_data,
                                     uint64_t input_size, uint64_t start_offset, rule_engine_re2_bridge_match *match,
                                     rule_engine_re2_bridge_diagnostic *diagnostic) RULE_ENGINE_RE2_BRIDGE_NOEXCEPT;

#if defined(__cplusplus)
} // extern "C"
#endif
