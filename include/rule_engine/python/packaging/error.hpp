#pragma once

#include <optional>
#include <string>

namespace rule_engine::python::packaging {

    enum struct PackagingErrorCode {
        invalid_manifest,
        invalid_index,
        invalid_signature_envelope,
        invalid_path,
        path_collision,
        noncanonical_archive,
        archive_crc_mismatch,
        unsupported_entry,
        filesystem_error,
        crypto_backend_unavailable,
        size_limit,
        entry_missing,
        entry_unindexed,
        entry_size_mismatch,
        entry_digest_mismatch,
        dependency_mismatch,
        dependency_cycle,
        signature_required,
        signer_unknown,
        signer_revoked,
        signer_out_of_scope,
        signature_invalid,
        signing_key_reference_invalid,
        signing_key_unavailable,
        signing_key_permissions,
        signing_key_mismatch,
        signing_failed,
        runtime_missing,
        runtime_mismatch,
        runtime_staging_failed,
        worker_unauthorized,
        worker_frame_malformed,
        worker_frame_too_large,
        worker_protocol_mismatch,
        worker_response_mismatch,
        worker_crashed,
        worker_timed_out,
        worker_output_limit,
        worker_rejected,
        invalid_binding,
        duplicate_binding,
        generator_limit,
        generator_nondeterministic,
        generator_seed_reused,
    };

    struct PackagingError {
        PackagingErrorCode code {};
        std::string message;
        std::optional<std::string> subject;
    };

} // namespace rule_engine::python::packaging
