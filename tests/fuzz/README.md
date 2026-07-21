# Optimizer scan-wire fuzzing

`python_optimizer_scan_fuzz.cpp` exercises the C++-owned scan boundary through a
single no-exception `LLVMFuzzerTestOneInput` entry point. It covers arbitrary
protocol-v2 frame decoding, canonical scan-plan decoding, RE2 compilation and
scanning, scan-result admission, and canonical request/result protocol
round-trips. Accepted values must re-encode and re-decode without changing their
canonical representation.

Uppercase `L`, `R`, or `M` select a literal, regex, or masked production-plan
payload without transformation. Lowercase selectors are reserved for curated
text corpus files and remove one final LF added by source-control tooling; the
remaining payload is still passed unchanged to the production decoder.

The harness preserves the provider trust boundary: `ProviderScanRequest`,
`ScanRequest`, and `ScanResponse` are compile-time checked to contain neither a
predicate nor a verdict. It requests and returns only typed scan facts; all
pattern semantics and match admission stay in C++.

## Bounds and abuse resistance

- The fuzzer rejects inputs larger than the production 1 MiB encoded-plan
  limit before parsing.
- Protocol frames and RE2 source use their production protocol and scan-wire
  ceilings.
- Scanner inputs are a fixed 15-byte source and never exceed the production
  16 MiB scan limit.
- Arbitrary result synthesis is additionally capped at 8 matches and 16 bytes
  per byte field, below the production result limits, to prevent the harness
  itself from amplifying allocations.
- The entry point is `noexcept`, contains no exception recovery, and links the
  same no-exception/no-RTTI project options as production code.

When `BUILD_TESTING=ON`, the normal Catch2 target compiles the same harness and
runs a deterministic mutation corpus. It starts from valid literal/regex plans
and a valid protocol work lease, then covers every truncation, low/high bit
flips, inflated counts and lengths, zero-length matches, invalid UTF-8,
malformed base64-like tokens, and invalid RE2 expressions. Base64 is not part
of the optimizer scan wire (which uses canonical ASCII `rsp1` framing); that
token is retained as a malformed-input seed for cross-boundary regressions
rather than claiming a base64 decoder exists here.

## Instrumented target

The standalone Clang libFuzzer + AddressSanitizer target is opt-in:

```powershell
cmake -S . -B build/fuzz-clang -G Ninja `
  -DCMAKE_C_COMPILER=clang-cl `
  -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_BUILD_TYPE=RelWithDebInfo `
  -DRULE_ENGINE_BUILD_FUZZERS=ON
cmake --build build/fuzz-clang --target rule_engine_python_scan_fuzzer
cmake -E copy_directory `
  tests/fuzz/corpus/python_optimizer_scan `
  build/fuzz-clang/run-corpus
build/fuzz-clang/rule_engine_python_scan_fuzzer.exe `
  -seed=195936478 -runs=4096 -max_len=65536 `
  build/fuzz-clang/run-corpus
```

Enabling `RULE_ENGINE_BUILD_FUZZERS` with a non-Clang compiler fails at configure
time. clang-cl uses `RelWithDebInfo` and a release static CRT because Windows
ASan does not support the Debug CRT and the installed libFuzzer runtime is built
for that release CRT. MSVC STL container annotations are disabled to match that
runtime's ABI; ordinary ASan compiler instrumentation remains enabled. The
contract, protocol, optimizer, and harness are ASan-instrumented;
the existing RE2 C-ABI DLL remains uninstrumented because its static-CRT
isolation is what prevents C++ and allocator ownership from crossing that DLL
boundary. The explicit clang-cl runtime lookup is x86-64-only, matching the
project's supported Windows architecture. The curated corpus contains only
small, reviewable source seeds;
canonical plans and protocol frames are generated through production encoders
by the normal regression test, and generated libFuzzer artifacts are not
required by that suite.

The checked-in corpus is copied to a build-local writable directory before the
fuzzer starts. CTest uses the same arrangement and never passes the source
directory to libFuzzer, so a smoke run cannot dirty the source tree.
