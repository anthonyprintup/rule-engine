# Clean install package

`RuleEngineInstall.cmake` defines the install/export surface for the Python
engine. The integration-owned root build includes this module after all desired
library and executable targets have been declared. Target discovery is
conditional, so a partially assembled build exports only targets that exist.

## Installed layout

```text
bin/                                      optional Python-engine executables
include/rule_engine/python/               Python-engine C++ public headers only
lib/                                      C++ libraries and import libraries
lib/cmake/rule_engine/                    relocatable config, version, targets
libexec/rule_engine/python/               one-request worker script
libexec/rule_engine/python/runtime/3.14.6/ optional exact private runtime
share/rule_engine/python-sdk/<version>/    PEP 561 author/generator packages
share/rule_engine/docs/python-engine/      architecture, ADRs, limitations
share/rule_engine/examples/python/         Python pack examples
share/rule_engine/package/                 package notes and runtime pin manifest
```

The install rules select explicit source directories. They do not copy a source
or build tree wholesale, and therefore do not package private keys, Git data,
Cargo/Rust artifacts, caches, `__pycache__`, bytecode, or unrelated build output.
The current CLI target names are `rule_engine_python_pack_cli`,
`rule_engine_python_check_cli`, and `rule_engine_python_admin_cli`; their public
installed names come from `OUTPUT_NAME`. The module also recognizes the
Python-owned server, agent, and benchmark targets when those integration lanes
are present. It never selects similarly named legacy targets.

Executables and shared libraries contribute to a CMake runtime-dependency set.
The install step recursively copies their non-system runtime libraries beside
the appropriate installed artifacts. Platform runtime libraries under Windows
System32, `/lib`, and `/usr/lib` remain owned by the host operating system.
All package rules use the dedicated `rule_engine` install component, so the
package target does not accidentally execute install rules contributed by
FetchContent dependencies.

Standalone Asio is a private header-only compile dependency of the static
protocol library. CMake would ordinarily serialize its build-tree-only alias as
`$<LINK_ONLY:asio::asio>`. The install module flattens that one private seam to
Asio's link-only requirements (`ws2_32` on Windows). This is safe because no Asio
type appears in a public header, and it keeps the installed graph offline and
independent of the FetchContent tree. The module fails closed if Asio ceases to
be header-only or gains link directories/options that cannot be flattened.

Downstream CMake consumers use:

```cmake
find_package(rule_engine 1 CONFIG REQUIRED COMPONENTS python_contract)
target_link_libraries(app PRIVATE rule_engine::python_contract)
```

The config also exposes relocatable `rule_engine_PYTHON_SDK_DIR`,
`rule_engine_PYTHON_WORKER`, `rule_engine_DOCUMENTATION_DIR`, and
`rule_engine_EXAMPLES_DIR` paths.

## Private CPython bundle

Private-runtime bundling is deliberately opt-in:

```text
-DRULE_ENGINE_INSTALL_PRIVATE_PYTHON=ON
-DRULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT=<staged-runtime-root>
-DRULE_ENGINE_PRIVATE_PYTHON_STAGE_TARGET=<optional-packaging-target>
```

The root must be the output of the packaging runtime staging contract, not an
extracted archive and never a system Python installation. It must contain the
canonical installation manifest, exact CPython 3.14.6 files, and the matching
worker script. Configure-time and install-time checks compare every file's size
and SHA-256, reject symlinks and extra entries, and fail closed on absence or
tampering. When a staging target is named and exists, the package-validation and
package-install targets depend on it. The packaging lane's
`rule_engine_stage_python_runtime` target is discovered first; compatibility
candidates are `rule_engine_stage_private_python_runtime`,
`rule_engine_python_runtime_stage`, and `rule_engine_python_runtime_bundle`.
Such a target may publish its root through the
`RULE_ENGINE_PRIVATE_PYTHON_RUNTIME_ROOT` or
`RULE_ENGINE_STAGED_RUNTIME_ROOT` target property. The packaging cache
`RULE_ENGINE_PYTHON_RUNTIME_STAGE_DIR` is the final explicit fallback. There is
no search of PATH, the registry, or a system Python installation.

With runtime bundling disabled, no Python executable or system Python path is
placed in the package. The worker script and PEP 561 SDK remain installable
source artifacts, but worker execution requires an independently staged exact
runtime.

## Verification

`RuleEngineInstallSmoke.cmake` is the focused packaging fixture. It configures a
minimal producer, installs it into a
fresh scoped prefix, relocates the prefix, checks the expected/forbidden package
inventory, runs each public CLI with `--version`, configures a downstream
`find_package` consumer, and builds it. That path removes Cargo and Rust from
PATH before configure and uses neither the repository's legacy targets nor
Cargo/Rust.

`RuleEngineRealInstallSmoke.cmake` is the release gate registered as
`rule_engine_install_smoke`. It configures the repository itself with tests off
and FetchContent fully disconnected. The parent configure passes only its
already-populated Asio, Abseil, and RE2 source directories into that fresh
producer. Both registration and execution validate dependency-specific marker
files, and no download or update fallback is allowed. The producer, relocated
prefix, and consumer use a unique short directory directly under the system
temporary directory; the harness validates that exact directory before safely
removing it on either success or failure. The gate builds and installs the real
exported target graph, relocates the prefix, runs every discovered public
executable with `--version`, and builds/runs a `python_protocol` downstream
consumer solely from the installed prefix plus normal platform dependencies.
The focused fixture is registered separately as
`rule_engine_install_fixture_smoke`.

When registered by the integration build, run:

```text
ctest --test-dir <build> -R rule_engine_install_smoke --output-on-failure
```

The standalone script accepts the source root, a disposable binary root,
generator, make program, and C/C++ compiler paths through `-D` arguments.

`tests/install/real-project/InstallHook.cmake` is the no-root-edit integration
probe. Pass it as `CMAKE_PROJECT_INCLUDE` when configuring the repository. It
defers this install module until the complete real target graph exists, so CMake
generation validates the actual export set and generated dependency decisions.
Building `rule_engine_install_package` then installs that real graph. All current
probe, packaging, and downstream-consumer paths run without Cargo or Rust.

## Known limitations

- The pinned runtime manifest currently describes the official Windows x64
  embeddable CPython artifact. A Linux relocatable runtime needs its separately
  pinned staging manifest before Linux runtime bundling can be enabled.
- The module does not download or construct CPython. Packaging staging owns that
  operation; install consumes only a validated staged root.
- Optional private static-library dependencies detected in exported link
  interfaces are resolved with `find_dependency`. A downstream using those
  components must provide the corresponding development package.
- On Linux the RE2 bridge is currently static, so its exported `LINK_ONLY`
  closure intentionally requires a discoverable `re2` CMake package. The
  real-graph smoke is the release gate for that dependency; a Linux package
  without `re2Config.cmake` fails instead of silently using a build-tree copy.
- Per-template generator binding modules are produced by pack compilation; the
  installed SDK contains the versioned base package and empty binding seam.
- Executables are installed only after their Python-engine targets exist. The
  module intentionally never falls back to similarly named legacy executables.
