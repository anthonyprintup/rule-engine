param(
    [string]$PrivatePython
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path

if (-not $PrivatePython) {
    $candidates = @(
        (Join-Path $repoRoot "build/python-runtime/python-3.14.6/python.exe"),
        "C:/Users/User/.codex/worktrees/rule-engine-python/integration/build/python-runtime/python-3.14.6/python.exe"
    )
    $PrivatePython = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

if (-not $PrivatePython -or -not (Test-Path -LiteralPath $PrivatePython)) {
    throw "Exact private CPython 3.14.6 was not found; system Python fallback is forbidden"
}

$resolvedPython = (Resolve-Path -LiteralPath $PrivatePython).Path
& $resolvedPython -I -S -B (Join-Path $PSScriptRoot "validate_sdk.py")
if ($LASTEXITCODE -ne 0) {
    throw "SDK validation failed with exit code $LASTEXITCODE"
}
