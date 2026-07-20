param(
    [string]$PrivatePython
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path

if (-not $PrivatePython) {
    $PrivatePython = Join-Path $repoRoot "build/python-runtime/python-3.14.6/python.exe"
}

if (-not $PrivatePython -or -not (Test-Path -LiteralPath $PrivatePython)) {
    throw "Exact private CPython 3.14.6 was not found; system Python fallback is forbidden"
}

$resolvedPython = (Resolve-Path -LiteralPath $PrivatePython).Path
& $resolvedPython -I -S -B (Join-Path $PSScriptRoot "validate_sdk.py")
if ($LASTEXITCODE -ne 0) {
    throw "SDK validation failed with exit code $LASTEXITCODE"
}
