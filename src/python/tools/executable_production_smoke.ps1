[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PackExe,

    [Parameter(Mandatory = $true)]
    [string] $CheckExe,

    [Parameter(Mandatory = $true)]
    [string] $RuntimeRoot,

    [Parameter(Mandatory = $true)]
    [string] $SmokeRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Content
    )

    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Set-PrivateAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [switch] $Directory
    )

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $caller = '*' + $identity.User.Value
    if ($Directory) {
        $rules = @(
            "${caller}:(OI)(CI)F",
            '*S-1-5-18:(OI)(CI)F',
            '*S-1-5-32-544:(OI)(CI)F'
        )
    }
    else {
        $rules = @(
            "${caller}:F",
            '*S-1-5-18:F',
            '*S-1-5-32-544:F'
        )
    }

    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    $aclArguments = @($Path, '/inheritance:r', '/grant:r') + $rules
    $null = & $icacls @aclArguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to apply the private signing-key ACL'
    }
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Label,

        [Parameter(Mandatory = $true)]
        [string] $Executable,

        [Parameter(Mandatory = $true)]
        [string[]] $ToolArguments
    )

    $captured = & $Executable @ToolArguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit $LASTEXITCODE`n$captured"
    }
    return $captured
}

$failure = $null
try {
    if (Test-Path -LiteralPath $SmokeRoot) {
        Remove-Item -LiteralPath $SmokeRoot -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $SmokeRoot
    Set-PrivateAcl -Path $SmokeRoot -Directory

    $sourceRoot = Join-Path $SmokeRoot 'source'
    $moduleRoot = Join-Path $sourceRoot 'src\tooling'
    $workerRoot = Join-Path $SmokeRoot 'workers'
    $null = New-Item -ItemType Directory -Path $moduleRoot
    $null = New-Item -ItemType Directory -Path $workerRoot

    $manifest = @'
format = 1

[pack]
id = "com.example.tooling-production-smoke"
version = "1.0.0"
kind = "rules"
engine_api = 1
python = "3.14.6"
entry_modules = ["tooling.rules"]
budget_profile = "balanced.v1"
policy_profile = "production.v1"

[capabilities]
required = []
optional = []
'@
    $ruleSource = @'
@rule("com.example.tooling.production-constant")
def constant() -> bool:
    return True
'@
    Write-Utf8NoBom -Path (Join-Path $sourceRoot 'rulepack.toml') -Content (($manifest -replace "`r`n", "`n") + "`n")
    Write-Utf8NoBom -Path (Join-Path $moduleRoot 'rules.py') -Content (($ruleSource -replace "`r`n", "`n") + "`n")

    # RFC 8032 test vector 1. This public test fixture is not production key material.
    $seedHex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
    $seed = [byte[]]::new(32)
    for ($index = 0; $index -lt $seed.Length; ++$index) {
        $seed[$index] = [Convert]::ToByte($seedHex.Substring($index * 2, 2), 16)
    }
    $seedPath = Join-Path $SmokeRoot 'signing.seed'
    [System.IO.File]::WriteAllBytes($seedPath, $seed)
    [System.Array]::Clear($seed, 0, $seed.Length)
    $seedHex = $null
    Set-PrivateAcl -Path $seedPath

    $unsignedArchive = Join-Path $SmokeRoot 'unsigned.rpack'
    $signedArchive = Join-Path $SmokeRoot 'signed.rpack'
    $trustConfig = Join-Path $SmokeRoot 'trust.conf'
    $cryptoLibrary = Join-Path $RuntimeRoot 'libcrypto-3.dll'
    if (-not (Test-Path -LiteralPath $cryptoLibrary -PathType Leaf)) {
        throw 'the staged exact runtime has no explicit OpenSSL 3 library'
    }

    $publicKey = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    $keyId = 'sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9'
    $canonicalCryptoPath = $cryptoLibrary.Replace('\', '/')
    $trustText = "format=1`nmode=production`ncrypto_library=$canonicalCryptoPath`nsigner=$keyId|$publicKey|com.example.|active`n"
    Write-Utf8NoBom -Path $trustConfig -Content $trustText

    $buildOutput = Invoke-Tool -Label 'rule_engine_pack build' -Executable $PackExe -ToolArguments @(
        'build', '--source', $sourceRoot, '--output', $unsignedArchive,
        '--trust-mode', 'development', '--format=json'
    )
    if ($buildOutput -notmatch '"success":true') {
        throw 'rule_engine_pack build did not report canonical success'
    }

    $seedReference = 'file:' + $seedPath.Replace('\', '/')
    $signOutput = Invoke-Tool -Label 'rule_engine_pack sign' -Executable $PackExe -ToolArguments @(
        'sign', $unsignedArchive, '--output', $signedArchive,
        '--signer', $seedReference, '--key-id', $keyId,
        '--runtime-root', $RuntimeRoot, '--format=json'
    )
    if ($signOutput -notmatch '"success":true' -or
        $signOutput -notmatch [regex]::Escape($keyId) -or
        $signOutput -notmatch 'signature_status' -or
        $signOutput -match [regex]::Escape($seedPath) -or
        $signOutput -match [regex]::Escape($seedReference)) {
        throw 'rule_engine_pack sign did not return its redacted signing result'
    }

    $verifyOutput = Invoke-Tool -Label 'rule_engine_pack verify' -Executable $PackExe -ToolArguments @(
        'verify', $signedArchive, '--trust-config', $trustConfig,
        '--trust-mode', 'production', '--format=json'
    )
    if ($verifyOutput -notmatch '"success":true' -or $verifyOutput -notmatch 'production-signed') {
        throw 'the real production verifier did not accept the signed archive'
    }

    $checkOutput = Invoke-Tool -Label 'rule_engine_check' -Executable $CheckExe -ToolArguments @(
        '--pack', $signedArchive, '--runtime-root', $RuntimeRoot,
        '--temporary-root', $workerRoot, '--trust-config', $trustConfig,
        '--trust-mode', 'production', '--format=json', '--explain-plan'
    )
    if ($checkOutput -notmatch '"success":true' -or
        $checkOutput -notmatch 'semantic_hash' -or
        $checkOutput -notmatch 'com.example.tooling.production-constant') {
        throw 'rule_engine_check did not compile the production-verified archive'
    }
}
catch {
    $failure = $_.Exception.Message
}
finally {
    try {
        if (Test-Path -LiteralPath $SmokeRoot) {
            Remove-Item -LiteralPath $SmokeRoot -Recurse -Force
        }
        if (Test-Path -LiteralPath $SmokeRoot) {
            throw 'temporary signing material was not removed'
        }
    }
    catch {
        if ($null -eq $failure) {
            $failure = $_.Exception.Message
        }
        else {
            $failure += "`ntemporary signing-material cleanup also failed"
        }
    }
}

if ($null -ne $failure) {
    [Console]::Error.WriteLine($failure)
    exit 1
}

[Console]::Out.WriteLine('production build, sign, verify, and check smoke passed; temporary key material removed')
