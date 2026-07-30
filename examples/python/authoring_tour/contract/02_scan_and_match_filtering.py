"""CONTRACT EXAMPLE: pattern declaration and scan lowering are not complete."""

from rule_engine import ScanSpace, pattern, rule


MZ_HEADER = pattern.bytes(
    b"MZ",
    id="com.example.pattern.mz-header",
)
POWERSHELL_UTF16 = pattern.text(
    "powershell",
    encoding="utf-16-le",
    case="ascii_insensitive",
    id="com.example.pattern.powershell-utf16",
)
INJECTOR_PROLOGUE = pattern.masked(
    "48 8B ?? ?5 A? ??",
    id="com.example.pattern.injector-prologue",
)
DOWNLOAD_URL = pattern.regex(
    r"https?://[^\s]+",
    dialect="re2",
    encoding="utf-8",
    id="com.example.pattern.download-url",
)


@rule("com.example.scan.executable-powershell")
def executable_powershell(memory: ScanSpace) -> bool:
    matches = memory.scan(
        [MZ_HEADER, POWERSHELL_UTF16, INJECTOR_PROLOGUE, DOWNLOAD_URL],
        before=8,
        after=16,
        maximum_matches=64,
    )

    for match in matches:
        if match.pattern_id != POWERSHELL_UTF16.id:
            continue
        if "execute" not in match.permissions:
            continue
        if match.length < 10:
            continue
        return True

    return False
