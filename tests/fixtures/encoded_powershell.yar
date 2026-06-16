import "process"

rule encoded_powershell {
    strings:
        $enc = "-enc" ascii
    condition:
        process.name == "powershell.exe" and $enc
}
