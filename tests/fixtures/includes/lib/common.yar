import "process"

rule powershell_process {
    condition:
        process.name == "powershell.exe"
}
