import "process"
import "pe"

rule supported_process_pe {
    strings:
        $mz = "MZ" ascii
    condition:
        process.pid > 0 and
        process.name iequals "cmd.exe" and
        pe.number_of_sections >= 0 and
        for any section in pe.sections : (section["name"] contains ".text") and
        for any of ($mz) : (# >= 0)
}
