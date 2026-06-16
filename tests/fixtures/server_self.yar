import "process"
import "pe"

rule current_server_process {
    condition:
        process.name == "rule_engine_server.exe" and pe.number_of_sections > 0
}
