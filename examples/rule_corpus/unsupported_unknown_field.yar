import "process"

rule unsupported_unknown_field {
    condition:
        process.no_such_field == "value"
}
