import "process"

rule included_bad_field {
    condition:
        process.no_such_field == "x"
}
