import "demo"

rule configured_custom_module_function {
    condition:
        demo.score(42, "alpha") > 7
}
