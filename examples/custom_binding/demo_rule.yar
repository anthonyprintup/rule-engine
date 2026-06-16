import "demo"

rule custom_demo_process_score {
    condition:
        scan_mode == "process" and
        demo.weight >= 2 and
        demo.score(42, "alpha") > 7
}
