package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/artefactual-labs/decision-spoa/internal/policy"
)

func main() {
	root := flag.String("root", getenv("DECISION_ROOT", "/etc/decision-policy"), "Config root directory")
	flag.Parse()

	loader := policy.Loader{Root: *root}
	cfg, err := loader.LoadAll()
	if err != nil {
		log.Fatalf("config-check: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("config validation: %v", err)
	}

	fmt.Printf("Config OK. Loaded %d rule(s); fallback reason=%q\n", len(cfg.Rules), cfg.Fallback.Reason)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
