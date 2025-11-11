package main

import (
    "flag"
    "fmt"
    "log"
    "os"

    "github.com/artefactual-labs/decision-spoa/internal/contextcfg"
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

    // Context check (context.yml is optional; loader returns defaults if missing)
    ctxLoader := contextcfg.Loader{Root: *root}
    ctx, err := ctxLoader.Load()
    if err != nil {
        log.Fatalf("context-check: %v", err)
    }

    fmt.Printf("Policy OK. Loaded %d rule(s); fallback reason=%q\n", len(cfg.Rules), cfg.Fallback.Reason)
    // Small context summary
    fmt.Printf("Context OK. headers=%d cookies=%d hash_mode=%s secret_present=%t\n",
        len(ctx.Response.Headers), len(ctx.Response.Cookies), string(ctx.Hash.Mode), len(ctx.Hash.Secret) > 0)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
