package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/artefactual-labs/decision-spoa/internal/geo"
	"github.com/artefactual-labs/decision-spoa/internal/policy"
	"github.com/artefactual-labs/decision-spoa/internal/spoe"
	"github.com/artefactual-labs/decision-spoa/internal/update"
	"github.com/artefactual-labs/decision-spoa/internal/xforwarded"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	version = "dev"
	commit  = "none"
	date    = ""
)

// Prometheus metrics
var (
	// NOTE: added "host" label. You can disable setting it via --metrics-host-label=false to reduce cardinality.
	decisionDecisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "decision_policy_decisions_total", Help: "Decisions by bucket and reason."},
		[]string{"backend", "host", "bucket", "reason"},
	)
	decisionRulesHitTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "decision_policy_rule_hits_total", Help: "Rule matches."},
		[]string{"backend", "host", "rule"},
	)
	decisionEvalSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "decision_policy_eval_seconds",
		Help:    "Policy evaluation time.",
		Buckets: prometheus.DefBuckets,
	})
	decisionGeoLookups = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "decision_policy_geo_lookups_total", Help: "Geo lookups."},
		[]string{"outcome"},
	)
	decisionCountryHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "decision_policy_country_hits_total", Help: "Country counters."},
		[]string{"country"},
	)
	decisionAsnHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "decision_policy_asn_hits_total", Help: "ASN counters."},
		[]string{"asn"},
	)
	decisionXffTrustedStripsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "decision_policy_xff_trusted_strips_total", Help: "Number of XFF hops stripped via trusted proxy lists."},
		[]string{"backend", "host"},
	)
)

type promRuleCounter struct {
	*prometheus.CounterVec
}

func (p promRuleCounter) Inc(backend, host, rule string) {
	p.WithLabelValues(backend, host, rule).Inc()
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type serverState struct {
	sync.RWMutex
	cfg policy.Config
	gdb *geo.DB
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Flags
	listen := flag.String("listen", getenv("DECISION_LISTEN", "127.0.0.1:9107"), "SPOA listen address")
	metricsAddr := flag.String("metrics", getenv("DECISION_METRICS", "127.0.0.1:9907"), "Prometheus metrics listen address")
	rootDir := flag.String("root", getenv("DECISION_ROOT", "/etc/decision-policy"), "Config root directory")
	debug := flag.Bool("debug", getenv("DECISION_DEBUG", "") != "", "Debug logging")
	checkConfig := flag.Bool("check-config", false, "Validate configuration and exit")

	// Host label toggle (avoid high cardinality in Grafana)
	metricsHostLabel := flag.Bool("metrics-host-label", getenv("DECISION_METRICS_HOST_LABEL", "") != "", "Include 'host' label in Prom metrics")

	// Geo & updater flags
	cityDB := flag.String("city-db", getenv("GEOIP_CITY_DB", "/var/lib/GeoIP/GeoLite2-City.mmdb"), "City .mmdb path")
	asnDB := flag.String("asn-db", getenv("GEOIP_ASN_DB", "/var/lib/GeoIP/GeoLite2-ASN.mmdb"), "ASN .mmdb path")
	cityURL := flag.String("city-url", getenv("GEOIP_CITY_URL", ""), "City DB URL (.mmdb or .tar.gz)")
	asnURL := flag.String("asn-url", getenv("GEOIP_ASN_URL", ""), "ASN DB URL (.mmdb or .tar.gz)")
	bestEffort := flag.Bool("best-effort", true, "Do not fail if DB download unavailable or unchanged")

	flag.Parse()

	log.Printf("decision-spoa starting (version=%s commit=%s date=%s)", version, commit, date)

	if *checkConfig {
		loader := policy.Loader{Root: *rootDir}
		cfg, err := loader.LoadAll()
		if err != nil {
			log.Fatalf("check-config: %v", err)
		}
		if err := cfg.Validate(); err != nil {
			log.Fatalf("check-config validation: %v", err)
		}
		log.Printf("configuration OK (%d rule(s), fallback reason=%q)", len(cfg.Rules), cfg.Fallback.Reason)
		return
	}

	// prometheus
	prometheus.MustRegister(
		decisionDecisionsTotal,
		decisionRulesHitTotal,
		decisionEvalSeconds,
		decisionGeoLookups,
		decisionCountryHits,
		decisionAsnHits,
		decisionXffTrustedStripsTotal,
	)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Printf("metrics on %s/metrics", *metricsAddr)
		if err := http.ListenAndServe(*metricsAddr, mux); err != nil {
			log.Fatalf("metrics http: %v", err)
		}
	}()

	// Updater at boot
	if *cityURL != "" || *asnURL != "" {
		if err := update.Run(update.Options{
			CountryURL: *cityURL,
			ASNURL:     *asnURL,
			CountryOut: *cityDB,
			ASNOut:     *asnDB,
			BestEffort: *bestEffort,
		}); err != nil && !*bestEffort {
			log.Fatalf("update error: %v", err)
		}
	}

	state := &serverState{}

	// Geo open
	if db, err := geo.Open(*cityDB, *asnDB); err != nil {
		log.Printf("open geo db: %v (daemon continues; lookups empty until DBs exist)", err)
	} else {
		state.Lock()
		state.gdb = db
		state.Unlock()
		log.Printf("using City DB: %s", *cityDB)
		log.Printf("using ASN  DB: %s", *asnDB)
	}

	defer func() {
		state.Lock()
		if state.gdb != nil {
			state.gdb.Close()
		}
		state.Unlock()
	}()

	// Config loader
	loader := policy.Loader{Root: *rootDir}
	loadedCfg, err := loader.LoadAll()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	loadedCfg.Debug = *debug
	state.Lock()
	state.cfg = loadedCfg
	state.Unlock()

	// SIGHUP reload
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Printf("SIGHUP: reloading configs + geo DB")

			var newDB *geo.DB
			if db, err := geo.Open(*cityDB, *asnDB); err != nil {
				log.Printf("reload geo: %v", err)
			} else {
				newDB = db
			}

			if newCfg, err := loader.LoadAll(); err != nil {
				log.Printf("reload config: %v", err)
				if newDB != nil {
					newDB.Close()
					newDB = nil
				}
			} else {
				newCfg.Debug = *debug
				state.Lock()
				oldDB := state.gdb
				if newDB != nil {
					state.gdb = newDB
				}
				state.cfg = newCfg
				state.Unlock()
				if newDB != nil && oldDB != nil && oldDB != newDB {
					oldDB.Close()
				}
			}

			if newDB != nil {
				log.Printf("SIGHUP: geo DB swapped")
			}
			log.Printf("SIGHUP: reload done")
		}
	}()

	// SPOE server
	s := &spoe.Server{
		Addr:   *listen,
		Logger: log.Default(),
		Handler: func(args map[string]string) (map[string]interface{}, error) {
			start := time.Now()

			state.RLock()
			cfgSnapshot := state.cfg
			gdbSnapshot := state.gdb
			state.RUnlock()

			src := args["src"]
			xff := args["xff"]
			ua := args["ua"]
			host := strings.ToLower(strings.TrimSpace(args["host"]))
			path := args["path"]
			method := args["method"]
			query := args["query"]
			sni := strings.ToLower(strings.TrimSpace(args["ssl_sni"]))
			ja3 := args["ja3"]
			backend := args["backend"]
			frontend := args["frontend"]
			protocol := strings.ToLower(strings.TrimSpace(args["protocol"]))
			if protocol == "" {
				protocol = "http"
			}

			// Normalize backend for metrics/rules context
			normBE := backend
			if normBE == "" || normBE == "default" {
				if frontend != "" {
					normBE = frontend
				} else {
					normBE = "frontend"
				}
			}

			trusted := cfgSnapshot.TrustedFor(backend, frontend)
			ip, strippedHops := xforwarded.FromXFF(src, xff, trusted)

			var asn uint
			var country string
			if ip != nil && gdbSnapshot != nil {
				if res, err := gdbSnapshot.Lookup(ip); err == nil {
					asn = res.ASN
					country = res.CountryISO
					decisionGeoLookups.WithLabelValues("ok").Inc()
					if country != "" {
						decisionCountryHits.WithLabelValues(country).Inc()
					}
					if asn != 0 {
						labelASN := fmt.Sprintf("%d", asn)
						decisionAsnHits.WithLabelValues(labelASN).Inc()
					}
				} else {
					decisionGeoLookups.WithLabelValues("error").Inc()
				}
			} else {
				decisionGeoLookups.WithLabelValues("no_db").Inc()
			}

			// Evaluate rules (engine will apply defaults precedence backend > frontend > global)
			out := cfgSnapshot.Evaluate(policy.Input{
				Backend:      backend,
				BackendLabel: normBE,
				Frontend:     frontend,
				Protocol:     protocol,
				XFF:          xff,
				Method:       method,
				Query:        query,
				SNI:          sni,
				JA3:          ja3,
				IP:           ip,
				ASN:          asn,
				Country:      country,
				UA:           ua,
				Host:         host,
				Path:         path,
			}, promRuleCounter{CounterVec: decisionRulesHitTotal}, *metricsHostLabel)

			elapsed := time.Since(start).Seconds()
			decisionEvalSeconds.Observe(elapsed)
			labelHost := ""
			if *metricsHostLabel {
				labelHost = host
			}
			if strippedHops > 0 {
				value := float64(strippedHops)
				decisionXffTrustedStripsTotal.WithLabelValues(normBE, labelHost).Add(value)
			}
			bucketLabel := labelValue(out.Vars["policy.bucket"])
			decisionDecisionsTotal.WithLabelValues(normBE, labelHost, bucketLabel, out.Reason).Inc()

			resp := make(map[string]interface{}, len(out.Vars)+1)
			for k, v := range out.Vars {
				resp[k] = normalizeValue(v)
			}
			if _, ok := resp["reason"]; !ok {
				if out.Reason != "" {
					resp["reason"] = out.Reason
				}
			}
			if cfgSnapshot.Debug {
				log.Printf("policy: fe=%s be=%s ip=%v xff_stripped=%d asn=%d c=%s method=%s host=%s path=%s query=%q sni=%s ja3=%s ua=%q vars=%v",
					frontend, normBE, ip, strippedHops, asn, country, strings.ToUpper(method), host, path, query, sni, ja3, ua, resp)
			}
			return resp, nil
		},
	}

	log.Printf("SPOA listening on %s (debug=%v)", *listen, *debug)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func labelValue(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "unset"
	case string:
		if t == "" {
			return "unset"
		}
		return t
	case fmt.Stringer:
		s := t.String()
		if s == "" {
			return "unset"
		}
		return s
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int, int8, int16, int32, int64:
		if fmt.Sprint(t) == "0" {
			return "false"
		}
		if fmt.Sprint(t) == "1" {
			return "true"
		}
	case uint, uint8, uint16, uint32, uint64:
		if fmt.Sprint(t) == "0" {
			return "false"
		}
		if fmt.Sprint(t) == "1" {
			return "true"
		}
	case float32, float64:
		if fmt.Sprint(t) == "0" || fmt.Sprint(t) == "0.0" {
			return "false"
		}
		if fmt.Sprint(t) == "1" || fmt.Sprint(t) == "1.0" {
			return "true"
		}
	}
	return fmt.Sprint(v)
}

func normalizeValue(v interface{}) interface{} {
	switch t := v.(type) {
	case bool:
		if t {
			return "true"
		}
		return "false"
	case fmt.Stringer:
		return t.String()
	case string, int, int64, uint, uint64, float32, float64:
		return v
	default:
		return v
	}
}
