package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/artefactual-labs/decision-spoa/internal/contextcfg"
	"github.com/artefactual-labs/decision-spoa/internal/geo"
	"github.com/artefactual-labs/decision-spoa/internal/policy"
	"github.com/artefactual-labs/decision-spoa/internal/session"
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
		[]string{"component_type", "component", "host", "bucket", "reason"},
	)
	decisionRulesHitTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "decision_policy_rule_hits_total", Help: "Rule matches."},
		[]string{"component_type", "component", "host", "rule"},
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
		[]string{"component_type", "component", "host"},
	)
	decisionTrustHintTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "decision_trust_hint_total", Help: "Count of trust hints recorded by Decision."},
		[]string{"hint"},
	)
	decisionSessionPublicEntries = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "decision_session_public_entries", Help: "Number of public session records currently in memory."},
	)
	decisionSessionSpecialEntries = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "decision_session_special_entries", Help: "Number of special session records currently in memory."},
	)
	decisionSessionPublicEvictionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "decision_session_public_evictions_total", Help: "LRU evictions from the public session table."},
	)
	decisionSessionSpecialEvictionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "decision_session_special_evictions_total", Help: "LRU evictions from the special session table."},
	)
	decisionChallengeLevelASNTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "decision_challenge_level_asn_total", Help: "Observed challenge levels per ASN."},
		[]string{"asn", "level"},
	)
	decisionCookieAgeSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{Name: "decision_cookie_age_seconds", Help: "Observed hb_v3 cookie ages reported by Cookie Guard.", Buckets: prometheus.DefBuckets},
	)
	decisionSessionKeySourceTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "decision_session_key_source_total", Help: "Count of session key sources used (ua_ip, hb_v2, hb_v3, cookieguard_session)."},
		[]string{"source"},
	)
)

type promRuleCounter struct {
	*prometheus.CounterVec
}

func (p promRuleCounter) Inc(componentType, component, host, rule string) {
	p.WithLabelValues(componentType, component, host, rule).Inc()
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
	}
	return def
}

func getenvDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			return parsed
		}
	}
	return def
}

type serverState struct {
	sync.RWMutex
	cfg   policy.Config
	ctx   contextcfg.Config
	gdb   *geo.DB
	trust *trustRuntime
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Flags
	listen := flag.String("listen", getenv("DECISION_LISTEN", "127.0.0.1:9107"), "SPOA listen address")
	metricsAddr := flag.String("metrics", getenv("DECISION_METRICS", "127.0.0.1:9907"), "Prometheus metrics listen address")
	rootDir := flag.String("root", getenv("DECISION_ROOT", "/etc/decision-policy"), "Config root directory")
	debug := flag.Bool("debug", getenv("DECISION_DEBUG", "") != "", "Debug logging")
	debugVerbose := flag.Bool("debug-verbose", getenv("DECISION_DEBUG_VERBOSE", "") != "", "Extra verbose per-request debug (raw inputs, snapshots, vars)")
	checkConfig := flag.Bool("check-config", false, "Validate configuration and exit")
	sessionPublicMax := flag.Int("session-public-max", getenvInt("DECISION_SESSION_PUBLIC_MAX", 200000), "Max entries in the public session table")
	sessionPublicWindow := flag.Duration("session-public-window", getenvDuration("DECISION_SESSION_PUBLIC_WINDOW", time.Minute), "Rolling window for public session rate calculations")
	sessionSpecialMax := flag.Int("session-special-max", getenvInt("DECISION_SESSION_SPECIAL_MAX", 50000), "Max entries in the special session table")

	// Host label toggle (avoid high cardinality in Grafana)
	metricsHostLabel := flag.Bool("metrics-host-label", getenv("DECISION_METRICS_HOST_LABEL", "") != "", "Include 'host' label in Prom metrics")
	metricsGeoip := flag.Bool("metrics-geoip", getenv("DECISION_METRICS_GEOIP", "") != "", "Include GeoIP metrics (country/ASN)")
	metricsChallengeASN := flag.Bool("metrics-challenge-level", getenv("DECISION_METRICS_CHALLENGE_LEVEL", "") != "", "Emit challenge level per ASN diagnostic metric")

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
	collectors := []prometheus.Collector{
		decisionDecisionsTotal,
		decisionRulesHitTotal,
		decisionEvalSeconds,
		decisionXffTrustedStripsTotal,
		decisionTrustHintTotal,
		decisionSessionPublicEntries,
		decisionSessionSpecialEntries,
		decisionSessionPublicEvictionsTotal,
		decisionSessionSpecialEvictionsTotal,
		decisionCookieAgeSeconds,
		decisionSessionKeySourceTotal,
	}
	if *metricsGeoip {
		collectors = append(collectors,
			decisionGeoLookups,
			decisionCountryHits,
			decisionAsnHits,
		)
	}
	prometheus.MustRegister(collectors...)
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
	if *metricsChallengeASN {
		collectors = append(collectors, decisionChallengeLevelASNTotal)
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
	ctxLoader := contextcfg.Loader{Root: *rootDir}
	contextCfg, err := ctxLoader.Load()
	if err != nil {
		log.Fatalf("load context: %v", err)
	}

	publicTable := session.NewPublicTable(*sessionPublicMax, *sessionPublicWindow)
	specialTable := session.NewSpecialTable(*sessionSpecialMax)
	trust := newTrustRuntime(publicTable, specialTable)
	if err := trust.ConfigureHash(contextCfg.Hash); err != nil {
		log.Fatalf("config hash: %v", err)
	}

	state.Lock()
	state.cfg = loadedCfg
	state.ctx = contextCfg
	state.trust = trust
	state.Unlock()

	startSessionMetricsCollector(trust)

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

			if newCtx, err := ctxLoader.Load(); err != nil {
				log.Printf("reload context: %v", err)
			} else {
				if err := trust.ConfigureHash(newCtx.Hash); err != nil {
					log.Printf("reload context hash: %v", err)
				} else {
					state.Lock()
					state.ctx = newCtx
					state.Unlock()
					log.Printf("context.yml reloaded")
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
		Handler: func(args map[string]string, raw map[string]string) (map[string]interface{}, error) {
			state.RLock()
			cfgSnapshot := state.cfg
			ctxSnapshot := state.ctx
			gdbSnapshot := state.gdb
			trustSnapshot := state.trust
			state.RUnlock()

			msgName := strings.ToLower(raw["spoe.message"])
			if isResponseMessage(msgName) {
				handleResponseMessage(raw, ctxSnapshot, trustSnapshot)
				return nil, nil
			}

			return handleRequestMessage(args, raw, cfgSnapshot, ctxSnapshot, trustSnapshot, gdbSnapshot, *metricsHostLabel, *metricsGeoip, *metricsChallengeASN, *debugVerbose)
		},
	}

	log.Printf("SPOA listening on %s (debug=%v)", *listen, *debug)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func startSessionMetricsCollector(trust *trustRuntime) {
	if trust == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		var lastPublicEvict uint64
		var lastSpecialEvict uint64
		for range ticker.C {
			decisionSessionPublicEntries.Set(float64(trust.public.Len()))
			decisionSessionSpecialEntries.Set(float64(trust.special.Len()))

			publicEvictions := trust.public.Evictions()
			if publicEvictions > lastPublicEvict {
				decisionSessionPublicEvictionsTotal.Add(float64(publicEvictions - lastPublicEvict))
				lastPublicEvict = publicEvictions
			}

			specialEvictions := trust.special.Evictions()
			if specialEvictions > lastSpecialEvict {
				decisionSessionSpecialEvictionsTotal.Add(float64(specialEvictions - lastSpecialEvict))
				lastSpecialEvict = specialEvictions
			}
		}
	}()
}

func handleRequestMessage(args map[string]string, raw map[string]string, cfg policy.Config, ctx contextcfg.Config, trust *trustRuntime, gdbSnapshot *geo.DB, metricsHostLabel, metricsGeoip, metricsChallengeASN bool, debugVerbose bool) (map[string]interface{}, error) {
	start := time.Now()

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

	componentType := "backend"
	componentName := backend
	if componentName == "" || componentName == "default" {
		componentType = "frontend"
		if frontend != "" {
			componentName = frontend
		} else {
			componentName = "frontend"
		}
	}
	componentLabel := labelValue(componentName)

	trusted := cfg.TrustedFor(backend, frontend)
	ip, strippedHops := xforwarded.FromXFF(src, xff, trusted)
	srcTrim := strings.TrimSpace(src)
	xffUsed := false
	if xff != "" && ip != nil {
		if srcTrim == "" || ip.String() != srcTrim {
			xffUsed = true
		}
	}
	_ = trusted.Has(srcTrim) // value not used in concise logs

	var asn uint
	var country string
	if ip != nil && gdbSnapshot != nil {
		if res, err := gdbSnapshot.Lookup(ip); err == nil {
			asn = res.ASN
			country = res.CountryISO
			if metricsGeoip {
				decisionGeoLookups.WithLabelValues("ok").Inc()
			}
			if metricsGeoip && country != "" {
				decisionCountryHits.WithLabelValues(country).Inc()
			}
			if metricsGeoip && asn != 0 {
				labelASN := fmt.Sprintf("%d", asn)
				decisionAsnHits.WithLabelValues(labelASN).Inc()
			}
		} else {
			if metricsGeoip {
				decisionGeoLookups.WithLabelValues("error").Inc()
			}
		}
	} else if metricsGeoip {
		decisionGeoLookups.WithLabelValues("no_db").Inc()
	}

	now := time.Now()
	cookieHeader := args["req_cookies"]
	cookies := parseCookieHeader(cookieHeader)
	cookieGuardValid := parseBool(args["cookieguard_valid"])
	cookieAgeSeconds := parseFloat(args["cookieguard_age"])
	if cookieAgeSeconds > 0 {
		decisionCookieAgeSeconds.Observe(cookieAgeSeconds)
	}
	challengeLevel := strings.ToLower(strings.TrimSpace(args["cookieguard_level"]))
	cookieSession := args["cookieguard_session"]

	var publicSnapshot session.PublicSnapshot
	var publicRate float64
	var publicIdle float64
	var publicKey string
	keySource := "ua_ip"
	firstPathDeep := false
	if trust != nil {
		// Prefer an explicit session HMAC if provided by a token verifier, then
		// fall back to the raw cookie tokens we know about. We include hb_v2 here
		// to support cookie-guard-spoa deployments without requiring a second
		// Decision pass after verification.
		if cookieSession != "" {
			keySource = "cookieguard_session"
		} else if cookies["hb_v3"] != "" {
			keySource = "hb_v3"
		} else if cookies["hb_v2"] != "" {
			keySource = "hb_v2"
		}
		baseToken := firstNonEmpty(cookieSession, cookies["hb_v3"], cookies["hb_v2"]) // may be empty → UA+IP
		publicKey = trust.publicSessionKey(baseToken, ip, ua)
		if publicKey != "" {
			decisionSessionKeySourceTotal.WithLabelValues(keySource).Inc()
			publicSnapshot = trust.public.Record(publicKey, path, now)
			if publicSnapshot.RecentWindowSec > 0 {
				publicRate = float64(publicSnapshot.RecentHits) / publicSnapshot.RecentWindowSec
			}
			if !publicSnapshot.LastSeen.IsZero() {
				publicIdle = now.Sub(publicSnapshot.LastSeen).Seconds()
			}
			firstPathDeep = pathLooksDeep(publicSnapshot.FirstPath)
		}
	}

	var specialSnapshot session.SpecialSnapshot
	var specialIdle float64
	if trust != nil && len(ctx.Response.Cookies) > 0 {
		for name, rule := range ctx.Response.Cookies {
			value, ok := cookies[name]
			if !ok || value == "" {
				continue
			}
			digest, err := trust.digestValue(rule.HashMode, value)
			if err != nil {
				trust.logMissingHasher(rule, err)
				continue
			}
			if snap, ok := trust.special.Touch(digest); ok {
				specialSnapshot = pickNewestSpecial(specialSnapshot, snap)
			}
		}
		if specialSnapshot.Key != "" {
			specialIdle = specialIdleSeconds(now, specialSnapshot)
		}
	}

	if metricsChallengeASN && challengeLevel != "" && asn != 0 {
		decisionChallengeLevelASNTotal.WithLabelValues(fmt.Sprintf("%d", asn), challengeLevel).Inc()
	}

	input := policy.Input{
		Backend:                    backend,
		BackendLabel:               componentLabel,
		BackendLabelType:           componentType,
		Frontend:                   frontend,
		Protocol:                   protocol,
		XFF:                        xff,
		Method:                     method,
		Query:                      query,
		SNI:                        sni,
		JA3:                        ja3,
		IP:                         ip,
		ASN:                        asn,
		Country:                    country,
		UA:                         ua,
		Host:                       host,
		Path:                       path,
		SessionPublicReqCount:      publicSnapshot.RequestCount,
		SessionPublicRate:          publicRate,
		SessionPublicFirstPath:     publicSnapshot.FirstPath,
		SessionPublicFirstPathDeep: firstPathDeep,
		SessionPublicIdleSeconds:   publicIdle,
		SessionSpecialRole:         specialSnapshot.Role,
		SessionSpecialIdleSeconds:  specialIdle,
		CookieAgeSeconds:           cookieAgeSeconds,
		ChallengeLevel:             challengeLevel,
		CookieGuardValid:           cookieGuardValid,
	}

	out := cfg.Evaluate(input, promRuleCounter{CounterVec: decisionRulesHitTotal}, metricsHostLabel)

	elapsed := time.Since(start).Seconds()
	decisionEvalSeconds.Observe(elapsed)
	labelHost := ""
	if metricsHostLabel {
		labelHost = host
	}
	if strippedHops > 0 {
		value := float64(strippedHops)
		decisionXffTrustedStripsTotal.WithLabelValues(componentType, componentLabel, labelHost).Add(value)
	}
	bucketLabel := labelValue(out.Vars["policy.bucket"])
	decisionDecisionsTotal.WithLabelValues(componentType, componentLabel, labelHost, bucketLabel, out.Reason).Inc()

	resp := make(map[string]interface{}, len(out.Vars)+8)
	for k, v := range out.Vars {
		resp[k] = normalizeValue(v)
	}
	if _, ok := resp["reason"]; !ok {
		if out.Reason != "" {
			resp["reason"] = out.Reason
		}
	}

	if publicSnapshot.Key != "" {
		setResp(resp, "session.public.key", publicSnapshot.Key)
		setResp(resp, "session.public.key_source", keySource)
		setResp(resp, "session.public.req_count", publicSnapshot.RequestCount)
		setResp(resp, "session.public.rate", publicRate)
		setResp(resp, "session.public.recent_hits", publicSnapshot.RecentHits)
		setResp(resp, "session.public.first_path", publicSnapshot.FirstPath)
		setResp(resp, "session.public.first_path_deep", firstPathDeep)
		setResp(resp, "session.public.idle_seconds", publicIdle)
		setResp(resp, "session.public.rate_window_seconds", publicSnapshot.RecentWindowSec)
	}
	if specialSnapshot.Key != "" {
		setResp(resp, "session.special.role", specialSnapshot.Role)
		setResp(resp, "session.special.idle_seconds", specialIdle)
		setResp(resp, "session.special.groups", strings.Join(specialSnapshot.Groups, ","))
	}
	setResp(resp, "cookieguard.valid", cookieGuardValid)
	setResp(resp, "cookieguard.age_seconds", cookieAgeSeconds)
	setResp(resp, "cookieguard.challenge_level", challengeLevel)

	if cfg.Debug {
		// Optional verbose line with raw inputs and snapshots
		if debugVerbose {
			pt := trusted.Has(srcTrim)
			entries := trusted.Entries()
			hb2 := cookies["hb_v2"] != ""
			hb3 := cookies["hb_v3"] != ""
			log.Printf("policy-verbose: raw_input=%v fe=%s be=%s src=%s xff=%s ip=%v xff_used=%t xff_stripped=%d trusted_peer=%t trusted_entries=%v asn=%d c=%s m=%s host=%s path=%s query=%q sni=%s ja3=%s hb2=%t hb3=%t key_src=%s public={key=%s req=%d hits=%d rate=%.6f idle=%.3f first_path=%s deep=%t} special={role=%s idle=%.3f groups=%s} reason=%s bucket=%s elapsed=%.6f ua=%q vars=%v",
				sortedRaw(raw), frontend, backend, src, xff, ip, xffUsed, strippedHops, pt, entries, asn, country, strings.ToUpper(method), host, truncatePath(path, 200), query, sni, ja3, hb2, hb3, keySource,
				publicSnapshot.Key, publicSnapshot.RequestCount, publicSnapshot.RecentHits, publicRate, publicIdle, publicSnapshot.FirstPath, firstPathDeep,
				specialSnapshot.Role, specialIdle, strings.Join(specialSnapshot.Groups, ","), out.Reason, bucketLabel, elapsed, ua, resp)
		}

		// Concise single-line summary
		hb2 := cookies["hb_v2"] != ""
		hb3 := cookies["hb_v3"] != ""
		useCh := labelValue(out.Vars["use_challenge"]) // may be "unset" if not provided
		log.Printf("policy: fe=%s be=%s ip=%s asn=%d c=%s m=%s host=%s path=%s bucket=%s reason=%s use_ch=%s hb2=%t hb3=%t key_src=%s key=%s req=%d hits=%d rate=%.6f xff_used=%t stripped=%d ua=%q",
			frontend, backend, safeIP(ip), asn, country, strings.ToUpper(method), host, truncatePath(path, 120),
			bucketLabel, out.Reason, useCh, hb2, hb3, keySource, publicSnapshot.Key, publicSnapshot.RequestCount, publicSnapshot.RecentHits, publicRate, xffUsed, strippedHops, ua)
	}

	return resp, nil
}

func handleResponseMessage(raw map[string]string, ctx contextcfg.Config, trust *trustRuntime) {
	if trust == nil {
		return
	}
	headers := parseHeaderBlock(raw["res.hdrs"])
	if len(headers) == 0 {
		return
	}
	cookies := make(map[string]string)
	for _, hdr := range headers {
		name := strings.ToLower(strings.TrimSpace(hdr.Name))
		rule, ok := ctx.Response.Headers[name]
		if ok {
			digest, err := trust.digestValue(rule.HashMode, hdr.Value)
			if err != nil {
				trust.logMissingHasher(rule, err)
			} else {
				applySignalToSpecial(rule, hdr.Value, digest, trust)
			}
		}
		if name == "set-cookie" {
			if cname, cval := parseSetCookie(hdr.Value); cname != "" {
				cookies[cname] = cval
			}
		}
	}
	for name, rule := range ctx.Response.Cookies {
		if value, ok := cookies[name]; ok {
			trust.updateSpecialFromCookie(rule, value)
		}
	}
}

func isResponseMessage(name string) bool {
	return strings.Contains(name, "response")
}

func parseBool(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func parseFloat(v string) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0
	}
	return f
}

func safeIP(ip net.IP) string {
	if ip == nil {
		return "-"
	}
	return ip.String()
}

func truncatePath(p string, max int) string {
	if len(p) <= max {
		return p
	}
	if max <= 3 {
		return p[:max]
	}
	return p[:max-3] + "..."
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
	case string, int, int64, uint, uint64:
		return v
	case float32:
		return fmt.Sprintf("%.6f", t)
	case float64:
		return fmt.Sprintf("%.6f", t)
	default:
		return v
	}
}

func setResp(resp map[string]interface{}, key string, value interface{}) {
	resp[key] = normalizeValue(value)
}

func sortedRaw(raw map[string]string) []string {
	out := make([]string, 0, len(raw))
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s=%s", k, raw[k]))
	}
	return out
}
