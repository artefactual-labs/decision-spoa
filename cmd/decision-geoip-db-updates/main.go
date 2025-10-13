package main

import (
	"flag"
	"log"
	"os"

	"github.com/artefactual-labs/decision-spoa/internal/update"
)

var (
	version = "dev"
	commit  = "none"
	date    = ""
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	cityOut := flag.String("city-out", getenv("GEOIP_CITY_DB", "/var/lib/GeoIP/GeoLite2-City.mmdb"), "City .mmdb destination")
	asnOut := flag.String("asn-out", getenv("GEOIP_ASN_DB", "/var/lib/GeoIP/GeoLite2-ASN.mmdb"), "ASN .mmdb destination")
	cityURL := flag.String("city-url", getenv("GEOIP_CITY_URL", ""), "City DB URL")
	asnURL := flag.String("asn-url", getenv("GEOIP_ASN_URL", ""), "ASN DB URL")
	bestEffort := flag.Bool("best-effort", true, "Best-effort (no error if unavailable/unchanged)")
	flag.Parse()

	err := update.Run(update.Options{
		CountryURL: *cityURL,
		ASNURL:     *asnURL,
		CountryOut: *cityOut,
		ASNOut:     *asnOut,
		BestEffort: *bestEffort,
	})
	if err != nil {
		if *bestEffort {
			log.Printf("update (best-effort): %v", err)
			os.Exit(0)
		}
		log.Fatalf("update error: %v", err)
	}
	log.Printf("update: databases refreshed")
}
