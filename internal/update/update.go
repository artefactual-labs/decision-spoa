package update

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var ErrNoChange = errors.New("no change")

type Options struct {
	CountryURL string // City (country ISO inside) URL (.mmdb or .tar.gz)
	ASNURL     string // ASN URL (.mmdb or .tar.gz)
	CountryOut string
	ASNOut     string
	Owner      string
	Group      string
	BestEffort bool
}

func Run(o Options) error {
	if o.CountryURL == "" && o.ASNURL == "" {
		return fmt.Errorf("no URLs provided (set GEOIP_CITY_URL / GEOIP_ASN_URL)")
	}
	var changed bool
	if o.CountryURL != "" {
		c, err := fetchMaybe(o.CountryURL, o.CountryOut)
		if err != nil {
			if o.BestEffort {
				return nil
			}
			return err
		}
		changed = changed || c
	}
	if o.ASNURL != "" {
		c, err := fetchMaybe(o.ASNURL, o.ASNOut)
		if err != nil {
			if o.BestEffort {
				return nil
			}
			return err
		}
		changed = changed || c
	}
	if !changed {
		return ErrNoChange
	}
	return nil
}

func fetchMaybe(url, dst string) (bool, error) {
	tmp := dst + ".tmp"
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	resp, err := http.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("download %s: %s", url, resp.Status)
	}

	var mmdbPath string
	if strings.HasSuffix(strings.ToLower(url), ".mmdb") {
		f, err := os.Create(tmp)
		if err != nil {
			return false, err
		}
		defer f.Close()
		if _, err := io.Copy(f, resp.Body); err != nil {
			return false, err
		}
		mmdbPath = tmp
	} else { // assume tar.gz
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return false, err
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		var found string
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return false, err
			}
			if h.FileInfo().IsDir() {
				continue
			}
			if strings.HasSuffix(h.Name, ".mmdb") {
				out, err := os.Create(tmp)
				if err != nil {
					return false, err
				}
				if _, err := io.Copy(out, tr); err != nil {
					out.Close()
					return false, err
				}
				out.Close()
				found = tmp
				break
			}
		}
		if found == "" {
			return false, fmt.Errorf("no .mmdb file found inside tar.gz")
		}
		mmdbPath = found
	}

	// compare hash with existing dst
	newHash, _ := fileHash(mmdbPath)
	oldHash, _ := fileHash(dst)
	if newHash != "" && newHash == oldHash {
		os.Remove(tmp)
		return false, ErrNoChange
	}
	if err := os.Rename(tmp, dst); err != nil {
		return false, err
	}
	return true, nil
}

func fileHash(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

