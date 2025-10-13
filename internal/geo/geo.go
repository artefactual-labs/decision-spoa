package geo

import (
	"net"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

type DB struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

type Result struct {
	CountryISO string
	ASN        uint
}

func Open(cityPath, asnPath string) (*DB, error) {
	db := &DB{}
	if cityPath != "" {
		if r, e := maxminddb.Open(cityPath); e == nil {
			db.city = r
		} else {
			return nil, e
		}
	}
	if asnPath != "" {
		if r, e := maxminddb.Open(asnPath); e == nil {
			db.asn = r
		} else {
			return nil, e
		}
	}
	return db, nil
}

func (d *DB) Close() {
	if d.city != nil {
		d.city.Close()
	}
	if d.asn != nil {
		d.asn.Close()
	}
}

func (d *DB) Lookup(ip net.IP) (Result, error) {
	var res Result
	if d.city != nil {
		var city struct {
			Country struct {
				ISO string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := d.city.Lookup(ip, &city); err == nil {
			res.CountryISO = city.Country.ISO
		}
	}
	if d.asn != nil {
		var asn struct {
			Number uint `maxminddb:"autonomous_system_number"`
		}
		if err := d.asn.Lookup(ip, &asn); err == nil {
			res.ASN = asn.Number
		}
	}
	return res, nil
}

