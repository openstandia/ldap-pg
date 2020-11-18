package main

import (
	"log"
	"strconv"
	"strings"
)

type DN struct {
	RDNs      []*RelativeDN
	suffix    []string
	cachedRDN map[string]string
}

type FetchedDNEntry struct {
	ID       int64  `db:"id"`
	ParentID int64  `db:"parent_id"`
	Path     string `db:"path"`
	DNOrig   string `db:"dn_orig"`
	dnNorm   string // not fetched from DB, it's computed
}

type FetchedDN struct {
	ID       int64  `db:"id"`
	ParentID int64  `db:"parent_id"`
	Path     string `db:"path"`
	DNOrig   string `db:"dn_orig"`
	HasSub   bool   `db:"has_sub"`
	dnNorm   string // not fetched from DB, it's computed
}

func (f *FetchedDN) IsRoot() bool {
	return strings.Contains(f.Path, ".")
}

func (f *FetchedDN) DNNorm() string {
	if f.dnNorm == "" {
		dn, err := NormalizeDN(nil, f.DNOrig)
		if err != nil {
			log.Printf("error: Invalid DN: %s, err: %w", f.DNOrig, err)
			return ""
		}
		// Cached
		f.dnNorm = dn.DNNormStr()
	}
	return f.dnNorm
}

func (f *FetchedDN) ParentDN() *FetchedDN {
	if f.IsRoot() {
		return nil
	}

	path := strings.Split(f.Path, ".")
	parentPath := strings.Join(path[:len(path)-2], ".")
	parentID, err := strconv.ParseInt(path[len(path)-1], 10, 64)
	if err != nil {
		log.Printf("error: Invalid path: %s, err: %w", f.Path, err)
		return nil
	}
	dn, err := NormalizeDN(nil, f.DNOrig)
	if err != nil {
		log.Printf("error: Invalid DN: %s, err: %w", f.DNOrig, err)
		return nil
	}
	parentDN := dn.ParentDN()

	return &FetchedDN{
		ID:     parentID,
		Path:   parentPath,
		DNOrig: parentDN.DNOrigStr(),
		dnNorm: parentDN.DNNormStr(),
		HasSub: true,
	}
}

type RelativeDN struct {
	Attributes []*AttributeTypeAndValue
}

func (r *RelativeDN) OrigStr() string {
	var b strings.Builder
	b.Grow(128)
	for i, attr := range r.Attributes {
		if i > 0 {
			b.WriteString("+")
		}
		b.WriteString(attr.TypeOrig)
		b.WriteString("=")
		b.WriteString(attr.ValueOrig)
	}
	return b.String()
}

func (r *RelativeDN) NormStr() string {
	var b strings.Builder
	b.Grow(128)
	for i, attr := range r.Attributes {
		if i > 0 {
			b.WriteString("+")
		}
		b.WriteString(attr.TypeNorm)
		b.WriteString("=")
		b.WriteString(attr.ValueNorm)
	}
	return b.String()
}

type AttributeTypeAndValue struct {
	// TypeOrig is the original attribute type
	TypeOrig string
	// TypeNorm is the normalized attribute type
	TypeNorm string
	// Value is the original attribute value
	ValueOrig string
	// Value is the normalized attribute value
	ValueNorm string
}

var anonymousDN = &DN{
	RDNs:   nil,
	suffix: nil,
}

func NormalizeDN(suffix []string, dn string) (*DN, error) {
	// Anonymous
	if dn == "" {
		return anonymousDN, nil
	}

	return ParseDN(dn)
}

func (d *DN) DNNormStr() string {
	var b strings.Builder
	b.Grow(256)
	for i, rdn := range d.RDNs {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(rdn.NormStr())
	}
	return b.String()
}

func (d *DN) DNOrigStr() string {
	var b strings.Builder
	b.Grow(256)
	for i, rdn := range d.RDNs {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(rdn.OrigStr())
	}
	return b.String()
}

func (d *DN) RDNNormStr() string {
	var b strings.Builder
	b.Grow(128)
	for i, attr := range d.RDNs[0].Attributes {
		if i > 0 {
			b.WriteString("+")
		}
		b.WriteString(attr.TypeNorm)
		b.WriteString("=")
		b.WriteString(attr.ValueNorm)
	}
	return b.String()
}

func (d *DN) RDNOrigStr() string {
	var b strings.Builder
	b.Grow(128)
	for i, attr := range d.RDNs[0].Attributes {
		if i > 0 {
			b.WriteString("+")
		}
		b.WriteString(attr.TypeOrig)
		b.WriteString("=")
		b.WriteString(attr.ValueOrig)
	}
	return b.String()
}

func (d *DN) Equal(o *DN) bool {
	return d.DNNormStr() == o.DNNormStr()
}

func (d *DN) RDN() map[string]string {
	if len(d.cachedRDN) > 0 {
		return d.cachedRDN
	}

	// Check DC case
	if len(d.RDNs) == 0 {
		return map[string]string{}
	}

	m := make(map[string]string, len(d.RDNs[0].Attributes))

	for _, a := range d.RDNs[0].Attributes {
		m[a.TypeNorm] = a.ValueNorm
	}

	d.cachedRDN = m

	return m
}

func (d *DN) ModifyRDN(newRDN string) (*DN, error) {
	newDN, err := ParseDN(newRDN)
	if err != nil {
		return nil, err
	}

	// Clone and apply the change
	newRDNs := make([]*RelativeDN, len(d.RDNs))
	for i, v := range d.RDNs {
		if i == 0 {
			newRDNs[i] = newDN.RDNs[0]
		} else {
			newRDNs[i] = v
		}
	}

	return &DN{
		RDNs:   newRDNs,
		suffix: d.suffix,
	}, nil
}

func (d *DN) Move(newParentDN *DN) (*DN, error) {
	leaf := d.RDNs[0]

	// Clone and apply the change
	newRDNs := make([]*RelativeDN, len(newParentDN.RDNs)+1)
	newRDNs[0] = leaf
	for i, v := range newParentDN.RDNs {
		newRDNs[i+1] = v
	}

	return &DN{
		RDNs:   newRDNs,
		suffix: newParentDN.suffix,
	}, nil
}

func (d *DN) ParentDN() *DN {
	if d.IsRoot() {
		return nil
	}

	return &DN{
		RDNs:   d.RDNs[1:],
		suffix: d.suffix,
	}
}

func (d *DN) IsRoot() bool {
	return len(d.RDNs) == 1
}

func (d *DN) IsDC() bool {
	for _, attr := range d.RDNs[0].Attributes {
		if attr.TypeNorm == "dc" {
			return true
		}
	}
	return false
}

func (d *DN) GetDCOrig() string {
	if len(d.suffix) > 0 {
		return d.suffix[0]
	}
	return ""
}

func (d *DN) IsContainer() bool {
	// TODO Can't implment here
	return d.IsDC()
}

func (d *DN) IsAnonymous() bool {
	return len(d.suffix) == 0 && len(d.RDNs) == 0
}
