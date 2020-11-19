package main

import (
	"log"
	"strconv"
	"strings"

	"github.com/jmoiron/sqlx/types"
)

type DN struct {
	RDNs      []*RelativeDN
	cachedRDN map[string]string
}

type FetchedDN struct {
	ID       int64  `db:"id"`
	ParentID int64  `db:"parent_id"`
	Path     string `db:"path"`
	DNOrig   string `db:"dn_orig"`
	HasSub   bool   `db:"has_sub"`
	dnNorm   string // not fetched from DB, it's computed
}

type FetchedEntry struct {
	FetchedDN
	AttrsOrig types.JSONText `db:"attrs_orig"`
}

func (e *FetchedEntry) GetAttrsOrig() map[string][]string {
	if len(e.AttrsOrig) > 0 {
		jsonMap := make(map[string][]string)
		e.AttrsOrig.Unmarshal(&jsonMap)

		return jsonMap
	}
	return nil
}

func (f *FetchedDN) IsRoot() bool {
	return strings.Contains(f.Path, ".")
}

func (f *FetchedDN) DNNorm() string {
	if f.dnNorm == "" {
		dn, err := NormalizeDN(f.DNOrig)
		if err != nil {
			log.Printf("error: Invalid DN: %s, err: %v", f.DNOrig, err)
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
		log.Printf("error: Invalid path: %s, err: %v", f.Path, err)
		return nil
	}
	dn, err := NormalizeDN(f.DNOrig)
	if err != nil {
		log.Printf("error: Invalid DN: %s, err: %v", f.DNOrig, err)
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
	RDNs: nil,
}

func NormalizeDN(dn string) (*DN, error) {
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
	if d == nil {
		return o == nil
	}
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

func (d *DN) ModifyRDN(newRDN string, deleteOld bool) (*DN, *RelativeDN, error) {
	newDN, err := ParseDN(newRDN)
	if err != nil {
		return nil, nil, err
	}

	// Clone and apply the change
	newRDNs := make([]*RelativeDN, len(d.RDNs))
	var oldRDN *RelativeDN
	for i, v := range d.RDNs {
		if i == 0 {
			if !deleteOld {
				oldRDN = v
			}
			newRDNs[i] = newDN.RDNs[0]
		} else {
			newRDNs[i] = v
		}
	}

	return &DN{
		RDNs: newRDNs,
	}, oldRDN, nil
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
		RDNs: newRDNs,
	}, nil
}

func (d *DN) ParentDN() *DN {
	if d.IsRoot() {
		return nil
	}

	return &DN{
		RDNs: d.RDNs[1:],
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

func (d *DN) IsAnonymous() bool {
	return len(d.RDNs) == 0
}
