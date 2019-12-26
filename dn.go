package main

import (
	"strings"

	goldap "gopkg.in/ldap.v3"
)

type DN struct {
	dn              *goldap.DN
	dnNorm          []string
	dnOrig          []string
	suffix          []string
	ReverseParentDN string
	cachedRDN       map[string]string
}

var anonymousDN = &DN{
	dn:              &goldap.DN{RDNs: nil},
	dnNorm:          nil,
	dnOrig:          nil,
	suffix:          nil,
	ReverseParentDN: "",
}

func normalizeDN(suffix []string, dn string) (*DN, error) {
	// Anonymous
	if dn == "" {
		return anonymousDN, nil
	}

	d, dnNorm, dnOrig, err := parseDN(dn)
	if err != nil {
		return nil, err
	}

	if len(dnNorm)-len(suffix) < 0 {
		// return nil, xerrors.Errorf("Invalid DN. It must have suffix. DN: %s", dn)
		return &DN{
			dn:              d,
			dnNorm:          dnNorm,
			dnOrig:          dnOrig,
			suffix:          suffix,
			ReverseParentDN: "",
		}, nil
	}

	for i, s := range suffix {
		if dnNorm[len(dnNorm)-len(suffix)+i] != s {
			return &DN{
				dn:              d,
				dnNorm:          dnNorm,
				dnOrig:          dnOrig,
				suffix:          suffix,
				ReverseParentDN: "",
			}, nil
		}
	}

	// Remove suffix DN
	d.RDNs = d.RDNs[:len(d.RDNs)-len(suffix)]
	dnNorm = dnNorm[:len(dnNorm)-len(suffix)]
	dnOrig = dnOrig[:len(dnOrig)-len(suffix)]

	reverse := toReverseDN(dnNorm)

	return &DN{
		dn:              d,
		dnNorm:          dnNorm,
		dnOrig:          dnOrig,
		suffix:          suffix,
		ReverseParentDN: reverse,
	}, nil
}

func normalizeDNBAK(dn string) (*DN, error) {
	d, dnNorm, dnOrig, err := parseDN(dn)
	if err != nil {
		return nil, err
	}

	reverse := toReverseDN(dnNorm)

	return &DN{
		dn:              d,
		dnNorm:          dnNorm,
		dnOrig:          dnOrig,
		ReverseParentDN: reverse,
	}, nil
}

func toReverseDN(dn []string) string {
	var path string
	// ignore last rdn
	for i := len(dn) - 1; i > 0; i-- {
		path += strings.ToLower(dn[i]) + "/"
	}
	return path
}

func (d *DN) DNNormStr() string {
	return strings.Join(d.dnNorm, ",")
}

func (d *DN) DNOrigStr() string {
	return strings.Join(d.dnOrig, ",")
}

func (d *DN) RDNNormStr() string {
	if d.IsDC() {
		return ""
	}
	return d.dnNorm[0]
}

func (d *DN) RDNOrigStr() string {
	if d.IsDC() {
		return ""
	}
	return d.dnOrig[0]
}

func (d *DN) Equal(o *DN) bool {
	return d.DNNormStr() == o.DNNormStr()
}

func (d *DN) GetRDN() map[string]string {
	if len(d.cachedRDN) > 0 {
		return d.cachedRDN
	}

	// Check DC case
	if len(d.dn.RDNs) == 0 {
		return map[string]string{}
	}

	m := make(map[string]string, len(d.dn.RDNs[0].Attributes))

	for _, a := range d.dn.RDNs[0].Attributes {
		m[a.Type] = a.Value
	}

	d.cachedRDN = m

	return m
}

func (d *DN) Modify(newRDN string) (*DN, error) {
	nd := make([]string, len(d.dnOrig))
	for i, v := range d.dnOrig {
		if i == 0 {
			nd[i] = newRDN
		} else {
			nd[i] = v
		}
	}
	nd = append(nd, d.suffix...)

	return normalizeDN(d.suffix, strings.Join(nd, ","))
}

func (d *DN) Move(newParentDN *DN) (*DN, error) {
	newDN := d.RDNOrigStr() + "," + newParentDN.DNOrigStr()
	return normalizeDN(d.suffix, newDN)
}

func (d *DN) ToPath() string {
	parts := strings.Split(d.DNNormStr(), ",")

	var path string
	for i := len(parts) - 1; i >= 0; i-- {
		path += strings.ToLower(parts[i]) + "/"
	}
	return path
}

func (d *DN) ParentDN() *DN {
	if d.IsDC() {
		return nil
	}
	var p *DN
	if len(d.dnOrig) == 1 {
		// Parent is DC
		p, _ = normalizeDN(d.suffix, strings.Join(d.suffix, ","))
	}

	nd := d.dnOrig[1:]
	nd = append(nd, d.suffix...)
	p, _ = normalizeDN(d.suffix, strings.Join(nd, ","))

	return p
}

func (d *DN) IsDC() bool {
	return len(d.suffix) > 0 && len(d.dnNorm) == 0
}

func (d *DN) IsContainer() bool {
	// TODO Check other container?
	return d.IsDC() || strings.HasPrefix(d.dnNorm[0], "ou=")
}

func (d *DN) IsAnonymous() bool {
	return len(d.suffix) == 0 && len(d.dnNorm) == 0
}
