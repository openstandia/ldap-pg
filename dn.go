package main

type DN struct {
	RDNs      []*RelativeDN
	suffix    []string
	cachedRDN map[string]string
}

type RelativeDN struct {
	Attributes []*AttributeTypeAndValue
}

func (r *RelativeDN) OrigStr() string {
	b := make([]byte, 0, 128)
	for i, attr := range r.Attributes {
		if i > 0 {
			b = append(b, "+"...)
		}
		b = append(b, attr.TypeOrig...)
		b = append(b, "="...)
		b = append(b, attr.ValueOrig...)
	}
	return string(b)
}

func (r *RelativeDN) NormStr() string {
	b := make([]byte, 0, 128)
	for i, attr := range r.Attributes {
		if i > 0 {
			b = append(b, "+"...)
		}
		b = append(b, attr.TypeNorm...)
		b = append(b, "="...)
		b = append(b, attr.ValueNorm...)
	}
	return string(b)
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
	b := make([]byte, 0, 256)
	for i, rdn := range d.RDNs {
		if i > 0 {
			b = append(b, ","...)
		}
		b = append(b, rdn.NormStr()...)
	}
	return string(b)
}

func (d *DN) DNOrigStr() string {
	b := make([]byte, 0, 128)
	for i, rdn := range d.RDNs {
		if i > 0 {
			b = append(b, ","...)
		}
		b = append(b, rdn.OrigStr()...)
	}
	return string(b)
}

func (d *DN) RDNNormStr() string {
	if d.IsDC() {
		return ""
	}
	b := make([]byte, 0, 128)
	for i, attr := range d.RDNs[0].Attributes {
		if i > 0 {
			b = append(b, "+"...)
		}
		b = append(b, attr.TypeNorm...)
		b = append(b, "="...)
		b = append(b, attr.ValueNorm...)
	}
	return string(b)
}

func (d *DN) RDNOrigStr() string {
	if d.IsDC() {
		return ""
	}
	b := make([]byte, 0, 128)
	for i, attr := range d.RDNs[0].Attributes {
		if i > 0 {
			b = append(b, "+"...)
		}
		b = append(b, attr.TypeOrig...)
		b = append(b, "="...)
		b = append(b, attr.ValueOrig...)
	}
	return string(b)
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
	if d.IsDC() {
		return nil
	}

	return &DN{
		RDNs:   d.RDNs[1:],
		suffix: d.suffix,
	}
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
