package main

type AddEntry struct {
	schemaMap  *SchemaMap
	dn         *DN
	attributes map[string]*SchemaValue
}

func NewAddEntry(dn *DN) *AddEntry {
	entry := &AddEntry{
		schemaMap:  &schemaMap,
		attributes: map[string]*SchemaValue{},
	}
	entry.SetDN(dn)

	return entry
}

func (j *AddEntry) HasAttr(attrName string) bool {
	s, ok := schemaMap.Get(attrName)
	if !ok {
		return false
	}

	_, ok = j.attributes[s.Name]
	return ok
}

func (j *AddEntry) SetDN(dn *DN) {
	j.dn = dn

	rdn := dn.GetRDN()
	for k, v := range rdn {
		// rdn is validated already
		j.attributes[k], _ = NewSchemaValue(k, []string{v})
	}
}

func (j *AddEntry) GetDN() *DN {
	return j.dn
}

func (j *AddEntry) GetDNNorm() string {
	return j.dn.DNNorm
}

func (j *AddEntry) Validate() error {
	if !j.HasAttr("objectClass") {
		return NewObjectClassViolation()
	}
	// TODO more validation

	return nil
}

// Append to current value(s).
func (j *AddEntry) Add(attrName string, attrValue []string) error {
	if len(attrValue) == 0 {
		return nil
	}
	sv, err := NewSchemaValue(attrName, attrValue)
	if err != nil {
		return err
	}
	if sv.IsNoUserModification() {
		return NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}
	return j.addsv(sv)
}

func (j *AddEntry) addsv(value *SchemaValue) error {
	name := value.Name()

	current, ok := j.attributes[name]
	if !ok {
		j.attributes[name] = value
	} else {
		current.Add(value)
	}
	return nil
}

func (j *AddEntry) GetAttrNorm(attrName string) ([]string, bool) {
	s, ok := j.schemaMap.Get(attrName)
	if !ok {
		return nil, false
	}

	v, ok := j.attributes[s.Name]
	if !ok {
		return nil, false
	}
	return v.GetNorm(), true
}

func (j *AddEntry) GetAttrs() (map[string]interface{}, map[string][]string) {
	norm := make(map[string]interface{}, len(j.attributes))
	orig := make(map[string][]string, len(j.attributes))
	for k, v := range j.attributes {
		norm[k] = v.GetForJSON()
		orig[k] = v.GetOrig()
	}
	return norm, orig
}
