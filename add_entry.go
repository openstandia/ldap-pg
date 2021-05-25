package main

type AddEntry struct {
	schemaMap  *SchemaMap
	dn         *DN
	attributes map[string]*SchemaValue
}

func NewAddEntry(schemaMap *SchemaMap, dn *DN) *AddEntry {
	entry := &AddEntry{
		schemaMap:  schemaMap,
		attributes: map[string]*SchemaValue{},
	}
	entry.SetDN(dn)

	return entry
}

func (j *AddEntry) HasAttr(attrName string) bool {
	s, ok := j.schemaMap.AttributeType(attrName)
	if !ok {
		return false
	}

	_, ok = j.attributes[s.Name]
	return ok
}

func (j *AddEntry) SetDN(dn *DN) {
	j.dn = dn

	rdn := dn.RDN()
	for k, v := range rdn {
		// rdn is validated already
		j.attributes[k], _ = NewSchemaValue(j.schemaMap, k, []string{v})
	}
}

func (j *AddEntry) IsRoot() bool {
	return j.dn.IsRoot()
}

func (j *AddEntry) RDNNorm() string {
	return j.dn.RDNNormStr()
}

func (j *AddEntry) RDNOrig() string {
	return j.dn.RDNOrigStr()
}

func (j *AddEntry) DN() *DN {
	return j.dn
}

func (j *AddEntry) ParentDN() *DN {
	return j.dn.ParentDN()
}

func (j *AddEntry) IsDC() bool {
	return j.dn.IsDC()
}

func (j *AddEntry) Validate() error {
	// objectClass is required
	if !j.HasAttr("objectClass") {
		return NewObjectClassViolation()
	}

	// Validate objectClass
	sv := j.attributes["objectClass"]
	if err := j.schemaMap.ValidateObjectClass(sv.Orig(), j.attributes); err != nil {
		return err
	}

	return nil
}

// Append to current value(s).
func (j *AddEntry) Add(attrName string, attrValue []string) error {
	if len(attrValue) == 0 {
		return nil
	}
	sv, err := NewSchemaValue(j.schemaMap, attrName, attrValue)
	if err != nil {
		return err
	}
	if sv.IsNoUserModificationWithMigrationDisabled() {
		return NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}
	return j.addsv(sv)
}

func (j *AddEntry) addsv(value *SchemaValue) error {
	name := value.Name()

	current, ok := j.attributes[name]
	if !ok {
		j.attributes[name] = value
		return nil
	} else {
		// TODO
		current.Add(value)
	}
	return nil
}

func (j *AddEntry) AttrNorm(attrName string) ([]string, bool) {
	s, ok := j.schemaMap.AttributeType(attrName)
	if !ok {
		return nil, false
	}

	v, ok := j.attributes[s.Name]
	if !ok {
		return nil, false
	}
	return v.Norm(), true
}

func (j *AddEntry) Attrs() (map[string]interface{}, map[string][]string) {
	norm := make(map[string]interface{}, len(j.attributes))
	orig := make(map[string][]string, len(j.attributes))
	for k, v := range j.attributes {
		norm[k] = v.GetForJSON()
		orig[k] = v.Orig()
	}
	return norm, orig
}
