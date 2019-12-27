package main

type AddEntry struct {
	schemaMap  *SchemaMap
	dn         *DN
	attributes map[string]*SchemaValue
}

type MemberEntry struct {
	AttrNameNorm   string
	MemberOfDNNorm string
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

	rdn := dn.RDN()
	for k, v := range rdn {
		// rdn is validated already
		j.attributes[k], _ = NewSchemaValue(k, []string{v})
	}
}

func (j *AddEntry) IsContainer() bool {
	return j.dn.IsContainer()
}

func (j *AddEntry) Member() []*MemberEntry {
	list := []*MemberEntry{}

	for _, sv := range j.attributes {
		if sv.IsMemberAttribute() {
			for _, v := range sv.Norm() {
				m := &MemberEntry{
					AttrNameNorm:   sv.Name(),
					MemberOfDNNorm: v,
				}
				list = append(list, m)
			}
		}
	}

	return list
}

func (j *AddEntry) RDNNorm() string {
	if j.dn.IsDC() {
		return ""
	}
	return j.dn.RDNNormStr()
}

func (j *AddEntry) RDNOrig() string {
	if j.dn.IsDC() {
		return ""
	}
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

func (j *AddEntry) AttrNorm(attrName string) ([]string, bool) {
	s, ok := j.schemaMap.Get(attrName)
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
