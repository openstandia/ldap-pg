package main

import (
	"log"
)

type ModifyEntry struct {
	schemaMap  *SchemaMap
	dn         *DN
	attributes map[string]*SchemaValue
	dbEntryId  int64
}

func NewModifyEntry(dn *DN, valuesOrig map[string][]string) (*ModifyEntry, error) {
	// TODO
	modifyEntry := &ModifyEntry{
		schemaMap:  &schemaMap,
		dn:         dn,
		attributes: map[string]*SchemaValue{},
	}

	for k, v := range valuesOrig {
		err := modifyEntry.Add(k, v)
		if err != nil {
			return nil, err
		}
	}

	return modifyEntry, nil
}

func (j *ModifyEntry) Put(value *SchemaValue) error {
	j.attributes[value.Name()] = value
	return nil
}

func (j *ModifyEntry) HasKey(s *Schema) bool {
	_, ok := j.attributes[s.Name]
	return ok
}

func (j *ModifyEntry) HasAttr(attrName string) bool {
	s, ok := schemaMap.Get(attrName)
	if !ok {
		return false
	}

	_, ok = j.attributes[s.Name]
	return ok
}

func (j *ModifyEntry) SetDN(dn *DN) {
	j.dn = dn

	rdn := dn.GetRDN()
	for k, v := range rdn {
		// rdn is validated already
		j.attributes[k], _ = NewSchemaValue(k, []string{v})
	}
}

func (j *ModifyEntry) GetDN() *DN {
	return j.dn
}

func (j *ModifyEntry) GetDNNorm() string {
	return j.dn.DNNorm
}

func (j *ModifyEntry) GetDNOrig() string {
	return j.dn.DNOrig
}

func (j *ModifyEntry) Validate() error {
	if !j.HasAttr("objectClass") {
		return NewObjectClassViolation()
	}
	// TODO more validation

	return nil
}

// Append to current value(s).
func (j *ModifyEntry) Add(attrName string, attrValue []string) error {
	sv, err := NewSchemaValue(attrName, attrValue)
	if err != nil {
		return err
	}
	if sv.IsNoUserModification() {
		return NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}
	return j.addsv(sv)
}

func (j *ModifyEntry) addsv(value *SchemaValue) error {
	name := value.Name()

	current, ok := j.attributes[name]
	if !ok {
		j.attributes[name] = value
	} else {
		return current.Add(value)
	}
	return nil
}

// Replace with the value(s).
func (j *ModifyEntry) Replace(attrName string, attrValue []string) error {
	sv, err := NewSchemaValue(attrName, attrValue)
	if err != nil {
		return err
	}
	if sv.IsNoUserModification() {
		return NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}
	return j.replacesv(sv)
}

func (j *ModifyEntry) replacesv(value *SchemaValue) error {
	name := value.Name()

	if value.IsEmpty() {
		delete(j.attributes, name)
	} else {
		j.attributes[name] = value
	}
	return nil
}

// Delete from current value(s) if the value matchs.
func (j *ModifyEntry) Delete(attrName string, attrValue []string) error {
	sv, err := NewSchemaValue(attrName, attrValue)
	if err != nil {
		return err
	}
	if sv.IsNoUserModification() {
		return NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}
	return j.deletesv(sv)
}

func (j *ModifyEntry) deletesv(value *SchemaValue) error {
	if value.IsEmpty() {
		return j.deleteAll(value.schema)
	}

	current, ok := j.attributes[value.Name()]
	if !ok {
		log.Printf("warn: Failed to modify/delete because of no attribute. dn: %s, attrName: %s", j.GetDN().DNNorm, value.Name())
		return NewNoSuchAttribute("modify/delete", value.Name())
	}

	if current.IsSingle() {
		delete(j.attributes, value.Name())
		return nil
	} else {
		err := current.Delete(value)
		if err != nil {
			return err
		}
		if current.IsEmpty() {
			delete(j.attributes, value.Name())
		}
		return nil
	}
}

func (j *ModifyEntry) deleteAll(s *Schema) error {
	if !j.HasAttr(s.Name) {
		log.Printf("warn: Failed to modify/delete because of no attribute. dn: %s", j.GetDN().DNNorm)
		return NewNoSuchAttribute("modify/delete", s.Name)
	}
	delete(j.attributes, s.Name)
	return nil
}

func (j *ModifyEntry) GetAttrNorm(attrName string) ([]string, bool) {
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

func (j *ModifyEntry) GetAttrsOrig() map[string][]string {
	orig := make(map[string][]string, len(j.attributes))
	for k, v := range j.attributes {
		orig[k] = v.GetOrig()
	}
	return orig
}

func (j *ModifyEntry) GetAttrs() (map[string]interface{}, map[string][]string) {
	norm := make(map[string]interface{}, len(j.attributes))
	orig := make(map[string][]string, len(j.attributes))
	for k, v := range j.attributes {
		norm[k] = v.GetForJSON()
		orig[k] = v.GetOrig()
	}
	return norm, orig
}

type diffAttr struct {
	add []string
	del []string
}

func calcDiffAttr(from, to *ModifyEntry, attrName string) *diffAttr {
	fromAttrsNorm, _ := from.GetAttrNorm(attrName)
	toAttrsNorm, _ := to.GetAttrNorm(attrName)

	fromMap := make(map[string]struct{}, len(fromAttrsNorm))
	toMap := make(map[string]struct{}, len(toAttrsNorm))

	for _, v := range fromAttrsNorm {
		fromMap[v] = struct{}{}
	}

	diff := &diffAttr{}

	for _, v := range toAttrsNorm {
		toMap[v] = struct{}{}
		if _, found := fromMap[v]; !found {
			diff.add = append(diff.add, v)
		}
	}

	for _, v := range fromAttrsNorm {
		if _, found := toMap[v]; !found {
			diff.del = append(diff.del, v)
		}
	}

	return diff
}

func (e *ModifyEntry) Clone() *ModifyEntry {
	clone := &ModifyEntry{
		schemaMap:  e.schemaMap,
		dn:         e.dn,
		attributes: map[string]*SchemaValue{},
		dbEntryId:  e.dbEntryId,
	}
	for k, v := range e.attributes {
		clone.attributes[k] = v.Clone()
	}

	return clone
}

func (e *ModifyEntry) ModifyDN(newDN *DN) *ModifyEntry {
	m := e.Clone()
	m.SetDN(newDN)

	return m
}
