package main

import (
	"log"
	"time"
)

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
	sv, err := NewSchemaValue(attrName, attrValue)
	if err != nil {
		return err
	}
	return j.AddSV(sv)
}

func (j *AddEntry) AddSV(value *SchemaValue) error {
	name := value.Name()

	current, ok := j.attributes[name]
	if !ok {
		j.attributes[name] = value
	} else {
		current.Add(value)
	}
	return nil
}

// Replace with the value(s).
func (j *AddEntry) Replace(attrName string, attrValue []string) error {
	sv, err := NewSchemaValue(attrName, attrValue)
	if err != nil {
		return err
	}
	return j.ReplaceSV(sv)
}

func (j *AddEntry) ReplaceSV(value *SchemaValue) error {
	name := value.Name()

	if value.IsEmpty() {
		delete(j.attributes, name)
	} else {
		j.attributes[name] = value
	}
	return nil
}

// Delete from current value(s) if the value matchs.
func (j *AddEntry) Delete(attrName string, attrValue []string) error {
	sv, err := NewSchemaValue(attrName, attrValue)
	if err != nil {
		return err
	}
	return j.DeleteSV(sv)
}

func (j *AddEntry) DeleteSV(value *SchemaValue) error {
	if value.IsEmpty() {
		return j.DeleteAll(value.schema)
	}

	current, ok := j.attributes[value.Name()]
	if !ok {
		log.Printf("warn: Failed to modify/delete because of no attribute. dn: %s", j.GetDN().DNNorm)
		return NewNoSuchAttribute("modify/delete", value.Name())
	}

	if current.IsSingle() {
		delete(j.attributes, value.Name())
		return nil
	} else {
		current.Delete(value)
		return nil
	}
}

func (j *AddEntry) DeleteAll(s *Schema) error {
	if !j.HasAttr(s.Name) {
		log.Printf("warn: Failed to modify/delete because of no attribute. dn: %s", j.GetDN().DNNorm)
		return NewNoSuchAttribute("modify/delete", s.Name)
	}
	delete(j.attributes, s.Name)
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

func (j *AddEntry) GetAttrNormAsTime(attrName string) ([]time.Time, bool) {
	s, ok := j.schemaMap.Get(attrName)
	if !ok {
		return nil, false
	}

	v, ok := j.attributes[s.Name]
	if !ok {
		return nil, false
	}
	return v.GetAsTime(), true
}

func (j *AddEntry) GetAttrsOrig() map[string][]string {
	orig := make(map[string][]string, len(j.attributes))
	for k, v := range j.attributes {
		orig[k] = v.GetOrig()
	}
	return orig
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
