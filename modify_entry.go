package main

import (
	"log"
)

type ModifyEntry struct {
	schemaMap        *SchemaMap
	dn               *DN
	attributes       map[string]*SchemaValue
	dbEntryID        int64
	dbParentID       int64
	hasSub           bool
	path             string
	AddChangeLog     map[string]*SchemaValue
	ReplaceChangeLog map[string]*SchemaValue
	DelChangeLog     map[string]*SchemaValue
}

func NewModifyEntry(schemaMap *SchemaMap, dn *DN, attrsOrig map[string][]string) (*ModifyEntry, error) {
	// TODO
	modifyEntry := &ModifyEntry{
		schemaMap:        schemaMap,
		dn:               dn,
		attributes:       map[string]*SchemaValue{},
		AddChangeLog:     map[string]*SchemaValue{},
		ReplaceChangeLog: map[string]*SchemaValue{},
		DelChangeLog:     map[string]*SchemaValue{},
	}

	for k, v := range attrsOrig {
		err := modifyEntry.AddNoCheck(k, v)
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

func (j *ModifyEntry) HasKey(s *AttributeType) bool {
	_, ok := j.attributes[s.Name]
	return ok
}

func (j *ModifyEntry) HasAttr(attrName string) bool {
	s, ok := j.schemaMap.AttributeType(attrName)
	if !ok {
		return false
	}

	_, ok = j.attributes[s.Name]
	return ok
}

func (j *ModifyEntry) SetDN(dn *DN) {
	j.dn = dn

	rdn := dn.RDN()
	for k, v := range rdn {
		// rdn is validated already, ignore error
		sv, _ := NewSchemaValue(j.schemaMap, k, []string{v})
		j.attributes[sv.Name()] = sv
	}
}

func (j *ModifyEntry) DN() *DN {
	return j.dn
}

func (j *ModifyEntry) GetDNNorm() string {
	return j.dn.DNNormStr()
}

func (j *ModifyEntry) GetDNOrig() string {
	return j.dn.DNOrigStr()
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
	sv, err := NewSchemaValue(j.schemaMap, attrName, attrValue)
	if err != nil {
		return err
	}
	if sv.IsNoUserModificationWithMigrationDisabled() {
		return NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}

	// Apply change
	if err := j.addsv(sv); err != nil {
		return err
	}

	// Record changelog
	if v, ok := j.AddChangeLog[sv.Name()]; !ok {
		j.AddChangeLog[sv.Name()] = sv
	} else {
		// Need this case?
		v.Add(sv)
	}

	return nil
}

func (j *ModifyEntry) AddNoCheck(attrName string, attrValue []string) error {
	sv, err := NewSchemaValue(j.schemaMap, attrName, attrValue)
	if err != nil {
		return err
	}
	if err := j.addsv(sv); err != nil {
		return err
	}

	// Record changelog
	if v, ok := j.AddChangeLog[sv.Name()]; !ok {
		j.AddChangeLog[sv.Name()] = sv
	} else {
		// Need this case?
		v.Add(sv)
	}

	return nil
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
	sv, err := NewSchemaValue(j.schemaMap, attrName, attrValue)
	if err != nil {
		return err
	}
	if sv.IsNoUserModificationWithMigrationDisabled() {
		return NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}

	// Validate ObjectClass
	if sv.Name() == "objectClass" {
		// Normalized objectClasses are sorted
		stoc, ok := j.GetAttrNorm("objectClass")
		if !ok {
			log.Printf("error: Unexpected entry. The entry doesn't have objectClass. Cancel the operation. id: %d, dn_norm: %s", j.dbEntryID, j.GetDNNorm())
			return NewOperationsError()
		}
		for i, v := range sv.Orig() {
			oc, ok := j.schemaMap.ObjectClass(v)
			if !ok {
				// e.g.
				// ldap_modify: Invalid syntax (21)
				// additional info: objectClass: value #0 invalid per syntax
				return NewInvalidPerSyntax("objectClass", i)
			}

			if oc.Structural {
				// e.g.
				// ldap_modify: Cannot modify object class (69)
				//     additional info: structural object class modification from 'inetOrgPerson' to 'person' not allowed
				return NewObjectClassModsProhibited(stoc[0], oc.Name)
			}
		}
	}

	// Apply change
	if err := j.replacesv(sv); err != nil {
		return err
	}

	// Record changelog
	j.ReplaceChangeLog[sv.Name()] = sv

	return nil
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
	sv, err := NewSchemaValue(j.schemaMap, attrName, attrValue)
	if err != nil {
		return err
	}
	if sv.IsNoUserModificationWithMigrationDisabled() {
		return NewNoUserModificationAllowedConstraintViolation(sv.Name())
	}

	// Validate ObjectClass
	if sv.Name() == "objectClass" {
		// Normalized objectClasses are sorted
		stoc, ok := j.GetAttrNorm("objectClass")
		if !ok {
			log.Printf("error: Unexpected entry. The entry doesn't have objectClass. Cancel the operation. id: %d, dn_norm: %s", j.dbEntryID, j.GetDNNorm())
			return NewOperationsError()
		}
		for i, v := range sv.Orig() {
			oc, ok := j.schemaMap.ObjectClass(v)
			if !ok {
				// e.g.
				// ldap_modify: Invalid syntax (21)
				// additional info: objectClass: value #0 invalid per syntax
				return NewInvalidPerSyntax("objectClass", i)
			}

			if oc.Structural && stoc[0] == oc.Name {
				// e.g.
				// ldap_modify: Object class violation (65)
				//     additional info: no objectClass attribute
				return NewObjectClassViolation()
			}
		}
	}

	// Apply change
	if err := j.deletesv(sv); err != nil {
		return err
	}

	// Record changelog
	if v, ok := j.DelChangeLog[sv.Name()]; !ok {
		j.DelChangeLog[sv.Name()] = sv
	} else {
		// TODO Need this case?
		v.Add(sv)
	}

	return nil
}

func (j *ModifyEntry) deletesv(value *SchemaValue) error {
	if value.IsEmpty() {
		return j.deleteAll(value.schema)
	}

	current, ok := j.attributes[value.Name()]
	if !ok {
		log.Printf("warn: Failed to modify/delete because of no attribute. dn: %s, attrName: %s", j.DN().DNNormStr(), value.Name())
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

func (j *ModifyEntry) deleteAll(s *AttributeType) error {
	if !j.HasAttr(s.Name) {
		log.Printf("warn: Failed to modify/delete because of no attribute. dn: %s", j.DN().DNNormStr())
		return NewNoSuchAttribute("modify/delete", s.Name)
	}
	delete(j.attributes, s.Name)
	return nil
}

func (j *ModifyEntry) ObjectClassLeaf() ([]string, bool) {
	v, ok := j.attributes["objectClass"]
	if !ok {
		return nil, false
	}
	return v.Orig(), true
}

func (j *ModifyEntry) ObjectClassesOrig() ([]string, bool) {
	v, ok := j.attributes["objectClass"]
	if !ok {
		return nil, false
	}
	return v.Orig(), true
}

func (j *ModifyEntry) GetAttrNorm(attrName string) ([]string, bool) {
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

func (j *ModifyEntry) GetAttrsOrig() map[string][]string {
	orig := make(map[string][]string, len(j.attributes))
	for k, v := range j.attributes {
		orig[k] = v.Orig()
	}
	return orig
}

func (j *ModifyEntry) GetAttrs() (map[string]interface{}, map[string][]string) {
	norm := make(map[string]interface{}, len(j.attributes))
	orig := make(map[string][]string, len(j.attributes))
	for k, v := range j.attributes {
		norm[k] = v.GetForJSON()
		orig[k] = v.Orig()
	}
	return norm, orig
}

func (e *ModifyEntry) Clone() *ModifyEntry {
	clone := &ModifyEntry{
		schemaMap:        e.schemaMap,
		dn:               e.dn,
		attributes:       map[string]*SchemaValue{},
		AddChangeLog:     map[string]*SchemaValue{},
		ReplaceChangeLog: map[string]*SchemaValue{},
		DelChangeLog:     map[string]*SchemaValue{},
		dbEntryID:        e.dbEntryID,
	}
	for k, v := range e.attributes {
		clone.attributes[k] = v.Clone()
	}

	return clone
}

func (e *ModifyEntry) ModifyRDN(newDN *DN) *ModifyEntry {
	m := e.Clone()
	m.SetDN(newDN)

	return m
}
