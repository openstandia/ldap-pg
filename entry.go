package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx/types"
)

type Entry struct {
	Id        int64          `db:"id"`
	Dn        string         `db:"dn"`
	Path      string         `db:"path"`
	EntryUUID string         `db:"uuid"`
	Created   time.Time      `db:"created"`
	Updated   time.Time      `db:"updated"`
	RawAttrs  types.JSONText `db:"attrs"`
	Count     int32          `db:"count"`
	jsonAttrs JSONAttrs
}

func NewEntry(dn *DN, jsonAttrs JSONAttrs) *Entry {
	return &Entry{
		Dn:        dn.DN,
		Path:      dn.ReverseParentDN,
		jsonAttrs: jsonAttrs,
	}
}

type diffAttr struct {
	add []string
	del []string
}

func calcDiffAttr(from, to *Entry, attrName string) *diffAttr {
	fromAttrs, _ := from.GetAttr(attrName)
	toAttrs, _ := to.GetAttr(attrName)

	fromMap := make(map[string]struct{}, len(fromAttrs))
	toMap := make(map[string]struct{}, len(toAttrs))

	for _, v := range fromAttrs {
		fromMap[v] = struct{}{}
	}

	diff := &diffAttr{}

	for _, v := range toAttrs {
		toMap[v] = struct{}{}
		if _, found := fromMap[v]; !found {
			diff.add = append(diff.add, v)
		}
	}

	for _, v := range fromAttrs {
		if _, found := toMap[v]; !found {
			diff.del = append(diff.del, v)
		}
	}

	return diff
}

func (e *Entry) ModifyDN(newDN *DN) (*Entry, error) {
	clone := e.Clone()
	clone.Dn = newDN.DN
	clone.Path = newDN.ReverseParentDN

	// Store RDN into attrs
	rdn := newDN.GetRDN()
	for k, v := range rdn {
		// TODO
		s, ok := schemaMap.Get(k)
		if !ok {
			log.Printf("warn: Invalid rdn. attrName: %s", k)
			return nil, NewInvalidDNSyntax()
		}
		if s.SingleValue {
			clone.jsonAttrs[s.Name] = v
		} else {
			// TODO replace old RDN
			clone.jsonAttrs[s.Name] = []interface{}{v}
		}
	}
	return clone, nil
}

func (e *Entry) Clone() *Entry {
	clone := &Entry{
		Id:        e.Id,
		Dn:        e.Dn,
		Path:      e.Path,
		Created:   e.Created,
		Updated:   e.Updated,
		jsonAttrs: JSONAttrs{},
	}
	for k, v := range e.GetAttrs() {
		if vv, ok := v.([]interface{}); ok {
			vvv := make([]interface{}, len(vv))
			copy(vvv, vv)
			clone.jsonAttrs[k] = vvv
		} else {
			clone.jsonAttrs[k] = v
		}
	}

	return clone
}

func (e *Entry) Clear() {
	e.Id = 0
	e.Dn = ""
	e.Path = ""
	e.EntryUUID = ""
	e.Created = time.Time{}
	e.Updated = time.Time{}
	e.RawAttrs = types.JSONText{}
	e.Count = 0
	e.jsonAttrs = JSONAttrs{}
}

func (e *Entry) GetAttrs() JSONAttrs {
	if len(e.jsonAttrs) == 0 {
		jsonMap := JSONAttrs{}
		e.RawAttrs.Unmarshal(&jsonMap)
		e.jsonAttrs = jsonMap
	}
	return e.jsonAttrs
}

func (e *Entry) SetAttrs(jsonAttrs JSONAttrs) {
	e.jsonAttrs = jsonAttrs
	e.RawAttrs = types.JSONText{}
}

func (e *Entry) GetRawAttrs() types.JSONText {
	// TODO cache?
	b, _ := json.Marshal(&e.jsonAttrs)
	jsonText := types.JSONText(string(b))
	e.RawAttrs = jsonText
	return e.RawAttrs
}

func (e *Entry) GetAttr(attrName string) ([]string, bool) {
	if e == nil {
		return make([]string, 0), true
	}

	s, ok := schemaMap.Get(attrName)
	if !ok {
		return nil, false
	}

	v := getColumnValue(e, s.Name)
	if v != "" {
		return []string{v}, true
	}

	if s.SingleValue {
		v, ok := e.GetAttrs().GetSingle(s)
		if !ok {
			return nil, false
		}
		return []string{v}, true
	} else {
		return e.GetAttrs().GetMultiValues(s)
	}
}

func getColumnValue(entry *Entry, s string) string {
	if s == "entryUUID" {
		return entry.EntryUUID
	} else if s == "createTimestamp" {
		return entry.Created.Format(TIMESTAMP_FORMAT)
	} else if s == "modifyTimestamp" {
		return entry.Updated.Format(TIMESTAMP_FORMAT)
	}
	return ""
}

func (e *Entry) HasAttr(attrName string) bool {
	s, ok := schemaMap.Get(attrName)
	if !ok {
		return false
	}

	key := s.Name
	if key == "entryUUID" ||
		key == "createTimestamp" ||
		key == "modifyTimestamp" {
		return true
	}

	jsonAttrs := e.GetAttrs()
	return jsonAttrs.HasKey(s)
}

func (e *Entry) HasAllValues(attrName string, values []string) bool {
	s, ok := schemaMap.Get(attrName)
	if !ok {
		return false
	}

	if s.SingleValue {
		current, ok := e.GetAttrs().GetSingle(s)
		if !ok {
			return false
		}
		for _, v := range values {
			// TODO Schema aware
			if current != v {
				return false
			}
		}
	} else {
		current, ok := e.GetAttrs().GetMultiValues(s)
		if !ok {
			return false
		}
		m := make(map[string]struct{}, len(current))
		for _, v := range current {
			m[v] = struct{}{}
		}
		for _, v := range values {
			// TODO Schema aware
			if _, ok := m[v]; !ok {
				return false
			}
		}
	}
	return true
}

func (e *Entry) AddAttrs(attrName string, values []string) error {
	s, ok := schemaMap.Get(attrName)
	if !ok {
		return NewUndefinedType(attrName)
	}

	if s.SingleValue {
		if len(values) > 1 {
			log.Printf("warn: Failed to modify/add because of adding multiple values to single-value attribute. dn: %s ", e.Dn)
			return NewMultipleValuesProvidedError(s.Name)
		}
		if e.HasAttr(s.Name) {
			log.Printf("warn: Failed to modify/add because of adding a value to single-value attribute which has a value already. dn: %s ", e.Dn)
			return NewMultipleValuesConstraintViolation(s.Name)
		}
		return e.putSingle(s, values[0])

	} else {
		if i, ok := hasDuplicate(s, values); ok {
			return NewMoreThanOnceError(s.Name, i)
		}
		return e.putMultiValues(s, values)
	}
	return nil
}

func (e *Entry) DeleteAttrs(attrName string, values []string) error {
	s, ok := schemaMap.Get(attrName)
	if !ok {
		return NewUndefinedType(attrName)
	}

	if len(values) == 0 {
		if !e.HasAttr(s.Name) {
			log.Printf("warn: Failed to modify/delete because of no attribute. dn: %s", e.Dn)
			return NewNoSuchAttribute("modify/delete", s.Name)
		}
		return e.removeAll(s)
	} else {
		if !e.HasAllValues(s.Name, values) {
			return NewNoSuchAttribute("modify/delete", attrName)
		}
		return e.remove(s, values)
	}
}

func (e *Entry) ReplaceAttrs(attrName string, values []string) error {
	s, ok := schemaMap.Get(attrName)
	if !ok {
		return NewUndefinedType(attrName)
	}

	if len(values) == 0 {
		// replace doesn't care if the attribute has value
		return e.removeAll(s)
	}

	if s.SingleValue {
		if len(values) > 1 {
			return NewMultipleValuesProvidedError(s.Name)
		}
		return e.replaceSingle(s, values[0])
	} else {
		return e.replaceMultiValues(s, values)
	}
}

func (e *Entry) putSingle(s *Schema, value string) error {
	attrName := s.Name

	// TODO More syntax validation

	if attrName == "entryUUID" {
		entryUUID, err := uuid.Parse(value)
		if err != nil {
			log.Printf("warn: Invalid entryUUID: %s", value)
			// TODO
			return NewInvalidPerSyntax(attrName, 0)
		}
		e.EntryUUID = entryUUID.String()
		return nil
	} else if attrName == "createTimestamp" {
		createTimestamp, err := time.Parse(TIMESTAMP_FORMAT, value)
		if err != nil {
			log.Printf("warn: Invalid createTimestamp %s, err: %s", value, err)
			return NewInvalidPerSyntax(attrName, 0)
		}
		e.Created = createTimestamp
		return nil
	} else if attrName == "modifyTimestamp" {
		modifyTimestamp, err := time.Parse(TIMESTAMP_FORMAT, value)
		if err != nil {
			log.Printf("warn: Invalid modifyTimestamp %s, err: %s", value, err)
			return NewInvalidPerSyntax(attrName, 0)
		}
		e.Updated = modifyTimestamp
		return nil
	} else {
		return e.GetAttrs().PutSingle(s, value)
	}
}

func (e *Entry) putMultiValues(s *Schema, values []string) error {
	return e.GetAttrs().MergeMultiValues(s, values)
}

func (e *Entry) removeAll(s *Schema) error {
	return e.GetAttrs().RemoveAll(s)
}

func (e *Entry) remove(s *Schema, values []string) error {
	return e.GetAttrs().Remove(s, values)
}

func (e *Entry) replaceSingle(s *Schema, value string) error {
	return e.GetAttrs().ReplaceSingle(s, value)
}

func (e *Entry) replaceMultiValues(s *Schema, values []string) error {
	return e.GetAttrs().ReplaceMultiValues(s, values)
}

type JSONAttrs map[string]interface{}

func (j JSONAttrs) HasKey(s *Schema) bool {
	_, ok := j[s.Name]
	return ok
}

func (j JSONAttrs) PutSingle(s *Schema, value string) error {
	j[s.Name] = value
	return nil
}

func (j JSONAttrs) MergeMultiValues(s *Schema, values []string) error {
	current, ok := j[s.Name]
	if !ok {
		j[s.Name] = values
		return nil
	}

	if cmv, ok := current.([]interface{}); ok {
		cMap := arrayToMap(cmv)

		for i, v := range values {
			// TODO Schema aware
			if _, ok := cMap[v]; ok {
				// Duplicate error
				return NewTypeOrValueExists("modify/add", s.Name, i)
			}
			cmv = append(cmv, v)
		}

		j[s.Name] = cmv
	} else {
		// Value in DB isn't array
		return fmt.Errorf("%s is not array.", s.Name)
	}
	return nil
}

func (j JSONAttrs) RemoveAll(s *Schema) error {
	delete(j, s.Name)
	return nil
}

func (j JSONAttrs) Remove(s *Schema, values []string) error {
	m := make(map[string]struct{}, len(values))
	for _, v := range values {
		m[v] = struct{}{}
	}

	current, ok := j[s.Name]
	if !ok {
		return nil
	}

	if s.SingleValue {
		cv, ok := current.(string)
		if !ok {
			return fmt.Errorf("Found inconsistency. '%s' is defiend as single-value but the stored data is multi-value.", s.Name)
		}

		// TODO Schema aware
		if _, ok := m[cv]; ok {
			delete(j, s.Name)
		}
		return nil
	} else {
		carray, ok := current.([]interface{})
		if !ok {
			return fmt.Errorf("Found inconsistency. '%s' is defiend as multi-value but the stored data is single-value.", s.Name)
		}

		newValues := []string{}
		for _, v := range carray {
			// TODO Schema aware
			vs, ok := v.(string)
			if !ok {
				return fmt.Errorf("Found inconsistency. '%s' contains unknown data. value: %#v", s.Name, v)
			}

			if _, ok := m[vs]; !ok {
				newValues = append(newValues, vs)
			}
		}

		if len(newValues) > 0 {
			j[s.Name] = newValues
		} else {
			delete(j, s.Name)
		}
		return nil
	}
}

func (j JSONAttrs) GetSingle(s *Schema) (string, bool) {
	v, ok := j[s.Name]
	if !ok {
		return "", false
	}
	vs, ok := v.(string)
	if !ok {
		return "", false
	}
	return vs, true
}

func (j JSONAttrs) GetMultiValues(s *Schema) ([]string, bool) {
	v, ok := j[s.Name]
	if !ok {
		return nil, false
	}
	vs, ok := v.([]interface{})
	if !ok {
		return nil, false
	}
	rv := make([]string, len(vs))
	for i, v := range vs {
		rv[i] = v.(string)
	}
	return rv, true
}

func (j JSONAttrs) ReplaceSingle(s *Schema, value string) error {
	if value != "" {
		j[s.Name] = value
	} else {
		delete(j, s.Name)
	}
	return nil
}

func (j JSONAttrs) ReplaceMultiValues(s *Schema, values []string) error {
	j[s.Name] = values
	return nil
}
