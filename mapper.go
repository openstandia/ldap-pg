package main

import (
	// "fmt"
	"encoding/json"
	"log"
	"time"

	"github.com/jmoiron/sqlx/types"
	"github.com/openstandia/goldap/message"
)

type Mapper struct {
	schemaMap SchemaMap
}

func NewMapper(s SchemaMap) *Mapper {
	return &Mapper{
		schemaMap: s,
	}
}

func (m *Mapper) LDAPMessageToAddEntry(dn *DN, ldapAttrs message.AttributeList) (*AddEntry, error) {
	entry := NewAddEntry(dn)

	for _, attr := range ldapAttrs {
		k := attr.Type_()
		attrName := string(k)

		arr := make([]string, len(attr.Vals()))
		for i, v := range attr.Vals() {
			arr[i] = string(v)
		}

		err := entry.Add(attrName, arr)
		if err != nil {
			log.Printf("warn: Invalid attribute. attrName: %s err: %s", k, err)
			return nil, err
		}
	}

	err := entry.Validate()
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func (m *Mapper) AddEntryToDBEntry(entry *AddEntry) (*DBEntry, error) {
	norm, orig := entry.GetAttrs()

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	// Already validated, ignore error
	created, _ := time.Parse(norm["createTimestamp"].(string), TIMESTAMP_FORMAT)
	updated, _ := time.Parse(norm["modifyTimestamp"].(string), TIMESTAMP_FORMAT)

	dbEntry := &DBEntry{
		DNNorm:    entry.GetDN().DNNorm,
		Path:      entry.GetDN().ReverseParentDN,
		EntryUUID: norm["entryUUID"].(string),
		Created:   created,
		Updated:   updated,
		AttrsNorm: types.JSONText(string(bNorm)),
		AttrsOrig: types.JSONText(string(bOrig)),
	}

	return dbEntry, nil
}

func (m *Mapper) ModifyEntryToDBEntry(entry *ModifyEntry) (*DBEntry, error) {
	norm, orig := entry.GetAttrs()

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	// modifyTimstamp will be updated by now() in SQL

	dbEntry := &DBEntry{
		Id:        entry.dbEntryId,
		AttrsNorm: types.JSONText(string(bNorm)),
		AttrsOrig: types.JSONText(string(bOrig)),
	}

	return dbEntry, nil
}

func (m *Mapper) FetchedDBEntryToSearchEntry(dbEntry *FetchedDBEntry) (*SearchEntry, error) {
	dn, err := normalizeDN(dbEntry.DNNorm)
	if err != nil {
		return nil, err
	}
	orig := dbEntry.GetAttrsOrig()
	// orig["entryUUID"] = []string{dbEntry.EntryUUID}
	// orig["createTimestamp"] = []string{dbEntry.Created.Format(TIMESTAMP_FORMAT)}
	// orig["modifyTimestamp"] = []string{dbEntry.Updated.Format(TIMESTAMP_FORMAT)}

	readEntry := NewSearchEntry(dn, orig)

	return readEntry, nil
}

func (m *Mapper) FetchedDBEntryToModifyEntry(dbEntry *FetchedDBEntry) (*ModifyEntry, error) {
	dn, err := normalizeDN(dbEntry.DNNorm)
	if err != nil {
		return nil, err
	}
	orig := dbEntry.GetAttrsOrig()
	// orig["entryUUID"] = []string{dbEntry.EntryUUID}
	// orig["createTimestamp"] = []string{dbEntry.Created.Format(TIMESTAMP_FORMAT)}
	// orig["modifyTimestamp"] = []string{dbEntry.Updated.Format(TIMESTAMP_FORMAT)}

	entry, err := NewModifyEntry(dn, orig)
	if err != nil {
		return nil, err
	}
	entry.dbEntryId = dbEntry.Id

	return entry, nil
}

// func (m *Mapper) DBEntryToEntry(dbEntry *DBEntry) (*Entry, error) {
// 	dn, err := normalizeDN(dbEntry.DNNorm)
// 	if err != nil {
// 		return nil, err
// 	}
// 	orig := dbEntry.GetAttrsOrig()
// 	orig["entryUUID"] = []string{dbEntry.EntryUUID}
// 	orig["createTimestamp"] = []string{dbEntry.Created.Format(TIMESTAMP_FORMAT)}
// 	orig["modifyTimestamp"] = []string{dbEntry.Updated.Format(TIMESTAMP_FORMAT)}
//
// 	entry, err := NewEntryWithValues(dn, orig)
// 	if err != nil {
// 		return nil, err
// 	}
// 	entry.dbEntryId = dbEntry.Id
//
// 	return entry, nil
// }

// func (m *Mapper) ToEntry(dn *DN, ldapAttrs message.AttributeList) (*Entry, error) {
// 	entryUUID, _ := uuid.NewRandom()
// 	createTimestamp := time.Now()
// 	modifyTimestamp := createTimestamp
//
// 	jsonAttrs := Entry{}
//
// 	// Store RDN into attrs
// 	rdn := dn.GetRDN()
// 	for k, v := range rdn {
// 		s, ok := m.schemaMap.Get(k)
// 		if !ok {
// 			log.Printf("warn: Invalid rdn. attrName: %s", k)
// 			return nil, NewInvalidDNSyntax()
// 		}
// 		if s.SingleValue {
// 			jsonAttrs[s.Name] = v
// 		} else {
// 			jsonAttrs[s.Name] = []interface{}{v}
// 		}
// 	}
//
// 	for _, attr := range ldapAttrs {
// 		k := attr.Type_()
// 		attrName := string(k)
//
// 		arr := make([]string, len(attr.Vals()))
// 		for i, v := range attr.Vals() {
// 			arr[i] = string(v)
// 		}
//
// 		sv, err := NewSchemaValue(attrName, arr)
// 		if err != nil {
// 			// TODO check classObject and return error response
// 			log.Printf("warn: Invalid attribute name. attrName: %s err: %s", k, err)
// 			return nil, fmt.Errorf("Unsupported attribute name: %s", k)
// 		}
//
// 		if err := sv.Validate(); err != nil {
// 			log.Printf("warn: Invalid syntax. attrName: %s attrValue: %s err: %s", k, sv.Get(), err)
// 			return err
// 		}
//
// 		var err error
// 		// TODO strict mode
// 		if s.Name == "entryUUID" {
// 			entryUUID, err = uuid.Parse(string(attr.Vals()[0]))
// 			if err != nil {
// 				log.Printf("warn: Invalid entryUUID %s", attr.Vals()[0])
// 				return nil, err
// 			}
// 			continue
// 		}
// 		// TODO strict mode
// 		if s.Name == "createTimestamp" {
// 			createTimestamp, err = time.Parse(TIMESTAMP_FORMAT, string(attr.Vals()[0]))
// 			if err != nil {
// 				log.Printf("warn: Invalid createTimestamp %s, err: %s", attr.Vals()[0], err)
// 				return nil, err
// 			}
// 			continue
// 		}
// 		// TODO strict mode
// 		if s.Name == "modifyTimestamp" {
// 			modifyTimestamp, err = time.Parse(TIMESTAMP_FORMAT, string(attr.Vals()[0]))
// 			if err != nil {
// 				log.Printf("warn: Invalid modifyTimestamp %s, err: %s", attr.Vals()[0], err)
// 				return nil, err
// 			}
// 			continue
// 		}
//
// 		mapAttributeValue(s, attr, jsonAttrs)
// 	}
//
// 	entry := NewEntry(dn, jsonAttrs)
// 	entry.EntryUUID = entryUUID.String()
// 	entry.Created = createTimestamp
// 	entry.Updated = modifyTimestamp
//
// 	return entry, nil
// }

// func mapAttributeValue(s *Schema, attr message.Attribute, jsonAttrs Entry) {
// 	if s.SingleValue {
// 		jsonAttrs[s.Name] = string(attr.Vals()[0])
// 	} else {
// 		arr := []interface{}{}
// 		for _, v := range attr.Vals() {
// 			arr = append(arr, string(v))
// 		}
// 		jsonAttrs[s.Name] = arr
// 	}
// }
