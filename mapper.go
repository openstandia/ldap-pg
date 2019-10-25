package main

import (
	// "fmt"
	"encoding/json"
	"log"
	"time"

	"github.com/google/uuid"
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

	created := time.Now()
	updated := created
	if _, ok := norm["createTimestamp"]; ok {
		// Already validated, ignore error
		created, _ = time.Parse(TIMESTAMP_FORMAT, norm["createTimestamp"].(string))
	}
	if _, ok := norm["modifyTimestamp"]; ok {
		// Already validated, ignore error
		updated, _ = time.Parse(TIMESTAMP_FORMAT, norm["modifyTimestamp"].(string))
	}

	// TODO strict mode
	var entryUUID string
	if e, ok := norm["entryUUID"]; ok {
		entryUUID = e.(string)
	} else {
		u, _ := uuid.NewRandom()
		entryUUID = u.String()
	}

	delete(norm, "entryUUID")
	delete(orig, "entryUUID")

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	dbEntry := &DBEntry{
		DNNorm:    entry.GetDN().DNNorm,
		Path:      entry.GetDN().ReverseParentDN,
		EntryUUID: entryUUID,
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

	updated := time.Now()

	dbEntry := &DBEntry{
		Id:        entry.dbEntryId,
		Updated:   updated,
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
	orig["createTimestamp"] = []string{dbEntry.Created.In(time.UTC).Format(TIMESTAMP_FORMAT)}
	orig["modifyTimestamp"] = []string{dbEntry.Updated.In(time.UTC).Format(TIMESTAMP_FORMAT)}

	readEntry := NewSearchEntry(dn, orig)

	return readEntry, nil
}

func (m *Mapper) FetchedDBEntryToModifyEntry(dbEntry *FetchedDBEntry) (*ModifyEntry, error) {
	dn, err := normalizeDN(dbEntry.DNNorm)
	if err != nil {
		return nil, err
	}
	orig := dbEntry.GetAttrsOrig()

	entry, err := NewModifyEntry(dn, orig)
	if err != nil {
		return nil, err
	}
	entry.dbEntryId = dbEntry.Id

	return entry, nil
}
