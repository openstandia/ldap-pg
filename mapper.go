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
	server    *Server
	schemaMap SchemaMap
}

func NewMapper(server *Server, s SchemaMap) *Mapper {
	return &Mapper{
		server:    server,
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
			log.Printf("warn: Invalid attribute. attrName: %s, err: %s", k, err)
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
	norm, orig := entry.Attrs()

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

	// TODO move to schema?
	delete(norm, "member")
	delete(orig, "member")
	delete(norm, "uniqueMember")
	delete(orig, "uniqueMember")

	delete(norm, "entryUUID")
	delete(orig, "entryUUID")

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	dbEntry := &DBEntry{
		DNNorm:    entry.DN().DNNormStr(),
		DNOrig:    entry.DN().DNOrigStr(),
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

	// TODO move to schema?
	delete(norm, "member")
	delete(orig, "member")
	delete(norm, "uniqueMember")
	delete(orig, "uniqueMember")

	delete(norm, "entryUUID")
	delete(orig, "entryUUID")

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	updated := time.Now()

	dbEntry := &DBEntry{
		ID:        entry.dbEntryId,
		Updated:   updated,
		AttrsNorm: types.JSONText(string(bNorm)),
		AttrsOrig: types.JSONText(string(bOrig)),
	}

	return dbEntry, nil
}

func (m *Mapper) ModifyEntryToAddEntry(entry *ModifyEntry) (*AddEntry, error) {
	add := NewAddEntry(entry.DN())

	// TODO

	return add, nil
}

func (m *Mapper) FetchedDBEntryToSearchEntry(dbEntry *FetchedDBEntry, dnOrigCache map[int64]string) (*SearchEntry, error) {
	if !dbEntry.IsDC() && dbEntry.DNOrig == "" {
		log.Printf("error: Invalid state. FetchedDBEntiry mush have DNOrig always...")
		return nil, NewUnavailable()
	}

	dn, err := m.normalizeDN(dbEntry.DNOrig)
	if err != nil {
		return nil, err
	}
	orig := dbEntry.GetAttrsOrig()
	orig["entryUUID"] = []string{dbEntry.EntryUUID}
	orig["createTimestamp"] = []string{dbEntry.Created.In(time.UTC).Format(TIMESTAMP_FORMAT)}
	orig["modifyTimestamp"] = []string{dbEntry.Updated.In(time.UTC).Format(TIMESTAMP_FORMAT)}

	// member
	members, err := dbEntry.Members(dnOrigCache, m.server.SuffixOrigStr())
	if err != nil {
		log.Printf("warn: Invalid state. FetchedDBEntiry cannot resolve member DN. err: %+v", err)
		// TODO busy?
		return nil, NewUnavailable()
	}
	for k, v := range members {
		orig[k] = v
	}

	// memberOf
	memberOfs, err := dbEntry.MemberOfs(dnOrigCache, m.server.SuffixOrigStr())
	if err != nil {
		log.Printf("warn: Invalid state. FetchedDBEntiry cannot resolve memberOf DN. err: %+v", err)
		// TODO busy?
		return nil, NewUnavailable()
	}
	orig["memberOf"] = memberOfs

	readEntry := NewSearchEntry(dn, orig)

	return readEntry, nil
}

func (m *Mapper) FetchedDBEntryToModifyEntry(dbEntry *FetchedDBEntry, dnOrigCache map[int64]string) (*ModifyEntry, error) {
	dn, err := m.normalizeDN(dbEntry.DNOrig)
	if err != nil {
		return nil, err
	}
	orig := dbEntry.GetAttrsOrig()

	members, err := dbEntry.Members(dnOrigCache, "") // For modification, don't need suffix
	for k, v := range members {
		orig[k] = v
	}

	entry, err := NewModifyEntry(dn, orig)
	if err != nil {
		return nil, err
	}
	entry.dbEntryId = dbEntry.ID
	entry.dbParentID = dbEntry.ParentID

	return entry, nil
}

func (m *Mapper) normalizeDN(dn string) (*DN, error) {
	return m.server.NormalizeDN(dn)
}
