package main

import (
	// "fmt"

	"log"
	"strconv"

	"github.com/openstandia/goldap/message"
)

type Mapper struct {
	server *Server
}

func NewMapper(server *Server) *Mapper {
	return &Mapper{
		server: server,
	}
}

func (m *Mapper) LDAPMessageToAddEntry(dn *DN, ldapAttrs message.AttributeList) (*AddEntry, error) {
	entry := NewAddEntry(m.server.schemaMap, dn)

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

// TODO move to schema?
func removeComputedAttrs(orig map[string][]string) {
	delete(orig, "member")
	delete(orig, "uniqueMember")
	// delete(orig, "createTimestamp")
	// delete(orig, "modifyTimestamp")
	// delete(orig, "entryUUID")
}

func uniqueIDs(target []int64) []string {
	m := map[int64]bool{}
	result := []string{}

	for _, v := range target {
		if !m[v] {
			m[v] = true
			result = append(result, strconv.FormatInt(v, 10))
		}
	}

	return result
}

func (m *Mapper) ModifyEntryToAddEntry(entry *ModifyEntry) (*AddEntry, error) {
	add := NewAddEntry(m.server.schemaMap, entry.DN())

	// TODO

	return add, nil
}

func (m *Mapper) FetchedDBEntryToSearchEntry(dbEntry *SimpleFetchedDBEntry, IdToDNOrigCache map[int64]string) (*SearchEntry, error) {
	if dbEntry.DNOrig == "" {
		log.Printf("error: Invalid state. FetchedDBEntiry mush have DNOrig always...")
		return nil, NewUnavailable()
	}

	dn, err := m.normalizeDN(dbEntry.DNOrig)
	if err != nil {
		return nil, err
	}
	orig := dbEntry.AttrsOrig()
	// orig["entryUUID"] = []string{dbEntry.EntryUUID}
	// orig["createTimestamp"] = []string{dbEntry.Created.In(time.UTC).Format(TIMESTAMP_FORMAT)}
	// orig["modifyTimestamp"] = []string{dbEntry.Updated.In(time.UTC).Format(TIMESTAMP_FORMAT)}

	// member
	members, err := dbEntry.Member(m.server.repo, IdToDNOrigCache)
	if err != nil {
		log.Printf("warn: Invalid state. FetchedDBEntiry cannot resolve member DN. err: %+v", err)
		// TODO busy?
		return nil, NewUnavailable()
	}
	if len(members) > 0 {
		orig["member"] = members
	}
	// for k, v := range members {
	// 	orig[k] = v
	// }

	// memberOf
	memberOfs, err := dbEntry.MemberOf(m.server.repo, IdToDNOrigCache)
	if err != nil {
		log.Printf("warn: Invalid state. FetchedDBEntiry cannot resolve memberOf DN. err: %+v", err)
		// TODO busy?
		return nil, NewUnavailable()
	}
	orig["memberOf"] = memberOfs

	// hasSubordinates
	if dbEntry.HasSubordinates != "" {
		orig["hasSubordinates"] = []string{dbEntry.HasSubordinates}
	}

	readEntry := NewSearchEntry(m.server.schemaMap, dn, orig)

	return readEntry, nil
}

func (m *Mapper) FetchedEntryToModifyEntry(dbEntry *FetchedEntry) (*ModifyEntry, error) {
	dn, err := m.normalizeDN(dbEntry.DNOrig)
	if err != nil {
		return nil, err
	}
	orig := dbEntry.GetAttrsOrig()

	entry, err := NewModifyEntry(m.server.schemaMap, dn, orig)
	if err != nil {
		return nil, err
	}
	entry.dbEntryID = dbEntry.ID
	entry.dbParentID = dbEntry.ParentID
	entry.hasSub = dbEntry.HasSub
	entry.path = dbEntry.Path

	return entry, nil
}

func (m *Mapper) normalizeDN(dn string) (*DN, error) {
	return m.server.NormalizeDN(dn)
}
