package main

import (
	// "fmt"
	"encoding/json"
	"log"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
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

// AddEntryToDBEntry converts LDAP entry object to DB entry object.
// It handles metadata such as createTimistamp, modifyTimestamp and entryUUID.
// Also, it handles member and uniqueMember attributes.
func (m *Mapper) AddEntryToDBEntry(tx *sqlx.Tx, entry *AddEntry) (*DBEntry, []string, error) {
	norm, orig := entry.Attrs()

	created := time.Now()
	updated := created
	if _, ok := norm["createTimestamp"]; ok {
		// Already validated, ignore error
		created, _ = time.Parse(TIMESTAMP_FORMAT, norm["createTimestamp"].([]string)[0])
	}
	norm["createTimestamp"] = []int64{created.Unix()}
	orig["createTimestamp"] = []string{created.In(time.UTC).Format(TIMESTAMP_FORMAT)}

	if _, ok := norm["modifyTimestamp"]; ok {
		// Already validated, ignore error
		updated, _ = time.Parse(TIMESTAMP_FORMAT, norm["modifyTimestamp"].([]string)[0])
	}
	norm["modifyTimestamp"] = []int64{updated.Unix()}
	orig["modifyTimestamp"] = []string{updated.In(time.UTC).Format(TIMESTAMP_FORMAT)}

	// TODO strict mode
	if _, ok := norm["entryUUID"]; !ok {
		u, _ := uuid.NewRandom()
		norm["entryUUID"] = []string{u.String()}
		orig["entryUUID"] = []string{u.String()}
	}

	// Remove attributes to reduce attrs_orig column size
	removeComputedAttrs(orig)

	memberOf := []int64{}

	// Convert the value of member and uniqueMamber attributes, DN => int64
	if err := m.dnArrayToIDArray(tx, norm, "member", &memberOf); err != nil {
		return nil, nil, err
	}
	if err := m.dnArrayToIDArray(tx, norm, "uniqueMember", &memberOf); err != nil {
		return nil, nil, err
	}

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	dbEntry := &DBEntry{
		DNNorm:    entry.DN().DNNormStr(),
		DNOrig:    entry.DN().DNOrigStr(),
		AttrsNorm: types.JSONText(string(bNorm)),
		AttrsOrig: types.JSONText(string(bOrig)),
	}

	return dbEntry, uniqueIDs(memberOf), nil
}

// TODO move to schema?
func removeComputedAttrs(orig map[string][]string) {
	delete(orig, "member")
	delete(orig, "uniqueMember")
	// delete(orig, "createTimestamp")
	// delete(orig, "modifyTimestamp")
	// delete(orig, "entryUUID")
}

func (m *Mapper) dnArrayToIDArray(tx *sqlx.Tx, norm map[string]interface{}, attrName string, memberOf *[]int64) error {
	if members, ok := norm[attrName].([]string); ok && len(members) > 0 {

		rdnGroup := map[string][]string{}
		for i, v := range members {
			dn, err := NormalizeDN(v)
			if err != nil {
				log.Printf("warn: Failed to normalize DN: %s", v)
				return NewInvalidPerSyntax(attrName, i)
			}

			parentDNNorm := dn.ParentDN().DNNormStr()
			rdnGroup[parentDNNorm] = append(rdnGroup[parentDNNorm], dn.RDNNormStr())
		}

		memberIDs := []int64{}

		for k, v := range rdnGroup {
			parentDN, err := NormalizeDN(k)
			if err != nil {
				log.Printf("error: Unexpected normalize DN error. DN: %s, err: %v", k, err)
				return NewUnavailable()
			}
			fetchedParentDN, err := m.server.repo.FindDNByDNWithLock(tx, parentDN, true)
			if err != nil {
				if lerr, ok := err.(*LDAPError); ok {
					if lerr.IsNoSuchObjectError() {
						log.Printf("warn: No such object: %s", parentDN.DNNormStr())
						// TODO should be return error or special handling?
						return NewInvalidPerSyntax(attrName, 0)
					}
				}
				// System error
				return NewUnavailable()
			}

			ids, err := m.server.repo.FindIDsByParentIDAndRDNNorms(tx, fetchedParentDN.ID, v)
			if err != nil {
				return err
			}

			memberIDs = append(memberIDs, ids...)
			*memberOf = append(*memberOf, ids...)
		}

		// Replace with id member
		norm[attrName] = memberIDs
	}
	return nil
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

func (m *Mapper) ModifyEntryToDBEntry(tx *sqlx.Tx, entry *ModifyEntry) (*DBEntry, []string, error) {
	norm, orig := entry.GetAttrs()

	// Remove attributes to reduce attrs_orig column size
	removeComputedAttrs(orig)

	var memberOf []int64

	// Convert the value of member and uniqueMamber attributes, DN => int64
	if err := m.dnArrayToIDArray(tx, norm, "member", &memberOf); err != nil {
		return nil, nil, err
	}
	if err := m.dnArrayToIDArray(tx, norm, "uniqueMember", &memberOf); err != nil {
		return nil, nil, err
	}

	updated := time.Now()
	norm["modifyTimestamp"] = []int64{updated.Unix()}
	orig["modifyTimestamp"] = []string{updated.In(time.UTC).Format(TIMESTAMP_FORMAT)}

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	dbEntry := &DBEntry{
		ID:        entry.dbEntryID,
		Updated:   updated,
		AttrsNorm: types.JSONText(string(bNorm)),
		AttrsOrig: types.JSONText(string(bOrig)),
	}

	return dbEntry, uniqueIDs(memberOf), nil
}

func (m *Mapper) ModifyEntryToAddEntry(entry *ModifyEntry) (*AddEntry, error) {
	add := NewAddEntry(entry.DN())

	// TODO

	return add, nil
}

func (m *Mapper) FetchedDBEntryToSearchEntry(dbEntry *FetchedDBEntry, IdToDNOrigCache map[int64]string) (*SearchEntry, error) {
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

	readEntry := NewSearchEntry(dn, orig)

	return readEntry, nil
}

func (m *Mapper) FetchedEntryToModifyEntry(dbEntry *FetchedEntry) (*ModifyEntry, error) {
	dn, err := m.normalizeDN(dbEntry.DNOrig)
	if err != nil {
		return nil, err
	}
	orig := dbEntry.GetAttrsOrig()

	entry, err := NewModifyEntry(dn, orig)
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
