package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
)

var (
	findByDNStmt     *sqlx.NamedStmt
	findCredByDNStmt *sqlx.NamedStmt
	baseSearchStmt   *sqlx.NamedStmt
)

// For generic filter
type FilterStmtMap struct {
	sm sync.Map
}

func (m *FilterStmtMap) Get(key string) (*sqlx.NamedStmt, bool) {
	val, ok := m.sm.Load(key)
	if !ok {
		return nil, false
	}
	return val.(*sqlx.NamedStmt), true
}

func (m *FilterStmtMap) Put(key string, value *sqlx.NamedStmt) {
	m.sm.Store(key, value)
}

var filterStmtMap FilterStmtMap

type Entry struct {
	Id        int            `db:"id"`
	Dn        string         `db:"dn"`
	Path      string         `db:"path"`
	EntryUUID string         `db:"uuid"`
	Created   time.Time      `db:"created"`
	Updated   time.Time      `db:"updated"`
	Attrs     types.JSONText `db:"attrs"`
	Count     int32          `db:"count"`
}

func initStmt(db *sqlx.DB) error {
	var err error

	findByDNStmt, err = db.PrepareNamed("SELECT id, attrs FROM ldap_entry WHERE LOWER(dn) = LOWER(:dn)")
	if err != nil {
		return err
	}

	findCredByDNStmt, err = db.PrepareNamed("SELECT attrs->>'userPassword' FROM ldap_entry WHERE LOWER(dn) = LOWER(:dn)")
	if err != nil {
		return err
	}

	baseSearchStmt, err = db.PrepareNamed("SELECT * FROM ldap_entry WHERE LOWER(dn) = LOWER(:baseDN)")
	if err != nil {
		return err
	}

	return nil
}

func findByDN(tx *sqlx.Tx, dn *DN) (*Entry, error) {
	entry := Entry{}
	err := tx.NamedStmt(findByDNStmt).Get(&entry, map[string]interface{}{
		"dn": dn.DN,
	})
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func findCredByDN(dn *DN) (string, error) {
	var bindUserCred string
	err := findCredByDNStmt.Get(&bindUserCred, map[string]interface{}{
		"dn": dn.DN,
	})
	if err != nil {
		return "", err
	}
	return bindUserCred, nil
}

func getBaseSearch(baseDN *DN) (*Entry, error) {
	var entry Entry
	err := baseSearchStmt.Get(&entry, map[string]interface{}{
		"baseDN": baseDN.DN,
	})
	// including not found
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func findByFilter(pathQuery string, q *Query) (*sqlx.Rows, error) {
	var query string
	if q.Query != "" {
		query = " AND " + q.Query
	}

	fetchQuery := fmt.Sprintf(`SELECT *, count(id) over() as count FROM ldap_entry WHERE %s %s LIMIT :pageSize OFFSET :offset`, pathQuery, query)

	log.Printf("Fetch Query: %s Params: %v", fetchQuery, q.Params)

	var fetchStmt *sqlx.NamedStmt
	var ok bool
	var err error
	if fetchStmt, ok = filterStmtMap.Get(fetchQuery); !ok {
		// cache
		fetchStmt, err = db.PrepareNamed(fetchQuery)
		if err != nil {
			return nil, err
		}
		filterStmtMap.Put(fetchQuery, fetchStmt)
	}

	var rows *sqlx.Rows
	rows, err = fetchStmt.Queryx(q.Params)
	if err != nil {
		return nil, err
	}

	return rows, nil
}

// func countOneByFilter(tx *sqlx.Tx, q *Query) (int, error) {
// 	var count int
// 	err := tx.NamedStmt(findByDNStmt).Get(&entry, map[string]interface{}{
// 		"dn": dn.DN,
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &entry, nil
// }

var useAssociationTable bool

func updateAssociation(tx *sqlx.Tx, ownerDN *DN, ownerJsonMap map[string]interface{}) error {
	if useAssociationTable {
		ownerEntry, err := findByDN(tx, ownerDN)
		if err != nil {
			log.Printf("Failed to get owner entry: %v", err)
			return err
		}
		resolveAssociation(tx, ownerEntry.Id, ownerJsonMap)
	} else {
		resolveMember(tx, ownerDN, ownerJsonMap)
	}
	return nil
}

func resolveMember(tx *sqlx.Tx, ownerDN *DN, jsonMap map[string]interface{}) {
	log.Printf("resolveMember dn: %s", ownerDN)
	if members, ok := jsonMap["member"]; ok {
		log.Printf("members %#v", members)
		if marr, ok := members.([]interface{}); ok {
			for _, mem := range marr {
				log.Printf("memberDN %#v", mem)

				var memberDN *DN
				var err error
				if memDN, ok := mem.(string); ok {
					if memberDN, err = normalizeDN(memDN); err != nil {
						log.Printf("error: Invalid member, can't normalize dn: %#v", err)
						continue
					}
				} else {
					log.Printf("error: Invalid member, not string dn: %#v", err)
					continue
				}

				entry, err := findByDN(tx, memberDN)

				if err != nil {
					log.Printf("error: Search member memberDN: %s error: %#v", memberDN.DN, err)
					continue
				}

				log.Printf("merging memberOf: %+v addDN: %s", entry.Attrs, ownerDN.DN)

				err = mergeMemberOf(entry, ownerDN)
				if err != nil {
					log.Printf("error: Merge memberOf error: %#v", err)
					continue
				}

				log.Printf("merged memberOf: %+v", entry.Attrs)

				_, err = tx.NamedExec(`UPDATE ldap_entry SET attrs = :attrs WHERE id = :id`, map[string]interface{}{
					"id":    entry.Id,
					"attrs": entry.Attrs,
				})
				if err != nil {
					log.Printf("error: Faild to modify memberOf dn: %s err: %#v", entry.Dn, err)
					continue
				}
			}
		}
	}
}

func updateOwnerAssociation(tx *sqlx.Tx, subjectDN *DN, jsonMap map[string]interface{}) error {
	log.Printf("updateOwnerAssociation subjectDN: %s", subjectDN)
	if memberOfs, ok := jsonMap["memberOf"]; ok {
		log.Printf("memberOfs %#v", memberOfs)
		if marr, ok := memberOfs.([]interface{}); ok {
			for _, mem := range marr {
				log.Printf("memberOfDN %#v", mem)

				var memberOfDN *DN
				var err error
				if memOfDN, ok := mem.(string); ok {
					if memberOfDN, err = normalizeDN(memOfDN); err != nil {
						log.Printf("error: Invalid memberOf, can't normalize dn: %#v", err)
						continue
					}
				} else {
					log.Printf("error: Invalid memberOf, not string dn: %#v", err)
					continue
				}

				entry, err := findByDN(tx, memberOfDN)

				if err != nil {
					log.Printf("error: Search memberOf memberOfDN: %s error: %#v", memberOfDN.DN, err)
					continue
				}

				log.Printf("merging member: %+v addDN: %s", entry.Attrs, subjectDN.DN)

				err = mergeMember(entry, subjectDN)
				if err != nil {
					log.Printf("error: Merge member error: %#v", err)
					continue
				}

				log.Printf("merged member: %+v", entry.Attrs)

				_, err = tx.NamedExec(`UPDATE ldap_entry SET attrs = :attrs WHERE id = :id`, map[string]interface{}{
					"id":    entry.Id,
					"attrs": entry.Attrs,
				})
				if err != nil {
					log.Printf("error: Faild to modify member dn: %s err: %#v", entry.Dn, err)
					continue
				}
			}
		}
	}
	return nil
}

func mergeMember(entry *Entry, subjectDN *DN) error {
	return appendDNArray(entry, subjectDN, "member")
}

func mergeMemberOf(entry *Entry, ownerDN *DN) error {
	return appendDNArray(entry, ownerDN, "memberOf")
}

func deleteMemberOf(entry *Entry, ownerDN *DN) error {
	return deleteDNArray(entry, ownerDN, "memberOf")
}

func appendDNArray(entry *Entry, dn *DN, attrName string) error {
	jsonMap := map[string]interface{}{}
	entry.Attrs.Unmarshal(&jsonMap)

	if val, ok := jsonMap[attrName]; ok {
		if valarr, ok := val.([]interface{}); ok {
			found := false
			for _, v := range valarr {
				if vv, ok := v.(string); ok {
					log.Printf("Check %s == %s", vv, dn.DN)
					if strings.ToLower(vv) == strings.ToLower(dn.DN) {
						found = true
						break
					}
				}
			}
			if !found {
				valarr = append(valarr, dn.DN)
			}
			jsonMap[attrName] = valarr
		}
	} else {
		// Nothing, add dn
		jsonMap[attrName] = []string{dn.DN}
	}

	attrs, err := json.Marshal(jsonMap)

	if err != nil {
		return err
	}

	jsonText := types.JSONText(string(attrs))
	entry.Attrs = jsonText

	return nil
}

func deleteDNArray(entry *Entry, dn *DN, attrName string) error {
	jsonMap := map[string]interface{}{}
	entry.Attrs.Unmarshal(&jsonMap)

	if val, ok := jsonMap[attrName]; ok {
		if valarr, ok := val.([]interface{}); ok {
			newarr := []string{}
			for _, v := range valarr {
				if vv, ok := v.(string); ok {
					log.Printf("Check %s == %s", vv, dn.DN)
					if strings.ToLower(vv) != strings.ToLower(dn.DN) {
						newarr = append(newarr, vv)
					}
				}
			}
			jsonMap[attrName] = newarr
		}
	}

	attrs, err := json.Marshal(jsonMap)

	if err != nil {
		return err
	}

	jsonText := types.JSONText(string(attrs))
	entry.Attrs = jsonText

	return nil
}

func resolveAssociation(tx *sqlx.Tx, ownerId int, jsonMap map[string]interface{}) {
	log.Printf("resolveAssociation id: %d", ownerId)
	if members, ok := jsonMap["member"]; ok {
		log.Printf("members %#v", members)
		if marr, ok := members.([]interface{}); ok {
			for _, mem := range marr {
				log.Printf("memberDN %#v", mem)

				var memberDN *DN
				var err error
				if memDN, ok := mem.(string); ok {
					if memberDN, err = normalizeDN(memDN); err != nil {
						log.Printf("error: Invalid member, can't normalize dn: %#v", err)
						continue
					}
				} else {
					log.Printf("error: Invalid member, not string dn: %#v", err)
					continue
				}

				entry, err := findByDN(tx, memberDN)

				if err != nil {
					log.Printf("error: Search member memberDN: %s error: %#v", memberDN.DN, err)
					continue
				}

				_, err = tx.NamedExec(`INSERT INTO relation (attr, ownerId, itemId) VALUES ('member', :ownerId, :itemId)`, map[string]interface{}{
					"ownerId": ownerId,
					"itemId":  entry.Id,
				})

				if err != nil {
					log.Printf("error: Faild to add association id: %d itemId: %d  err: %#v", ownerId, entry.Id, err)
					continue
				}
			}
		}
	}
}
