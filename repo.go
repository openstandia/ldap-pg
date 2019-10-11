package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/jmoiron/sqlx"
)

var (
	findByDNStmt         *sqlx.NamedStmt
	findByDNWithLockStmt *sqlx.NamedStmt
	findCredByDNStmt     *sqlx.NamedStmt
	baseSearchStmt       *sqlx.NamedStmt
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

func initStmt(db *sqlx.DB) error {
	var err error

	findByDNStmt, err = db.PrepareNamed("SELECT id, attrs FROM ldap_entry WHERE LOWER(dn) = LOWER(:dn)")
	if err != nil {
		return err
	}

	findByDNWithLockStmt, err = db.PrepareNamed("SELECT id, attrs FROM ldap_entry WHERE LOWER(dn) = LOWER(:dn) FOR UPDATE")
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

func insert(tx *sqlx.Tx, entry *Entry) (int64, error) {
	rows, err := tx.NamedQuery(`INSERT INTO ldap_entry (dn, path, uuid, created, updated, attrs) SELECT :dn, :path, :uuid, :created, :updated, :attrs WHERE NOT EXISTS (SELECT id FROM ldap_entry WHERE dn = :dn) RETURNING id`, map[string]interface{}{
		"dn":      entry.Dn,
		"path":    entry.Path,
		"uuid":    entry.EntryUUID,
		"created": entry.Created,
		"updated": entry.Updated,
		"attrs":   entry.GetRawAttrs(),
	})
	if err != nil {
		log.Printf("error: Failed to insert entry record. entry: %#v err: %v", entry, err)
		return 0, err
	}

	var id int64
	if rows.Next() {
		rows.Scan(&id)
	} else {
		return 0, NewAlreadyExists()
	}

	return id, nil
}

func update(tx *sqlx.Tx, entry *Entry) error {
	_, err := tx.NamedExec(`UPDATE ldap_entry SET updated = now(), attrs = :attrs WHERE id = :id`, map[string]interface{}{
		"id":    entry.Id,
		"attrs": entry.GetRawAttrs(),
	})
	if err != nil {
		log.Printf("error: Failed to update entry record. entry: %#v err: %v", entry, err)
		return err
	}

	return nil
}

func updateDN(tx *sqlx.Tx, entry *Entry, newDN *DN) error {
	_, err := tx.NamedExec(`UPDATE ldap_entry SET updated = now(), dn = :newdn, path = :newpath, attrs = :attrs WHERE id = :id`, map[string]interface{}{
		"id":      entry.Id,
		"newdn":   newDN.DN,
		"newpath": newDN.ReverseParentDN,
		"attrs":   entry.GetRawAttrs(),
	})

	if err != nil {
		log.Printf("error: Failed to update entry DN. entry: %#v newDN: %s err: %v", entry, newDN.DN, err)
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

func findByDNWithLock(tx *sqlx.Tx, dn *DN) (*Entry, error) {
	entry := Entry{}
	err := tx.NamedStmt(findByDNWithLockStmt).Get(&entry, map[string]interface{}{
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

				log.Printf("merging memberOf: %+v addDN: %s", entry.GetAttrs(), ownerDN.DN)

				err = mergeMemberOf(entry, ownerDN)
				if err != nil {
					log.Printf("error: Merge memberOf error: %#v", err)
					continue
				}

				log.Printf("merged memberOf: %+v", entry.GetAttrs())

				_, err = tx.NamedExec(`UPDATE ldap_entry SET attrs = :attrs WHERE id = :id`, map[string]interface{}{
					"id":    entry.Id,
					"attrs": entry.GetRawAttrs(),
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

				log.Printf("merging member: %+v addDN: %s", entry.GetAttrs(), subjectDN.DN)

				err = mergeMember(entry, subjectDN)
				if err != nil {
					log.Printf("error: Merge member error: %#v", err)
					continue
				}

				log.Printf("merged member: %+v", entry.GetAttrs())

				_, err = tx.NamedExec(`UPDATE ldap_entry SET attrs = :attrs WHERE id = :id`, map[string]interface{}{
					"id":    entry.Id,
					"attrs": entry.GetRawAttrs(),
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
	s, _ := schemaMap.Get(attrName)
	return entry.GetAttrs().MergeMultiValues(s, []string{dn.DN})
}

func deleteDNArray(entry *Entry, dn *DN, attrName string) error {
	s, _ := schemaMap.Get(attrName)
	return entry.GetAttrs().Remove(s, []string{dn.DN})
}

func resolveAssociation(tx *sqlx.Tx, ownerId int64, jsonMap map[string]interface{}) {
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
