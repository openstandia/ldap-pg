package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/jmoiron/sqlx"
)

var (
	findByDNStmt               *sqlx.NamedStmt
	findByDNWithLockStmt       *sqlx.NamedStmt
	findCredByDNStmt           *sqlx.NamedStmt
	baseSearchStmt             *sqlx.NamedStmt
	findByMemberOfWithLockStmt *sqlx.NamedStmt
	findByMemberWithLockStmt   *sqlx.NamedStmt
	updateAttrsByIdStmt        *sqlx.NamedStmt
	updateDNByIdStmt           *sqlx.NamedStmt
	deleteByDNStmt             *sqlx.NamedStmt
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

	findByDNStmt, err = db.PrepareNamed("SELECT id, dn, attrs FROM ldap_entry WHERE LOWER(dn) = LOWER(:dn)")
	if err != nil {
		return err
	}

	findByDNWithLockStmt, err = db.PrepareNamed("SELECT id, dn, attrs FROM ldap_entry WHERE LOWER(dn) = LOWER(:dn) FOR UPDATE")
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

	findByMemberOfWithLockStmt, err = db.PrepareNamed(`SELECT id, attrs FROM ldap_entry WHERE f_jsonb_array_lower(attrs->'memberOf') @> f_jsonb_array_lower('[":dn"]') FOR UPDATE`)
	if err != nil {
		return err
	}

	findByMemberWithLockStmt, err = db.PrepareNamed(`SELECT id, attrs FROM ldap_entry WHERE f_jsonb_array_lower(attrs->'member') @> f_jsonb_array_lower('[":dn"]') FOR UPDATE`)
	if err != nil {
		return err
	}

	updateAttrsByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = now(), attrs = :attrs WHERE id = :id`)
	if err != nil {
		return err
	}

	updateDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = now(), dn = :newdn, path = :newpath, attrs = :attrs WHERE id = :id`)
	if err != nil {
		return err
	}

	deleteByDNStmt, err = db.PrepareNamed(`DELETE FROM ldap_entry WHERE dn = :dn RETURNING id`)
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
	_, err := tx.NamedStmt(updateAttrsByIdStmt).Exec(map[string]interface{}{
		"id":    entry.Id,
		"attrs": entry.GetRawAttrs(),
	})
	if err != nil {
		log.Printf("error: Failed to update entry record. entry: %#v err: %v", entry, err)
		return err
	}

	return nil
}

func updateDNWithAssociationWithLock(tx *sqlx.Tx, oldDN, newDN *DN) error {
	return renameAssociation(tx, oldDN, newDN, func() error {
		oldEntry, err := findByDNWithLock(tx, oldDN)
		if err != nil {
			return err
		}

		newEntry, err := oldEntry.ModifyDN(newDN)
		if err != nil {
			return err
		}

		_, err = tx.NamedStmt(updateDNByIdStmt).Exec(map[string]interface{}{
			"id":      newEntry.Id,
			"newdn":   newDN.DN,
			"newpath": newDN.ReverseParentDN,
			"attrs":   newEntry.GetRawAttrs(),
		})

		if err != nil {
			log.Printf("error: Failed to update entry DN. entry: %#v newDN: %s err: %v", newEntry, newDN.DN, err)
			return err
		}

		return nil
	})
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

func findByFilter(pathQuery string, q *Query) (*sqlx.Rows, error) {
	var query string
	if q.Query != "" {
		query = " AND " + q.Query
	}

	var fetchQuery string
	if isSupportedFetchMemberOf() {
		fetchQuery = fmt.Sprintf(`SELECT id, dn, created, updated, attrs, (select jsonb_agg(e2.dn) AS memberOf FROM ldap_entry e2 WHERE f_jsonb_array_lower(e2.attrs->'member') @> jsonb_build_array(LOWER(e1.dn))) AS memberOf, count(id) over() AS count FROM ldap_entry e1 WHERE %s %s LIMIT :pageSize OFFSET :offset`, pathQuery, query)
	} else {
		fetchQuery = fmt.Sprintf(`SELECT *, COUNT(id) OVER() AS count FROM ldap_entry WHERE %s %s LIMIT :pageSize OFFSET :offset`, pathQuery, query)
	}

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

func deleteWithAssociationByDNWithLock(tx *sqlx.Tx, dn *DN) error {
	return deleteAssociation(tx, dn, func() error {
		var id int = 0
		err := tx.NamedStmt(deleteByDNStmt).Get(&id, map[string]interface{}{
			"dn": dn.DN,
		})
		if err != nil {
			return err
		}
		if id == 0 {
			return NewNoSuchObject()
		}
		return nil
	})
}

func addMemberOf(tx *sqlx.Tx, dn, memberOfDN string) error {
	entry := Entry{}
	err := tx.NamedStmt(findByDNWithLockStmt).Get(&entry, map[string]interface{}{
		"dn": dn,
	})
	if err != nil {
		return err
	}

	err = entry.AddAttrs("memberOf", []string{memberOfDN})
	if err != nil {
		log.Printf("error: Failed to add memberOf. dn: %s memberOf: %s err: %#v", entry.Dn, memberOfDN, err)
		return err
	}

	log.Printf("Add memberOf. dn: %s memberOf: %s", dn, memberOfDN)

	err = update(tx, &entry)
	if err != nil {
		log.Printf("error: Failed to add memberOf. dn: %s memberOf: %s err: %#v", entry.Dn, memberOfDN, err)
		return err
	}

	return nil
}

func deleteMemberOf(tx *sqlx.Tx, dn, memberOfDN string) error {
	entry := Entry{}
	err := tx.NamedStmt(findByDNWithLockStmt).Get(&entry, map[string]interface{}{
		"dn": dn,
	})
	if err != nil {
		return err
	}

	err = entry.DeleteAttrs("memberOf", []string{memberOfDN})
	if err != nil {
		if err != NewNoSuchAttribute("modify/delete", "memberOf") {
			log.Printf("error: Faild to delete memberOf. dn: %s memberOf: %s error: %#v", entry.Dn, memberOfDN, err)
			return err
		}
	}

	err = update(tx, &entry)
	if err != nil {
		log.Printf("error: Failed to delete memberOf. dn: %s memberOf: %s err: %#v", entry.Dn, memberOfDN, err)
		return err
	}

	return nil
}
