package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"golang.org/x/xerrors"
)

var (
	findByDNStmt                  *sqlx.NamedStmt
	findByDNWithMemberOfStmt      *sqlx.NamedStmt
	findByDNWithLockStmt          *sqlx.NamedStmt
	findCredByDNStmt              *sqlx.NamedStmt
	baseSearchStmt                *sqlx.NamedStmt
	findByMemberOfWithLockStmt    *sqlx.NamedStmt
	findByMemberWithLockStmt      *sqlx.NamedStmt
	appendMemberByDNStmt          *sqlx.NamedStmt
	removeMemberByMemberStmt      *sqlx.NamedStmt
	removeMemberOfByMemberOfStmt  *sqlx.NamedStmt
	replaceMemberByMemberStmt     *sqlx.NamedStmt
	replaceMemberOfByMemberOfStmt *sqlx.NamedStmt
	addStmt                       *sqlx.NamedStmt
	updateAttrsByIdStmt           *sqlx.NamedStmt
	updateDNByIdStmt              *sqlx.NamedStmt
	deleteByDNStmt                *sqlx.NamedStmt
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

	findByDNSQL := "SELECT id, dn_norm, attrs_orig FROM ldap_entry WHERE dn_norm = :dnNorm"
	findByDNWithMemberOfSQL := "SELECT id, dn_norm, attrs_orig, (select jsonb_agg(e2.dn_norm) AS memberOf FROM ldap_entry e2 WHERE e2.attrs_norm->'member' @> jsonb_build_array(e1.dn_norm)) AS memberOf FROM ldap_entry e1 WHERE dn_norm = :dnNorm"

	findByDNStmt, err = db.PrepareNamed(findByDNSQL)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByDNWithMemberOfStmt, err = db.PrepareNamed(findByDNWithMemberOfSQL)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByDNWithLockStmt, err = db.PrepareNamed(findByDNSQL + " FOR UPDATE")
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findCredByDNStmt, err = db.PrepareNamed("SELECT attrs_norm->>'userPassword' FROM ldap_entry WHERE dn_norm = :dnNorm")
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	baseSearchStmt, err = db.PrepareNamed("SELECT id, attrs_orig FROM ldap_entry WHERE dn_norm = :baseDNNorm")
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByMemberOfWithLockStmt, err = db.PrepareNamed(`SELECT id, attrs_orig FROM ldap_entry WHERE attrs_norm->'memberOf' @> jsonb_build_array(CAST(:dnNorm AS text)) FOR UPDATE`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByMemberWithLockStmt, err = db.PrepareNamed(`SELECT id, attrs_orig FROM ldap_entry WHERE attrs_norm->'member' @> jsonb_build_array(CAST(:dnNorm AS text)) FOR UPDATE`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	appendMemberByDNStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = jsonb_set(attrs_norm, array['member'], CAST(attrs_norm->'member' AS jsonb) || jsonb_build_array(CAST(:memberDNNorm AS text)) ), attrs_orig = jsonb_set(attrs_orig, array['member'], CAST(attrs_orig->'member' AS jsonb) || jsonb_build_array(CAST(:memberDNOrig AS text)) ) WHERE dn_norm = :dnNorm`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	removeMemberByMemberStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = jsonb_set(attrs_norm, array['member'], CAST(attrs_norm->'member' AS jsonb) - :memberDNNorm ), attrs_orig = jsonb_set(attrs_orig, array['member'], CAST(attrs_orig->'member' AS jsonb) - :memberDNOrig ) WHERE attrs_norm->'member' @> jsonb_build_array(CAST(:dnNorm AS text))`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	removeMemberOfByMemberOfStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = jsonb_set(attrs_norm, array['memberOf'], CAST(attrs_norm->'memberOf' AS jsonb) - :memberOfDNNorm ), attrs_orig = jsonb_set(attrs_orig, array['memberOf'], CAST(attrs_orig->'memberOf' AS jsonb) - :memberOfDNOrig ) WHERE attrs_norm->'memberOf' @> jsonb_build_array(CAST(:dnNorm AS text))`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	replaceMemberByMemberStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = jsonb_set(attrs_norm, array['member'], CAST(attrs_norm->'member' AS jsonb) - :oldMemberDNNorm || jsonb_build_array(CAST(:newMemberDNNorm AS text)) ) WHERE attrs_norm->'member' @> jsonb_build_array(CAST(:dnNorm AS text))`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	replaceMemberOfByMemberOfStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = jsonb_set(attrs_norm, array['memberOf'], CAST(attrs_norm->'memberOf' AS jsonb) - :oldMemberOfDNNorm || jsonb_build_array(CAST(:newMemberOfDNNorm AS text)) ) WHERE attrs_norm->'memberOf' @> jsonb_build_array(CAST(:dnNorm AS text))`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	addStmt, err = db.PrepareNamed(`INSERT INTO ldap_entry (dn_norm, path, uuid, created, updated, attrs_norm, attrs_orig) SELECT :dnNorm, :path, :uuid, :created, :updated, :attrsNorm, :attrsOrig WHERE NOT EXISTS (SELECT id FROM ldap_entry WHERE dn_norm = :dnNorm) RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	updateAttrsByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = now(), attrs_norm = :attrsNorm, attrs_orig = :attrsOrig WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	updateDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = now(), dn_norm = :newdnNorm, path = :newpath, attrs_norm = :attrsNorm, attrs_orig = :attrsOrig WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	deleteByDNStmt, err = db.PrepareNamed(`DELETE FROM ldap_entry WHERE dn_norm = :dnNorm RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	return nil
}

type FetchedDBEntry struct {
	Id        int64          `db:"id"`
	DNNorm    string         `db:"dn_norm"`
	AttrsOrig types.JSONText `db:"attrs_orig"`
	MemberOf  types.JSONText `db:"memberof"` // No real column in the table
	Count     int32          `db:"count"`    // No real column in the table
}

func (e *FetchedDBEntry) GetAttrsOrig() map[string][]string {
	if len(e.AttrsOrig) > 0 {
		jsonMap := make(map[string][]string)
		e.AttrsOrig.Unmarshal(&jsonMap)

		if len(e.MemberOf) > 0 {
			jsonArray := []string{}
			e.MemberOf.Unmarshal(&jsonArray)
			jsonMap["memberOf"] = jsonArray
		}

		return jsonMap
	}
	return nil
}

func (e *FetchedDBEntry) Clear() {
	e.Id = 0
	e.DNNorm = ""
	e.AttrsOrig = nil
	e.MemberOf = nil
	e.Count = 0
}

type DBEntry struct {
	Id            int64          `db:"id"`
	DNNorm        string         `db:"dn_norm"`
	Path          string         `db:"path"`
	EntryUUID     string         `db:"uuid"`
	Created       time.Time      `db:"created"`
	Updated       time.Time      `db:"updated"`
	AttrsNorm     types.JSONText `db:"attrs_norm"`
	AttrsOrig     types.JSONText `db:"attrs_orig"`
	Count         int32          `db:"count"`    // No real column in the table
	MemberOf      types.JSONText `db:"memberof"` // No real column in the table
	jsonAttrsNorm map[string]interface{}
	jsonAttrsOrig map[string][]string
}

func insert(tx *sqlx.Tx, entry *AddEntry) (int64, error) {
	dbEntry, err := mapper.AddEntryToDBEntry(entry)
	if err != nil {
		return 0, err
	}

	rows, err := tx.NamedStmt(addStmt).Queryx(map[string]interface{}{
		"dnNorm":    dbEntry.DNNorm,
		"path":      dbEntry.Path,
		"uuid":      dbEntry.EntryUUID,
		"created":   dbEntry.Created,
		"updated":   dbEntry.Updated,
		"attrsNorm": dbEntry.AttrsNorm,
		"attrsOrig": dbEntry.AttrsOrig,
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

func update(tx *sqlx.Tx, entry *ModifyEntry) error {
	if entry.dbEntryId == 0 {
		return fmt.Errorf("Invalid dbEntryId for update DBEntry.")
	}

	dbEntry, err := mapper.ModifyEntryToDBEntry(entry)
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(updateAttrsByIdStmt).Exec(map[string]interface{}{
		"id":        dbEntry.Id,
		"attrsNorm": dbEntry.AttrsNorm,
		"attrsOrig": dbEntry.AttrsOrig,
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

		newEntry := oldEntry.ModifyDN(newDN)
		dbEntry, err := mapper.ModifyEntryToDBEntry(newEntry)
		if err != nil {
			return err
		}

		_, err = tx.NamedStmt(updateDNByIdStmt).Exec(map[string]interface{}{
			"id":        newEntry.dbEntryId,
			"newdnNorm": newDN.DNNorm,
			"newpath":   newDN.ReverseParentDN,
			"attrsNorm": dbEntry.AttrsNorm,
			"attrsOrig": dbEntry.AttrsOrig,
		})

		if err != nil {
			log.Printf("error: Failed to update entry DN. entry: %#v newDN: %s err: %v", newEntry, newDN.DNNorm, err)
			return err
		}

		return nil
	})
}

func findByDN(tx *sqlx.Tx, dn *DN) (*SearchEntry, error) {
	dbEntry := FetchedDBEntry{}
	err := tx.NamedStmt(findByDNStmt).Get(&dbEntry, map[string]interface{}{
		"dnNorm": dn.DNNorm,
	})
	if err != nil {
		return nil, err
	}
	dbEntry.Count = 1
	return mapper.FetchedDBEntryToSearchEntry(&dbEntry)
}

func findByDNWithLock(tx *sqlx.Tx, dn *DN) (*ModifyEntry, error) {
	return findByDNNormWithLock(tx, dn.DNNorm)
}

func findByDNNormWithLock(tx *sqlx.Tx, dnNorm string) (*ModifyEntry, error) {
	dbEntry := FetchedDBEntry{}
	err := tx.NamedStmt(findByDNWithLockStmt).Get(&dbEntry, map[string]interface{}{
		"dnNorm": dnNorm,
	})
	if err != nil {
		return nil, err
	}
	dbEntry.Count = 1
	return mapper.FetchedDBEntryToModifyEntry(&dbEntry)
}

func findCredByDN(dn *DN) (string, error) {
	var bindUserCred string
	err := findCredByDNStmt.Get(&bindUserCred, map[string]interface{}{
		"dnNorm": dn.DNNorm,
	})
	if err != nil {
		return "", err
	}
	return bindUserCred, nil
}

func findByFilter(pathQuery string, q *Query, reqMemberOf bool, handler func(entry *SearchEntry) error) (int32, int32, error) {
	var query string
	if q.Query != "" {
		query = " AND " + q.Query
	}

	var fetchQuery string
	if reqMemberOf {
		fetchQuery = fmt.Sprintf(`SELECT id, dn_norm, attrs_orig, (select jsonb_agg(e2.dn_norm) AS memberOf FROM ldap_entry e2 WHERE e2.attrs_norm->'member' @> jsonb_build_array(e1.dn_norm)) AS memberOf, count(id) over() AS count FROM ldap_entry e1 WHERE %s %s LIMIT :pageSize OFFSET :offset`, pathQuery, query)
	} else {
		fetchQuery = fmt.Sprintf(`SELECT id, dn_norm, attrs_orig, count(id) over() AS count FROM ldap_entry WHERE %s %s LIMIT :pageSize OFFSET :offset`, pathQuery, query)
	}

	log.Printf("Fetch Query: %s Params: %v", fetchQuery, q.Params)

	var fetchStmt *sqlx.NamedStmt
	var ok bool
	var err error
	if fetchStmt, ok = filterStmtMap.Get(fetchQuery); !ok {
		// cache
		fetchStmt, err = db.PrepareNamed(fetchQuery)
		if err != nil {
			return 0, 0, err
		}
		filterStmtMap.Put(fetchQuery, fetchStmt)
	}

	var rows *sqlx.Rows
	rows, err = fetchStmt.Queryx(q.Params)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	dbEntry := FetchedDBEntry{}
	var maxCount int32 = 0
	var count int32 = 0

	for rows.Next() {
		err := rows.StructScan(&dbEntry)
		if err != nil {
			log.Printf("error: DBEntry struct mapping error: %#v", err)
			return 0, 0, err
		}

		readEntry, err := mapper.FetchedDBEntryToSearchEntry(&dbEntry)
		if err != nil {
			log.Printf("error: Mapper error: %#v", err)
			return 0, 0, err
		}

		if maxCount == 0 {
			maxCount = dbEntry.Count
		}

		err = handler(readEntry)
		if err != nil {
			log.Printf("error: Handler error: %#v", err)
			return 0, 0, err
		}

		count++
		dbEntry.Clear()
	}

	err = rows.Err()
	if err != nil {
		log.Printf("error: Search error: %#v", err)
		return 0, 0, err
	}

	return maxCount, count, nil
}

func deleteWithAssociationByDNWithLock(tx *sqlx.Tx, dn *DN) error {
	return deleteAssociation(tx, dn, func() error {
		var id int = 0
		err := tx.NamedStmt(deleteByDNStmt).Get(&id, map[string]interface{}{
			"dnNorm": dn.DNNorm,
		})
		if err != nil {
			log.Printf("error: Failed to delete entry")
			return err
		}
		if id == 0 {
			return NewNoSuchObject()
		}
		return nil
	})
}

func addMemberOf(tx *sqlx.Tx, dnNorm, memberOfDN string) error {
	entry, err := findByDNNormWithLock(tx, dnNorm)
	if err != nil {
		return err
	}

	err = entry.Add("memberOf", []string{memberOfDN})
	if err != nil {
		log.Printf("error: Failed to add memberOf. dn: %s memberOf: %s err: %#v", dnNorm, memberOfDN, err)
		return err
	}

	log.Printf("Add memberOf. dn: %s memberOf: %s", dnNorm, memberOfDN)

	err = update(tx, entry)
	if err != nil {
		log.Printf("error: Failed to add memberOf. dn: %s memberOf: %s err: %#v", dnNorm, memberOfDN, err)
		return err
	}

	return nil
}

func deleteMemberOf(tx *sqlx.Tx, dnNorm, memberOfDN string) error {
	entry, err := findByDNNormWithLock(tx, dnNorm)
	if err != nil {
		return err
	}

	err = entry.Delete("memberOf", []string{memberOfDN})
	if err != nil {
		if err != NewNoSuchAttribute("modify/delete", "memberOf") {
			log.Printf("error: Faild to delete memberOf. dn: %s memberOf: %s error: %#v", dnNorm, memberOfDN, err)
			return err
		}
	}

	err = update(tx, entry)
	if err != nil {
		log.Printf("error: Failed to delete memberOf. dn: %s memberOf: %s err: %#v", dnNorm, memberOfDN, err)
		return err
	}

	return nil
}
