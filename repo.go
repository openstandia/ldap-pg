package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"golang.org/x/xerrors"
)

var (
	findByDNStmt                     *sqlx.NamedStmt
	findByDNWithMemberOfStmt         *sqlx.NamedStmt
	findByDNWithLockStmt             *sqlx.NamedStmt
	findCredByDNStmt                 *sqlx.NamedStmt
	findByMemberWithLockStmt         *sqlx.NamedStmt
	findByMemberOfWithLockStmt       *sqlx.NamedStmt
	findParentIDByDNWithLockStmt     *sqlx.NamedStmt
	addTreeStmt                      *sqlx.NamedStmt
	addStmt                          *sqlx.NamedStmt
	addMemberOfByDNNormStmt          *sqlx.NamedStmt
	updateAttrsByIdStmt              *sqlx.NamedStmt
	updateAttrsWithNoUpdatedByIdStmt *sqlx.NamedStmt
	updateDNByIdStmt                 *sqlx.NamedStmt
	deleteByDNStmt                   *sqlx.NamedStmt
	ROOT_ID                          int64 = 0
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

	findByDNSQL := "SELECT id, uuid, created, updated, dn_norm, attrs_orig FROM ldap_entry WHERE dn_norm = :dnNorm"
	findByDNWithMemberOfSQL := "SELECT id, uuid, created, updated, dn_norm, attrs_orig, (select jsonb_agg(e2.dn_norm) AS memberOf FROM ldap_entry e2 WHERE e2.attrs_norm->'member' @> jsonb_build_array(e1.dn_norm)) AS memberOf FROM ldap_entry e1 WHERE dn_norm = :dnNorm"

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

	findByMemberWithLockStmt, err = db.PrepareNamed(`SELECT id, dn_norm, attrs_orig FROM ldap_entry WHERE attrs_norm->'member' @> jsonb_build_array(:dnNorm ::::text) FOR UPDATE`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByMemberOfWithLockStmt, err = db.PrepareNamed(`SELECT id, dn_norm, attrs_orig FROM ldap_entry WHERE attrs_norm->'memberOf' @> jsonb_build_array(:dnNorm ::::text) FOR UPDATE`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findParentIDByDNWithLockStmt, err = db.PrepareNamed(`WITH RECURSIVE child (dn_norm, id, parent_id, rdn_norm) AS
	(
		SELECT e.rdn_norm::::TEXT AS dn_norm, e.id, e.parent_id, e.rdn_norm FROM
		ldap_tree e WHERE e.parent_id = 0
		UNION ALL
			SELECT
				e.rdn_norm || ',' || child.dn_norm,
				e.id,
				e.parent_id,
				e.rdn_norm
			FROM ldap_tree e, child
			WHERE e.parent_id = child.id
	)
	SELECT id from child WHERE dn_norm = :dn_norm`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	addTreeStmt, err = db.PrepareNamed(`INSERT INTO ldap_tree (id, parent_id, rdn_norm)
		VALUES (:id, :parent_id, :rdn_norm)`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	addStmt, err = db.PrepareNamed(`INSERT INTO ldap_entry (parent_id, rdn_norm, dn_norm, path, uuid, created, updated, attrs_norm, attrs_orig)
		SELECT :parent_id, :rdn_norm, :dnNorm, :path, :uuid, :created, :updated, :attrsNorm, :attrsOrig
			WHERE NOT EXISTS (SELECT id FROM ldap_entry WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm)
		RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	addMemberOfByDNNormStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = jsonb_set(attrs_norm, array['memberOf'], coalesce(attrs_norm->'memberOf', '[]'::::jsonb) || jsonb_build_array(:memberOfDNNorm ::::text)), attrs_orig = jsonb_set(attrs_orig, array['memberOf'], coalesce(attrs_orig->'memberOf', '[]'::::jsonb) || jsonb_build_array(:memberOfDNOrig ::::text)) WHERE dn_norm = :dnNorm`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	updateAttrsByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = :updated, attrs_norm = :attrsNorm, attrs_orig = :attrsOrig WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	// When updating memberOf, don't update 'updated'
	updateAttrsWithNoUpdatedByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = :attrsNorm, attrs_orig = :attrsOrig WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	updateDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = :updated, dn_norm = :newdnNorm, path = :newpath, attrs_norm = :attrsNorm, attrs_orig = :attrsOrig WHERE id = :id`)
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
	EntryUUID string         `db:"uuid"`
	Created   time.Time      `db:"created"`
	Updated   time.Time      `db:"updated"`
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

type DBTree struct {
	ID       int64  `db:"id"`
	parentID int64  `db:"parent_id"`
	RDNNorm  string `db:"rdn_norm"`
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
	if *twowayEnabled {
		hasMemberEntries, err := findByMemberDNWithLock(tx, entry.GetDN())
		if err != nil {
			return 0, err
		}
		memberOfDNsOrig := make([]string, len(hasMemberEntries))
		for i, v := range hasMemberEntries {
			memberOfDNsOrig[i] = v.GetDNOrig()
		}
		err = entry.Add("memberOf", memberOfDNsOrig)
		if err != nil {
			return 0, err
		}
	}

	dbEntry, err := mapper.AddEntryToDBEntry(entry)
	if err != nil {
		return 0, err
	}

	var parentID int64
	if entry.GetDN().ParentDNNorm == "" {
		parentID = ROOT_ID
	} else {
		parentID, err = findParentIDbyDNWithLock(tx, entry.GetDN())
		if err != nil {
			return 0, err
		}
	}

	rows, err := tx.NamedStmt(addStmt).Queryx(map[string]interface{}{
		"rdn_norm":  entry.RDNNorm(),
		"parent_id": parentID,
		"dnNorm":    dbEntry.DNNorm,
		"path":      dbEntry.Path,
		"uuid":      dbEntry.EntryUUID,
		"created":   dbEntry.Created,
		"updated":   dbEntry.Updated,
		"attrsNorm": dbEntry.AttrsNorm,
		"attrsOrig": dbEntry.AttrsOrig,
	})
	if err != nil {
		return 0, xerrors.Errorf("Failed to insert entry record. entry: %v, err: %w", entry, err)
	}
	defer rows.Close()

	var id int64
	if rows.Next() {
		rows.Scan(&id)
	} else {
		log.Printf("debug: Already exists. parentID: %d, rdn_norm: %s", parentID, entry.RDNNorm())
		return 0, NewAlreadyExists()
	}

	// work around to avoid "pq: unexpected Bind response 'C'"
	rows.Close()

	if entry.IsContainer() {
		_, err := tx.NamedStmt(addTreeStmt).Exec(map[string]interface{}{
			"id":        id,
			"parent_id": parentID,
			"rdn_norm":  entry.RDNNorm(),
		})
		if err != nil {
			return 0, xerrors.Errorf("Failed to insert tree record. parent_id: %s, rdn_norm: %s err: %w", parentID, entry.RDNNorm(), err)
		}
	}

	if *twowayEnabled {
		if members, ok := entry.GetAttrNorm("member"); ok {
			for _, dnNorm := range members {
				err := addMemberOfByDNNorm(tx, dnNorm, entry.GetDN())
				if err != nil {
					return 0, xerrors.Errorf("Faild to add memberOf. err: %w", err)
				}
			}
		}
	}

	return id, nil
}

func addMemberOfByDNNorm(tx *sqlx.Tx, dnNorm string, addMemberOfDN *DN) error {
	// This query doesn't update updated
	_, err := tx.NamedStmt(addMemberOfByDNNormStmt).Exec(map[string]interface{}{
		"dnNorm":         dnNorm,
		"memberOfDNNorm": addMemberOfDN.DNNorm,
		"memberOfDNOrig": addMemberOfDN.DNOrig,
	})
	if err != nil {
		return xerrors.Errorf("Failed to add memberOf. dn: %s, memberOf: %s, err: %w", dnNorm, addMemberOfDN.DNOrig, err)
	}
	return nil
}

func deleteMemberOfByDNNorm(tx *sqlx.Tx, dnNorm string, deleteMemberOfDN *DN) error {
	modifyEntry, err := findByDNNormWithLock(tx, dnNorm)
	if err != nil {
		return err
	}
	err = modifyEntry.Delete("memberOf", []string{deleteMemberOfDN.DNOrig})
	if err != nil {
		return err
	}

	err = update(tx, nil, modifyEntry)
	if err != nil {
		return xerrors.Errorf("Failed to delete memberOf. dn: %s, memberOf: %s, err: %w", dnNorm, deleteMemberOfDN.DNNorm, err)
	}
	return nil
}

func update(tx *sqlx.Tx, oldEntry, newEntry *ModifyEntry) error {
	if newEntry.dbEntryId == 0 {
		return xerrors.Errorf("Invalid dbEntryId for update DBEntry.")
	}

	dbEntry, err := mapper.ModifyEntryToDBEntry(newEntry)
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(updateAttrsByIdStmt).Exec(map[string]interface{}{
		"id":        dbEntry.Id,
		"updated":   dbEntry.Updated,
		"attrsNorm": dbEntry.AttrsNorm,
		"attrsOrig": dbEntry.AttrsOrig,
	})
	if err != nil {
		return xerrors.Errorf("Failed to update entry. entry: %v, err: %w", newEntry, err)
	}

	if *twowayEnabled {
		if oldEntry != nil {
			diff := calcDiffAttr(oldEntry, newEntry, "member")

			for _, dnNorm := range diff.add {
				err := addMemberOfByDNNorm(tx, dnNorm, oldEntry.GetDN())
				if err != nil {
					return err
				}
			}
			for _, dnNorm := range diff.del {
				err := deleteMemberOfByDNNorm(tx, dnNorm, oldEntry.GetDN())
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func updateWithNoUpdated(tx *sqlx.Tx, modifyEntry *ModifyEntry) error {
	if modifyEntry.dbEntryId == 0 {
		return xerrors.Errorf("Invalid dbEntryId for update DBEntry.")
	}

	dbEntry, err := mapper.ModifyEntryToDBEntry(modifyEntry)
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(updateAttrsWithNoUpdatedByIdStmt).Exec(map[string]interface{}{
		"id":        dbEntry.Id,
		"attrsNorm": dbEntry.AttrsNorm,
		"attrsOrig": dbEntry.AttrsOrig,
	})
	if err != nil {
		return xerrors.Errorf("Failed to update entry with no updated. entry: %v, err: %w", modifyEntry, err)
	}

	return nil
}

func updateDN(tx *sqlx.Tx, oldDN, newDN *DN) error {
	err := renameMemberByMemberDN(tx, oldDN, newDN)
	if err != nil {
		return xerrors.Errorf("Faild to rename member. err: %w", err)
	}

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
		"updated":   dbEntry.Updated,
		"newdnNorm": newDN.DNNorm,
		"newpath":   newDN.ReverseParentDN,
		"attrsNorm": dbEntry.AttrsNorm,
		"attrsOrig": dbEntry.AttrsOrig,
	})

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			log.Printf("warn: Failed to update entry DN because of already exists. oldDN: %s newDN: %s err: %v", oldDN.DNNorm, newDN.DNNorm, err)
			return NewAlreadyExists()
		}
		return xerrors.Errorf("Faild to update entry DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNorm, newDN.DNNorm, err)
	}

	if *twowayEnabled {
		err := renameMemberOfByMemberOfDN(tx, oldDN, newDN)
		if err != nil {
			return xerrors.Errorf("Faild to rename memberOf. err: %w", err)
		}
	}

	return nil
}

func renameMemberByMemberDN(tx *sqlx.Tx, oldMemberDN, newMemberDN *DN) error {
	// We need to fetch all rows and close before updating due to avoiding "pq: unexpected Parse response" error.
	// https://github.com/lib/pq/issues/635
	modifyEntries, err := findByMemberDNWithLock(tx, oldMemberDN)
	if err != nil {
		return err
	}

	if len(modifyEntries) == 0 {
		log.Printf("No entries which have member for rename. memberDN: %s", oldMemberDN.DNNorm)
		return nil
	}

	for _, modifyEntry := range modifyEntries {
		err := modifyEntry.Delete("member", []string{oldMemberDN.DNOrig})
		if err != nil {
			return err
		}
		err = modifyEntry.Add("member", []string{newMemberDN.DNOrig})
		if err != nil {
			return err
		}

		err = update(tx, nil, modifyEntry)
		if err != nil {
			return err
		}
	}
	return nil
}

func renameMemberOfByMemberOfDN(tx *sqlx.Tx, oldMemberOfDN, newMemberOfDN *DN) error {
	// We need to fetch all rows and close before updating due to avoiding "pq: unexpected Parse response" error.
	// https://github.com/lib/pq/issues/635
	modifyEntries, err := findByMemberOfDNWithLock(tx, oldMemberOfDN)
	if err != nil {
		return err
	}

	if len(modifyEntries) == 0 {
		log.Printf("No entries which have memberOf for rename. memberOfDN: %s", oldMemberOfDN.DNNorm)
		return nil
	}

	for _, modifyEntry := range modifyEntries {
		err := modifyEntry.Delete("memberOf", []string{oldMemberOfDN.DNOrig})
		if err != nil {
			return err
		}
		err = modifyEntry.Add("memberOf", []string{newMemberOfDN.DNOrig})
		if err != nil {
			return err
		}

		err = updateWithNoUpdated(tx, modifyEntry)
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteByDN(tx *sqlx.Tx, dn *DN) error {
	err := deleteMemberByMemberDN(tx, dn)
	if err != nil {
		return xerrors.Errorf("Faild to delete member. err: %w", err)
	}

	var id int = 0
	err = tx.NamedStmt(deleteByDNStmt).Get(&id, map[string]interface{}{
		"dnNorm": dn.DNNorm,
	})
	if err != nil {
		if strings.Contains(err.Error(), "sql: no rows in result set") {
			return NewNoSuchObject()
		}
		return xerrors.Errorf("Faild to delete entry. dn: %s, err: %w", dn.DNNorm, err)
	}
	if id == 0 {
		return NewNoSuchObject()
	}

	if *twowayEnabled {
		err := deleteMemberOfByMemberOfDN(tx, dn)
		if err != nil {
			return xerrors.Errorf("Faild to delete memberOf. err: %w", err)
		}
	}

	return nil
}

func deleteMemberByMemberDN(tx *sqlx.Tx, memberDN *DN) error {
	// We need to fetch all rows and close before updating due to avoiding "pq: unexpected Parse response" error.
	// https://github.com/lib/pq/issues/635
	modifyEntries, err := findByMemberDNWithLock(tx, memberDN)
	if err != nil {
		return err
	}

	if len(modifyEntries) == 0 {
		log.Printf("No entries which have member for delete. memberDN: %s", memberDN.DNNorm)
		return nil
	}

	for _, modifyEntry := range modifyEntries {
		err := modifyEntry.Delete("member", []string{memberDN.DNOrig})
		if err != nil {
			return err
		}

		err = update(tx, nil, modifyEntry)
		if err != nil {
			return err
		}
	}
	return nil
}

func deleteMemberOfByMemberOfDN(tx *sqlx.Tx, memberOfDN *DN) error {
	// We need to fetch all rows and close before updating due to avoiding "pq: unexpected Parse response" error.
	// https://github.com/lib/pq/issues/635
	modifyEntries, err := findByMemberOfDNWithLock(tx, memberOfDN)
	if err != nil {
		return err
	}

	if len(modifyEntries) == 0 {
		log.Printf("No entries which have memberOf for delete. memberOfDN: %s", memberOfDN.DNNorm)
		return nil
	}

	for _, modifyEntry := range modifyEntries {
		err := modifyEntry.Delete("memberOf", []string{memberOfDN.DNOrig})
		if err != nil {
			return err
		}

		err = updateWithNoUpdated(tx, modifyEntry)
		if err != nil {
			return err
		}
	}
	return nil
}

func findByMemberDNWithLock(tx *sqlx.Tx, memberDN *DN) ([]*ModifyEntry, error) {
	rows, err := tx.NamedStmt(findByMemberWithLockStmt).Queryx(map[string]interface{}{
		"dnNorm": memberDN.DNNorm,
	})
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dbEntry := FetchedDBEntry{}
	modifyEntries := []*ModifyEntry{}

	for rows.Next() {
		err := rows.StructScan(&dbEntry)
		if err != nil {
			return nil, err
		}
		modifyEntry, err := mapper.FetchedDBEntryToModifyEntry(&dbEntry)
		if err != nil {
			return nil, err
		}

		modifyEntries = append(modifyEntries, modifyEntry)

		dbEntry.Clear()
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return modifyEntries, nil
}

func findByMemberOfDNWithLock(tx *sqlx.Tx, memberDN *DN) ([]*ModifyEntry, error) {
	rows, err := tx.NamedStmt(findByMemberOfWithLockStmt).Queryx(map[string]interface{}{
		"dnNorm": memberDN.DNNorm,
	})
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dbEntry := FetchedDBEntry{}
	modifyEntries := []*ModifyEntry{}

	for rows.Next() {
		err := rows.StructScan(&dbEntry)
		if err != nil {
			return nil, err
		}
		modifyEntry, err := mapper.FetchedDBEntryToModifyEntry(&dbEntry)
		if err != nil {
			return nil, err
		}

		modifyEntries = append(modifyEntries, modifyEntry)

		dbEntry.Clear()
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return modifyEntries, nil
}

func findParentIDbyDNWithLock(tx *sqlx.Tx, dn *DN) (int64, error) {
	rows, err := tx.NamedStmt(findParentIDByDNWithLockStmt).Queryx(map[string]interface{}{
		"dn_norm": dn.ParentDNNorm,
	})
	if err != nil {
		return 0, xerrors.Errorf("Failed to fetch parentID by DN: %s, err: %w", dn.DNOrig, err)
	}
	defer rows.Close()
	if rows.Next() {
		var id int64
		rows.Scan(&id)
		return id, nil
	}
	log.Printf("debug: Not found parent DN. dn_norm: %s", dn.ParentDNNorm)
	// TODO check LDAP error code
	return 0, NewNoSuchObject()
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

func findCredByDN(dn *DN) ([]string, error) {
	var j types.JSONText
	err := findCredByDNStmt.Get(&j, map[string]interface{}{
		"dnNorm": dn.DNNorm,
	})
	if err != nil {
		return nil, xerrors.Errorf("Faild to find cred by DN. dn: %s, err: %w", dn.DNNorm, err)
	}
	var bindUserCred []string
	err = j.Unmarshal(&bindUserCred)
	if err != nil {
		return nil, xerrors.Errorf("Faild to unmarshal cred. dn: %s, err: %w", dn.DNNorm, err)
	}
	return bindUserCred, nil
}

func findByFilter(pathQuery string, q *Query, reqMemberOf bool, handler func(entry *SearchEntry) error) (int32, int32, error) {
	var query string
	if q.Query != "" {
		query = " AND " + q.Query
	}

	var fetchQuery string
	if reqMemberOf && !*twowayEnabled {
		fetchQuery = fmt.Sprintf(`SELECT id, uuid, created, updated, dn_norm, attrs_orig, (select jsonb_agg(e2.dn_norm) AS memberOf FROM ldap_entry e2 WHERE e2.attrs_norm->'member' @> jsonb_build_array(e1.dn_norm)) AS memberOf, count(id) over() AS count FROM ldap_entry e1 WHERE %s %s LIMIT :pageSize OFFSET :offset`, pathQuery, query)
	} else {
		fetchQuery = fmt.Sprintf(`SELECT id, uuid, created, updated, dn_norm, attrs_orig, count(id) over() AS count FROM ldap_entry WHERE %s %s LIMIT :pageSize OFFSET :offset`, pathQuery, query)
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
