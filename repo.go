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
	findByDNStmt                             *sqlx.NamedStmt
	findByDNWithMemberOfStmt                 *sqlx.NamedStmt
	findByDNWithLockStmt                     *sqlx.NamedStmt
	findByParentIDAndRDNNormStmt             *sqlx.NamedStmt
	findByParentIDAndRDNNormStmtWithLockStmt *sqlx.NamedStmt
	findByIDWithLockStmt                     *sqlx.NamedStmt
	findCredByDNStmt                         *sqlx.NamedStmt
	findByMemberWithLockStmt                 *sqlx.NamedStmt
	findByMemberOfWithLockStmt               *sqlx.NamedStmt
	findChildrenByParentIDStmt               *sqlx.NamedStmt
	getDCStmt                                *sqlx.NamedStmt
	addTreeStmt                              *sqlx.NamedStmt
	addStmt                                  *sqlx.NamedStmt
	addMemberOfByDNNormStmt                  *sqlx.NamedStmt
	updateAttrsByIdStmt                      *sqlx.NamedStmt
	updateAttrsWithNoUpdatedByIdStmt         *sqlx.NamedStmt
	updateDNByIdStmt                         *sqlx.NamedStmt
	deleteByDNStmt                           *sqlx.NamedStmt
	ROOT_ID                                  int64 = 0
)

// For generic filter
type StmtCache struct {
	sm sync.Map
}

func (m *StmtCache) Get(key string) (*sqlx.NamedStmt, bool) {
	val, ok := m.sm.Load(key)
	if !ok {
		return nil, false
	}
	return val.(*sqlx.NamedStmt), true
}

func (m *StmtCache) Put(key string, value *sqlx.NamedStmt) {
	m.sm.Store(key, value)
}

var filterStmtMap StmtCache
var treeStmtCache StmtCache

type Repository struct {
	server *Server
}

func NewRepository(server *Server) *Repository {
	return &Repository{
		server: server,
	}
}

func (r *Repository) initStmt(db *sqlx.DB) error {
	var err error

	findByParentIDAndRDNNormSQL := `SELECT id, uuid, created, updated, rdn_orig || ',' || :parent_dn_orig AS dn_orig, attrs_orig
		FROM ldap_entry
		WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm`

	findByParentIDAndRDNNormStmt, err = db.PrepareNamed(findByParentIDAndRDNNormSQL)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByParentIDAndRDNNormStmtWithLockStmt, err = db.PrepareNamed(findByParentIDAndRDNNormSQL + " FOR UPDATE")
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	// findByDNSQL := "SELECT id, uuid, created, updated, dn_norm, attrs_orig FROM ldap_entry WHERE parent_id =rdn_norm = :dn_norm"
	// findByDNWithMemberOfSQL := "SELECT id, uuid, created, updated, dn_norm, attrs_orig, (select jsonb_agg(e2.dn_norm) AS memberOf FROM ldap_entry e2 WHERE e2.attrs_norm->'member' @> jsonb_build_array(e1.dn_norm)) AS memberOf FROM ldap_entry e1 WHERE dn_norm = :dnNorm"

	// findByDNStmt, err = db.PrepareNamed(findByDNSQL)
	// if err != nil {
	// 	return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	// }

	// findByDNWithMemberOfStmt, err = db.PrepareNamed(findByDNWithMemberOfSQL)
	// if err != nil {
	// 	return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	// }

	// findByDNWithLockStmt, err = db.PrepareNamed(findByDNSQL + " FOR UPDATE")
	// if err != nil {
	// 	return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	// }

	findByIDWithLockStmt, err = db.PrepareNamed(`SELECT id, uuid, created, updated, rdn_orig, attrs_orig
		FROM ldap_entry
		WHERE id = :id
		FOR UPDATE`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findCredByDNStmt, err = db.PrepareNamed(`SELECT attrs_norm->>'userPassword'
		FROM ldap_entry
		WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByMemberWithLockStmt, err = db.PrepareNamed(`SELECT id, parent_id, rdn_norm, attrs_orig
		FROM ldap_entry
		WHERE parent_id = :parent_id AND attrs_norm->'member' @> jsonb_build_array(:dn_norm ::::text) FOR UPDATE`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findByMemberOfWithLockStmt, err = db.PrepareNamed(`SELECT id, parent_id, rdn_norm, attrs_orig
		FROM ldap_entry
		WHERE parent_id = :parent_id AND attrs_norm->'memberOf' @> jsonb_build_array(:dn_norm ::::text) FOR UPDATE`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	findChildrenByParentIDStmt, err = db.PrepareNamed(`WITH RECURSIVE child (dn_orig, id, parent_id, rdn_orig) AS
	(
		SELECT e.rdn_orig::::TEXT AS dn_orig, e.id, e.parent_id, e.rdn_orig FROM
		ldap_tree e WHERE e.parent_id = :parent_id 
		UNION ALL
			SELECT
				e.rdn_orig || ',' || child.dn_orig,
				e.id,
				e.parent_id,
				e.rdn_orig
			FROM ldap_tree e, child
			WHERE e.parent_id = child.id
	)
	SELECT id, dn_orig from child`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	getDCStmt, err = db.PrepareNamed(`SELECT id, '' as dn_orig FROM ldap_tree
		WHERE parent_id = 0`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	addTreeStmt, err = db.PrepareNamed(`INSERT INTO ldap_tree (id, parent_id, rdn_norm, rdn_orig)
		VALUES (:id, :parent_id, :rdn_norm, :rdn_orig)`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	addStmt, err = db.PrepareNamed(`INSERT INTO ldap_entry (parent_id, rdn_norm, rdn_orig, uuid, created, updated, attrs_norm, attrs_orig)
		SELECT :parent_id, :rdn_norm, :rdn_orig, :uuid, :created, :updated, :attrs_norm, :attrs_orig
			WHERE NOT EXISTS (SELECT id FROM ldap_entry WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm)
		RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	addMemberOfByDNNormStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = jsonb_set(attrs_norm, array['memberOf'], coalesce(attrs_norm->'memberOf', '[]'::::jsonb) || jsonb_build_array(:memberOfDNNorm ::::text)), attrs_orig = jsonb_set(attrs_orig, array['memberOf'], coalesce(attrs_orig->'memberOf', '[]'::::jsonb) || jsonb_build_array(:memberOfDNOrig ::::text))
		WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	updateAttrsByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = :updated, attrs_norm = :attrsNorm, attrs_orig = :attrsOrig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	// When updating memberOf, don't update 'updated'
	updateAttrsWithNoUpdatedByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = :attrsNorm, attrs_orig = :attrsOrig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	updateDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET updated = :updated, rdn_norm = :new_rdn_norm, attrs_norm = :attrsNorm, attrs_orig = :attrsOrig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	deleteByDNStmt, err = db.PrepareNamed(`DELETE FROM ldap_entry
		WHERE parent_id = :parent_id AND rdn_norm = :rdn_norm RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Faild to initialize prepared statement: %w", err)
	}

	return nil
}

type FetchedDBEntry struct {
	ID        int64          `db:"id"`
	ParentID  int64          `db:"parent_id"`
	EntryUUID string         `db:"uuid"`
	Created   time.Time      `db:"created"`
	Updated   time.Time      `db:"updated"`
	RDNOrig   string         `db:"rdn_orig"`
	AttrsOrig types.JSONText `db:"attrs_orig"`
	DNOrig    string         `db:"dn_orig"`  // No real clumn in t he table
	MemberOf  types.JSONText `db:"memberof"` // No real column in the table
	Count     int32          `db:"count"`    // No real column in the table
}

func (e *FetchedDBEntry) IsDC() bool {
	return e.ParentID == ROOT_ID
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
	e.ID = 0
	e.DNOrig = ""
	e.AttrsOrig = nil
	e.MemberOf = nil
	e.Count = 0
}

type FetchedParent struct {
	ID     int64  `db:"id"`
	DNOrig string `db:"dn_orig"`
}

type FetchedChild FetchedParent

type DBTree struct {
	ID       int64  `db:"id"`
	ParentID int64  `db:"parent_id"`
	RDNNorm  string `db:"rdn_norm"`
	RDNOrig  string `db:"rdn_orig"`
}

type DBEntry struct {
	ID            int64          `db:"id"`
	DNNorm        string         `db:"dn_norm"`
	DNOrig        string         `db:"dn_orig"`
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

func (r *Repository) insert(tx *sqlx.Tx, entry *AddEntry) (int64, error) {
	if *twowayEnabled {
		hasMemberEntries, err := findByMemberDNWithLock(tx, entry.DN())
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
	if entry.IsDC() {
		parentID = ROOT_ID
		// } else if entry.ParentDN().IsDC() {
		// 	parentID = DCID
	} else {
		parent, err := findParentByDN(tx, entry.DN())
		if err != nil {
			return 0, err
		}
		parentID = parent.ID
	}

	rows, err := tx.NamedStmt(addStmt).Queryx(map[string]interface{}{
		"rdn_norm":   entry.RDNNorm(),
		"rdn_orig":   entry.RDNOrig(),
		"parent_id":  parentID,
		"uuid":       dbEntry.EntryUUID,
		"created":    dbEntry.Created,
		"updated":    dbEntry.Updated,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
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
			"rdn_norm":  entry.dn.RDNNormStr(),
			"rdn_orig":  entry.dn.RDNOrigStr(),
		})
		if err != nil {
			return 0, xerrors.Errorf("Failed to insert tree record. parent_id: %d, rdn_norm: %s err: %w", parentID, entry.RDNNorm(), err)
		}
	}

	if *twowayEnabled {
		if members, ok := entry.GetAttrNorm("member"); ok {
			for _, dnNorm := range members {
				err := r.addMemberOfByDNNorm(tx, dnNorm, entry.DN())
				if err != nil {
					return 0, xerrors.Errorf("Faild to add memberOf. err: %w", err)
				}
			}
		}
	}

	return id, nil
}

func (r *Repository) addMemberOfByDNNorm(tx *sqlx.Tx, dnNorm string, addMemberOfDN *DN) error {
	// This query doesn't update updated
	_, err := tx.NamedStmt(addMemberOfByDNNormStmt).Exec(map[string]interface{}{
		"dnNorm":         dnNorm,
		"memberOfDNNorm": addMemberOfDN.DNNormStr(),
		"memberOfDNOrig": addMemberOfDN.DNOrigStr(),
	})
	if err != nil {
		return xerrors.Errorf("Failed to add memberOf. dn: %s, memberOf: %s, err: %w", dnNorm, addMemberOfDN.DNOrigStr(), err)
	}
	return nil
}

func (r *Repository) deleteMemberOfByDNNorm(tx *sqlx.Tx, dnNorm string, deleteMemberOfDN *DN) error {
	modifyEntry, err := r.findByDNNormWithLock(tx, dnNorm)
	if err != nil {
		return err
	}
	err = modifyEntry.Delete("memberOf", []string{deleteMemberOfDN.DNOrigStr()})
	if err != nil {
		return err
	}

	err = r.update(tx, nil, modifyEntry)
	if err != nil {
		return xerrors.Errorf("Failed to delete memberOf. dn: %s, memberOf: %s, err: %w", dnNorm, deleteMemberOfDN.DNOrigStr(), err)
	}
	return nil
}

func (r *Repository) update(tx *sqlx.Tx, oldEntry, newEntry *ModifyEntry) error {
	if newEntry.dbEntryId == 0 {
		return xerrors.Errorf("Invalid dbEntryId for update DBEntry.")
	}

	dbEntry, err := mapper.ModifyEntryToDBEntry(newEntry)
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(updateAttrsByIdStmt).Exec(map[string]interface{}{
		"id":        dbEntry.ID,
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
				err := r.addMemberOfByDNNorm(tx, dnNorm, oldEntry.GetDN())
				if err != nil {
					return err
				}
			}
			for _, dnNorm := range diff.del {
				err := r.deleteMemberOfByDNNorm(tx, dnNorm, oldEntry.GetDN())
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
		"id":        dbEntry.ID,
		"attrsNorm": dbEntry.AttrsNorm,
		"attrsOrig": dbEntry.AttrsOrig,
	})
	if err != nil {
		return xerrors.Errorf("Failed to update entry with no updated. entry: %v, err: %w", modifyEntry, err)
	}

	return nil
}

func (r *Repository) updateDN(tx *sqlx.Tx, oldDN, newDN *DN) error {
	err := r.renameMemberByMemberDN(tx, oldDN, newDN)
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
		"newdnNorm": newDN.DNNormStr(),
		"newpath":   newDN.ReverseParentDN,
		"attrsNorm": dbEntry.AttrsNorm,
		"attrsOrig": dbEntry.AttrsOrig,
	})

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			log.Printf("warn: Failed to update entry DN because of already exists. oldDN: %s newDN: %s err: %v", oldDN.DNNormStr(), newDN.DNNormStr(), err)
			return NewAlreadyExists()
		}
		return xerrors.Errorf("Faild to update entry DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
	}

	if *twowayEnabled {
		err := renameMemberOfByMemberOfDN(tx, oldDN, newDN)
		if err != nil {
			return xerrors.Errorf("Faild to rename memberOf. err: %w", err)
		}
	}

	return nil
}

func (r *Repository) renameMemberByMemberDN(tx *sqlx.Tx, oldMemberDN, newMemberDN *DN) error {
	// We need to fetch all rows and close before updating due to avoiding "pq: unexpected Parse response" error.
	// https://github.com/lib/pq/issues/635
	modifyEntries, err := findByMemberDNWithLock(tx, oldMemberDN)
	if err != nil {
		return err
	}

	if len(modifyEntries) == 0 {
		log.Printf("No entries which have member for rename. memberDN: %s", oldMemberDN.DNNormStr())
		return nil
	}

	for _, modifyEntry := range modifyEntries {
		err := modifyEntry.Delete("member", []string{oldMemberDN.DNOrigStr()})
		if err != nil {
			return err
		}
		err = modifyEntry.Add("member", []string{newMemberDN.DNOrigStr()})
		if err != nil {
			return err
		}

		err = r.update(tx, nil, modifyEntry)
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
		log.Printf("No entries which have memberOf for rename. memberOfDN: %s", oldMemberOfDN.DNNormStr())
		return nil
	}

	for _, modifyEntry := range modifyEntries {
		err := modifyEntry.Delete("memberOf", []string{oldMemberOfDN.DNOrigStr()})
		if err != nil {
			return err
		}
		err = modifyEntry.Add("memberOf", []string{newMemberOfDN.DNOrigStr()})
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

func (r Repository) deleteByDN(tx *sqlx.Tx, dn *DN) error {
	err := r.deleteMemberByMemberDN(tx, dn)
	if err != nil {
		return xerrors.Errorf("Faild to delete member. err: %w", err)
	}

	var id int = 0
	err = tx.NamedStmt(deleteByDNStmt).Get(&id, map[string]interface{}{
		"dnNorm": dn.DNNormStr(),
	})
	if err != nil {
		if strings.Contains(err.Error(), "sql: no rows in result set") {
			return NewNoSuchObject()
		}
		return xerrors.Errorf("Faild to delete entry. dn: %s, err: %w", dn.DNNormStr(), err)
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

func (r *Repository) deleteMemberByMemberDN(tx *sqlx.Tx, memberDN *DN) error {
	// We need to fetch all rows and close before updating due to avoiding "pq: unexpected Parse response" error.
	// https://github.com/lib/pq/issues/635
	modifyEntries, err := findByMemberDNWithLock(tx, memberDN)
	if err != nil {
		return err
	}

	if len(modifyEntries) == 0 {
		log.Printf("No entries which have member for delete. memberDN: %s", memberDN.DNNormStr())
		return nil
	}

	for _, modifyEntry := range modifyEntries {
		err := modifyEntry.Delete("member", []string{memberDN.DNOrigStr()})
		if err != nil {
			return err
		}

		err = r.update(tx, nil, modifyEntry)
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
		log.Printf("No entries which have memberOf for delete. memberOfDN: %s", memberOfDN.DNNormStr())
		return nil
	}

	for _, modifyEntry := range modifyEntries {
		err := modifyEntry.Delete("memberOf", []string{memberOfDN.DNOrigStr()})
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
		"dnNorm": memberDN.DNNormStr(),
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
		"dnNorm": memberDN.DNNormStr(),
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

func getDC(tx *sqlx.Tx, dn *DN) (*FetchedParent, error) {
	var err error
	parent := FetchedParent{}

	if tx != nil {
		err = tx.NamedStmt(getDCStmt).Get(&parent, map[string]interface{}{})
	} else {
		err = getDCStmt.Get(&parent, map[string]interface{}{})
	}
	if err != nil {
		return nil, err
	}

	return &parent, nil
}

func findParentByDN(tx *sqlx.Tx, dn *DN) (*FetchedParent, error) {
	// 	select e0.id, e1.rdn_orig || ',' || e1.rdn_orig from || ',' || e2.rdn_orig AS dn_orig FROM ldap_tree e2
	//     LEFT OUTER JOIN ldap_tree e1 ON e1.parent_id = e2.id
	//     LEFT OUTER JOIN ldap_tree e0 ON e0.parent_id = e1.id
	//     WHERE e2.rdn_norm = 'ou=mycompany' AND e1.rdn_norm = 'ou=mysection' AND e0.rdn_nrom = 'ou=mydept';

	pdn := dn.ParentDN()

	if pdn.IsDC() {
		return getDC(tx, dn)
	}

	size := len(pdn.dnNorm)
	last := size - 1
	params := make(map[string]interface{}, size)

	key := pdn.DNNormStr()

	var fetchStmt *sqlx.NamedStmt
	var ok bool
	var err error
	if fetchStmt, ok = treeStmtCache.Get(key); !ok {
		projection := make([]string, size)
		join := make([]string, size)
		where := make([]string, size)

		for i := last; i >= 0; i-- {
			projection[i] = fmt.Sprintf("e%d.rdn_norm", i)
			if i == last {
				join[last-i] = fmt.Sprintf("ldap_tree e%d", i)
			} else {
				join[last-i] = fmt.Sprintf("LEFT OUTER JOIN ldap_tree e%d ON e%d.parent_id = e%d.id", i, i, i+1)
			}
			where[last-i] = fmt.Sprintf("e%d.rdn_norm = :rdn_norm_%d", i, i)

			params[fmt.Sprintf("rdn_norm_%d", i)] = pdn.dnNorm[i]
		}

		q := fmt.Sprintf("SELECT e0.id, %s AS dn_orig FROM %s WHERE %s",
			strings.Join(projection, " || ',' || "), strings.Join(join, " "), strings.Join(where, " AND "))

		log.Printf("debug: findByDN query: %s, params: %v", q, params)

		// cache
		fetchStmt, err = db.PrepareNamed(q)
		if err != nil {
			return nil, err
		}
		treeStmtCache.Put(key, fetchStmt)

	} else {
		for i := last; i >= 0; i-- {
			params[fmt.Sprintf("rdn_norm_%d", i)] = pdn.dnNorm[i]
		}
	}

	parent := FetchedParent{}
	if tx != nil {
		err = tx.NamedStmt(fetchStmt).Get(&parent, params)
	} else {
		err = fetchStmt.Get(&parent, params)
	}
	if err != nil {
		return nil, err
	}

	return &parent, nil
}

func findChildrenByParentID(parentID int64) ([]*FetchedChild, error) {
	rows, err := findChildrenByParentIDStmt.Queryx(map[string]interface{}{
		"parent_id": parentID,
	})
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch child ID by parentID: %s, err: %w", parentID, err)
	}
	defer rows.Close()

	list := []*FetchedChild{}
	for rows.Next() {
		child := FetchedChild{}
		rows.StructScan(&child)
		list = append(list, &child)
	}

	err = rows.Err()
	if err != nil {
		log.Printf("error: Search children error: %#v", err)
		return nil, err
	}

	return list, nil
}

func findByDN(tx *sqlx.Tx, dn *DN) (*SearchEntry, error) {
	dbEntry, err := findByDNWithOption(tx, dn, false)
	if err != nil {
		return nil, err
	}
	return mapper.FetchedDBEntryToSearchEntry(dbEntry)
}

func findByDNWithLock(tx *sqlx.Tx, dn *DN) (*ModifyEntry, error) {
	dbEntry, err := findByDNWithOption(tx, dn, true)
	if err != nil {
		return nil, err
	}
	return mapper.FetchedDBEntryToModifyEntry(dbEntry)
}

func (r *Repository) findByDNNormWithLock(tx *sqlx.Tx, dnNormStr string) (*ModifyEntry, error) {
	dn, err := r.server.NormalizeDN(dnNormStr)
	if err != nil {
		return nil, err
	}

	return findByDNWithLock(tx, dn)
}

func findByDNWithOption(tx *sqlx.Tx, dn *DN, lock bool) (*FetchedDBEntry, error) {
	parent, err := findParentByDN(tx, dn)
	if err != nil {
		return nil, err
	}

	dbEntry := FetchedDBEntry{}

	var stmt *sqlx.NamedStmt
	if lock {
		stmt = findByParentIDAndRDNNormStmtWithLockStmt
	} else {
		stmt = findByParentIDAndRDNNormStmt
	}
	if tx != nil {
		err = tx.NamedStmt(stmt).Get(&dbEntry, map[string]interface{}{
			"parent_id":      parent.ID,
			"parent_dn_orig": parent.DNOrig,
			"rdn_norm":       dn.RDNNormStr,
		})
	} else {
		err = stmt.Get(&dbEntry, map[string]interface{}{
			"parent_id":      parent.ID,
			"parent_dn_orig": parent.DNOrig,
			"rdn_norm":       dn.RDNNormStr,
		})
	}
	if err != nil {
		return nil, err
	}
	dbEntry.Count = 1

	return &dbEntry, nil
}

func findByDNWithSingleQuery(tx *sqlx.Tx, dnNorm []string) (*FetchedDBEntry, error) {
	// 	select e3.rdn_norm, e2.rdn_norm from, e1.rdn_norm ldap_entry e3
	//     LEFT OUTER JOIN ldap_entry e2 ON e2.parent_id = e3.id
	//     LEFT OUTER JOIN ldap_entry e1 ON e1.parent_id = e2.id
	//     WHERE e3.rdn_norm = 'ou=mycompany' AND e2.rdn_norm = 'ou=people' AND e1.rdn_nrom = 'uid=...';

	size := len(dnNorm)

	projection := make([]string, size)
	join := make([]string, size)
	where := make([]string, size)

	last := size - 1

	params := make(map[string]interface{}, size)

	for i := last; i >= 0; i-- {
		projection[i] = fmt.Sprintf("e%d.rdn_norm", i)
		if i == last {
			join = append(join, fmt.Sprintf("ldap_entry e%d", i))
		} else {
			join = append(join, fmt.Sprintf("LEFT OUTER JOIN ldap_entry e%d ON e%d.parent_id = e%d.id", i, i, i+1))
		}
		where = append(where, fmt.Sprintf("e%d.rdn_norm = :rdn_norm_%d", i, i))

		params[fmt.Sprintf("rdn_norm_%d", i)] = dnNorm[i]
	}

	q := fmt.Sprintf("SELECT %s FROM ldap_entry %s WHERE %s",
		strings.Join(projection, " || ',' || "), strings.Join(join, " "), strings.Join(where, " AND "))

	log.Printf("debug: findByDN query: %s, params: %v", q, params)

	var fetchStmt *sqlx.NamedStmt
	var ok bool
	var err error
	if fetchStmt, ok = filterStmtMap.Get(q); !ok {
		// cache
		fetchStmt, err = db.PrepareNamed(q)
		if err != nil {
			return nil, err
		}
		filterStmtMap.Put(q, fetchStmt)
	}

	dbEntry := FetchedDBEntry{}
	err = tx.NamedStmt(fetchStmt).Get(&dbEntry, params)
	if err != nil {
		return nil, err
	}
	dbEntry.Count = 1

	return &dbEntry, nil
}

func findCredByDN(dn *DN) ([]string, error) {
	var j types.JSONText
	err := findCredByDNStmt.Get(&j, map[string]interface{}{
		"dnNorm": dn.DNNormStr(),
	})
	if err != nil {
		return nil, xerrors.Errorf("Faild to find cred by DN. dn: %s, err: %w", dn.DNNormStr(), err)
	}
	var bindUserCred []string
	err = j.Unmarshal(&bindUserCred)
	if err != nil {
		return nil, xerrors.Errorf("Faild to unmarshal cred. dn: %s, err: %w", dn.DNNormStr(), err)
	}
	return bindUserCred, nil
}

func appenScopeFilter(scope int, q *Query, baseDNID int64, childrenDNIDs []int64) (string, error) {
	// Make query based on the requested scope

	// Scope handling, one and sub need to includ base.
	// 0: base
	// 1: one
	// 2: sub
	// 3: children
	var parentFilter string
	// path := baseDN.ToPath()
	if scope == 0 {
		parentFilter = "e.id = :baseDNID"
		q.Params["baseDNID"] = baseDNID

	} else if scope == 1 {
		parentFilter = "e.parent_id = :baseDNID"
		q.Params["baseDNID"] = baseDNID

	} else if scope == 2 {
		childrenDNIDs = append(childrenDNIDs, baseDNID)
		in, params := expandIn(childrenDNIDs)
		parentFilter = "(e.id = :baseDNID OR e.parent_id IN (" + in + "))"
		q.Params["baseDNID"] = baseDNID
		for k, v := range params {
			q.Params[k] = v
		}

	} else if scope == 3 {
		childrenDNIDs = append(childrenDNIDs, baseDNID)
		in, params := expandIn(childrenDNIDs)
		parentFilter = "e.parent_id IN (" + in + ")"
		for k, v := range params {
			q.Params[k] = v
		}
	}

	var query string
	if q.Query != "" {
		query = " AND " + q.Query
	}

	return fmt.Sprintf("%s %s", parentFilter, query), nil
}

func collectParentIDs(baseDN *DN, scope int) (int64, []int64, map[int64]string, error) {
	// Collect parent ID(s) based on baseDN
	var baseDNID int64 = -1
	var children []*FetchedChild
	dnOrigCache := map[int64]string{ROOT_ID: ""} // Cache for id => dn_orig

	if baseDN.IsDC() {
		entry, err := getDC(nil, baseDN)
		if err != nil {
			return 0, nil, nil, err
		}
		baseDNID = entry.ID
		dnOrigCache[entry.ID] = entry.DNOrig

		if scope > 1 {
			// baseDNID is DCID with default
			children, err = findChildrenByParentID(baseDNID)
			if err != nil {
				return 0, nil, nil, err
			}
		}
	} else {
		if baseDN.IsContainer() {
			entry, err := findParentByDN(nil, baseDN)
			if err != nil {
				return 0, nil, nil, err
			}
			baseDNID = entry.ID
			dnOrigCache[entry.ID] = entry.DNOrig

			if scope > 1 {
				children, err = findChildrenByParentID(baseDNID)
				if err != nil {
					return 0, nil, nil, err
				}
			}
		} else {
			// baseDN is pointed to entry (not container).
			// In that case, don't need to collect children since it can't have children.
			entry, err := findByDNWithOption(nil, baseDN, false)
			if err != nil {
				return 0, nil, nil, err
			}
			baseDNID = entry.ID
			dnOrigCache[entry.ID] = entry.DNOrig
		}
	}

	var cid []int64

	if len(children) > 0 {
		for _, v := range children {
			dnOrigCache[v.ID] = v.DNOrig
		}
		cid = make([]int64, len(children))
		for i := 0; i < len(children); i++ {
			cid[i] = children[i].ID
		}
	}

	return baseDNID, cid, dnOrigCache, nil
}

func findByFilter(baseDN *DN, scope int, q *Query, reqMemberOf bool, handler func(entry *SearchEntry) error) (int32, int32, error) {
	baseDNID, cid, dnOrigCache, err := collectParentIDs(baseDN, scope)
	if err != nil {
		return 0, 0, err
	}

	query, err := appenScopeFilter(scope, q, baseDNID, cid)
	if err != nil {
		return 0, 0, err
	}

	var fetchQuery string
	if reqMemberOf && !*twowayEnabled {
		fetchQuery = fmt.Sprintf(`SELECT id, parent_id, uuid, created, updated, rdn_orig, '' AS dn_orig attrs_orig,
				(select jsonb_agg(e2.dn_norm) AS memberOf
				FROM ldap_entry e2
				WHERE e2.attrs_norm->'member' @> jsonb_build_array(e1.dn_norm)) AS memberOf,
				count(id) over() AS count
			FROM ldap_entry e1
			WHERE %s
			LIMIT :pageSize OFFSET :offset`, query)
	} else {
		// LEFT JOIN LATERAL(
		// 		SELECT t.rdn_norm, t.rdn_orig FROM ldap_tree t WHERE t.id = e.parent_id
		// 	) p ON true
		fetchQuery = fmt.Sprintf(`SELECT e.id, e.parent_id, e.uuid, e.created, e.updated, e.rdn_orig, '' AS dn_orig, e.attrs_orig, count(e.id) over() AS count
			FROM ldap_entry e
			WHERE %s
			LIMIT :pageSize OFFSET :offset`, query)
	}

	log.Printf("Fetch Query: %s Params: %v", fetchQuery, q.Params)

	var fetchStmt *sqlx.NamedStmt
	var ok bool
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

		parentDNOrig, ok := dnOrigCache[dbEntry.ParentID]
		if !ok {
			log.Printf("warn: Failed to retrive parent by parent_id: %d. The parent might be removed or renamed.", dbEntry.ParentID)
			// TODO return busy?
			return 0, 0, xerrors.Errorf("Failed to retrive parent by parent_id: %d", dbEntry.ParentID)
		}

		// Set dn_orig using cache from fetching ldap_tree table
		var dnOrig string
		if parentDNOrig != "" {
			dnOrig = fmt.Sprintf("%s,%s", dbEntry.RDNOrig, parentDNOrig)
		} else {
			dnOrig = dbEntry.RDNOrig
		}
		dbEntry.DNOrig = dnOrig

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
