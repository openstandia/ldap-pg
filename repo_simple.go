package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"golang.org/x/xerrors"
)

type SimpleRepository struct {
	*DBRepository
}

func (r *SimpleRepository) Init() error {
	var err error
	db := r.db

	_, err = db.Exec(`
	CREATE EXTENSION IF NOT EXISTS pgcrypto;
	CREATE EXTENSION IF NOT EXISTS ltree;
	
	CREATE TABLE IF NOT EXISTS ldap_tree (
		id BIGINT PRIMARY KEY,
		path ltree NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_ldap_tree_path ON ldap_tree USING GIST (path);
	
	CREATE TABLE IF NOT EXISTS ldap_entry (
		id BIGSERIAL PRIMARY KEY,
		parent_id BIGINT,
		rdn_norm VARCHAR(255) NOT NULL,
		rdn_orig VARCHAR(255) NOT NULL,
		attrs_norm JSONB NOT NULL,
		attrs_orig JSONB NOT NULL
	);
	
	-- basic index
	CREATE UNIQUE INDEX IF NOT EXISTS idx_ldap_entry_rdn_norm ON ldap_entry (parent_id, rdn_norm);
	
	-- all json index
	CREATE INDEX IF NOT EXISTS idx_ldap_entry_attrs ON ldap_entry USING gin (attrs_norm jsonb_path_ops);
	`)

	// Can't find root by this query
	findDNByIDStmt, err = db.PrepareNamed(`SELECT
		e.id, e.rdn_orig || ',' || string_agg(pe.rdn_orig, ',' ORDER BY dn.ord DESC) AS dn_orig
		FROM
			ldap_entry e
			INNER JOIN ldap_tree t ON t.id = e.parent_id
			JOIN regexp_split_to_table(t.path::::text, '[.]') WITH ORDINALITY dn(id, ord) ON true
			JOIN ldap_entry pe ON pe.id = dn.id::::bigint
		WHERE
			e.id = :id
		GROUP BY e.id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findRDNByIDStmt, err = db.PrepareNamed(`SELECT
		e.rdn_orig, e.parent_id
		FROM
			ldap_entry e
		WHERE
			e.id = :id
		`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findRDNsByIDsStmt, err = db.PrepareNamed(`SELECT
		e.rdn_orig, e.parent_id
		FROM
			ldap_entry e
		WHERE
			e.id in (:id)
		`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findContainerByPathStmt, err = db.PrepareNamed(`SELECT
		t.id, string_agg(e.rdn_orig, ',' ORDER BY dn.ord DESC) AS dn_orig
		FROM
			ldap_tree t
			JOIN regexp_split_to_table(t.path::::text, '[.]') WITH ORDINALITY dn(id, ord) ON true
			JOIN ldap_entry e ON e.id = dn.id::::bigint
		WHERE
			t.path ~ :path
		GROUP BY t.id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findIDByParentIDAndRDNNormStmt, err = db.PrepareNamed(`SELECT
		e.id
		FROM
			ldap_entry e
		WHERE
			e.parent_id = :parent_id AND e.rdn_norm = :rdn_norm
	`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	updateAttrsByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET attrs_norm = :attrs_norm, attrs_orig = :attrs_orig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	updateDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET
		rdn_orig = :new_rdn_orig, rdn_norm = :new_rdn_norm,
		attrs_norm = :attrs_norm, attrs_orig = :attrs_orig,
		parent_id = :parent_id
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	updateRDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_entry SET
		rdn_orig = :new_rdn_orig, rdn_norm = :new_rdn_norm,
		attrs_norm = :attrs_norm, attrs_orig = :attrs_orig
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	deleteTreeByIDStmt, err = db.PrepareNamed(`DELETE FROM ldap_tree
		WHERE id = :id RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	deleteByIDStmt, err = db.PrepareNamed(`DELETE FROM ldap_entry 
		WHERE id = :id RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	hasSubStmt, err = db.PrepareNamed(`SELECT EXISTS (SELECT 1 FROM ldap_entry WHERE parent_id = :id)`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	// Don't need to update modifyTimestamp since it's overlay function
	removeMemberByIDStmt, err = db.PrepareNamed(`UPDATE ldap_entry
		SET attrs_norm =
			CASE WHEN (jsonb_array_length(attrs_norm->'member')) = 1
				THEN
					attrs_norm #- '{member}'
				ELSE
					attrs_norm || jsonb_build_object('member', jsonb_path_query_array(attrs_norm->'member', :cond_filter))
			END
		WHERE attrs_norm @@ :cond_where
		RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	// Don't need to update modifyTimestamp since it's overlay function
	removeUniqueMemberByIDStmt, err = db.PrepareNamed(`UPDATE ldap_entry
		SET attrs_norm =
			CASE WHEN (jsonb_array_length(attrs_norm->'uniqueMember')) = 1
				THEN
					attrs_norm #- '{uniqueMember}'
				ELSE
					attrs_norm || jsonb_build_object('uniqueMember', jsonb_path_query_array(attrs_norm->'uniqueMember', :cond_filter))
			END
		WHERE attrs_norm @@ :cond_where
		RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	return nil
}

type SimpleDBEntry struct {
	ID        int64          `db:"id"`
	DNNorm    string         `db:"dn_norm"`
	DNOrig    string         `db:"dn_orig"`
	EntryUUID string         `db:"uuid"`
	Created   time.Time      `db:"created"`
	Updated   time.Time      `db:"updated"`
	AttrsNorm types.JSONText `db:"attrs_norm"`
	AttrsOrig types.JSONText `db:"attrs_orig"`
	Count     int32          `db:"count"`    // No real column in the table
	MemberOf  types.JSONText `db:"memberof"` // No real column in the table
}

type SimpleFetchedDBEntry struct {
	ID              int64          `db:"id"`
	ParentID        int64          `db:"parent_id"`
	RDNOrig         string         `db:"rdn_orig"`
	RawAttrsOrig    types.JSONText `db:"attrs_orig"`
	RawMember       types.JSONText `db:"member"`          // No real column in the table
	RawUniqueMember types.JSONText `db:"uniquemember"`    // No real column in the table
	RawMemberOf     types.JSONText `db:"member_of"`       // No real column in the table
	HasSubordinates string         `db:"hassubordinates"` // No real column in the table
	DNOrig          string         `db:"dn_orig"`         // No real clumn in t he table
	Count           int32          `db:"count"`           // No real column in the table
	ParentDNOrig    string         // No real column in the table
}

//////////////////////////////////////////
// ADD operation
//////////////////////////////////////////

func (r *SimpleRepository) Insert(entry *AddEntry) (int64, error) {
	tx := r.db.MustBegin()
	return r.insertWithTx(tx, entry)
}

func (r *SimpleRepository) insertWithTx(tx *sqlx.Tx, entry *AddEntry) (int64, error) {
	var err error
	var newID int64

	if entry.dn.IsRoot() {
		newID, err = r.insertRootEntry(tx, entry)
	} else {
		newID, _, err = r.insertEntryAndTree(tx, entry)
	}
	if err != nil {
		rollback(tx)
		return 0, err
	}

	err = tx.Commit()
	if err != nil {
		rollback(tx)
		return 0, NewUnavailable()
	}
	return newID, nil
}

func (r *SimpleRepository) insertEntryAndTree(tx *sqlx.Tx, entry *AddEntry) (int64, int64, error) {
	if entry.DN().IsRoot() {
		return 0, 0, xerrors.Errorf("Invalid entry, it should not be root DN. DN: %v", entry.dn)
	}

	newID, parentId, err := r.insertEntry(tx, entry)
	if err != nil {
		return 0, 0, err
	}

	// Now, the parent entry has a child
	// Insert tree entry for the parent
	err = r.insertTree(tx, parentId, entry.ParentDN().IsRoot())
	if err != nil {
		return 0, 0, err
	}

	return newID, parentId, nil
}

func (r *SimpleRepository) insertEntry(tx *sqlx.Tx, entry *AddEntry) (int64, int64, error) {
	if entry.DN().IsRoot() {
		return 0, 0, xerrors.Errorf("Invalid entry, it should not be root DN. DN: %v", entry.dn)
	}

	dbEntry, memberOf, err := r.AddEntryToDBEntry(tx, entry)
	if err != nil {
		return 0, 0, err
	}

	params := createFindTreePathByDNParams(entry.ParentDN())
	params["rdn_norm"] = entry.RDNNorm()
	params["rdn_orig"] = entry.RDNOrig()
	params["attrs_norm"] = dbEntry.AttrsNorm
	params["attrs_orig"] = dbEntry.AttrsOrig

	// When inserting new entry, we need to lock the parent DN entry while the processing
	// because there is a chance other thread deletes the parent DN entry before the inserting if no lock.
	findParentDNByDN, err := createFindBasePathByDNSQL(entry.ParentDN(), &FindOption{Lock: true})
	if err != nil {
		return 0, 0, xerrors.Errorf("Failed to create findTreePathByDN sql, err: %w", err)
	}

	q := fmt.Sprintf(`
		INSERT INTO ldap_entry (parent_id, rdn_norm, rdn_orig, attrs_norm, attrs_orig)
		SELECT p.id AS parent_id, :rdn_norm, :rdn_orig, :attrs_norm, :attrs_orig
			FROM (%s) p
			WHERE NOT EXISTS (
				SELECT id FROM ldap_entry WHERE parent_id = p.id AND rdn_norm = :rdn_norm
			)
		RETURNING id, parent_id`, findParentDNByDN)

	log.Printf("insert entry query:\n%s\nparams:\n%v", q, params)

	stmt, err := tx.PrepareNamed(q)
	if err != nil {
		return 0, 0, xerrors.Errorf("Failed to prepare insert query. query: %s, err: %w", q, err)
	}

	rows, err := tx.NamedStmt(stmt).Queryx(params)
	if err != nil {
		return 0, 0, xerrors.Errorf("Failed to insert entry record. entry: %v, err: %w", entry, err)
	}
	defer rows.Close()

	var id int64
	var parentId int64
	if rows.Next() {
		err := rows.Scan(&id, &parentId)
		if err != nil {
			return 0, 0, xerrors.Errorf("Failed to scan. entry: %v, err: %w", entry, err)
		}
	} else {
		log.Printf("debug: The new entry already exists. parentId: %d, rdn_norm: %s", parentId, entry.RDNNorm())
		return 0, 0, NewAlreadyExists()
	}
	rows.Close()

	// Add memberOf
	if len(memberOf) > 0 {
		uq := `
			UPDATE ldap_entry
				SET attrs_norm = attrs_norm || jsonb_build_object('memberOf', COALESCE(attrs_norm->'memberOf', '[]') || :id)
			WHERE id IN (` + strings.Join(memberOf, ",") + `)
		`

		log.Printf("debug: Update memberOf query: %s", uq)

		stmt, err := tx.PrepareNamed(uq)
		if err != nil {
			return 0, 0, xerrors.Errorf("Failed to update memberOf for id: %d. err: %w", id, err)
		}

		result, err := tx.NamedStmt(stmt).Exec(map[string]interface{}{
			"id": strconv.FormatInt(id, 10),
		})
		if err != nil {
			return 0, 0, xerrors.Errorf("Failed to update memberOf for id: %d. err: %w", id, err)
		}

		count, err := result.RowsAffected()
		if err != nil {
			return 0, 0, xerrors.Errorf("Failed to get rows affected for id: %d. err: %w", id, err)
		}

		if count != int64(len(memberOf)) {
			return 0, 0, xerrors.Errorf("Unexpected update memberOf count. expected: %d, got: %d", len(memberOf), count)
		}
	}

	return id, parentId, nil
}

func (r *SimpleRepository) insertTree(tx *sqlx.Tx, id int64, isRoot bool) error {
	var q string
	if isRoot {
		q = `
			INSERT INTO ldap_tree (id, path)
			SELECT :id, :id as path
			WHERE NOT EXISTS (
				SELECT id FROM ldap_tree WHERE id = :id
			)
			RETURNING id, path
	`
	} else {
		q = `
			INSERT INTO ldap_tree (id, path)
			SELECT :id, p.path || :id as path
			FROM (
				SELECT
					t.id, t.path
				FROM
					ldap_tree t, ldap_entry e
				WHERE 
					e.id = :id AND e.parent_id = t.id
			) p
			WHERE NOT EXISTS (
				SELECT id FROM ldap_tree WHERE id = :id
			)
			RETURNING id, path
		`
	}
	params := map[string]interface{}{}
	params["id"] = id

	log.Printf("insert tree query:\n%s\nparams:\n%v", q, params)

	stmt, err := tx.PrepareNamed(q)
	if err != nil {
		return xerrors.Errorf("Failed to prepare insert tree entry query. query: %s, params: %v, err: %w", q, params, err)
	}

	rows, err := tx.NamedStmt(stmt).Queryx(params)
	if err != nil {
		return xerrors.Errorf("Failed to insert tree entry record. query: %s, params: %v, err: %w", q, params, err)
	}
	defer rows.Close()

	var newTreeID int64
	var path string
	if rows.Next() {
		err := rows.Scan(&newTreeID, &path)
		if err != nil {
			return xerrors.Errorf("Failed to scan. id: %d, err: %w", id, err)
		}
		log.Printf("debug: Inserted new tree entry. id: %d, path: %s", newTreeID, path)
	} else {
		log.Printf("debug: The tree entry already exists. id: %d", id)
	}

	return nil
}

func (r *SimpleRepository) insertRootEntry(tx *sqlx.Tx, entry *AddEntry) (int64, error) {
	if !entry.DN().IsRoot() {
		return 0, xerrors.Errorf("Invalid entry, it should be root DN. DN: %v", entry.dn)
	}
	if !entry.DN().IsDC() {
		return 0, xerrors.Errorf("Invalid entry, it should be dc for rootDN. DN: %v", entry.dn)
	}

	// Root entry (DC) doesn't have member, ignore it
	dbEntry, _, err := r.AddEntryToDBEntry(tx, entry)
	if err != nil {
		return 0, err
	}

	params := map[string]interface{}{}
	params["rdn_norm"] = entry.RDNNorm()
	params["rdn_orig"] = entry.RDNOrig()
	params["attrs_norm"] = dbEntry.AttrsNorm
	params["attrs_orig"] = dbEntry.AttrsOrig

	q := `
		INSERT INTO ldap_entry (parent_id, rdn_norm, rdn_orig, attrs_norm, attrs_orig)
		SELECT NULL as parent_id, :rdn_norm, :rdn_orig, :attrs_norm, :attrs_orig
		WHERE NOT EXISTS (
			SELECT id FROM ldap_entry WHERE parent_id IS NULL AND rdn_norm = :rdn_norm
		)
		RETURNING id`

	log.Printf("insert root entry query:\n%s\nparams:\n%v", q, params)

	stmt, err := tx.PrepareNamed(q)
	if err != nil {
		return 0, xerrors.Errorf("Failed to prepare insert root query. query: %s, err: %w", q, err)
	}

	rows, err := tx.NamedStmt(stmt).Queryx(params)
	if err != nil {
		return 0, xerrors.Errorf("Failed to insert root entry record. entry: %v, err: %w", entry, err)
	}
	defer rows.Close()

	var id int64
	if rows.Next() {
		err := rows.Scan(&id)
		if err != nil {
			return 0, xerrors.Errorf("Failed to scan result of the new root entry. entry: %v, err: %w", entry, err)
		}
	} else {
		log.Printf("debug: The root entry already exists. rdn_norm: %s", entry.RDNNorm())
		return 0, NewAlreadyExists()
	}

	return id, nil
}

//////////////////////////////////////////
// MOD operation
//////////////////////////////////////////

func (r *SimpleRepository) Update(dn *DN, callback func(current *ModifyEntry) error) error {
	tx := r.db.MustBegin()

	// Fetch target entry with lock
	oldEntry, err := r.findByDNForUpdate(tx, dn)
	if err != nil {
		rollback(tx)
		return err
	}

	newEntry, err := mapper.FetchedEntryToModifyEntry(oldEntry)
	if err != nil {
		rollback(tx)
		xerrors.Errorf("Failed to map to ModifyEntry in %s: %v, err: %w", txLabel(tx), dn, err)
	}

	// Apply modify operations from LDAP request
	err = callback(newEntry)
	if err != nil {
		rollback(tx)
		return err
	}

	// Then, update database
	if newEntry.dbEntryID == 0 {
		return xerrors.Errorf("Invalid dbEntryId for update DBEntry in %s.", txLabel(tx))
	}

	dbEntry, _, err := r.modifyEntryToDBEntry(tx, newEntry)
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(updateAttrsByIdStmt).Exec(map[string]interface{}{
		"id":         dbEntry.ID,
		"updated":    dbEntry.Updated,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
	})
	if err != nil {
		return xerrors.Errorf("Failed to update entry in %s. entry: %v, err: %w", txLabel(tx), newEntry, err)
	}

	return commit(tx)
}

func (r *SimpleRepository) findByDNForUpdate(tx *sqlx.Tx, dn *DN) (*FetchedEntry, error) {
	stmt, params, err := r.PrepareFindDNByDN(dn, &FindOption{Lock: true, FetchAttrs: true})
	if err != nil {
		return nil, xerrors.Errorf("Failed to prepare FindEntryByDN in %s: %v, err: %w", txLabel(tx), dn, err)
	}

	var dest FetchedEntry
	err = namedStmt(tx, stmt).Get(&dest, params)
	if err != nil {
		if isNoResult(err) {
			return nil, NewNoSuchObject()
		}
		return nil, xerrors.Errorf("Failed to fetch FindEntryByDN in %s: %v, err: %w", txLabel(tx), dn, err)
	}

	return &dest, nil
}

func (r *SimpleRepository) UpdateDN(oldDN, newDN *DN, oldRDN *RelativeDN) error {
	tx := r.db.MustBegin()

	// Fetch target entry with lock
	oldEntry, err := r.findByDNForUpdate(tx, oldDN)
	if err != nil {
		rollback(tx)
		return err
	}

	me, err := mapper.FetchedEntryToModifyEntry(oldEntry)
	if err != nil {
		return err
	}

	if !oldDN.ParentDN().Equal(newDN.ParentDN()) {
		// Move or copy onto the new parent case
		err = r.updateDNOntoNewParent(tx, oldDN, newDN, oldRDN, me)
	} else {
		// Update rdn only case
		err = r.updateRDN(tx, oldDN, newDN, oldRDN, me)
	}

	if err != nil {
		rollback(tx)
		return err
	}

	return commit(tx)
}

func (r *SimpleRepository) updateDNOntoNewParent(tx *sqlx.Tx, oldDN, newDN *DN, oldRDN *RelativeDN, oldEntry *ModifyEntry) error {
	oldParentDN := oldDN.ParentDN()
	newParentDN := newDN.ParentDN()

	newParentID := oldEntry.dbParentID
	var oldParentID int64 = -1

	if !oldParentDN.Equal(newParentDN) {
		// Lock the old/new parent entry
		newParentFetchedDN, err := r.findDNByDNWithLock(tx, newParentDN, true)
		if err != nil {
			log.Printf("debug: Failed to fetch the new parent by DN: %s, err: %v", newParentDN.DNOrigStr(), err)
			return NewNoSuchObject()
		}
		oldParentFetchedDN, err := r.findDNByDNWithLock(tx, oldParentDN, true)
		if err != nil {
			log.Printf("debug: Failed to fetch the old parent by DN: %s, err: %v", oldParentDN.DNOrigStr(), err)
			return NewNoSuchObject()
		}

		newParentID = newParentFetchedDN.ID
		oldParentID = oldParentFetchedDN.ID

		if !newParentFetchedDN.HasSub {
			// If the parent doesn't have any sub, need to insert tree entry first.
			// Also, need to lock the parent entry of the parent before it.
			newGrandParentDN := newParentDN.ParentDN()
			if newGrandParentDN != nil {
				_, err := r.findDNByDNWithLock(tx, newParentDN.ParentDN(), true)
				if err != nil {
					return NewNoSuchObject()
				}
			}

			// Register as container
			err = r.insertTree(tx, newParentFetchedDN.ID, newParentFetchedDN.IsRoot())
			if err != nil {
				return err
			}
		}

		// Move tree if the operation is for tree which means the old entry has children
		if oldEntry.hasSub {
			if err := r.moveTree(tx, oldEntry.path, newParentFetchedDN.Path); err != nil {
				return err
			}
		}
	}

	newEntry := oldEntry.ModifyRDN(newDN)

	if oldRDN != nil {
		for _, attr := range oldRDN.Attributes {
			if err := newEntry.Add(attr.TypeOrig, []string{attr.ValueOrig}); err != nil {
				log.Printf("warn: Failed to remain old RDN, err: %s", err)
				return err
			}
		}
	}

	// ModifyDN doesn't affect the member, ignore it
	dbEntry, _, err := r.modifyEntryToDBEntry(tx, newEntry)
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(updateDNByIdStmt).Exec(map[string]interface{}{
		"id":           oldEntry.dbEntryID,
		"parent_id":    newParentID,
		"new_rdn_norm": newDN.RDNNormStr(),
		"new_rdn_orig": newDN.RDNOrigStr(),
		"attrs_norm":   dbEntry.AttrsNorm,
		"attrs_orig":   dbEntry.AttrsOrig,
	})
	if err != nil {
		return xerrors.Errorf("Failed to update entry DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
	}

	if !oldParentDN.Equal(newParentDN) {
		// Check if the old parent entry still has children
		hasSub, err := r.hasSub(tx, oldParentID)
		if err != nil {
			return err
		}

		// Delete the tree entry if the old parent doesn't have any children now
		if !hasSub {
			if err := r.deleteTreeByID(tx, oldParentID); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *SimpleRepository) updateRDN(tx *sqlx.Tx, oldDN, newDN *DN, oldRDN *RelativeDN, oldEntry *ModifyEntry) error {
	// Update the entry even if it's same RDN to update modifyTimestamp
	newEntry := oldEntry.ModifyRDN(newDN)

	if oldRDN != nil {
		for _, attr := range oldRDN.Attributes {
			if err := newEntry.Add(attr.TypeOrig, []string{attr.ValueOrig}); err != nil {
				log.Printf("info: Schema error but ignore it. err: %s", err)
			}
		}
	}

	// Modify RDN doesn't affect the member, ignore it
	dbEntry, _, err := r.modifyEntryToDBEntry(tx, newEntry)
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(updateRDNByIdStmt).Exec(map[string]interface{}{
		"id":           oldEntry.dbEntryID,
		"new_rdn_norm": newDN.RDNNormStr(),
		"new_rdn_orig": newDN.RDNOrigStr(),
		"attrs_norm":   dbEntry.AttrsNorm,
		"attrs_orig":   dbEntry.AttrsOrig,
	})

	if err != nil {
		return xerrors.Errorf("Failed to update entry DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
	}

	return nil

}

func (r *SimpleRepository) moveTree(tx *sqlx.Tx, sourcePath, newParentPath string) error {
	// http://patshaughnessy.net/2017/12/14/manipulating-trees-using-sql-and-the-postgres-ltree-extension
	// update tree set path = DESTINATION_PATH || subpath(path, nlevel(SOURCE_PATH)-1) where path <@ SOURCE_PATH;

	q := `
		UPDATE ldap_tree SET path = :dest_path || subpath(path, nlevel(:source_path)-1)
		WHERE path <@ :source_path
	`

	_, err := tx.NamedExec(q, map[string]interface{}{
		"dest_path":   newParentPath,
		"source_path": sourcePath,
	})

	if err != nil {
		return xerrors.Errorf("Failed to move tree, sourcePath: %s, destPath: %s, err: %w", sourcePath, newParentPath, err)
	}

	return nil
}

//////////////////////////////////////////
// DEL operation
//////////////////////////////////////////

func (r SimpleRepository) DeleteByDN(dn *DN) error {
	tx := r.db.MustBegin()

	// First, fetch the target entry with lock
	fetchedDN, err := r.findDNByDNWithLock(tx, dn, true)
	if err != nil {
		rollback(tx)
		return err
	}

	// Not allowed error if the entry has children yet
	if fetchedDN.HasSub {
		rollback(tx)
		return NewNotAllowedOnNonLeaf()
	}

	// Delete entry
	delID, err := r.deleteByID(tx, fetchedDN.ID)
	if err != nil {
		rollback(tx)
		return err
	}

	log.Printf("debug: deleteByID end")

	// Delete tree entry if the parent doesn't have children
	hasSub, err := r.hasSub(tx, fetchedDN.ParentID)
	if err != nil {
		rollback(tx)
		return err
	}
	log.Printf("debug: hasSub end")
	if !hasSub {
		if err := r.deleteTreeByID(tx, fetchedDN.ParentID); err != nil {
			rollback(tx)
			return err
		}
		log.Printf("debug: deleteTreeByID end")
	}
	log.Printf("debug: removeAssociationById start")

	// Remove member and uniqueMember if the others have association for the target entry
	err = r.removeAssociationById(tx, delID)
	if err != nil {
		rollback(tx)
		return err
	}
	log.Printf("debug: removeAssociationById end")

	// Commit!
	return commit(tx)
}

func (r *SimpleRepository) hasSub(tx *sqlx.Tx, id int64) (bool, error) {
	var hasSub bool
	err := tx.NamedStmt(hasSubStmt).Get(&hasSub, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		return false, xerrors.Errorf("Failed to check existence. id: %d, err: %w", id, err)
	}

	return hasSub, nil
}

func (r *SimpleRepository) deleteByID(tx *sqlx.Tx, id int64) (int64, error) {
	var delID int64 = -1

	err := namedStmt(tx, deleteByIDStmt).Get(&delID, map[string]interface{}{
		"id": id,
	})

	if err != nil {
		if isNoResult(err) {
			return 0, NewNoSuchObject()
		}
		return 0, xerrors.Errorf("Failed to exec deleteByID query. query: %s, params: %v, err: %w",
			deleteByIDStmt.QueryString, deleteByIDStmt.Params, err)
	}

	// TODO need?
	if delID == -1 {
		return 0, NewNoSuchObject()
	}

	return delID, nil
}

func (r *SimpleRepository) deleteTreeByID(tx *sqlx.Tx, id int64) error {
	var delID int64 = -1
	err := tx.NamedStmt(deleteTreeByIDStmt).Get(&delID, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		if isNoResult(err) {
			return NewNoSuchObject()
		}
		return xerrors.Errorf("Failed to delete tree node. id: %d, err: %w", id, err)
	}

	// TODO need?
	if delID == -1 {
		return NewNoSuchObject()
	}

	return nil
}

func (r *SimpleRepository) removeAssociationById(tx *sqlx.Tx, id int64) error {
	if err := r.execRemoveAssociatio(tx, id, removeMemberByIDStmt, "member"); err != nil {
		return err
	}
	if err := r.execRemoveAssociatio(tx, id, removeUniqueMemberByIDStmt, "uniqueMember"); err != nil {
		return err
	}
	return nil
}

func (r *SimpleRepository) execRemoveAssociatio(tx *sqlx.Tx, id int64, stmt *sqlx.NamedStmt, attrName string) error {
	idStr := strconv.FormatInt(id, 10)

	var updatedID int64 = -1
	err := tx.NamedStmt(stmt).Get(&updatedID, map[string]interface{}{
		"cond_filter": `$ ? (@ != ` + idStr + `)`,
		"cond_where":  `$.` + attrName + ` == ` + idStr + ``,
	})
	if err != nil {
		if isNoResult(err) {
			// Ignore
			return nil
		}
		return xerrors.Errorf("Failed to delete association. query: %s, id: %d, err: %w", stmt.QueryString, id, err)
	}

	// TODO need?
	if updatedID == -1 {
		// Ignore
		return nil
	}

	return nil
}

//////////////////////////////////////////
// SEARCH operation
//////////////////////////////////////////

func (e *SimpleFetchedDBEntry) Member(repo Repository, IdToDNOrigCache map[int64]string) ([]string, error) {
	if len(e.RawMember) == 0 {
		return nil, nil
	}

	jsonArray := []int64{}
	err := e.RawMember.Unmarshal(&jsonArray)
	if err != nil {
		return nil, err
	}

	dns, err := e.findRDNsByIDs(nil, jsonArray, false)
	if err != nil {
		return nil, err
	}

	results := make([]string, len(dns))

	for i, m := range dns {
		parentId := m.ParentID

		parentDNOrig, ok := IdToDNOrigCache[parentId]
		if !ok {
			// TODO optimize
			parentDN, err := e.findDNByID(nil, parentId, false)
			if err != nil {
				// TODO ignore no result
				return nil, xerrors.Errorf("Failed to fetch by parent_id: %s, err: %w", parentId, err)
			}
			parentDNOrig = parentDN.DNOrig

			// Cache
			IdToDNOrigCache[parentId] = parentDN.DNOrig
		}

		results[i] = m.RDNOrig + `,` + parentDNOrig
	}
	return results, nil
}

func (e *SimpleFetchedDBEntry) Member2(repo Repository, IdToDNOrigCache map[int64]string) ([]string, error) {
	if len(e.RawMember) == 0 {
		return nil, nil
	}

	jsonArray := []int64{}
	err := e.RawMember.Unmarshal(&jsonArray)
	if err != nil {
		return nil, err
	}

	dns, err := e.findDNsByIDs(nil, jsonArray, false)
	if err != nil {
		return nil, err
	}

	results := make([]string, len(dns))

	for i, m := range dns {
		results[i] = m.DNOrig
	}
	return results, nil
}

func (e *SimpleFetchedDBEntry) MemberOf(repo Repository, IdToDNOrigCache map[int64]string) ([]string, error) {
	if len(e.RawMemberOf) == 0 {
		return nil, nil
	}

	jsonArray := []int64{}
	err := e.RawMemberOf.Unmarshal(&jsonArray)
	if err != nil {
		return nil, err
	}

	dns, err := e.findRDNsByIDs(nil, jsonArray, false)
	if err != nil {
		return nil, err
	}

	results := make([]string, len(dns))

	for i, m := range dns {
		parentId := m.ParentID

		parentDNOrig, ok := IdToDNOrigCache[parentId]
		if !ok {
			// TODO optimize
			parentDN, err := e.findDNByID(nil, parentId, false)
			if err != nil {
				// TODO ignore no result
				return nil, xerrors.Errorf("Failed to fetch by parent_id: %s, err: %w", parentId, err)
			}
			parentDNOrig = parentDN.DNOrig

			// Cache
			IdToDNOrigCache[parentId] = parentDN.DNOrig
		}

		results[i] = m.RDNOrig + `,` + parentDNOrig
	}
	return results, nil
}

func (e *SimpleFetchedDBEntry) MemberOf2(repo Repository, IdToDNOrigCache map[int64]string) ([]string, error) {
	if len(e.RawMemberOf) == 0 {
		return nil, nil
	}

	jsonArray := []int64{}
	err := e.RawMemberOf.Unmarshal(&jsonArray)
	if err != nil {
		return nil, err
	}

	dns, err := e.findDNsByIDs(nil, jsonArray, false)
	if err != nil {
		return nil, err
	}

	results := make([]string, len(dns))

	for i, m := range dns {
		results[i] = m.DNOrig
	}
	return results, nil
}

func (e *SimpleFetchedDBEntry) AttrsOrig() map[string][]string {
	if len(e.RawAttrsOrig) > 0 {
		jsonMap := make(map[string][]string)
		if err := e.RawAttrsOrig.Unmarshal(&jsonMap); err != nil {
			log.Printf("erro: Unexpectd umarshal error: %s", err)
		}

		if len(e.RawMemberOf) > 0 {
			jsonArray := []string{}
			if err := e.RawMemberOf.Unmarshal(&jsonArray); err != nil {
				log.Printf("erro: Unexpectd umarshal error: %s", err)
			}
			jsonMap["memberOf"] = jsonArray
		}

		return jsonMap
	}
	return nil
}

func (e *SimpleFetchedDBEntry) Clear() {
	e.ID = 0
	e.DNOrig = ""
	e.RawAttrsOrig = nil
	e.RawMemberOf = nil
	e.Count = 0
}

type FetchedRDNOrig struct {
	RDNOrig  string `db:"rdn_orig"`
	ParentID int64  `db:"parent_id"`
}

type FetchedDNOrig struct {
	ID     int64  `db:"id"`
	DNOrig string `db:"dn_orig"`
}

func (r *SimpleRepository) Search(baseDN *DN, scope int, q *Query, reqMemberAttrs []string,
	reqMemberOf, isHasSubordinatesRequested bool, handler func(entry *SearchEntry) error) (int32, int32, error) {

	fetchedDN, err := r.findDNByDNWithLock(nil, baseDN, false)
	if err != nil {
		log.Printf("debug: Failed to find DN by DN. err: %+v", err)
		return 0, 0, err
	}

	// Cache
	q.IdToDNOrigCache[fetchedDN.ID] = fetchedDN.DNOrig

	where, err := r.AppenScopeFilter(scope, q, fetchedDN)
	if err != nil {
		return 0, 0, err
	}

	log.Printf("debug: where: %s", where)

	var hasSubordinatesCol string
	if isHasSubordinatesRequested {
		hasSubordinatesCol = `,
			CASE
			WHEN EXISTS (
				SELECT 1 FROM ldap_entry sle WHERE sle.parent_id = e.id
			) THEN 'TRUE' ELSE 'FALSE' END as hassubordinates`
	}

	memberCols := make([]string, len(reqMemberAttrs))
	if len(reqMemberAttrs) > 0 {
		for i, attr := range reqMemberAttrs {
			memberCols[i] = `e.attrs_norm->'` + attr + `' AS ` + attr + `, `
		}
	}

	var memberOfCol string
	if reqMemberOf {
		memberOfCol = `e.attrs_norm->'memberOf' AS member_of,`
	}

	searchQuery := `
		SELECT
			e.id,
			e.parent_id,
			e.rdn_orig,
			'' AS dn_orig,
			` + strings.Join(memberCols, "") + `
			` + memberOfCol + `
			e.attrs_orig,
			count(e.id) over() AS count
			` + hasSubordinatesCol + `
		FROM ldap_entry e
		WHERE
			` + where + ` 
		LIMIT :pageSize OFFSET :offset
	`

	// Resolve pending params
	if len(q.PendingParams) > 0 {
		// Create contaner DN cache
		for k, v := range q.IdToDNOrigCache {
			dn, err := NormalizeDN(r.server.schemaMap, v)
			if err != nil {
				log.Printf("error: Failed to normalize DN fetched from DB, err: %s", err)
				return 0, 0, NewUnavailable()
			}
			q.DNNormToIdCache[dn.DNNormStr()] = k
		}
		for pendingDN, paramKey := range q.PendingParams {
			// Find it from cache
			dnNorm := pendingDN.DNNormStr()
			if id, ok := q.DNNormToIdCache[dnNorm]; ok {
				q.Params["filter"] = strings.Replace(q.Params["filter"].(string), ":"+paramKey, strconv.FormatInt(id, 10), 1)
				continue
			}
			// Find the parent container from cache
			parentDNNorm := pendingDN.ParentDN().DNNormStr()
			if parentId, ok := q.DNNormToIdCache[parentDNNorm]; ok {
				// Find by the parent_id and rdn_norm
				rdnNorm := pendingDN.RDNs[0].NormStr()
				id, err := r.findIDByParentIDAndRDNNorm(nil, parentId, rdnNorm)
				if err != nil {
					log.Printf("debug: Can't find the DN by parent_id: %d and rdn_norm: %s, err: %s", parentId, rdnNorm, err)
					continue
				}

				q.Params["filter"] = strings.Replace(q.Params["filter"].(string), ":"+paramKey, strconv.FormatInt(id, 10), 1)

				// Update cache
				q.DNNormToIdCache[dnNorm] = id

				continue
			}
			// No cache, need to full search...

			dn, err := r.findDNByDNWithLock(nil, pendingDN, false)
			if err != nil {
				log.Printf("debug: Can't find the DN by DN: %s, err: %s", pendingDN.DNNormStr(), err)
				continue
			}

			q.Params["filter"] = strings.Replace(q.Params["filter"].(string), ":"+paramKey, strconv.FormatInt(dn.ID, 10), 1)

			// Update cache
			q.DNNormToIdCache[dnNorm] = dn.ID
			// Update cache with the parent DN
			if _, ok := q.DNNormToIdCache[parentDNNorm]; !ok {
				parentDN := dn.ParentDN(r.server.schemaMap)
				for parentDN != nil {
					if _, ok := q.DNNormToIdCache[parentDN.DNNorm(r.server.schemaMap)]; ok {
						break
					}
					q.DNNormToIdCache[parentDN.DNNorm(r.server.schemaMap)] = parentDN.ID

					// Next parent
					parentDN = parentDN.ParentDN(r.server.schemaMap)
				}
			}
		}
	}

	log.Printf("Fetch Query: %s Params: %v", searchQuery, q.Params)

	var fetchStmt *sqlx.NamedStmt
	var ok bool
	if fetchStmt, ok = filterStmtMap.Get(searchQuery); !ok {
		// cache
		fetchStmt, err = r.db.PrepareNamed(searchQuery)
		if err != nil {
			return 0, 0, err
		}
		filterStmtMap.Put(searchQuery, fetchStmt)
	}

	var rows *sqlx.Rows
	rows, err = fetchStmt.Queryx(q.Params)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()

	dbEntry := SimpleFetchedDBEntry{}
	var maxCount int32 = 0
	var count int32 = 0

	for rows.Next() {
		err := rows.StructScan(&dbEntry)
		if err != nil {
			log.Printf("error: DBEntry struct mapping error: %#v", err)
			return 0, 0, err
		}

		// Set dn_orig using cache from fetching before phase
		var dnOrig string
		if dnOrig, ok = q.IdToDNOrigCache[dbEntry.ID]; !ok {
			parentDNOrig, ok := q.IdToDNOrigCache[dbEntry.ParentID]
			if !ok {
				log.Printf("error: Invalid state, failed to retrieve parent by parent_id: %d", dbEntry.ParentID)
				return 0, 0, xerrors.Errorf("Failed to retrieve parent by parent_id: %d", dbEntry.ParentID)
			}

			dnOrig = dbEntry.RDNOrig + "," + parentDNOrig
		}
		dbEntry.DNOrig = dnOrig

		readEntry, err := mapper.FetchedDBEntryToSearchEntry(&dbEntry, q.IdToDNOrigCache)
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

type FindOption struct {
	Lock       bool
	FetchAttrs bool
	FetchCred  bool
}

func (r *SimpleRepository) PrepareFindDNByDN(dn *DN, opt *FindOption) (*sqlx.NamedStmt, map[string]interface{}, error) {
	//  Key for stmt cache
	key := fmt.Sprintf("PrepareFindDNByDN/LOCK:%v/FETCH_ATTRS:%v/FETCH_CRED:%v/DEPTH:%d",
		opt.Lock, opt.FetchAttrs, opt.FetchCred, len(dn.RDNs))

	// make params
	params := createFindTreePathByDNParams(dn)

	if stmt, ok := treeStmtCache.Get(key); ok {
		// Already cached
		return stmt, params, nil
	}

	// Not cached yet, create query and params, then cache the stmt
	q, err := createFindBasePathByDNSQL(dn, opt)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("debug: createFindTreePathByDNSQL: %s\nparams: %v", q, params)

	stmt, err := r.db.PrepareNamed(q)
	if err != nil {
		return nil, nil, err
	}
	treeStmtCache.Put(key, stmt)

	return stmt, params, nil
}

func createFindTreePathByDNParams(baseDN *DN) map[string]interface{} {
	if baseDN == nil {
		return map[string]interface{}{}
	}

	depth := len(baseDN.RDNs)
	last := depth - 1
	params := make(map[string]interface{}, depth)
	ii := 0
	for i := last; i >= 0; i-- {
		params["rdn_norm"+strconv.Itoa(ii)] = baseDN.RDNs[i].NormStr()
		ii++
	}
	return params
}

// createFindBasePathByDNSQL returns a SQL which selects id, parent_id, path, dn_orig and has_sub.
func createFindBasePathByDNSQL(baseDN *DN, opt *FindOption) (string, error) {
	if len(baseDN.RDNs) == 0 {
		return "", xerrors.Errorf("Invalid DN, it's anonymous")
	}

	var fetchAttrsCols string
	if opt.FetchAttrs {
		fetchAttrsCols = `e0.attrs_orig,`
	}

	var fetchCredCols string
	if opt.FetchCred {
		fetchCredCols = `e0.attrs_orig->'userPassword' as cred,`
	}

	if baseDN.IsRoot() {
		return `
			SELECT
				e0.rdn_orig as dn_orig,
				e0.id,
				e0.parent_id,
				` + fetchAttrsCols + `
				` + fetchCredCols + `
				e0.id as path,
				COALESCE((SELECT true FROM ldap_tree t WHERE t.id = e0.id), false) as has_sub
			FROM
				ldap_entry e0 
			WHERE
				e0.rdn_norm = :rdn_norm0 AND e0.parent_id is NULL
		`, nil
	}

	// Caution: We can't use out join when locking because it causes the following error.
	// ERROR:  FOR UPDATE cannot be applied to the nullable side of an outer join
	// Instead of it, use sub query in projection.

	/*
		SELECT
			e2.rdn_orig || ',' || e1.rdn_orig || ',' || e0.rdn_orig,
			e2.id,
			e2.parent_id,
			(e0.id || '.' || e1.id || '.' || e2.id) as path,
			COALESCE((SELECT true FROM ldap_tree t WHERE t.id = e2.id), false) as has_sub
		FROM
			ldap_entry e0, ldap_entry e1, ldap_entry e2
		WHERE
			e0.rdn_norm = 'dc=com' AND e1.rdn_norm = 'dc=example' AND e2.rdn_norm = 'ou=users'
			AND e0.parent_id is NULL AND e1.parent_id = e0.id AND e2.parent_id = e1.id

				?column?          | id | parent_id | path  | has_sub
		----------------------------+----+-----------+-------+---------
		ou=Users,dc=Example,dc=com |  2 |         1 | 0.1.2 |      t


		SELECT
			e3.rdn_orig || ',' || e2.rdn_orig || ',' || e1.rdn_orig || ',' || e0.rdn_orig,
			e3.id,
			e3.parent_id,
			(e0.id || '.' || e1.id || '.' || e2.id || '.' || e3.id) as path,
			COALESCE((SELECT true FROM ldap_tree t WHERE t.id = e3.id), false) as has_sub
		FROM
			ldap_entry e0, ldap_entry e1, ldap_entry e2, ldap_entry e3
		WHERE
			e0.rdn_norm = 'dc=com' AND e1.rdn_norm = 'dc=example' AND e2.rdn_norm = 'ou=users' AND e3.rdn_norm = 'uid=u000001'
			AND e0.parent_id is NULL AND e1.parent_id = e0.id AND e2.parent_id = e1.id AND e3.parent_id = e2.id

						?column?                | id | parent_id |  path   | has_sub
		----------------------------------------+----+-----------+---------+---------
		uid=u000001,ou=Users,dc=Example,dc=com |  4 |         2 | 0.1.2.4 |       f

	*/
	lastIndex := len(baseDN.RDNs) - 1
	lastIndexStr := strconv.Itoa(lastIndex)

	proj := []string{}
	proj2 := []string{}
	table := []string{}
	where := []string{}
	where2 := []string{}
	for index := range baseDN.RDNs {
		proj = append(proj, fmt.Sprintf("e%d.rdn_orig", lastIndex-index))
		proj2 = append(proj2, fmt.Sprintf("e%d.id", index))
		table = append(table, fmt.Sprintf("ldap_entry e%d", index))
		where = append(where, fmt.Sprintf("e%d.rdn_norm = :rdn_norm%d", index, index))
		if index == 0 {
			where2 = append(where2, fmt.Sprintf("e%d.parent_id is NULL", index))
		} else {
			where2 = append(where2, fmt.Sprintf("e%d.parent_id = e%d.id", index, index-1))
		}
	}
	if opt.FetchAttrs {
		fetchAttrsCols = `e` + lastIndexStr + `.attrs_orig,`
	}

	if opt.FetchCred {
		fetchCredCols = `e` + lastIndexStr + `.attrs_orig->'userPassword' as cred,`
	}

	var lock string
	if opt.Lock {
		lock = " for UPDATE"
	}

	sql := `
	SELECT
	  ` + strings.Join(proj, " || ',' || ") + ` as dn_orig,
	  e` + lastIndexStr + `.id, 
	  e` + lastIndexStr + `.parent_id, 
	  ` + fetchAttrsCols + `
	  ` + fetchCredCols + `
	  ` + strings.Join(proj2, " || '.' || ") + ` as path,
	  COALESCE((SELECT true FROM ldap_tree t WHERE t.id = e` + lastIndexStr + `.id), false) as has_sub
	FROM
	  ` + strings.Join(table, ", ") + `
	WHERE
	  ` + strings.Join(where, " AND ") + ` 
	  AND
	  ` + strings.Join(where2, " AND ") + ` 
	` + lock + `
	`

	log.Printf("debug: createFindBasePathByDNSQL: %s", sql)

	return sql, nil
}

func (r *SimpleRepository) FindRDNByID(tx *sqlx.Tx, id []int64, lock bool) (*FetchedRDNOrig, error) {
	var dest FetchedRDNOrig
	err := namedStmt(tx, findRDNByIDStmt).Get(&dest, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		if isNoResult(err) {
			return nil, NewNoSuchObject()
		}
		return nil, xerrors.Errorf("Failed to fetch FindDNByID in %s, id: %d, err: %w", txLabel(tx), id, err)
	}

	return &dest, nil
}

func (r *SimpleFetchedDBEntry) findRDNsByIDs(tx *sqlx.Tx, id []int64, lock bool) ([]*FetchedRDNOrig, error) {
	in := make([]string, len(id))
	for i, v := range id {
		in[i] = strconv.FormatInt(v, 10)
	}

	q := `SELECT
		e.rdn_orig, e.parent_id
		FROM
			ldap_entry e
		WHERE
			e.id in (` + strings.Join(in, ",") + `)
		`

	rows, err := tx.Queryx(q)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	list := []*FetchedRDNOrig{}
	for rows.Next() {
		child := FetchedRDNOrig{}
		err = rows.StructScan(&child)
		if err != nil {
			return nil, xerrors.Errorf("Failed to find containers by DN due to fail struct scan, err: %w", err)
		}
		list = append(list, &child)
	}

	return list, nil
}

func (r *SimpleFetchedDBEntry) findDNsByIDs(tx *sqlx.Tx, id []int64, lock bool) ([]*FetchedDNOrig, error) {
	in := make([]string, len(id))
	for i, v := range id {
		in[i] = strconv.FormatInt(v, 10)
	}

	q := `
	SELECT
	e.rdn_orig || ',' || string_agg(pe.rdn_orig, ',' ORDER BY dn.ord DESC) AS dn_orig
	FROM
		ldap_entry e
		INNER JOIN ldap_tree t ON t.id = e.parent_id
		JOIN regexp_split_to_table(t.path::text, '[.]') WITH ORDINALITY dn(id, ord) ON true
		JOIN ldap_entry pe ON pe.id = dn.id::bigint
	WHERE
		e.id in (` + strings.Join(in, ",") + `)
	GROUP BY e.id
	`

	rows, err := tx.Queryx(q)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	list := []*FetchedDNOrig{}
	for rows.Next() {
		child := FetchedDNOrig{}
		err = rows.StructScan(&child)
		if err != nil {
			return nil, xerrors.Errorf("Failed to find containers by DN due to fail struct scan, err: %w", err)
		}
		list = append(list, &child)
	}

	return list, nil
}

func (r *SimpleRepository) FindMemberDNsByID(tx *sqlx.Tx, id int64, lock bool) ([]*FetchedDNOrig, error) {
	q := `
	SELECT
	e.rdn_orig || ',' || string_agg(pe.rdn_orig, ',' ORDER BY dn.ord DESC) AS dn_orig
	FROM
		ldap_entry e
		INNER JOIN ldap_tree t ON t.id = e.parent_id
		JOIN regexp_split_to_table(t.path::text, '[.]') WITH ORDINALITY dn(id, ord) ON true
		JOIN ldap_entry pe ON pe.id = dn.id::bigint
	WHERE
		e.attrs_norm @@ '$.member[*] == ` + strconv.FormatInt(id, 10) + `'
	GROUP BY e.id
	`

	rows, err := r.db.Queryx(q)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	list := []*FetchedDNOrig{}
	for rows.Next() {
		child := FetchedDNOrig{}
		err = rows.StructScan(&child)
		if err != nil {
			return nil, xerrors.Errorf("Failed to find containers by DN due to fail struct scan, err: %w", err)
		}
		list = append(list, &child)
	}

	return list, nil
}

func (r *SimpleRepository) FindRDNsByID(tx *sqlx.Tx, id int64, lock bool) ([]*FetchedRDNOrig, error) {
	q := `
	SELECT
	e.rdn_orig, e.parent_id
	FROM
		ldap_entry e
	WHERE
		e.attrs_norm @@ '$.member[*] == ` + strconv.FormatInt(id, 10) + `'
	`

	rows, err := r.db.Queryx(q)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	list := []*FetchedRDNOrig{}
	for rows.Next() {
		child := FetchedRDNOrig{}
		err = rows.StructScan(&child)
		if err != nil {
			return nil, xerrors.Errorf("Failed to find containers by DN due to fail struct scan, err: %w", err)
		}
		list = append(list, &child)
	}

	return list, nil
}

func (r *SimpleFetchedDBEntry) findDNByID(tx *sqlx.Tx, id int64, lock bool) (*FetchedDNOrig, error) {
	var dest FetchedDNOrig
	err := namedStmt(tx, findDNByIDStmt).Get(&dest, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		if isNoResult(err) {
			return nil, NewNoSuchObject()
		}
		return nil, xerrors.Errorf("Failed to fetch FindDNByID in %s, id: %d, err: %w", txLabel(tx), id, err)
	}

	return &dest, nil
}

func (r *SimpleRepository) findDNByDNWithLock(tx *sqlx.Tx, dn *DN, lock bool) (*FetchedDN, error) {
	stmt, params, err := r.PrepareFindDNByDN(dn, &FindOption{Lock: lock})
	if err != nil {
		return nil, xerrors.Errorf("Failed to prepare FindDNOnlyByDN: %v, err: %w", dn, err)
	}

	var dest FetchedDN
	err = namedStmt(tx, stmt).Get(&dest, params)
	if err != nil {
		if isNoResult(err) {
			return nil, NewNoSuchObject()
		}
		return nil, xerrors.Errorf("Failed to fetch FindDNOnlyByDN in %s: %v, err: %w", txLabel(tx), dn, err)
	}

	return &dest, nil
}

func (r *SimpleRepository) FindContainerByDN(tx *sqlx.Tx, dn *FetchedDN, scope int) ([]*FetchedDNOrig, error) {
	// Scope handling, sub need to include base.
	// 0: base
	// 1: one
	// 2: sub
	// 3: children

	if scope == 0 || scope == 1 {
		return nil, xerrors.Errorf("Invalid scope, it should be 2(sub) or 3(children): %d", scope)
	}

	var rows *sqlx.Rows
	var err error

	if !dn.HasSub {
		return []*FetchedDNOrig{{
			ID:     dn.ID,
			DNOrig: dn.DNOrig,
		}}, nil
	}

	if scope == 2 { // sub
		rows, err = namedStmt(tx, findContainerByPathStmt).Queryx(map[string]interface{}{
			"path": dn.Path + ".*{0,}",
		})
	} else if scope == 3 { // children
		rows, err = namedStmt(tx, findContainerByPathStmt).Queryx(map[string]interface{}{
			"path": dn.Path + ".*{1,}",
		})
	}

	if err != nil {
		return nil, xerrors.Errorf("Failed to find containers by DN: %v, err: %w", dn, err)
	}
	defer rows.Close()

	list := []*FetchedDNOrig{}
	for rows.Next() {
		child := FetchedDNOrig{}
		err = rows.StructScan(&child)
		if err != nil {
			return nil, xerrors.Errorf("Failed to find containers by DN due to fail struct scan, DN: %v, err: %w", dn, err)
		}
		list = append(list, &child)
	}

	err = rows.Err()
	if err != nil {
		log.Printf("error: Search children error: %#v", err)
		return nil, err
	}

	return list, nil
}

func (r *SimpleRepository) findIDByParentIDAndRDNNorm(tx *sqlx.Tx, parentId int64, rdn_norm string) (int64, error) {
	var dest int64
	err := namedStmt(tx, findIDByParentIDAndRDNNormStmt).Get(&dest, map[string]interface{}{
		"parent_id": parentId,
		"rdn_norm":  rdn_norm,
	})
	if err != nil {
		if isNoResult(err) {
			return 0, NewNoSuchObject()
		}
		return 0, xerrors.Errorf("Failed to find ID by parent_id: %d and rdn_norm: %s, err: %w", parentId, rdn_norm, err)
	}

	return dest, nil
}

func (r *SimpleRepository) findIDsByParentIDAndRDNNorms(tx *sqlx.Tx, parentID int64, rdnNorms []string) ([]int64, error) {
	stmt, err := r.db.PrepareNamed(`
		SELECT e.id
		FROM ldap_entry e
		WHERE e.parent_id = :parent_id AND e.rdn_norm IN ('` + strings.Join(rdnNorms, "','") + `')
		FOR UPDATE
	`)
	if err != nil {
		return nil, err
	}

	rows, err := namedStmt(tx, stmt).Queryx(map[string]interface{}{
		"parent_id": parentID,
	})
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []int64{}

	for rows.Next() {
		var id int64 = 0
		err := rows.Scan(&id)
		if err != nil {
			log.Printf("error: Struct scan error: %v", err)
			return nil, err
		}
		result = append(result, id)
	}

	if len(result) != len(rdnNorms) {
		return nil, xerrors.Errorf("Can't fetch all rdn_norms. expected: %d, got: %d", len(rdnNorms), len(result))
	}

	return result, nil
}

func (r *SimpleRepository) FindCredByDN(dn *DN) ([]string, error) {
	stmt, params, err := r.PrepareFindDNByDN(dn, &FindOption{FetchCred: true})
	if err != nil {
		return nil, xerrors.Errorf("Failed to prepare FindCredByDN: %v, err: %w", dn, err)
	}

	dest := struct {
		ID       int64          `db:"id"`
		ParentID int64          `db:"parent_id"`
		Path     string         `db:"path"`
		DNOrig   string         `db:"dn_orig"`
		HasSub   bool           `db:"has_sub"`
		Cred     types.JSONText `db:"cred"`
	}{}

	err = stmt.Get(&dest, params)
	if err != nil {
		if isNoResult(err) {
			return nil, NewInvalidCredentials()
		}
		return nil, xerrors.Errorf("Failed to find cred by DN. dn: %s, err: %w", dn.DNOrigStr(), err)
	}

	var cred []string
	err = dest.Cred.Unmarshal(&cred)
	if err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal cred array. dn: %s, err: %w", dn.DNOrigStr(), err)
	}

	return cred, nil
}

func (r *SimpleRepository) AppenScopeFilter(scope int, q *Query, fetchedDN *FetchedDN) (string, error) {

	// Make query based on the requested scope

	// Scope handling, one and sub need to include base.
	// 0: base
	// 1: one
	// 2: sub
	// 3: children
	var parentFilter string
	if scope == 0 { // base
		parentFilter = "e.id = :baseDNID"
		q.Params["baseDNID"] = fetchedDN.ID

	} else if scope == 1 { // one
		parentFilter = "e.parent_id = :baseDNID"
		q.Params["baseDNID"] = fetchedDN.ID

	} else if scope == 2 { // sub
		containers, err := r.FindContainerByDN(nil, fetchedDN, scope)
		if err != nil {
			return "", err
		}

		if len(containers) > 0 {
			// Cache
			for _, c := range containers {
				q.IdToDNOrigCache[c.ID] = c.DNOrig
			}

			in, params := expandContainersIn(containers)
			parentFilter = "(e.id = :baseDNID OR e.parent_id IN (" + in + "))"
			for k, v := range params {
				q.Params[k] = v
			}
		} else {
			parentFilter = "(e.id = :baseDNID)"
		}
		q.Params["baseDNID"] = fetchedDN.ID

	} else if scope == 3 { // children
		containers, err := r.FindContainerByDN(nil, fetchedDN, scope)
		if err != nil {
			return "", err
		}

		// Cache
		for _, c := range containers {
			q.IdToDNOrigCache[c.ID] = c.DNOrig
		}

		in, params := expandContainersIn(containers)
		parentFilter = "e.parent_id = :baseDNID OR e.parent_id IN (" + in + ")"
		q.Params["baseDNID"] = fetchedDN.ID
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

//////////////////////////////////////////
// Mapping
//////////////////////////////////////////

// AddEntryToDBEntry converts LDAP entry object to DB entry object.
// It handles metadata such as createTimistamp, modifyTimestamp and entryUUID.
// Also, it handles member and uniqueMember attributes.
func (m *SimpleRepository) AddEntryToDBEntry(tx *sqlx.Tx, entry *AddEntry) (*SimpleDBEntry, []string, error) {
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

	dbEntry := &SimpleDBEntry{
		DNNorm:    entry.DN().DNNormStr(),
		DNOrig:    entry.DN().DNOrigStr(),
		AttrsNorm: types.JSONText(string(bNorm)),
		AttrsOrig: types.JSONText(string(bOrig)),
	}

	return dbEntry, uniqueIDs(memberOf), nil
}

func (r *SimpleRepository) dnArrayToIDArray(tx *sqlx.Tx, norm map[string]interface{}, attrName string, memberOf *[]int64) error {
	if members, ok := norm[attrName].([]string); ok && len(members) > 0 {

		rdnGroup := map[string][]string{}
		for i, v := range members {
			dn, err := NormalizeDN(r.server.schemaMap, v)
			if err != nil {
				log.Printf("warn: Failed to normalize DN: %s", v)
				return NewInvalidPerSyntax(attrName, i)
			}

			parentDNNorm := dn.ParentDN().DNNormStr()
			rdnGroup[parentDNNorm] = append(rdnGroup[parentDNNorm], dn.RDNNormStr())
		}

		memberIDs := []int64{}

		for k, v := range rdnGroup {
			parentDN, err := NormalizeDN(r.server.schemaMap, k)
			if err != nil {
				log.Printf("error: Unexpected normalize DN error. DN: %s, err: %v", k, err)
				return NewUnavailable()
			}
			fetchedParentDN, err := r.findDNByDNWithLock(tx, parentDN, true)
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

			ids, err := r.findIDsByParentIDAndRDNNorms(tx, fetchedParentDN.ID, v)
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

func (r *SimpleRepository) modifyEntryToDBEntry(tx *sqlx.Tx, entry *ModifyEntry) (*SimpleDBEntry, []string, error) {
	norm, orig := entry.GetAttrs()

	// Remove attributes to reduce attrs_orig column size
	removeComputedAttrs(orig)

	var memberOf []int64

	// Convert the value of member and uniqueMamber attributes, DN => int64
	if err := r.dnArrayToIDArray(tx, norm, "member", &memberOf); err != nil {
		return nil, nil, err
	}
	if err := r.dnArrayToIDArray(tx, norm, "uniqueMember", &memberOf); err != nil {
		return nil, nil, err
	}

	updated := time.Now()
	norm["modifyTimestamp"] = []int64{updated.Unix()}
	orig["modifyTimestamp"] = []string{updated.In(time.UTC).Format(TIMESTAMP_FORMAT)}

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	dbEntry := &SimpleDBEntry{
		ID:        entry.dbEntryID,
		Updated:   updated,
		AttrsNorm: types.JSONText(string(bNorm)),
		AttrsOrig: types.JSONText(string(bOrig)),
	}

	return dbEntry, uniqueIDs(memberOf), nil
}
