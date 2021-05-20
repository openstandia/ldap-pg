package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"github.com/openstandia/goldap/message"
	"golang.org/x/xerrors"
)

type HybridRepository struct {
	*DBRepository
	translator *HybridDBFilterTranslator
}

var (
	// repo_insert
	insertContainerStmtWithUpdateLock *sqlx.NamedStmt
	insertEntryStmt                   *sqlx.NamedStmt

	// repo_read for update
	findEntryIDByDNWithShareLock  *sqlx.NamedStmt
	findEntryIDByDNWithUpdateLock *sqlx.NamedStmt
	findEntryByDNWithShareLock    *sqlx.NamedStmt
	findEntryByDNWithUpdateLock   *sqlx.NamedStmt

	// repo_update
	updateAttrsByIdStmt        *sqlx.NamedStmt
	updateDNByIdStmt           *sqlx.NamedStmt
	updateRDNByIdStmt          *sqlx.NamedStmt
	updateContainerDNByIdStmt  *sqlx.NamedStmt
	updateContainerDNsByIdStmt *sqlx.NamedStmt

	// repo_delete
	deleteContainerStmt          *sqlx.NamedStmt
	deleteByIDStmt               *sqlx.NamedStmt
	deleteAllAssociationByIDStmt *sqlx.NamedStmt
	hasSubStmt                   *sqlx.NamedStmt

	// repo_read for bind
	findCredByDN *sqlx.NamedStmt
)

func (r *HybridRepository) Init() error {
	var err error
	db := r.db

	_, err = db.Exec(`
	CREATE EXTENSION IF NOT EXISTS pgcrypto;
	
	CREATE TABLE IF NOT EXISTS ldap_container (
		id BIGINT PRIMARY KEY,
		dn_norm VARCHAR(512) NOT NULL, -- cache
		dn_orig VARCHAR(512) NOT NULL  -- cache
	);
	CREATE INDEX IF NOT EXISTS idx_ldap_container_dn_norm_reversed ON ldap_container (REVERSE(dn_norm));

	CREATE TABLE IF NOT EXISTS ldap_entry (
		id BIGSERIAL PRIMARY KEY,
		parent_id BIGINT,
		rdn_norm VARCHAR(256) NOT NULL, -- cache
		rdn_orig VARCHAR(256) NOT NULL, -- cache
		attrs_norm JSONB NOT NULL,
		attrs_orig JSONB NOT NULL,
		CONSTRAINT fk_parent_id
			FOREIGN KEY (parent_id)
			REFERENCES ldap_container (id)
			ON DELETE RESTRICT ON UPDATE RESTRICT
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_ldap_entry_rdn_norm ON ldap_entry (parent_id, rdn_norm);
	CREATE INDEX IF NOT EXISTS idx_ldap_entry_attrs ON ldap_entry USING gin (attrs_norm jsonb_path_ops);

	CREATE TABLE IF NOT EXISTS ldap_association (
		name VARCHAR(32) NOT NULL,
		id BIGINT NOT NULL,
		member_id BIGINT NOT NULL,
		UNIQUE (name, id, member_id),
		CONSTRAINT fk_id
			FOREIGN KEY (id)
			REFERENCES ldap_entry (id)
			ON DELETE RESTRICT ON UPDATE RESTRICT,
		CONSTRAINT fk_member_id
			FOREIGN KEY (member_id)
			REFERENCES ldap_entry (id)
			ON DELETE RESTRICT ON UPDATE RESTRICT
	);
	CREATE INDEX IF NOT EXISTS idx_ldap_association_id ON ldap_association(name, id);
	CREATE INDEX IF NOT EXISTS idx_ldap_association_member_id ON ldap_association(name, member_id);
	`)

	findCredByDN, err = db.PrepareNamed(`SELECT
		e.id, e.attrs_orig->'userPassword' AS credential
	FROM
		ldap_entry e
		LEFT JOIN ldap_container c ON e.parent_id = c.id
	WHERE
		e.rdn_norm = :rdn_norm
		AND c.dn_norm = :parent_dn_norm
	`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findEntryByDNWithUpdateLock, err = db.PrepareNamed(`SELECT
		e.id, e.parent_id, e.rdn_orig, e.attrs_orig, has_sub.has_sub
	FROM
		ldap_entry e
		LEFT JOIN ldap_container c ON e.parent_id = c.id
		LEFT JOIN LATERAL (
			SELECT EXISTS (SELECT 1 FROM ldap_container WHERE id = e.id) AS has_sub
	    ) AS has_sub ON true
	WHERE
		e.rdn_norm = :rdn_norm
		AND c.dn_norm = :parent_dn_norm
	FOR UPDATE
	`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findEntryIDByDN := `SELECT
		e.id, e.parent_id, has_sub.has_sub
	FROM
		ldap_entry e
		LEFT JOIN ldap_container c ON e.parent_id = c.id
		LEFT JOIN LATERAL (
			SELECT EXISTS (SELECT 1 FROM ldap_container WHERE id = e.id) AS has_sub
		) AS has_sub ON true
	WHERE
		e.rdn_norm = :rdn_norm
		AND c.dn_norm = :parent_dn_norm
	`

	findEntryIDByDNWithShareLock, err = db.PrepareNamed(findEntryIDByDN + `
	FOR SHARE
	`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findEntryIDByDNWithUpdateLock, err = db.PrepareNamed(findEntryIDByDN + `
	FOR UPDATE
	`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	insertContainerStmtWithUpdateLock, err = db.PrepareNamed(`INSERT INTO ldap_container (id, dn_norm, dn_orig)
	VALUES (:id, :dn_norm, :dn_orig)
	-- Lock the record without change if already exists
	ON CONFLICT (id) DO NOTHING`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	deleteContainerStmt, err = db.PrepareNamed(`DELETE FROM ldap_container WHERE id = :id
	AND
	NOT EXISTS (SELECT 1 FROM ldap_entry WHERE parent_id = :id)
	RETURNING id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	deleteAllAssociationByIDStmt, err = db.PrepareNamed(`DELETE FROM ldap_association WHERE id = :id OR member_id = :id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	insertEntryStmt, err = db.PrepareNamed(`INSERT INTO ldap_entry (parent_id, rdn_norm, rdn_orig, attrs_norm, attrs_orig)
	VALUES (:parent_id, :rdn_norm, :rdn_orig, :attrs_norm, :attrs_orig)
	RETURNING id`)
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

	updateContainerDNByIdStmt, err = db.PrepareNamed(`UPDATE ldap_container SET
		dn_orig = :new_dn_orig, dn_norm = :new_dn_norm
		WHERE id = :id`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	updateContainerDNsByIdStmt, err = db.PrepareNamed(`UPDATE ldap_container SET
		dn_orig = regexp_replace(dn_orig, :old_dn_orig_pattern, :new_dn_orig),
		dn_norm = regexp_replace(dn_norm, :old_dn_norm_pattern, :new_dn_norm)
		WHERE dn_norm ~ :old_dn_norm_pattern`)
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

	return nil
}

// HybridDBEntry is used as insert or update entry.
type HybridDBEntry struct {
	ID                  int64          `db:"id"`
	DNNormWithoutSuffix string         `db:"dn_norm"`
	DNOrigWithoutSuffix string         `db:"dn_orig"`
	RDNNorm             string         `db:"rdn_norm"`
	RDNOrig             string         `db:"rdn_orig"`
	AttrsNorm           types.JSONText `db:"attrs_norm"`
	AttrsOrig           types.JSONText `db:"attrs_orig"`
	ParentDN            *DN
}

//////////////////////////////////////////
// ADD operation
//////////////////////////////////////////

func (r *HybridRepository) Insert(ctx context.Context, entry *AddEntry) (int64, error) {
	tx, err := r.begin(ctx)
	if err != nil {
		return 0, err
	}

	var newID int64

	// We lock the association entries here first.
	// From a performance standpoint, lock with share mode.
	dbEntry, association, err := r.AddEntryToDBEntry(tx, entry)
	if err != nil {
		return 0, err
	}

	if entry.DN().Equal(r.server.Suffix) {
		// Insert level 0
		newID, err = r.insertLevel0(tx, dbEntry)

	} else {
		// Insert level 1+
		newID, err = r.insertInternal(tx, dbEntry)
	}

	if err != nil {
		log.Printf("warn: Failed to insert entry. dn_norm: %s, err: %v", entry.DN().DNNormStr(), err)
		rollback(tx)
		return 0, err
	}

	// Insert association if necessary
	err = r.insertAssociation(tx, entry.dn, newID, association)

	if err != nil {
		log.Printf("warn: Failed to insert association. dn_norm: %s, newID: %d, err: %v", entry.DN().DNNormStr(), newID, err)
		rollback(tx)
		return 0, err
	}

	if err := commit(tx); err != nil {
		log.Printf("error: Failed to commit insert. dn_norm: %s, newID: %d, err: %v", entry.DN().DNNormStr(), newID, err)
		return 0, err
	}

	log.Printf("info: Added. id: %d, dn_norm: %s", newID, entry.DN().DNNormStr())

	return newID, nil
}

func (r *HybridRepository) insertLevel0(tx *sqlx.Tx, dbEntry *HybridDBEntry) (int64, error) {
	var parentId int64 = 0

	// Step 1: Insert parent container for level 0 entry
	if _, err := r.exec(tx, insertContainerStmtWithUpdateLock, map[string]interface{}{
		"id":      parentId,
		"dn_norm": "",
		"dn_orig": "",
	}); err != nil {
		return 0, xerrors.Errorf("Failed to insert level 0 parent container record. err: %w", err)
	}

	// Step 2: Insert entry
	var newID int64
	err := r.get(tx, insertEntryStmt, &newID, map[string]interface{}{
		"parent_id":  parentId,
		"rdn_norm":   dbEntry.RDNNorm,
		"rdn_orig":   dbEntry.RDNOrig,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
	})
	if err != nil {
		if isDuplicateKeyError(err) {
			log.Printf("warn: The new entry already exists. parentId: %d, rdn_norm: %s", parentId, dbEntry.RDNNorm)
			return 0, NewAlreadyExists()
		}
		return 0, xerrors.Errorf("Failed to insert entry record. dbEntry: %v, err: %w", dbEntry, err)
	}

	return newID, nil
}

func (r *HybridRepository) insertInternal(tx *sqlx.Tx, dbEntry *HybridDBEntry) (int64, error) {
	parentDN := dbEntry.ParentDN

	// Step 1: Find the parent ID container or insert the container
	dest := struct {
		ID       int64 `db:"id"`
		ParentID int64 `db:"parent_id"`
		HasSub   bool  `db:"has_sub"`
	}{}

	// When inserting new entry, we need to lock the parent DN entry while the processing
	// because there is a chance other thread deletes the parent DN entry or container before the inserting if no lock.
	// From a performance standpoint, lock with share mode.
	if err := r.get(tx, findEntryIDByDNWithShareLock, &dest, map[string]interface{}{
		"rdn_norm":       parentDN.RDNNormStr(),
		"parent_dn_norm": parentDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix),
	}); err != nil {
		if isNoResult(err) {
			log.Printf("warn: No Parent entry but try to insert the sub. dn_norm: %s,%s",
				dbEntry.RDNNorm, dbEntry.ParentDN.DNNormStr())
			// TODO Add matched DN
			return 0, NewNoSuchObject()
		}
		return 0, xerrors.Errorf("Failed to fetch parent container. dn_norm: %s,%s, err: %w",
			dbEntry.RDNNorm, dbEntry.ParentDN.DNNormStr(), err)
	}

	parentId := dest.ID
	if !dest.HasSub {
		// Not found parent container yet
		// We need to insert new container first and lock it
		if _, err := r.exec(tx, insertContainerStmtWithUpdateLock, map[string]interface{}{
			"id":      parentId,
			"dn_norm": parentDN.DNNormStrWithoutSuffix(r.server.Suffix),
			"dn_orig": parentDN.DNOrigStrWithoutSuffix(r.server.Suffix),
		}); err != nil {
			return 0, xerrors.Errorf("Failed to insert container record.dn_norm: %s,%s, err: %w",
				dbEntry.RDNNorm, dbEntry.ParentDN.DNNormStr(), err)
		}
	}

	// Step 2: Insert entry
	var newID int64
	if err := r.get(tx, insertEntryStmt, &newID, map[string]interface{}{
		"parent_id":  parentId,
		"rdn_norm":   dbEntry.RDNNorm,
		"rdn_orig":   dbEntry.RDNOrig,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
	}); err != nil {
		if isDuplicateKeyError(err) {
			log.Printf("warn: The new entry already exists. dn_norm: %s,%s", dbEntry.RDNNorm, dbEntry.ParentDN.DNNormStr())
			return 0, NewAlreadyExists()
		}
		return 0, xerrors.Errorf("Failed to insert entry record. dn_norm: %s.%s, err: %w",
			dbEntry.RDNNorm, dbEntry.ParentDN.DNNormStr(), err)
	}

	return newID, nil
}

func (r *HybridRepository) insertAssociation(tx *sqlx.Tx, dn *DN, newID int64, association map[string][]int64) error {
	// TODO Use strings.Builder
	values := []string{}
	for k, v := range association {
		// Use bulk insert
		for _, id := range v {
			if k == "memberOf" {
				// TODO configuable the default name when inserting memberOf
				values = append(values, fmt.Sprintf(`('%s', %d, %d)`, "member", id, newID))
			} else {
				values = append(values, fmt.Sprintf(`('%s', %d, %d)`, k, newID, id))
			}
		}
	}
	if len(values) > 0 {
		// Use bulk insert
		q := fmt.Sprintf(`INSERT INTO ldap_association (name, id, member_id) VALUES %s`,
			strings.Join(values, ","))

		result, err := r.execQuery(tx, q)
		if err != nil {
			return xerrors.Errorf("Failed to insert association record. id: %d, dn_norm: %s, err: %w",
				newID, dn.DNNormStr(), err)
		}

		if num, err := result.RowsAffected(); err != nil {
			log.Printf("Inserted association. dn_norm: %s, num: %d", dn.DNNormStr(), num)
		}
	}

	return nil
}

//////////////////////////////////////////
// MOD operation
//////////////////////////////////////////

func (r *HybridRepository) Update(ctx context.Context, dn *DN, callback func(current *ModifyEntry) error) error {
	tx, err := r.begin(ctx)
	if err != nil {
		return err
	}

	// Step 1: Fetch current entry with update lock
	// TODO: Need to fetch all associations
	oID, oParentID, _, oJSONMap, oHasSub, err := r.findByDNForUpdate(tx, dn)
	if err != nil {
		rollback(tx)
		return err
	}

	newEntry, err := NewModifyEntry(r.server.schemaMap, dn, oJSONMap)
	if err != nil {
		rollback(tx)
		xerrors.Errorf("Failed to map to ModifyEntry in %s: %v, err: %w", txLabel(tx), dn, err)
	}
	newEntry.dbEntryID = oID
	newEntry.dbParentID = oParentID
	newEntry.hasSub = oHasSub

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

	dbEntry, addAssociation, delAssociation, err := r.modifyEntryToDBEntry(tx, newEntry)
	if err != nil {
		return err
	}

	// Step 2: Update entry
	_, err = tx.NamedStmt(updateAttrsByIdStmt).Exec(map[string]interface{}{
		"id":         dbEntry.ID,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
	})
	if err != nil {
		return xerrors.Errorf("Failed to update entry in %s. entry: %v, err: %w", txLabel(tx), newEntry, err)
	}

	// Step 3: Update association if neccesary
	// Step 3-1: Add association if neccesary
	values := []string{}

	for k, v := range addAssociation {
		for _, id := range v {
			if k == "memberOf" {
				// TODO configuable the default name when inserting memberOf
				values = append(values, fmt.Sprintf(`('%s', %d, %d)`, "member", id, dbEntry.ID))
			} else {
				values = append(values, fmt.Sprintf(`('%s', %d, %d)`, k, dbEntry.ID, id))
			}
		}
	}

	if len(values) > 0 {
		// Use bulk insert
		q := fmt.Sprintf(`INSERT INTO ldap_association (name, id, member_id) VALUES %s`,
			strings.Join(values, ","))

		log.Printf("insert association query:\n%s", q)

		result, err := tx.Exec(q)
		if err != nil {
			return xerrors.Errorf("Failed to insert association record. id: %d, dn_norm: %s, dn_orig: %s, err: %w",
				dbEntry.ID, dn.DNNormStr(), dn.DNOrigStr(), err)
		}
		if num, err := result.RowsAffected(); err != nil {
			log.Printf("inserted assiciation rows: %d", num)
		}
	}

	// Step 3-2: Delete association if neccesary
	where := []string{}
	whereTemplate := `(id = '%s' AND id = %d AND member_id = %d)`

	for k, v := range delAssociation {
		for _, id := range v {
			if k == "memberOf" {
				// TODO configuable the default name when inserting memberOf
				where = append(where, fmt.Sprintf(whereTemplate, "member", id, dbEntry.ID))
			} else {
				where = append(where, fmt.Sprintf(whereTemplate, k, dbEntry.ID, id))
			}
		}
	}

	if len(where) > 0 {
		// Multiple delete rows
		q := fmt.Sprintf(`DELETE FROM ldap_association WHERE %s`,
			strings.Join(where, " OR "))

		log.Printf("delete association query:\n%s", q)

		result, err := tx.Exec(q)
		if err != nil {
			return xerrors.Errorf("Failed to delete association record. id: %d, dn_norm: %s, dn_orig: %s, err: %w",
				dbEntry.ID, dn.DNNormStr(), dn.DNOrigStr(), err)
		}
		if num, err := result.RowsAffected(); err != nil {
			log.Printf("deleted association rows: %d", num)
		}
	}

	if err := commit(tx); err != nil {
		log.Printf("error: Failed to commit update. dn_norm: %s, err: %v", dn.DNNormStr(), err)
		return err
	}

	log.Printf("info: Updated. id: %d, dn_norm: %s", oID, dn.DNNormStr())

	return nil
}

func (r *HybridRepository) findByDNForUpdate(tx *sqlx.Tx, dn *DN) (int64, int64, string, map[string][]string, bool, error) {
	dest := struct {
		ID        int64          `db:"id"`
		ParentID  int64          `db:"parent_id"`
		RDNOrig   string         `db:"rdn_orig"`
		AttrsOrig types.JSONText `db:"attrs_orig"`
		HasSub    bool           `db:"has_sub"`
	}{}

	if err := r.get(tx, findEntryByDNWithUpdateLock, &dest, map[string]interface{}{
		"rdn_norm":       dn.RDNNormStr(),
		"parent_dn_norm": dn.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix),
	}); err != nil {
		if isNoResult(err) {
			return 0, 0, "", nil, false, NewNoSuchObject()
		}
		return 0, 0, "", nil, false, xerrors.Errorf("Failed to fetch current entry. dn_norm: %s, err: %w", dn.DNNormStr(), err)
	}

	// Convert JSON => map
	var attrsOrig map[string][]string
	if len(dest.AttrsOrig) > 0 {
		if err := dest.AttrsOrig.Unmarshal(&attrsOrig); err != nil {
			return 0, 0, "", nil, false, xerrors.Errorf("Unexpected unmarshal error. dn_norm: %s, err: %w", dn.DNNormStr(), err)
		}
	}

	log.Printf("Fetched current attrs_orig: %v", attrsOrig)

	return dest.ID, dest.ParentID, dest.RDNOrig, attrsOrig, dest.HasSub, nil
}

// oldRDN: set when keeping current entry
func (r *HybridRepository) UpdateDN(ctx context.Context, oldDN, newDN *DN, oldRDN *RelativeDN) error {
	tx, err := r.begin(ctx)
	if err != nil {
		return err
	}

	// Fetch current entry with update lock
	oID, oParentID, _, attrsOrig, oHasSub, err := r.findByDNForUpdate(tx, oldDN)
	if err != nil {
		rollback(tx)
		return err
	}

	entry, err := NewModifyEntry(r.server.schemaMap, oldDN, attrsOrig)
	if err != nil {
		return err
	}
	entry.dbEntryID = oID
	entry.dbParentID = oParentID
	entry.hasSub = oHasSub

	if !oldDN.ParentDN().Equal(newDN.ParentDN()) {
		// Move or copy under the new parent case
		err = r.updateDNUnderNewParent(tx, oldDN, newDN, oldRDN, entry)
	} else {
		// Update rdn only case
		err = r.updateRDN(tx, oldDN, newDN, oldRDN, entry)
	}

	if err != nil {
		rollback(tx)
		return err
	}

	if err := commit(tx); err != nil {
		log.Printf("error: Failed to commit update. id: %d, old_dn_norm: %s, new_dn_norm: %s, err: %v", oID, oldDN.DNNormStr(), newDN.DNNormStr(), err)
		return err
	}

	log.Printf("info: Updated DN. id: %d, old_dn_norm: %s, new_dn_norm: %s", oID, oldDN.DNNormStr(), newDN.DNNormStr())

	return nil
}

func (r *HybridRepository) updateDNUnderNewParent(tx *sqlx.Tx, oldDN, newDN *DN, oldRDN *RelativeDN, oldEntry *ModifyEntry) error {
	oldParentDN := oldDN.ParentDN()
	newParentDN := newDN.ParentDN()

	var oldParentID int64
	var newParentID int64

	// Determine old parent ID
	if oldParentDN.IsRoot() {
		oldParentID = 0
	} else {
		oldParentID = oldEntry.dbParentID
		// After updating DN, determine if we need to delete the container for old parent
	}

	// Determine new parent ID
	if newParentDN.IsRoot() {
		oldParentID = 0
		// Root entry doesn't need to insert container record always
	} else {
		dest := struct {
			ID       int64 `db:"id"`
			ParentID int64 `db:"parent_id"`
			HasSub   bool  `db:"has_sub"`
		}{}

		// Find the new parent entry and the container with share lock
		if err := r.get(tx, findEntryIDByDNWithShareLock, &dest, map[string]interface{}{
			"rdn_norm":       newParentDN.RDNNormStr(),
			"parent_dn_norm": newParentDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix),
		}); err != nil {
			if isNoResult(err) {
				return NewNoSuchObject()
			}
			return xerrors.Errorf("Failed to execute findEntryIDByDNWithShareLock in %s: %v, err: %w", txLabel(tx), newParentDN, err)
		}
		newParentID = dest.ID

		// If the new parent doesn't have any sub, we need to insert new container first and lock it
		if !dest.HasSub {
			if _, err := r.exec(tx, insertContainerStmtWithUpdateLock, map[string]interface{}{
				"id":      newParentID,
				"dn_norm": newParentDN.DNNormStrWithoutSuffix(r.server.Suffix),
				"dn_orig": newParentDN.DNNormStrWithoutSuffix(r.server.Suffix),
			}); err != nil {
				return xerrors.Errorf("Failed to insert container record. id: %d, dn_norm: %s, err: %w",
					newParentID, oldParentDN.DNNormStr(), err)
			}
		}
	}

	// Move tree if the operation is for tree which means the old entry has children
	if oldEntry.hasSub {
		// TODO move children?
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
	dbEntry, _, _, err := r.modifyEntryToDBEntry(tx, newEntry)
	if err != nil {
		return err
	}

	// Update RDN
	if _, err := r.exec(tx, updateDNByIdStmt, map[string]interface{}{
		"id":           oldEntry.dbEntryID,
		"parent_id":    newParentID,
		"new_rdn_norm": newDN.RDNNormStr(),
		"new_rdn_orig": newDN.RDNOrigStr(),
		"attrs_norm":   dbEntry.AttrsNorm,
		"attrs_orig":   dbEntry.AttrsOrig,
	}); err != nil {
		return xerrors.Errorf("Failed to update entry DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
	}

	// Modify DN orig of container record if the entry has sub.
	// Don't update if the entry is root which has suffix as the RDN.
	if oldEntry.hasSub && oldEntry.dbParentID != 0 {
		if _, err = r.exec(tx, updateContainerDNByIdStmt, map[string]interface{}{
			"id":          oldEntry.dbEntryID,
			"new_dn_norm": newDN.RDNNormStr(),
			"new_dn_orig": newDN.RDNOrigStr(),
		}); err != nil {
			return xerrors.Errorf("Failed to update container DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
		}

		if _, err = tx.NamedStmt(updateContainerDNByIdStmt).Exec(map[string]interface{}{
			"new_dn_norm":         "\\1" + newDN.RDNNormStr(),
			"new_dn_orig":         "\\1" + newDN.RDNOrigStr(),
			"old_dn_norm_pattern": "(.*,)" + escapeRegex(oldDN.DNNormStrWithoutSuffix(r.server.Suffix)) + "$",
			"old_dn_orig_pattern": "(.*,)" + escapeRegex(oldDN.DNOrigStrWithoutSuffix(r.server.Suffix)) + "$",
		}); err != nil {
			return xerrors.Errorf("Failed to update sub containers DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
		}
	}

	// Determine we need to delete container for old parent
	hasSub, err := r.hasSub(tx, oldParentID)
	if err != nil {
		rollback(tx)
		return err
	}

	// If the old parent doesn't have any sub, need to delete container record.
	if !hasSub {
		if err := r.deleteContainerByID(tx, oldParentID); err != nil {
			if !isNoResult(err) {
				rollback(tx)
				return err
			}
			// Other threads inserted sub. Ignore the error.
		}
	}

	return nil
}

func (r *HybridRepository) updateRDN(tx *sqlx.Tx, oldDN, newDN *DN, oldRDN *RelativeDN, oldEntry *ModifyEntry) error {
	// Update the entry even if it's same RDN to update modifyTimestamp
	newEntry := oldEntry.ModifyRDN(newDN)

	if oldRDN != nil {
		for _, attr := range oldRDN.Attributes {
			if err := newEntry.Add(attr.TypeOrig, []string{attr.ValueOrig}); err != nil {
				log.Printf("info: Schema error but ignore it. err: %s", err)
			}
		}
	}

	log.Printf("Update RDN. newDN: %s, hasSub: %v", newDN.DNOrigStr(), oldEntry.hasSub)

	// Modify RDN doesn't affect the member, ignore it
	dbEntry, _, _, err := r.modifyEntryToDBEntry(tx, newEntry)
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
		return xerrors.Errorf("Failed to update RDN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
	}

	// Modify DN orig of container record if the entry has sub.
	// Don't update if the entry is root which has suffix as the RDN.
	if oldEntry.hasSub && oldEntry.dbParentID != 0 {
		if _, err = r.exec(tx, updateContainerDNByIdStmt, map[string]interface{}{
			"id":          oldEntry.dbEntryID,
			"new_dn_norm": newDN.RDNNormStr(),
			"new_dn_orig": newDN.RDNOrigStr(),
		}); err != nil {
			return xerrors.Errorf("Failed to update container DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
		}

		if _, err = tx.NamedStmt(updateContainerDNByIdStmt).Exec(map[string]interface{}{
			"new_dn_norm":         "\\1" + newDN.RDNNormStr(),
			"new_dn_orig":         "\\1" + newDN.RDNOrigStr(),
			"old_dn_norm_pattern": "(.*,)" + escapeRegex(oldDN.DNNormStrWithoutSuffix(r.server.Suffix)) + "$",
			"old_dn_orig_pattern": "(.*,)" + escapeRegex(oldDN.DNOrigStrWithoutSuffix(r.server.Suffix)) + "$",
		}); err != nil {
			return xerrors.Errorf("Failed to update sub containers DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
		}
	}

	return nil
}

//////////////////////////////////////////
// DEL operation
//////////////////////////////////////////

func (r HybridRepository) DeleteByDN(ctx context.Context, dn *DN) error {
	tx, err := r.begin(ctx)
	if err != nil {
		return err
	}

	// Step 1: fetch the target entry and parent container with lock for update
	fetchedEntry := struct {
		ID       int64 `db:"id"`
		ParentID int64 `db:"parent_id"`
		HasSub   bool  `db:"has_sub"`
	}{}

	err = r.get(tx, findEntryIDByDNWithUpdateLock, &fetchedEntry, map[string]interface{}{
		"rdn_norm":       dn.RDNNormStr(),
		"parent_dn_norm": dn.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix),
	})
	if err != nil {
		rollback(tx)

		if isNoResult(err) {
			return NewNoSuchObject()
		}
		return xerrors.Errorf("Unexpected query error. dn_norm: %v, err: %w", dn.DNNormStr(), err)
	}

	// Not allowed error if the entry has children yet
	if fetchedEntry.HasSub {
		rollback(tx)
		return NewNotAllowedOnNonLeaf()
	}

	// Step 2: Delete entry
	delID, err := r.deleteByID(tx, fetchedEntry.ID)
	if err != nil {
		rollback(tx)
		return err
	}

	// Step 3: Delete container if the parent doesn't have children
	hasSub, err := r.hasSub(tx, fetchedEntry.ParentID)
	if err != nil {
		rollback(tx)
		return err
	}

	if !hasSub {
		if err := r.deleteContainerByID(tx, fetchedEntry.ParentID); err != nil {
			if !isNoResult(err) {
				rollback(tx)
				return err
			}
			// Other threads inserted sub. Ignore the error.
		}
	}

	// Step 4: Remove all association
	// TODO LOCK
	err = r.removeAssociationById(tx, delID)
	if err != nil {
		rollback(tx)
		return err
	}

	if err := commit(tx); err != nil {
		log.Printf("error: Failed to commit deletion. dn_norm: %s, err: %v", dn.DNNormStr(), err)
		return err
	}

	log.Printf("info: Deleted. id: %d, dn_norm: %s", fetchedEntry.ID, dn.DNNormStr())

	return nil
}

func (r *HybridRepository) hasSub(tx *sqlx.Tx, id int64) (bool, error) {
	var hasSub bool
	if err := r.get(tx, hasSubStmt, &hasSub, map[string]interface{}{
		"id": id,
	}); err != nil {
		return false, xerrors.Errorf("Failed to check existence. id: %d, err: %w", id, err)
	}

	return hasSub, nil
}

func (r *HybridRepository) deleteByID(tx *sqlx.Tx, id int64) (int64, error) {
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

// deleteContainerByID deletes the container record if the container doesn't have any sub entries.
func (r *HybridRepository) deleteContainerByID(tx *sqlx.Tx, id int64) error {
	result, err := r.exec(tx, deleteContainerStmt, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		if isNoResult(err) {
			log.Printf("warn: the container already deleted. id: %d", id)
			return err
		}
		return xerrors.Errorf("Failed to delete container. id: %d, err: %w", id, err)
	}
	if num, err := result.RowsAffected(); err == nil {
		log.Printf("info: Deleted container. id: %d, num: %d", id, num)
	}

	return nil
}

func (r *HybridRepository) removeAssociationById(tx *sqlx.Tx, id int64) error {
	result, err := tx.NamedStmt(deleteAllAssociationByIDStmt).Exec(map[string]interface{}{
		"id": id,
	})
	if err != nil {
		return xerrors.Errorf("Failed to delete association. query: %s, id: %d, err: %w",
			deleteAllAssociationByIDStmt.QueryString, id, err)
	}

	if num, err := result.RowsAffected(); err != nil {
		log.Printf("Deleted all association. id: %d, num: %d", id, num)
	}

	return nil
}

//////////////////////////////////////////
// SEARCH operation
//////////////////////////////////////////

type HybridFetchedDBEntry struct {
	ID              int64          `db:"id"`
	ParentID        int64          `db:"parent_id"`
	RDNOrig         string         `db:"rdn_orig"`
	RawAttrsOrig    types.JSONText `db:"attrs_orig"`
	RawMember       types.JSONText `db:"member"`       // No real column in the table
	RawUniqueMember types.JSONText `db:"uniquemember"` // No real column in the table
	RawMemberOf     types.JSONText `db:"memberof"`     // No real column in the table
	HasSubordinates string         `db:"has_sub"`      // No real column in the table
	DNOrig          string         `db:"dn_orig"`      // No real column in the table
	Count           int32          `db:"count"`        // No real column in the table
}

func (e *HybridFetchedDBEntry) Clear() {
	e.ID = 0
	e.ParentID = 0
	e.RDNOrig = ""
	e.DNOrig = ""
	e.RawAttrsOrig = nil
	e.RawMemberOf = nil
	e.RawMember = nil
	e.RawUniqueMember = nil
	e.HasSubordinates = ""
	e.Count = 0
}

func (e *HybridFetchedDBEntry) AttrsOrig() map[string][]string {
	jsonMap := make(map[string][]string)

	if len(e.RawAttrsOrig) > 0 {
		if err := e.RawAttrsOrig.Unmarshal(&jsonMap); err != nil {
			log.Printf("erro: Unexpectd umarshal error: %s", err)
		}
	}

	if len(e.RawMember) > 0 {
		jsonArray := []string{}
		if err := e.RawMember.Unmarshal(&jsonArray); err != nil {
			log.Printf("erro: Unexpectd umarshal error: %s", err)
		}
		jsonMap["member"] = jsonArray
	}

	if len(e.RawUniqueMember) > 0 {
		jsonArray := []string{}
		if err := e.RawUniqueMember.Unmarshal(&jsonArray); err != nil {
			log.Printf("erro: Unexpectd umarshal error: %s", err)
		}
		jsonMap["uniqueMember"] = jsonArray
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

func (r *HybridRepository) Search(ctx context.Context, baseDN *DN, option *SearchOption, handler func(entry *SearchEntry) error) (int32, int32, error) {
	tx, err := r.beginReadonly(ctx)
	if err != nil {
		return 0, 0, nil
	}

	log.Printf("Search option: %v", option)

	// Filter
	var scopeWhere strings.Builder
	filterJoin := []string{}
	filterWhere := []string{}
	params := map[string]interface{}{
		"pageSize": option.PageSize,
		"offset":   option.Offset,
	}
	r.collectScopeWhereSQL(baseDN, option, &scopeWhere, params)
	r.collectFilterWhereSQL(baseDN, option, &filterJoin, &filterWhere, params)

	// Projection(Association etc.)
	var proj strings.Builder
	var join strings.Builder
	r.collectAssociationSQLPlanA(option, &proj, &join, params)
	// r.collectAssociationSQLPlanB(option, &proj, &join, params)
	r.collectHasSubordinatesSQL(option, &proj, &join)

	q := fmt.Sprintf(`WITH
	filtered_entry AS NOT MATERIALIZED (
		SELECT
			e.id,
			e.parent_id,
			e.rdn_orig || ',' || dnc.dn_orig AS dn_orig,
			e.attrs_orig,
			count(e.id) over() AS count
		FROM
			ldap_entry e
		-- DN join
		LEFT JOIN ldap_container dnc ON e.parent_id = dnc.id
		%s
		WHERE
			-- scope filter
			%s
			AND
			-- ldap filter
			(%s)
		ORDER BY e.id
		LIMIT :pageSize OFFSET :offset
	)
SELECT
	fe.id,
	fe.parent_id,
	fe.dn_orig,
	fe.attrs_orig,
	fe.count
	%s
FROM
	filtered_entry fe
%s
	`, strings.Join(filterJoin, ""), scopeWhere.String(), strings.Join(filterWhere, " AND "), proj.String(), join.String())

	start := time.Now()
	rows, err := r.namedQuery(tx, q, params)
	end := time.Now()

	defer rollback(tx)

	if err != nil {
		if isNoResult(err) {
			// Need to return successful response
			return 0, 0, nil
		}
		return 0, 0, xerrors.Errorf("Unexpected search query error. err: %w", err)
	}

	var maxCount int32 = 0
	var count int32 = 0
	var dbEntry HybridFetchedDBEntry

	for rows.Next() {
		err = rows.StructScan(&dbEntry)
		if err != nil {
			return 0, 0, xerrors.Errorf("Unexpected struct scan error. err: %w", err)
		}
		if maxCount == 0 {
			maxCount = dbEntry.Count
			log.Printf("info: Executed DB search: %d [ms], count: %d", end.Sub(start).Milliseconds(), maxCount)
		}

		readEntry := r.toSearchEntry(&dbEntry)

		err = handler(readEntry)
		if err != nil {
			log.Printf("error: Unexpected handler error: %v", err)
			return 0, 0, err
		}

		count++
		dbEntry.Clear()
	}

	return maxCount, count, nil
}

func (r *HybridRepository) toSearchEntry(dbEntry *HybridFetchedDBEntry) *SearchEntry {
	orig := dbEntry.AttrsOrig()

	// hasSubordinates
	if dbEntry.HasSubordinates != "" {
		orig["hasSubordinates"] = []string{dbEntry.HasSubordinates}
	}

	// resolve association suffix
	r.resolveAssociationSuffix(orig, "member")
	r.resolveAssociationSuffix(orig, "uniqueMember")
	r.resolveAssociationSuffix(orig, "memberOf")

	readEntry := NewSearchEntry(r.server.schemaMap, dbEntry.DNOrig, orig)

	return readEntry
}

func (r *HybridRepository) resolveAssociationSuffix(attrsOrig map[string][]string, attrName string) {
	um := attrsOrig[attrName]
	if len(um) > 0 {
		for i, v := range um {
			um[i] = resolveSuffix(r.server, v)
		}
	}
}

func (r *HybridRepository) collectAssociationSQLPlanA(option *SearchOption, proj, join *strings.Builder, params map[string]interface{}) {
	for _, v := range option.RequestedAssocation {
		proj.WriteString(`, `)
		join.WriteString("\n")

		key := strconv.Itoa(len(params))
		params[key] = v

		proj.WriteString(v)
		proj.WriteString(`.`)
		proj.WriteString(v)
		proj.WriteString(` AS `)
		proj.WriteString(v)

		join.WriteString(`-- requested association - `)
		join.WriteString(v)
		join.WriteString(`
LEFT JOIN LATERAL (
	SELECT jsonb_agg(rae.rdn_orig || ',' || rc.dn_orig) AS `)
		join.WriteString(v)
		join.WriteString(`
	FROM ldap_association ra, ldap_entry rae, ldap_container rc
	WHERE fe.id = ra.id AND ra.name = :`)
		join.WriteString(key)
		join.WriteString(` AND rae.id = ra.member_id AND rc.id = rae.parent_id
) AS `)
		join.WriteString(v)
		join.WriteString(` ON true`)
	}

	if option.IsMemberOfRequested {
		proj.WriteString(`, `)
		join.WriteString("\n")

		v := "memberOf"

		key := strconv.Itoa(len(params))
		params[key] = v

		proj.WriteString(v)
		proj.WriteString(`.`)
		proj.WriteString(v)
		proj.WriteString(` AS `)
		proj.WriteString(v)

		join.WriteString(`-- requested reverse association - `)
		join.WriteString(v)
		join.WriteString(`
LEFT JOIN LATERAL (
	SELECT jsonb_agg(rae.rdn_orig || ',' || rc.dn_orig) AS `)
		join.WriteString(v)
		join.WriteString(`
	FROM ldap_association ra, ldap_entry rae, ldap_container rc
	WHERE fe.id = ra.member_id AND rae.id = ra.id AND rc.id = rae.parent_id
) AS `)
		join.WriteString(v)
		join.WriteString(` ON true`)
	}
}

func (r *HybridRepository) collectAssociationSQLPlanB(option *SearchOption, proj, join *strings.Builder, params map[string]interface{}) {
	for _, v := range option.RequestedAssocation {
		proj.WriteString(`,`)
		proj.WriteString("\n")

		key := strconv.Itoa(len(params))
		params[key] = v

		proj.WriteString(`-- requested association - `)
		proj.WriteString(v)
		proj.WriteString(`
	(SELECT jsonb_agg(rae.rdn_orig || ',' || rc.dn_orig) AS `)
		proj.WriteString(v)
		proj.WriteString(`
	FROM ldap_association ra, ldap_entry rae, ldap_container rc
	WHERE fe.id = ra.id AND ra.name = :`)
		proj.WriteString(key)
		proj.WriteString(` AND rae.id = ra.member_id AND rc.id = rae.parent_id`)
		proj.WriteString(`) AS `)
		proj.WriteString(v)
	}

	if option.IsMemberOfRequested {
		proj.WriteString(`, `)
		proj.WriteString("\n")

		v := "memberOf"

		key := strconv.Itoa(len(params))
		params[key] = v

		proj.WriteString(`	-- requested reverse association - `)
		proj.WriteString(v)
		proj.WriteString(`
	(SELECT jsonb_agg(rae.rdn_orig || ',' || rc.dn_orig) AS `)
		proj.WriteString(v)
		proj.WriteString(`
	FROM ldap_association ra, ldap_entry rae, ldap_container rc
	WHERE fe.id = ra.member_id AND rae.id = ra.id AND rc.id = rae.parent_id`)
		proj.WriteString(`) AS `)
		proj.WriteString(v)
	}
}

func (r *HybridRepository) collectHasSubordinatesSQL(option *SearchOption, proj, join *strings.Builder) {
	if option.IsHasSubordinatesRequested {
		proj.WriteString(`,`)
		join.WriteString("\n")

		proj.WriteString(`has_sub.has_sub AS has_sub`)
		join.WriteString(`
-- requested has_sub
LEFT JOIN LATERAL (
	SELECT EXISTS (SELECT 1 FROM ldap_container WHERE id = fe.id) AS has_sub
) AS has_sub ON true`)
	}
}

func (r *HybridRepository) collectScopeWhereSQL(baseDN *DN, option *SearchOption, where *strings.Builder, params map[string]interface{}) {
	// Scope handling
	// 0: base (only base)
	// 1: one (only one level, not include base)
	// 2: sub (subtree, include base)
	// 3: children (subtree, not include base)
	if option.Scope == 0 || option.Scope == 1 {
		var col string
		if option.Scope == 0 {
			col = "id"
		} else {
			col = "parent_id"
		}
		where.WriteString(`e.`)
		where.WriteString(col)
		where.WriteString(` = (SELECT
					e.id
				FROM
					ldap_entry e
					LEFT JOIN ldap_container c ON e.parent_id = c.id
				WHERE
					e.rdn_norm = :rdn_norm
					AND c.dn_norm = :parent_dn_norm)`)
		params["rdn_norm"] = baseDN.RDNNormStr()
		params["parent_dn_norm"] = baseDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix)

	} else {
		var subWhere string
		if baseDN.Equal(r.server.Suffix) {
			subWhere = `
				e.parent_id IN (
					SELECT
						id
					FROM
						ldap_container c
					WHERE
						id != 0
				)`
		} else {
			if baseDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix) == "" {
				subWhere = `
				e.parent_id IN (SELECT
						e.parent_id
					FROM
						ldap_entry e
						LEFT JOIN ldap_container c ON e.parent_id = c.id
					WHERE
						c.dn_norm = :dn_norm
						OR
						REVERSE(c.dn_norm) LIKE REVERSE('%,' || :dn_norm)
				)`
			} else {
				subWhere = `
				e.parent_id IN (SELECT
						e.parent_id
					FROM
						ldap_entry e
						LEFT JOIN ldap_container c ON e.parent_id = c.id
					WHERE
						c.dn_norm = :dn_norm
						OR
						REVERSE(c.dn_norm) LIKE REVERSE('%,' || :dn_norm)
				)`
			}
		}

		if option.Scope == 2 {
			where.WriteString(`e.id IN (SELECT
					e.id
				FROM
					ldap_entry e
					LEFT JOIN ldap_container c ON e.parent_id = c.id
				WHERE
					e.rdn_norm = :rdn_norm
					AND c.dn_norm = :parent_dn_norm
				OR`)
			where.WriteString(subWhere)
			where.WriteString(`
			)`)
			params["rdn_norm"] = baseDN.RDNNormStr()
			params["parent_dn_norm"] = baseDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix)
			params["dn_norm"] = baseDN.DNNormStrWithoutSuffix(r.server.Suffix)
		} else {
			where.WriteString(subWhere)
			params["parent_dn_norm"] = baseDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix)
			params["dn_norm"] = baseDN.DNNormStrWithoutSuffix(r.server.Suffix)
		}
	}
}

func (r *HybridRepository) collectFilterWhereSQL(baseDN *DN, option *SearchOption, join *[]string, where *[]string, params map[string]interface{}) error {
	var jsb, wsb strings.Builder
	// TODO calc initial capacity
	jsb.Grow(128)
	wsb.Grow(128)

	result := &HybridDBFilterTranslatorResult{
		join:   &jsb,
		where:  &wsb,
		params: params,
	}

	err := r.translator.translate(r.server.schemaMap, option.Filter, result, false)
	if err != nil {
		return err
	}

	if result.where.Len() == 0 {
		wsb.WriteString(`TRUE`)
	}

	*join = append(*join, jsb.String())
	*where = append(*where, wsb.String())

	return nil
}

type HybridDBFilterTranslator struct {
}

type HybridDBFilterTranslatorResult struct {
	join   *strings.Builder
	where  *strings.Builder
	params map[string]interface{}
}

func (r *HybridDBFilterTranslatorResult) nextParamKey(name string) string {
	return strconv.Itoa(len(r.params))
}

func (t *HybridDBFilterTranslator) translate(schemaMap *SchemaMap, packet message.Filter, q *HybridDBFilterTranslatorResult, isNot bool) (err error) {
	err = nil

	switch f := packet.(type) {
	case message.FilterAnd:
		q.where.WriteString("(")
		for i, child := range f {
			err = t.translate(schemaMap, child, q, false || isNot)

			if err != nil {
				return
			}
			if i < len(f)-1 {
				if isNot {
					q.where.WriteString(" OR ")
				} else {
					q.where.WriteString(" AND ")
				}
			}
		}
		q.where.WriteString(")")
	case message.FilterOr:
		q.where.WriteString("(")
		for i, child := range f {
			err = t.translate(schemaMap, child, q, false || isNot)

			if err != nil {
				return
			}
			if i < len(f)-1 {
				if isNot {
					q.where.WriteString(" AND ")
				} else {
					q.where.WriteString(" OR ")
				}
			}
		}
		q.where.WriteString(")")
	case message.FilterNot:
		err = t.translate(schemaMap, f.Filter, q, !isNot)

		if err != nil {
			return
		}
	case message.FilterSubstrings:
		attrName := string(f.Type_())

		var s *Schema
		s, ok := schemaMap.Get(attrName)
		if !ok {
			log.Printf("warn: Ignore filter due to unsupported attribute: %s", attrName)
			return
		}

		var sb strings.Builder
		sb.Grow(64)

		if isNot {
			sb.WriteString(`!(`)
		}

		for i, fs := range f.Substrings() {
			switch fsv := fs.(type) {
			case message.SubstringInitial:
				t.StartsWithMatch(s, &sb, string(fsv), i)
			case message.SubstringAny:
				if i > 0 {
					sb.WriteString(" && ")
				}
				t.AnyMatch(s, &sb, string(fsv), i)
			case message.SubstringFinal:
				if i > 0 {
					sb.WriteString(" && ")
				}
				t.EndsMatch(s, &sb, string(fsv), i)
			}
		}

		if isNot {
			sb.WriteString(`)`)
		}

		filterKey := q.nextParamKey(s.Name)
		q.params[filterKey] = sb.String()

		q.where.WriteString(`e.attrs_norm @@ :`)
		q.where.WriteString(filterKey)
	case message.FilterEqualityMatch:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.EqualityMatch(s, q, string(f.AssertionValue()), isNot)
		}
	case message.FilterGreaterOrEqual:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.GreaterOrEqualMatch(s, q, string(f.AssertionValue()), isNot)
		}
	case message.FilterLessOrEqual:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.LessOrEqualMatch(s, q, string(f.AssertionValue()), isNot)
		}
	case message.FilterPresent:
		if s, ok := findSchema(schemaMap, string(f)); ok {
			t.PresentMatch(s, q, isNot)
		}
	case message.FilterApproxMatch:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.ApproxMatch(s, q, string(f.AssertionValue()), isNot)
		}
	}

	return nil
}

func (t *HybridDBFilterTranslator) StartsWithMatch(s *Schema, sb *strings.Builder, val string, i int) {
	sv, err := NewSchemaValue(s.server.schemaMap, s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support substring initial")
		writeFalseJsonpath(s.Name, sb)
		return
	}

	// attrs_norm @@ '$.cn starts with "foo"';
	sb.WriteString(`$."`)
	sb.WriteString(escapeName(s.Name))
	sb.WriteString(`" starts with "`)
	sb.WriteString(escapeValue(sv.Norm()[0]))
	sb.WriteString(`"`)
}

func (t *HybridDBFilterTranslator) AnyMatch(s *Schema, sb *strings.Builder, val string, i int) {
	sv, err := NewSchemaValue(s.server.schemaMap, s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support substring any")
		writeFalseJsonpath(s.Name, sb)
		return
	}

	// attrs_norm @@ '$.cn like_regex ".*foo.*"';
	sb.WriteString(`$."`)
	sb.WriteString(escapeName(s.Name))
	sb.WriteString(`" like_regex ".*`)
	sb.WriteString(escapeRegex(sv.Norm()[0]))
	sb.WriteString(`.*"`)
}

func (t *HybridDBFilterTranslator) EndsMatch(s *Schema, sb *strings.Builder, val string, i int) {
	sv, err := NewSchemaValue(s.server.schemaMap, s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support substring final")
		writeFalseJsonpath(s.Name, sb)
		return
	}

	// attrs_norm @@ '$.cn like_regex ".*foo.*"';
	sb.WriteString(`$."`)
	sb.WriteString(escapeName(s.Name))
	sb.WriteString(`" like_regex ".*`)
	sb.WriteString(escapeRegex(sv.Norm()[0]))
	sb.WriteString(`$"`)
}

func (t *HybridDBFilterTranslator) EqualityMatch(s *Schema, q *HybridDBFilterTranslatorResult, val string, isNot bool) {

	sv, err := NewSchemaValue(s.server.schemaMap, s.Name, []string{val})
	if err != nil {
		// TODO error no entry response
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s, err: %+v", s.Name, val, err)
		q.where.WriteString(`FALSE`)
		return
	}

	if s.IsAssociationAttribute() {
		reqDN, err := s.server.NormalizeDN(val)
		if err != nil {
			log.Printf("warn: Ignore filter due to invalid DN syntax of member. attrName: %s, value: %s, err: %+v", s.Name, val, err)
			q.where.WriteString(`FALSE`)
			return
		}

		nameKey := q.nextParamKey(s.Name)
		q.params[nameKey] = s.Name

		rdnNormKey := q.nextParamKey(s.Name)
		q.params[rdnNormKey] = reqDN.RDNNormStr()

		parentDNNormKey := q.nextParamKey(s.Name)
		q.params[parentDNNormKey] = reqDN.ParentDN().DNNormStrWithoutSuffix(s.server.Suffix)

		/*
			[CASE EXISTS]
			-- association filter by uniqueMember
			INNER JOIN (
				SELECT DISTINCT
					a1.id
				 FROM
					ldap_association a1 INNER JOIN ldap_entry ae1 ON a1.name = 'uniqueMember' AND a1.member_id = ae1.id INNER JOIN ldap_container c1 ON ae1.parent_id = c1.id
				 WHERE
					ae1.rdn_norm = 'uid=user1' AND c1.dn_norm = 'ou=people'
			) t1 ON t1.id = e.id

			[CASE NOT EXISTS]
			-- association filter by memberOf
			LEFT JOIN (
				SELECT DISTINCT
					a1.id
				FROM
					ldap_association a1 INNER JOIN ldap_entry ae1 ON a1.name = 'uniqueMember' AND a1.member_id = ae1.id INNER JOIN ldap_container c1 ON ae1.parent_id = c1.id
				WHERE
					ae1.rdn_norm = 'uid=user1' AND c1.dn_norm = 'ou=people'
			) t1 ON t1.id = e.id
			WHERE
				t1.id IS NULL
		*/
		q.join.WriteString("\n")
		q.join.WriteString(`		-- association filter by `)
		q.join.WriteString(s.Name)
		q.join.WriteString(" \n		")
		if isNot {
			q.join.WriteString(`LEFT JOIN (`)
		} else {
			q.join.WriteString(`INNER JOIN (`)
		}
		q.join.WriteString(`SELECT DISTINCT a`)
		q.join.WriteString(nameKey)
		q.join.WriteString(`.id FROM ldap_association a`)
		q.join.WriteString(nameKey)
		q.join.WriteString(` INNER JOIN ldap_entry ae`)
		q.join.WriteString(nameKey)
		q.join.WriteString(` ON a`)
		q.join.WriteString(nameKey)
		q.join.WriteString(`.name = :`)
		q.join.WriteString(nameKey)
		q.join.WriteString(` AND a`)
		q.join.WriteString(nameKey)
		q.join.WriteString(`.member_id = ae`)
		q.join.WriteString(nameKey)
		q.join.WriteString(`.id INNER JOIN ldap_container c`)
		q.join.WriteString(nameKey)
		q.join.WriteString(` ON ae`)
		q.join.WriteString(nameKey)
		q.join.WriteString(`.parent_id = c`)
		q.join.WriteString(nameKey)
		q.join.WriteString(`.id WHERE ae`)
		q.join.WriteString(nameKey)
		q.join.WriteString(`.rdn_norm = :`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(` AND c`)
		q.join.WriteString(nameKey)
		q.join.WriteString(`.dn_norm = :`)
		q.join.WriteString(parentDNNormKey)
		q.join.WriteString(`) t`)
		q.join.WriteString(nameKey)
		q.join.WriteString(` ON t`)
		q.join.WriteString(nameKey)
		q.join.WriteString(`.id = e.id`)
		if isNot {
			q.where.WriteString(`t`)
			q.where.WriteString(nameKey)
			q.where.WriteString(`.id IS NULL`)
		} else {
			q.where.WriteString(`TRUE`)
		}

	} else if s.IsReverseAssociationAttribute() {
		reqDN, err := s.server.NormalizeDN(val)
		if err != nil {
			log.Printf("warn: Ignore filter due to invalid DN syntax of memberOf. attrName: %s, value: %s, err: %+v", s.Name, val, err)
			return
		}

		rdnNormKey := q.nextParamKey(s.Name)
		q.params[rdnNormKey] = reqDN.RDNNormStr()

		parentDNNormKey := q.nextParamKey(s.Name)
		q.params[parentDNNormKey] = reqDN.ParentDN().DNNormStrWithoutSuffix(s.server.Suffix)

		/*
			[CASE EXISTS]
			-- association filter by memberOf
			INNER JOIN (
				SELECT DISTINCT
					a1.member_id
				 FROM
					ldap_association a1 INNER JOIN ldap_entry ae1 ON ae1.id = a1.id INNER JOIN ldap_container c1 ON c1.id = ae1.parent_id
				 WHERE
					ae1.rdn_norm = 'cn=group1' AND c1.dn_norm = 'ou=groups'
			) t1 ON t1.member_id = e.id

			[CASE NOT EXISTS]
			-- association filter by memberOf
			LEFT JOIN (
				SELECT DISTINCT
					a1.member_id
				FROM
					ldap_association a1 INNER JOIN ldap_entry ae1 ON ae1.id = a1.id INNER JOIN ldap_container c1 ON c1.id = ae1.parent_id
				WHERE
					ae1.rdn_norm = 'cn=group1' AND c1.dn_norm = 'ou=groups'
			) t1 ON t1.member_id = e.id
			WHERE
				t1.member_id IS NULL
		*/
		q.join.WriteString("\n")
		q.join.WriteString(`		-- association filter by `)
		q.join.WriteString(s.Name)
		q.join.WriteString(" \n		")
		if isNot {
			q.join.WriteString(`LEFT JOIN (`)
		} else {
			q.join.WriteString(`INNER JOIN (`)
		}
		q.join.WriteString(`SELECT DISTINCT a`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(`.member_id FROM ldap_association a`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(` INNER JOIN ldap_entry ae`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(` ON ae`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(`.id = a`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(`.id INNER JOIN ldap_container c`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(` ON c`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(`.id = ae`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(`.parent_id WHERE ae`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(`.rdn_norm = :`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(` AND c`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(`.dn_norm = :`)
		q.join.WriteString(parentDNNormKey)
		q.join.WriteString(`) t`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(` ON t`)
		q.join.WriteString(rdnNormKey)
		q.join.WriteString(`.member_id = e.id`)
		if isNot {
			q.where.WriteString(`t`)
			q.where.WriteString(rdnNormKey)
			q.where.WriteString(`.member_id IS NULL`)
		} else {
			q.where.WriteString(`TRUE`)
		}

	} else {
		var sb strings.Builder
		sb.Grow(10 + len(s.Name) + len(sv.Norm()[0]))

		if isNot {
			sb.WriteString(`!(`)
		}
		sb.WriteString(`$."`)
		sb.WriteString(escapeName(s.Name))
		sb.WriteString(`" == "`)
		sb.WriteString(escapeValue(sv.Norm()[0]))
		sb.WriteString(`"`)
		if isNot {
			sb.WriteString(`)`)
		}

		filterKey := q.nextParamKey(s.Name)
		q.params[filterKey] = sb.String()

		// attrs_norm @@ '$.cn == "foo"';
		q.where.WriteString(`e.attrs_norm @@ :`)
		q.where.WriteString(filterKey)
	}
}

func (t *HybridDBFilterTranslator) GreaterOrEqualMatch(s *Schema, q *HybridDBFilterTranslatorResult, val string, isNot bool) {
	sv, err := NewSchemaValue(s.server.schemaMap, s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support greater or equal")
		writeFalse(q.where)
		return
	}
	if !s.IsNumberOrdering() {
		log.Printf("Not number ordering doesn't support reater or equal")
		writeFalse(q.where)
		return
	}

	var sb strings.Builder
	sb.Grow(10 + len(s.Name) + len(sv.Norm()[0]))

	if isNot {
		sb.WriteString(`!(`)
	}
	sb.WriteString(`$."`)
	sb.WriteString(escapeName(s.Name))
	sb.WriteString(`" >= `)
	sb.WriteString(escapeValue(sv.Norm()[0]))
	if isNot {
		sb.WriteString(`)`)
	}

	filterKey := q.nextParamKey(s.Name)
	// TODO escape check
	q.params[filterKey] = sb.String()

	// attrs_norm @@ '$.createTimestamp >= "20070101000000Z"';
	q.where.WriteString(`e.attrs_norm @@ :`)
	q.where.WriteString(filterKey)
}

func (t *HybridDBFilterTranslator) LessOrEqualMatch(s *Schema, q *HybridDBFilterTranslatorResult, val string, isNot bool) {
	sv, err := NewSchemaValue(s.server.schemaMap, s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support less or equal")
		writeFalse(q.where)
		return
	}
	if !s.IsNumberOrdering() {
		log.Printf("Not number ordering doesn't support less or equal")
		writeFalse(q.where)
		return
	}

	var sb strings.Builder
	sb.Grow(10 + len(s.Name) + len(sv.Norm()[0]))

	if isNot {
		sb.WriteString(`!(`)
	}
	sb.WriteString(`$."`)
	sb.WriteString(escapeName(s.Name))
	sb.WriteString(`" <= `)
	sb.WriteString(escapeValue(sv.Norm()[0]))
	if isNot {
		sb.WriteString(`)`)
	}

	filterKey := q.nextParamKey(s.Name)
	// TODO escape check
	q.params[filterKey] = sb.String()

	// attrs_norm @@ '$.createTimestamp <= "20070101000000Z"';
	q.where.WriteString(`e.attrs_norm @@ :`)
	q.where.WriteString(filterKey)
}

func (t *HybridDBFilterTranslator) PresentMatch(s *Schema, q *HybridDBFilterTranslatorResult, isNot bool) {
	if s.IsAssociationAttribute() {
		nameKey := q.nextParamKey(s.Name)
		q.params[nameKey] = s.Name

		q.where.WriteString(`
		(SELECT EXISTS (
			SELECT 1 FROM ldap_association a
			WHERE
				a.name = :`)
		q.where.WriteString(nameKey)
		q.where.WriteString(` AND e.id = a.id
	    ))`)

	} else if s.IsReverseAssociationAttribute() {
		q.where.WriteString(`
		(SELECT EXISTS (
			SELECT 1 FROM ldap_association a, ldap_entry moe, ldap_container moc
			WHERE
				e.id = a.member_id
	    ))`)

	} else {
		var sb strings.Builder
		sb.Grow(15 + len(s.Name))

		if isNot {
			sb.WriteString(`!(`)
		}
		sb.WriteString(`exists($."`)
		sb.WriteString(escapeName(s.Name))
		sb.WriteString(`")`)
		if isNot {
			sb.WriteString(`)`)
		}

		filterKey := q.nextParamKey(s.Name)
		q.params[filterKey] = sb.String()

		// attrs_norm @@ 'exists($.cn)';
		q.where.WriteString(`e.attrs_norm @@ :`)
		q.where.WriteString(filterKey)
	}
}

func (t *HybridDBFilterTranslator) ApproxMatch(s *Schema, q *HybridDBFilterTranslatorResult, val string, isNot bool) {
	sv, err := NewSchemaValue(s.server.schemaMap, s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	if s.IsAssociationAttribute() || s.IsReverseAssociationAttribute() {
		log.Printf("Filter for association doesn't support approx match")
		writeFalse(q.where)
		return
	}

	var sb strings.Builder
	sb.Grow(25 + len(s.Name) + len(sv.Norm()[0]))

	if isNot {
		sb.WriteString(`!(`)
	}
	sb.WriteString(`$."`)
	sb.WriteString(escapeName(s.Name))
	sb.WriteString(`" like_regex ".*`)
	sb.WriteString(escapeRegex(sv.Norm()[0]))
	sb.WriteString(`.*"`)
	if isNot {
		sb.WriteString(`)`)
	}

	filterKey := q.nextParamKey(s.Name)
	q.params[filterKey] = sb.String()

	// TODO Find better solution?
	// attrs_norm @@ '$.cn like_regex ".*foo.*"';
	q.where.WriteString(`e.attrs_norm @@ :`)
	q.where.WriteString(filterKey)
}

//////////////////////////////////////////
// Mapping
//////////////////////////////////////////

// AddEntryToDBEntry converts LDAP entry object to DB entry object.
// It handles metadata such as createTimistamp, modifyTimestamp and entryUUID.
// Also, it handles member and uniqueMember attributes.
func (r *HybridRepository) AddEntryToDBEntry(tx *sqlx.Tx, entry *AddEntry) (*HybridDBEntry, map[string][]int64, error) {
	norm, orig := entry.Attrs()

	// TODO strict mode
	if _, ok := norm["entryUUID"]; !ok {
		u, _ := uuid.NewRandom()
		norm["entryUUID"] = []string{u.String()}
		orig["entryUUID"] = []string{u.String()}
	}

	// Convert the value of member, uniqueMamber and memberOf attributes, DN => int64
	association := map[string][]int64{}

	member, err := r.dnArrayToIDArray(tx, norm, "member")
	if err != nil {
		return nil, nil, err
	}
	association["member"] = member

	uniqueMember, err := r.dnArrayToIDArray(tx, norm, "uniqueMember")
	if err != nil {
		return nil, nil, err
	}
	association["uniqueMember"] = uniqueMember

	memberOf, err := r.dnArrayToIDArray(tx, norm, "memberOf")
	if err != nil {
		return nil, nil, err
	}
	association["memberOf"] = memberOf

	// Remove attributes to reduce attrs_orig column size
	r.dropAssociationAttrs(norm, orig)

	// Timestamp
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

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	dn := entry.DN()

	dbEntry := &HybridDBEntry{
		DNNormWithoutSuffix: dn.DNNormStrWithoutSuffix(r.server.Suffix),
		DNOrigWithoutSuffix: dn.DNOrigStrWithoutSuffix(r.server.Suffix),
		RDNNorm:             dn.RDNNormStr(),
		RDNOrig:             dn.RDNOrigStr(),
		AttrsNorm:           types.JSONText(string(bNorm)),
		AttrsOrig:           types.JSONText(string(bOrig)),
		ParentDN:            entry.ParentDN(),
	}

	return dbEntry, association, nil
}

func (r *HybridRepository) dropAssociationAttrs(norm map[string]interface{}, orig map[string][]string) {
	delete(norm, "member")
	delete(norm, "uniqueMember")
	delete(norm, "memberOf")

	delete(orig, "member")
	delete(orig, "uniqueMember")
	delete(orig, "memberOf")
}

func (r *HybridRepository) schemaValueToIDArray(tx *sqlx.Tx, schemaValueMap map[string]*SchemaValue, attrName string) ([]int64, error) {
	rtn := []int64{}

	schemaValue, ok := schemaValueMap[attrName]
	if !ok || schemaValue.IsEmpty() {
		return rtn, nil
	}

	dnMap := map[string][]string{}
	for i, v := range schemaValue.Orig() {
		dn, err := NormalizeDN(r.server.schemaMap, v)
		if err != nil {
			log.Printf("warn: Failed to normalize DN: %s", v)
			return nil, NewInvalidPerSyntax(attrName, i)
		}

		parentDNNorm := dn.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix)
		dnMap[parentDNNorm] = append(dnMap[parentDNNorm], dn.RDNNormStr())
	}

	return r.resolveDNMap(tx, dnMap)
}

func (r *HybridRepository) dnArrayToIDArray(tx *sqlx.Tx, norm map[string]interface{}, attrName string) ([]int64, error) {
	rtn := []int64{}

	dnArray, ok := norm[attrName].([]string)
	if !ok || len(dnArray) == 0 {
		return rtn, nil
	}

	dnMap := map[string][]string{}
	for i, v := range dnArray {
		dn, err := NormalizeDN(r.server.schemaMap, v)
		if err != nil {
			log.Printf("warn: Failed to normalize DN: %s", v)
			return nil, NewInvalidPerSyntax(attrName, i)
		}

		parentDNNorm := dn.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix)
		dnMap[parentDNNorm] = append(dnMap[parentDNNorm], dn.RDNNormStr())
	}

	return r.resolveDNMap(tx, dnMap)
}

// resolveDNMap resolves Map(key: rdn_norm, value: parent_dn_norm) to the entry's ids.
func (r *HybridRepository) resolveDNMap(tx *sqlx.Tx, dnMap map[string][]string) ([]int64, error) {
	rtn := []int64{}

	bq := `SELECT
			e.id
		FROM
			ldap_entry e
			LEFT JOIN ldap_container c ON e.parent_id = c.id
		WHERE
			e.rdn_norm IN (:rdn_norm)
			AND c.dn_norm = :parent_dn_norm
		FOR SHARE
		`

	for k, v := range dnMap {
		q, params, err := sqlx.Named(bq, map[string]interface{}{
			"rdn_norm":       v,
			"parent_dn_norm": k,
		})
		if err != nil {
			log.Printf("error: Unexpected named query error. rdn_norm: %s, parent_dn_norm: %v, err: %v", k, v, err)
			// System error
			return nil, NewUnavailable()
		}

		q, params, err = sqlx.In(q, params...)
		if err != nil {
			log.Printf("error: Unexpected expand IN error. rdn_norm: %s, parent_dn_norm: %v, err: %v", k, v, err)
			// System error
			return nil, NewUnavailable()
		}

		q = tx.Rebind(q)

		rows, err := tx.Query(q, params...)
		if err != nil {
			log.Printf("error: Unexpected execute query error. rdn_norm: %s, parent_dn_norm: %v, err: %v", k, v, err)
			// System error
			return nil, NewUnavailable()
		}

		defer rows.Close()

		var ids []int64
		for rows.Next() {
			var id int64
			err = rows.Scan(&id)
			if err != nil {
				log.Printf("error: Unexpected query result scan error. rdn_norm: %s, parent_dn_norm: %v, err: %v", k, v, err)
				// System error
				return nil, NewUnavailable()
			}
			ids = append(ids, id)
		}

		rtn = append(rtn, ids...)
	}

	return rtn, nil
}

func (r *HybridRepository) modifyEntryToDBEntry(tx *sqlx.Tx, entry *ModifyEntry) (*HybridDBEntry, map[string][]int64, map[string][]int64, error) {
	norm, orig := entry.GetAttrs()

	// Convert the value of member, uniqueMamber and memberOf attributes, DN => int64
	addAssociation := map[string][]int64{}

	member, err := r.schemaValueToIDArray(tx, entry.AddChangeLog, "member")
	if err != nil {
		return nil, nil, nil, err
	}
	addAssociation["member"] = member

	uniqueMember, err := r.schemaValueToIDArray(tx, entry.AddChangeLog, "uniqueMember")
	if err != nil {
		return nil, nil, nil, err
	}
	addAssociation["uniqueMember"] = uniqueMember

	memberOf, err := r.schemaValueToIDArray(tx, entry.AddChangeLog, "memberOf")
	if err != nil {
		return nil, nil, nil, err
	}
	addAssociation["memberOf"] = memberOf

	delAssociation := map[string][]int64{}

	member, err = r.schemaValueToIDArray(tx, entry.DelChangeLog, "member")
	if err != nil {
		return nil, nil, nil, err
	}
	delAssociation["member"] = member

	uniqueMember, err = r.schemaValueToIDArray(tx, entry.DelChangeLog, "uniqueMember")
	if err != nil {
		return nil, nil, nil, err
	}
	delAssociation["uniqueMember"] = uniqueMember

	memberOf, err = r.schemaValueToIDArray(tx, entry.DelChangeLog, "memberOf")
	if err != nil {
		return nil, nil, nil, err
	}
	delAssociation["memberOf"] = memberOf

	// Remove attributes to reduce attrs_orig column size
	r.dropAssociationAttrs(norm, orig)

	// Timestamp
	updated := time.Now()
	norm["modifyTimestamp"] = []int64{updated.Unix()}
	orig["modifyTimestamp"] = []string{updated.In(time.UTC).Format(TIMESTAMP_FORMAT)}

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	dbEntry := &HybridDBEntry{
		ID:        entry.dbEntryID,
		AttrsNorm: types.JSONText(string(bNorm)),
		AttrsOrig: types.JSONText(string(bOrig)),
	}

	return dbEntry, addAssociation, delAssociation, nil
}

//////////////////////////////////////////
// Bind
//////////////////////////////////////////

func (r *HybridRepository) FindCredByDN(ctx context.Context, dn *DN) ([]string, error) {
	tx, err := r.beginReadonly(ctx)
	if err != nil {
		return nil, err
	}

	dest := struct {
		ID   int64          `db:"id"`
		Cred types.JSONText `db:"credential"`
	}{}

	if err := r.get(tx, findCredByDN, &dest, map[string]interface{}{
		"rdn_norm":       dn.RDNNormStr(),
		"parent_dn_norm": dn.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix),
	}); err != nil {
		if isNoResult(err) {
			return nil, NewInvalidCredentials()
		}
		return nil, xerrors.Errorf("Failed to find cred by DN. dn_orig: %s, err: %w", dn.DNOrigStr(), err)
	}

	var cred []string
	err = dest.Cred.Unmarshal(&cred)
	if err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal cred array. dn_orig: %s, err: %w", dn.DNOrigStr(), err)
	}

	return cred, nil
}

//////////////////////////////////////////
// Utilities
//////////////////////////////////////////

func (r *HybridRepository) begin(ctx context.Context) (*sqlx.Tx, error) {
	tx, err := r.db.BeginTxx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	// TODO Configurable isolation level
	// tx, err := r.db.BeginTxx(ctx, &sql.TxOptions{
	// 	Isolation: sql.LevelSerializable,
	// })
	if err != nil {
		return nil, xerrors.Errorf("Failed to begin transaction. err: %w", err)
	}
	return tx, nil
}

func (r *HybridRepository) beginReadonly(ctx context.Context) (*sqlx.Tx, error) {
	tx, err := r.db.BeginTxx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	// TODO Configurable isolation level
	// tx, err := r.db.BeginTxx(ctx, &sql.TxOptions{
	// 	Isolation: sql.LevelSerializable,
	// 	ReadOnly:  true,
	// })
	if err != nil {
		return nil, xerrors.Errorf("Failed to begin transaction. err: %w", err)
	}
	return tx, nil
}

func (r *HybridRepository) exec(tx *sqlx.Tx, stmt *sqlx.NamedStmt, params map[string]interface{}) (sql.Result, error) {
	debugSQL(r.server.config.LogLevel, stmt.QueryString, params)
	result, err := tx.NamedStmt(stmt).Exec(params)
	errorSQL(err, stmt.QueryString, params)
	return result, err
}

func (r *HybridRepository) execQuery(tx *sqlx.Tx, query string) (sql.Result, error) {
	debugSQL(r.server.config.LogLevel, query, nil)
	result, err := tx.Exec(query)
	errorSQL(err, query, nil)
	if isForeignKeyError(err) {
		return nil, NewRetryError(err)
	}
	return result, err
}

func (r *HybridRepository) namedQuery(tx *sqlx.Tx, query string, params map[string]interface{}) (*sqlx.Rows, error) {
	debugSQL(r.server.config.LogLevel, query, nil)
	rows, err := tx.NamedQuery(query, params)
	errorSQL(err, query, nil)
	if isForeignKeyError(err) {
		return nil, NewRetryError(err)
	}
	return rows, err
}

func (r *HybridRepository) get(tx *sqlx.Tx, stmt *sqlx.NamedStmt, dest interface{}, params map[string]interface{}) error {
	debugSQL(r.server.config.LogLevel, stmt.QueryString, params)
	err := tx.NamedStmt(stmt).Get(dest, params)
	errorSQL(err, stmt.QueryString, params)
	if isForeignKeyError(err) {
		return NewRetryError(err)
	}
	return err
}

func debugSQL(logLevel string, query string, params map[string]interface{}) {
	if logLevel == "debug" {
		var fname, method string
		var line int
		if pc, f, l, ok := runtime.Caller(2); ok {
			fname = filepath.Base(f)
			line = l
			method = runtime.FuncForPC(pc).Name()
		}

		log.Printf(`Exec SQL at %s:%d:%s
--
%s
%v
--`, fname, line, method, query, params)
	}
}

func errorSQL(err error, query string, params map[string]interface{}) {
	if err != nil {
		var fname, method string
		var line int
		if pc, f, l, ok := runtime.Caller(2); ok {
			fname = filepath.Base(f)
			line = l
			method = runtime.FuncForPC(pc).Name()
		}
		logLevel := "error"
		if isDuplicateKeyError(err) || isForeignKeyError(err) {
			logLevel = "info"
		}
		log.Printf(`%s: Failed to execute SQL at %s:%d:%s: err: %v
--
%s
%v
--`, logLevel, fname, line, method, err, query, params)
	}
}

func findSchema(schemaMap *SchemaMap, attrName string) (*Schema, bool) {
	var s *Schema
	s, ok := schemaMap.Get(attrName)
	if !ok {
		log.Printf("Unsupported filter attribute: %s", attrName)
		return nil, false
	}
	return s, true
}

func escapeRegex(s string) string {
	return regexp.QuoteMeta(s)
}

// escape escapes meta characters used in PostgreSQL jsonpath name.
// See https://www.postgresql.org/docs/12/datatype-json.html#DATATYPE-JSONPATH
func escapeName(s string) string {
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `'`, `''`) // Write two adjacent single quotes
	s = strings.ReplaceAll(s, `[`, `\[`)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `*`, `\*`)
	return s
}

// escapeValue escapes meta characters used in PostgreSQL jsonpath value.
// See https://www.postgresql.org/docs/12/datatype-json.html#DATATYPE-JSONPATH
func escapeValue(s string) string {
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `'`, `''`)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return s
}

func writeFalseJsonpath(attrName string, sb *strings.Builder) {
	sb.WriteString(`$."`)
	sb.WriteString(escapeName(attrName))
	sb.WriteString(`" == false`)
}

func writeFalse(sb *strings.Builder) {
	sb.WriteString(`FALSE`)
}
