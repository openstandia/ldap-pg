package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"golang.org/x/xerrors"
)

type HybridRepository struct {
	*DBRepository
}

var (
	// repo_insert
	insertContainerStmt *sqlx.NamedStmt
	insertEntryStmt     *sqlx.NamedStmt

	// repo_read for update
	findEntryIDByDNWithShareLock  *sqlx.NamedStmt
	findEntryIDByDNWithUpdateLock *sqlx.NamedStmt
	findEntryByDNWithShareLock    *sqlx.NamedStmt

	// repo_update
	updateAttrsByIdStmt *sqlx.NamedStmt
	updateDNByIdStmt    *sqlx.NamedStmt
	updateRDNByIdStmt   *sqlx.NamedStmt

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
		attrs_orig JSONB NOT NULL
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_ldap_entry_rdn_norm ON ldap_entry (parent_id, rdn_norm);
	CREATE INDEX IF NOT EXISTS idx_ldap_entry_attrs ON ldap_entry USING gin (attrs_norm jsonb_path_ops);

	CREATE TABLE IF NOT EXISTS ldap_association (
		name VARCHAR(32) NOT NULL,
		id BIGINT NOT NULL,
		member_id BIGINT NOT NULL,
		UNIQUE (name, id, member_id)
	);
	CREATE INDEX IF NOT EXISTS idx_ldap_association_id ON ldap_association(name, id);
	CREATE INDEX IF NOT EXISTS idx_ldap_association_member_id ON ldap_association(name, member_id);
	`)

	findCredByDN, err = db.PrepareNamed(`SELECT
		e.id, e.attrs_orig->'userPassword' 
	FROM
		ldap_entry e
		LEFT JOIN ldap_container c ON e.parent_id = c.id
	WHERE
		e.rdn_norm = :rdn_norm
		AND c.dn_norm = :parent_dn_norm
	FOR SHARE
	`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	// Lock the entry to block update or delete.
	// By using 'FOR SHARE', other transactions can read the entry without lock.
	findEntryByDNWithShareLock, err = db.PrepareNamed(`SELECT
		e.id, e.parent_id, e.rdn_orig, e.attrs_orig
	FROM
		ldap_entry e
		LEFT JOIN ldap_container c ON e.parent_id = c.id
	WHERE
		e.rdn_norm = :rdn_norm
		AND c.dn_norm = :parent_dn_norm
	FOR SHARE
	`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findEntryIDByDNWithShareLock, err = db.PrepareNamed(`SELECT
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
	FOR SHARE
	`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	findEntryIDByDNWithUpdateLock, err = db.PrepareNamed(`SELECT
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
	FOR UPDATE 
	`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	insertContainerStmt, err = db.PrepareNamed(`INSERT INTO ldap_container (id, dn_norm, dn_orig)
	VALUES (:id, :dn_norm, :dn_orig)`)
	if err != nil {
		return xerrors.Errorf("Failed to initialize prepared statement: %w", err)
	}

	deleteContainerStmt, err = db.PrepareNamed(`DELETE FROM ldap_container WHERE id = :id RETURNING id`)
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

func (r *HybridRepository) Insert(entry *AddEntry) (int64, error) {
	tx := r.db.MustBegin()

	var newID int64
	var err error

	dbEntry, association, err := r.AddEntryToDBEntry(tx, entry)
	if err != nil {
		return 0, err
	}

	if entry.DN().Equal(r.server.Suffix) {
		// Insert level 0
		newID, _, err = r.insertLevel0(tx, dbEntry)

	} else {
		// Insert level 1+
		newID, _, err = r.insertInternal(tx, dbEntry)
	}

	// Insert association if necessary
	r.insertAssociation(tx, entry.dn, newID, association)

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

func (r *HybridRepository) insertLevel0(tx *sqlx.Tx, dbEntry *HybridDBEntry) (int64, int64, error) {
	// Step 1: Insert entry
	var parentId int64 = 0

	params := map[string]interface{}{
		"parent_id":  parentId,
		"rdn_norm":   dbEntry.RDNNorm,
		"rdn_orig":   dbEntry.RDNOrig,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
	}

	log.Printf("insert entry query:\n%s\nparams:\n%v", insertEntryStmt.QueryString, params)

	var newID int64
	err := tx.NamedStmt(insertEntryStmt).Get(&newID, params)
	if err != nil {
		if isDuplicateKeyError(err) {
			log.Printf("debug: The new entry already exists. parentId: %d, rdn_norm: %s", parentId, dbEntry.RDNNorm)
			return 0, 0, NewAlreadyExists()
		}
		return 0, 0, xerrors.Errorf("Failed to insert entry record. dbEntry: %v, err: %w", dbEntry, err)
	}

	// Step 2: Insert parent container for level 0 entry
	params = map[string]interface{}{
		"id":      parentId,
		"dn_norm": "",
		"dn_orig": "",
	}

	log.Printf("insert container query:\n%s\nparams:\n%v", insertContainerStmt.QueryString, params)

	_, err = tx.NamedStmt(insertContainerStmt).Exec(params)
	if err != nil {
		return 0, 0, xerrors.Errorf("Failed to insert level 0 parent container record. err: %w", err)
	}

	return newID, parentId, nil
}

func (r *HybridRepository) insertInternal(tx *sqlx.Tx, dbEntry *HybridDBEntry) (int64, int64, error) {
	parentDN := dbEntry.ParentDN

	// Step 1: Find the parent ID
	params := map[string]interface{}{
		"rdn_norm":       parentDN.RDNNormStr(),
		"parent_dn_norm": parentDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix),
	}

	dest := struct {
		ID       int64 `db:"id"`
		ParentID int64 `db:"parent_id"`
		HasSub   bool  `db:"has_sub"`
	}{}

	log.Printf("findEntryIDByDNWithShareLock start. query: %s, params: %v",
		findEntryIDByDNWithShareLock.QueryString, params)

	// When inserting new entry, we need to lock the parent DN entry while the processing
	// because there is a chance other thread deletes the parent DN entry before the inserting if no lock.
	err := tx.NamedStmt(findEntryIDByDNWithShareLock).Get(&dest, params)
	if err != nil {
		if isNoResult(err) {
			// TODO
			log.Printf("warn: No Parent case")
			// TODO error when no parent
			return 0, 0, NewNoSuchObject()
		}
		return 0, 0, xerrors.Errorf("Failed to fetch parent entry. dn_norm: %s, err: %w", parentDN.DNNormStr(), err)
	}

	parentId := dest.ID
	needCreateContainer := false
	if !dest.HasSub {
		// Not found parent container yet
		// We need to insert new container later
		needCreateContainer = true
	}

	// Step 2: Insert entry
	params = map[string]interface{}{
		"parent_id":  parentId,
		"rdn_norm":   dbEntry.RDNNorm,
		"rdn_orig":   dbEntry.RDNOrig,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
	}

	log.Printf("insert entry query:\n%s\nparams:\n%v", insertEntryStmt.QueryString, params)

	var newID int64
	err = tx.NamedStmt(insertEntryStmt).Get(&newID, params)
	if err != nil {
		if isDuplicateKeyError(err) {
			log.Printf("debug: The new entry already exists. parentId: %d, rdn_norm: %s", parentId, dbEntry.RDNNorm)
			return 0, 0, NewAlreadyExists()
		}
		return 0, 0, xerrors.Errorf("Failed to insert entry record. dbEntry: %v, err: %w", dbEntry, err)
	}

	// Step 3: Insert parent container if necessary
	if needCreateContainer {
		params := map[string]interface{}{
			"id":      parentId,
			"dn_norm": parentDN.DNNormStrWithoutSuffix(r.server.Suffix),
			"dn_orig": parentDN.DNOrigStrWithoutSuffix(r.server.Suffix),
		}

		log.Printf("insert container query:\n%s\nparams:\n%v", insertContainerStmt.QueryString, params)

		rows, err := tx.NamedStmt(insertContainerStmt).Queryx(params)
		if err != nil {
			return 0, 0, xerrors.Errorf("Failed to insert container record. id: %d, dn_norm: %s, err: %w",
				newID, dbEntry.DNNormWithoutSuffix, err)
		}
		defer rows.Close()
	}

	return newID, parentId, nil
}

func (r *HybridRepository) insertAssociation(tx *sqlx.Tx, dn *DN, newID int64, association map[string][]int64) error {
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

		log.Printf("insert association query:\n%s", q)

		result, err := tx.Exec(q)
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

func (r *HybridRepository) Update(dn *DN, callback func(current *ModifyEntry) error) error {
	tx := r.db.MustBegin()

	// Step 1: Fetch current entry with share lock(blocking update and delete)
	// TODO: Need to fetch all associations
	oID, oParentID, _, oJSONMap, err := r.findByDNForUpdate(tx, dn)
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

	return commit(tx)
}

func (r *HybridRepository) findByDNForUpdate(tx *sqlx.Tx, dn *DN) (int64, int64, string, map[string][]string, error) {
	dest := struct {
		id        int64          `db:"id"`
		parentID  int64          `db:"parent_id"`
		rdnOrig   string         `db:"rdn_orig"`
		attrsOrig types.JSONText `db:"attrs_orig"`
	}{}

	err := namedStmt(tx, findEntryByDNWithShareLock).Get(&dest, map[string]interface{}{
		"rdn_norm":       dn.RDNNormStr(),
		"parent_dn_norm": dn.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix),
	})
	if err != nil {
		if isNoResult(err) {
			return 0, 0, "", nil, NewNoSuchObject()
		}
		return 0, 0, "", nil, xerrors.Errorf("Failed to execute findByDNForUpdate in %s. dn_norm: %s, err: %w", txLabel(tx), dn.DNNormStr(), err)
	}

	var jsonMap map[string][]string
	if len(dest.attrsOrig) > 0 {
		jsonMap := make(map[string][]string)
		if err := dest.attrsOrig.Unmarshal(&jsonMap); err != nil {
			return 0, 0, "", nil, xerrors.Errorf("Unexpected unmarshal error in %s. dn_norm: %s, err: %w", txLabel(tx), dn.DNNormStr(), err)
		}
	}

	return dest.id, dest.parentID, dest.rdnOrig, jsonMap, nil
}

// oldRDN: set when keeping current entry
func (r *HybridRepository) UpdateDN(oldDN, newDN *DN, oldRDN *RelativeDN) error {
	tx := r.db.MustBegin()

	// Fetch target entry with lock
	oID, oParentID, _, oJSONMap, err := r.findByDNForUpdate(tx, oldDN)
	if err != nil {
		rollback(tx)
		return err
	}

	entry, err := NewModifyEntry(r.server.schemaMap, oldDN, oJSONMap)
	if err != nil {
		return err
	}
	entry.dbEntryID = oID
	entry.dbParentID = oParentID

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

	return commit(tx)
}

func (r *HybridRepository) updateDNUnderNewParent(tx *sqlx.Tx, oldDN, newDN *DN, oldRDN *RelativeDN, oldEntry *ModifyEntry) error {
	oldParentDN := oldDN.ParentDN()
	newParentDN := newDN.ParentDN()

	var oldParentID int64
	var newParentID int64
	var needCreateContainer bool
	var needDeleteContainer bool

	// Determine old parent ID
	if oldParentDN.IsRoot() {
		oldParentID = 0
		needDeleteContainer = false
	} else {
		oldParentID = oldEntry.dbParentID
		// After updating DN, determine if we need to delete the container for old parent
	}

	// Determine new parent ID
	if newParentDN.IsRoot() {
		oldParentID = 0
		// Root entry doesn't need to insert container record always
		needCreateContainer = false
	} else {
		dest := struct {
			ID       int64 `db:"id"`
			ParentID int64 `db:"parent_id"`
			HasSub   bool  `db:"has_sub"`
		}{}

		err := namedStmt(tx, findEntryIDByDNWithShareLock).Get(&dest, map[string]interface{}{
			"rdn_norm":       newParentDN.RDNNormStr(),
			"parent_dn_norm": newParentDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix),
		})
		if err != nil {
			if isNoResult(err) {
				return NewNoSuchObject()
			}
			return xerrors.Errorf("Failed to execute findEntryIDByDNWithShareLock in %s: %v, err: %w", txLabel(tx), newParentDN, err)
		}
		newParentID = dest.ID
		needCreateContainer = !dest.HasSub
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
	result, err := tx.NamedStmt(updateDNByIdStmt).Exec(map[string]interface{}{
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
	if num, err := result.RowsAffected(); err != nil {
		log.Printf("MOD RDN updated row num: %d", num)
	}

	// Determine we need to delete container for old parent
	dest := struct {
		ID       int64 `db:"id"`
		ParentID int64 `db:"parent_id"`
		HasSub   bool  `db:"has_sub"`
	}{}

	err = namedStmt(tx, findEntryIDByDNWithShareLock).Get(&dest, map[string]interface{}{
		"rdn_norm":       newParentDN.RDNNormStr(),
		"parent_dn_norm": newParentDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix),
	})
	if err != nil {
		if isNoResult(err) {
			return NewNoSuchObject()
		}
		return xerrors.Errorf("Failed to execute findEntryIDByDNWithShareLock in %s: %v, err: %w", txLabel(tx), newParentDN, err)
	}
	if !dest.HasSub {
		needDeleteContainer = true
	}

	// If the new parent doesn't have any sub, need to insert container record.
	if needCreateContainer {
		params := map[string]interface{}{
			"id":      newParentID,
			"dn_norm": newParentDN.DNNormStrWithoutSuffix(r.server.Suffix),
			"dn_orig": newParentDN.DNNormStrWithoutSuffix(r.server.Suffix),
		}

		log.Printf("insert container query:\n%s\nparams:\n%v", insertContainerStmt.QueryString, params)

		rows, err := tx.NamedStmt(insertContainerStmt).Queryx(params)
		if err != nil {
			return xerrors.Errorf("Failed to insert container record. id: %d, dn_norm: %s, dn_orig: %s, err: %w",
				newParentID, newParentDN.DNNormStr(), newParentDN.DNOrigStr(), err)
		}
		defer rows.Close()
		result, err := namedStmt(tx, insertContainerStmt).Exec(params)
		if err != nil {
			return xerrors.Errorf("Failed to insert container record. id: %d, dn_norm: %s, dn_orig: %s, err: %w",
				newParentID, oldParentDN.DNNormStr(), newParentDN.DNOrigStr(), err)
		}
		if num, err := result.RowsAffected(); err != nil {
			log.Printf("Insert container row num: %d", num)
		}
	}

	// If the old parent doesn't have any sub, need to delete container record.
	if needDeleteContainer {
		params := map[string]interface{}{
			"id":      oldParentID,
			"dn_norm": oldParentDN.DNNormStrWithoutSuffix(r.server.Suffix),
			"dn_orig": oldParentDN.DNNormStrWithoutSuffix(r.server.Suffix),
		}

		log.Printf("delete container query:\n%s\nparams:\n%v", deleteContainerStmt.QueryString, params)

		result, err := namedStmt(tx, deleteContainerStmt).Exec(params)
		if err != nil {
			return xerrors.Errorf("Failed to delete container record. id: %d, dn_norm: %s, dn_orig: %s, err: %w",
				oldParentID, oldParentDN.DNNormStr(), oldParentDN.DNOrigStr(), err)
		}
		if num, err := result.RowsAffected(); err != nil {
			log.Printf("Deleted container row num: %d", num)
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
		return xerrors.Errorf("Failed to update entry DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
	}

	return nil
}

//////////////////////////////////////////
// DEL operation
//////////////////////////////////////////

func (r HybridRepository) DeleteByDN(dn *DN) error {
	tx := r.db.MustBegin()

	// Step 1: fetch the target entry and parent container with lock for update
	fetchedEntry := struct {
		ID       int64 `db:"id"`
		ParentID int64 `db:"parent_id"`
		HasSub   bool  `db:"has_sub"`
	}{}

	err := namedStmt(tx, findEntryIDByDNWithUpdateLock).Get(&fetchedEntry, map[string]interface{}{
		"rdn_norm":       dn.RDNNormStr(),
		"parent_dn_norm": dn.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix),
	})
	if err != nil {
		rollback(tx)

		if isNoResult(err) {
			return NewNoSuchObject()
		}
		return xerrors.Errorf("Failed to execute findEntryIDByDNWithShareLock in %s: %v, err: %w", txLabel(tx), dn, err)
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

	log.Printf("Deleted id: %d, dn: %v", fetchedEntry.ID, dn)

	// Step 3: Delete container if the parent doesn't have children
	hasSub, err := r.hasSub(tx, fetchedEntry.ParentID)
	if err != nil {
		rollback(tx)
		return err
	}
	log.Printf("HasSub: %v", hasSub)

	if !hasSub {
		if err := r.deleteContainerByID(tx, fetchedEntry.ParentID); err != nil {
			rollback(tx)
			return err
		}
		log.Printf("deleteContainerByID end")
	}

	log.Printf("removeAssociationById start")

	// Step 4: Remove all association
	err = r.removeAssociationById(tx, delID)
	if err != nil {
		rollback(tx)
		return err
	}
	log.Printf("removeAssociationById end")

	return commit(tx)
}

func (r *HybridRepository) hasSub(tx *sqlx.Tx, id int64) (bool, error) {
	var hasSub bool
	err := tx.NamedStmt(hasSubStmt).Get(&hasSub, map[string]interface{}{
		"id": id,
	})
	if err != nil {
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

func (r *HybridRepository) deleteContainerByID(tx *sqlx.Tx, id int64) error {
	result, err := tx.NamedStmt(deleteContainerStmt).Exec(map[string]interface{}{
		"id": id,
	})
	if err != nil {
		if isNoResult(err) {
			log.Printf("warn: the container already deleted. id: %d", id)
			return NewNoSuchObject()
		}
		return xerrors.Errorf("Failed to delete container. id: %d, err: %w", id, err)
	}
	if num, err := result.RowsAffected(); err == nil {
		log.Printf("Deleted container. id: %d, num: %d", id, num)
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
	RawMember       types.JSONText `db:"member"`          // No real column in the table
	RawUniqueMember types.JSONText `db:"uniquemember"`    // No real column in the table
	RawMemberOf     types.JSONText `db:"memberof"`        // No real column in the table
	HasSubordinates string         `db:"hassubordinates"` // No real column in the table
	DNOrig          string         `db:"dn_orig"`         // No real column in the table
	Count           int32          `db:"count"`           // No real column in the table
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

func (r *HybridRepository) Search(baseDN *DN, option *SearchOption, handler func(entry *SearchEntry) error) (int32, int32, error) {
	log.Printf("Search option: %v", option)

	proj := []string{}
	join := []string{}
	where := []string{}
	params := map[string]interface{}{
		"pageSize": option.PageSize,
		"offset":   option.Offset,
	}
	r.collectAssociationSQL(option, &proj, &join)
	r.collectHasSubordinatesSQL(option, &proj, &join)
	r.collectWhereSQL(baseDN, option, &where, params)

	// TODO search filter
	// TODO filter by association. Should only support `equal` or `presence` filter for association.

	q := fmt.Sprintf(`
	SELECT
		e.id,
		e.parent_id,
		e.rdn_orig || ',' || dnc.dn_orig AS dn_orig,
		e.attrs_orig,
		count(e.id) over() AS count
		%s
	FROM
		ldap_entry e
		-- DN join
		LEFT JOIN ldap_container dnc ON e.parent_id = dnc.id
		%s
	WHERE
		%s
	LIMIT :pageSize OFFSET :offset
	`, strings.Join(proj, ", "), strings.Join(join, ""), strings.Join(where, " AND "))

	log.Printf("Search SQL\n==\n%s\n==\n%v\n==", q, params)

	rows, err := r.db.NamedQuery(q, params)

	if err != nil {
		if isNoResult(err) {
			return 0, 0, nil
		}
		return 0, 0, xerrors.Errorf("Failed to search, err: %w", err)
	}

	var maxCount int32 = 0
	var count int32 = 0
	var dbEntry HybridFetchedDBEntry

	for rows.Next() {
		err = rows.StructScan(&dbEntry)
		if err != nil {
			return 0, 0, xerrors.Errorf("Failed to scan, err: %w", err)
		}
		if maxCount == 0 {
			maxCount = dbEntry.Count
		}

		readEntry, err := r.toSearchEntry(&dbEntry)
		if err != nil {
			log.Printf("error: Mapper error: %#v", err)
			return 0, 0, err
		}

		err = handler(readEntry)
		if err != nil {
			log.Printf("error: Handler error: %#v", err)
			return 0, 0, err
		}

		count++
		dbEntry.Clear()
	}

	return maxCount, count, nil
}

func (m *HybridRepository) toSearchEntry(dbEntry *HybridFetchedDBEntry) (*SearchEntry, error) {
	orig := dbEntry.AttrsOrig()

	// hasSubordinates
	if dbEntry.HasSubordinates != "" {
		orig["hasSubordinates"] = []string{dbEntry.HasSubordinates}
	}

	// resolve association suffix
	m.resolveAssociationSuffix(orig, "member")
	m.resolveAssociationSuffix(orig, "uniqueMember")
	m.resolveAssociationSuffix(orig, "memberOf")

	readEntry := NewSearchEntry(m.server.schemaMap, dbEntry.DNOrig, orig)

	return readEntry, nil
}

func (r *HybridRepository) resolveAssociationSuffix(attrsOrig map[string][]string, attrName string) {
	um := attrsOrig[attrName]
	if len(um) > 0 {
		for i, v := range um {
			um[i] = resolveSuffix(r.server, v)
		}
	}
}

// func (r *HybridRepository) createAssociationFilterSQL(option *SearchOption) (string, string) {
// 	join := ""
// 	where := ""
// 	for i, v := range option.RequestedAssocation {
// 		if i > 0 {
// 			proj += ", "
// 		}
// 		proj += fmt.Sprintf("%s AS %s", v, v)
// 		join += fmt.Sprintf(`
// 		-- filter by %s
// 		INNER JOIN ldap_association a ON e.id = a.member_id
// 		INNER JOIN ldap_entry ae ON ae.id = a.id
// 		INNER JOIN ldap_container c ON c.id = ae.parent_id
// 		`, v, v, v)

// 		where += fmt.Sprintf(`
// 		(
// 			ae.rdn_norm = 'cn=group13'
// 			AND c.dn_norm = 'ou=group,ou=t0
// 		)
// 		`)
// 	}

// 	return proj, join
// }

func (r *HybridRepository) collectAssociationSQL(option *SearchOption, proj, join *[]string) {
	if len(*proj) == 0 {
		*proj = append(*proj, "")
	}

	for _, v := range option.RequestedAssocation {
		*proj = append(*proj, fmt.Sprintf("%s.%s AS %s", v, v, v))
		*join = append(*join, fmt.Sprintf(`
	-- requested association - %s 
	LEFT JOIN LATERAL (
		SELECT jsonb_agg(rae.rdn_orig || ',' || rc.dn_orig) AS %s
		FROM ldap_association ra, ldap_entry rae, ldap_container rc
		WHERE e.id = ra.id AND ra.name = '%s' AND rae.id = ra.member_id AND rc.id = rae.parent_id
	) AS %s ON true`, v, v, v, v))
	}

	if option.IsMemberOfRequested {
		*proj = append(*proj, "memberOf.memberOf AS memberOf")
		*join = append(*join, `
	-- requested association - memberOf
	LEFT JOIN LATERAL (
		SELECT jsonb_agg(rae.rdn_orig || ',' || rc.dn_orig) AS memberOf
		FROM ldap_association ra, ldap_entry rae, ldap_container rc
		WHERE e.id = ra.member_id AND rae.id = ra.id AND rc.id = rae.parent_id
	) AS memberOf ON true`)
	}
}

func (r *HybridRepository) collectHasSubordinatesSQL(option *SearchOption, proj, join *[]string) {
	if len(*proj) == 0 {
		*proj = append(*proj, "")
	}

	if option.IsHasSubordinatesRequested {
		*proj = append(*proj, "has_sub.has_sub AS has_sub")
		*join = append(*join, `
	-- requested has_sub
	LEFT JOIN LATERAL (
		SELECT EXISTS (SELECT 1 FROM ldap_container WHERE id = e.id) AS has_sub
	) AS has_sub ON true`)
	}
}

func (r *HybridRepository) collectWhereSQL(baseDN *DN, option *SearchOption, where *[]string, params map[string]interface{}) {
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
		*where = append(*where, fmt.Sprintf(`
	e.%s = (SELECT
			e.id
		FROM
			ldap_entry e
			LEFT JOIN ldap_container c ON e.parent_id = c.id
		WHERE
			e.rdn_norm = :rdn_norm
			AND c.dn_norm = :parent_dn_norm
	)`, col))
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
			subWhere = `
	e.parent_id IN (SELECT
			e.id
		FROM
			ldap_entry e
			LEFT JOIN ldap_container c ON e.parent_id = c.id
		WHERE
			REVERSE(c.dn_norm) LIKE REVERSE('%,' || :parent_dn_norm)
	)`
		}

		if option.Scope == 2 {
			*where = append(*where, `
	e.id = (SELECT
			e.id
		FROM
			ldap_entry e
			LEFT JOIN ldap_container c ON e.parent_id = c.id
		WHERE
			e.rdn_norm = :rdn_norm
			AND c.dn_norm = :parent_dn_norm
	) OR
	`+subWhere)
			params["rdn_norm"] = baseDN.RDNNormStr()
			params["parent_dn_norm"] = baseDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix)
		} else {
			*where = append(*where, subWhere)
			params["parent_dn_norm"] = baseDN.ParentDN().DNNormStrWithoutSuffix(r.server.Suffix)
		}
	}
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

func (r *HybridRepository) FindCredByDN(dn *DN) ([]string, error) {
	dest := struct {
		ID   int64          `db:"id"`
		Cred types.JSONText `db:"cred"`
	}{}

	err := findCredByDN.Get(&dest, map[string]interface{}{})
	if err != nil {
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
