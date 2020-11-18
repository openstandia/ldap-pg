package main

import (
	"log"
	"strings"

	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func (r *Repository) Update(tx *sqlx.Tx, oldEntry, newEntry *ModifyEntry) error {
	if newEntry.dbEntryId == 0 {
		return xerrors.Errorf("Invalid dbEntryId for update DBEntry.")
	}

	dbEntry, err := mapper.ModifyEntryToDBEntry(tx, newEntry)
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
		return xerrors.Errorf("Failed to update entry. entry: %v, err: %w", newEntry, err)
	}

	return nil
}

func (r *Repository) UpdateDN(oldDN, newDN *DN, deleteOld bool) error {
	tx := r.db.MustBegin()
	err := r.updateDN(tx, oldDN, newDN, deleteOld)
	if err != nil {
		tx.Rollback()
		return err
	}

	err = tx.Commit()

	return err
}

func (r *Repository) updateDN(tx *sqlx.Tx, oldDN, newDN *DN, deleteOld bool) error {
	oldEntry, err := r.FindEntryByDN(tx, oldDN, true)
	if err != nil {
		return NewNoSuchObject()
	}

	parentID := oldEntry.dbParentID
	if !oldDN.ParentDN().Equal(newDN.ParentDN()) {
		p, err := r.FindEntryByDN(tx, newDN.ParentDN(), true)
		if err != nil {
			return NewNoSuchObject()
		}
		parentID = p.dbEntryId
	}

	newEntry := oldEntry.ModifyRDN(newDN)
	dbEntry, err := mapper.ModifyEntryToDBEntry(tx, newEntry)
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(updateDNByIdStmt).Exec(map[string]interface{}{
		"id":           oldEntry.dbEntryId,
		"parent_id":    parentID,
		"new_rdn_norm": newDN.RDNNormStr(),
		"new_rdn_orig": newDN.RDNOrigStr(),
		"attrs_norm":   dbEntry.AttrsNorm,
		"attrs_orig":   dbEntry.AttrsOrig,
	})

	if !deleteOld {
		add, err := mapper.ModifyEntryToAddEntry(oldEntry)
		if err != nil {
			return err
		}
		_, err = r.insertWithTx(tx, add)
		if err != nil {
			return err
		}
	}

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			log.Printf("warn: Failed to update entry DN because of already exists. oldDN: %s newDN: %s err: %+v", oldDN.DNNormStr(), newDN.DNNormStr(), err)
			return NewAlreadyExists()
		}
		return xerrors.Errorf("Failed to update entry DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
	}

	return nil
}
