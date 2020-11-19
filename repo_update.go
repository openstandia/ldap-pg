package main

import (
	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func (r *Repository) Update(tx *sqlx.Tx, oldEntry, newEntry *ModifyEntry) error {
	if newEntry.dbEntryID == 0 {
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

func (r *Repository) UpdateDN(oldDN, newDN *DN, oldRDN *RelativeDN) error {
	tx := r.db.MustBegin()

	err := r.updateDN(tx, oldDN, newDN, oldRDN)
	if err != nil {
		rollback(tx)
		return err
	}

	return commit(tx)
}

func (r *Repository) updateDN(tx *sqlx.Tx, oldDN, newDN *DN, oldRDN *RelativeDN) error {
	// Lock the entry
	oldEntry, err := r.FindEntryByDN(tx, oldDN, true)
	if err != nil {
		return NewNoSuchObject()
	}

	if !oldDN.ParentDN().Equal(newDN.ParentDN()) {
		// Move or copy onto the new parent case
		return r.updateDNOntoNewParent(tx, oldDN, newDN, oldRDN, oldEntry)
	} else {
		// Update rdn only case
		return r.updateRDN(tx, oldDN, newDN, oldRDN, oldEntry)
	}
}

func (r *Repository) updateDNOntoNewParent(tx *sqlx.Tx, oldDN, newDN *DN, oldRDN *RelativeDN, oldEntry *ModifyEntry) error {
	oldParentDN := oldDN.ParentDN()
	newParentDN := newDN.ParentDN()

	parentID := oldEntry.dbParentID

	if !oldParentDN.Equal(newParentDN) {
		// Lock the old/new parent entry
		newParentFetchedDN, err := r.FindDNByDNWithLock(tx, newParentDN, true)
		if err != nil {
			return NewNoSuchObject()
		}
		_, err = r.FindDNByDNWithLock(tx, oldParentDN, true)
		if err != nil {
			return NewNoSuchObject()
		}

		parentID = newParentFetchedDN.ID

		if !newParentFetchedDN.HasSub {
			// If the parent doesn't have any sub, need to insert tree entry first.
			// Also, need to lock the parent entry of the parent before it.
			newGrandParentDN := newParentDN.ParentDN()
			if newGrandParentDN != nil {
				_, err := r.FindDNByDNWithLock(tx, newParentDN.ParentDN(), true)
				if err != nil {
					return NewNoSuchObject()
				}
			}

			// Register as container
			err = r.insertTree(tx, newParentFetchedDN.ID)
			if err != nil {
				return err
			}
		}
	}

	newEntry := oldEntry.ModifyRDN(newDN)

	if oldRDN != nil {
		for _, attr := range oldRDN.Attributes {
			newEntry.Add(attr.TypeOrig, []string{attr.ValueOrig})
		}
	}

	dbEntry, err := mapper.ModifyEntryToDBEntry(tx, newEntry)
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(updateDNByIdStmt).Exec(map[string]interface{}{
		"id":           oldEntry.dbEntryID,
		"parent_id":    parentID,
		"new_rdn_norm": newDN.RDNNormStr(),
		"new_rdn_orig": newDN.RDNOrigStr(),
		"attrs_norm":   dbEntry.AttrsNorm,
		"attrs_orig":   dbEntry.AttrsOrig,
	})
	if err != nil {
		return xerrors.Errorf("Failed to update entry DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
	}

	if !oldParentDN.Equal(newParentDN) {
		// Reload the old parent entry
		oldParentFetchedDN, err := r.FindDNByDNWithLock(tx, oldParentDN, true)
		if err != nil {
			return NewNoSuchObject()
		}

		// Delete the tree entry if the old parent doesn't have any children now
		if !oldParentFetchedDN.HasSub {
			if err := r.deleteTreeByID(tx, oldParentFetchedDN.ID); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *Repository) updateRDN(tx *sqlx.Tx, oldDN, newDN *DN, oldRDN *RelativeDN, oldEntry *ModifyEntry) error {
	// Update the entry even if it's same RDN to update modifyTimestamp
	newEntry := oldEntry.ModifyRDN(newDN)

	if oldRDN != nil {
		for _, attr := range oldRDN.Attributes {
			newEntry.Add(attr.TypeOrig, []string{attr.ValueOrig})
		}
	}

	dbEntry, err := mapper.ModifyEntryToDBEntry(tx, newEntry)
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
