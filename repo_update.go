package main

import (
	"log"

	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func (r *Repository) Update(tx *sqlx.Tx, oldEntry, newEntry *ModifyEntry) error {
	if newEntry.dbEntryID == 0 {
		return xerrors.Errorf("Invalid dbEntryId for update DBEntry.")
	}

	dbEntry, _, err := mapper.ModifyEntryToDBEntry(tx, newEntry)
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
		log.Printf("debug: Failed to fetch the entry by DN: %v, err: %v", oldDN, err)
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

	newParentID := oldEntry.dbParentID
	var oldParentID int64 = -1

	if !oldParentDN.Equal(newParentDN) {
		// Lock the old/new parent entry
		newParentFetchedDN, err := r.FindDNByDNWithLock(tx, newParentDN, true)
		if err != nil {
			log.Printf("debug: Failed to fetch the new parent by DN: %s, err: %v", newParentDN.DNOrigStr(), err)
			return NewNoSuchObject()
		}
		oldParentFetchedDN, err := r.FindDNByDNWithLock(tx, oldParentDN, true)
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
				_, err := r.FindDNByDNWithLock(tx, newParentDN.ParentDN(), true)
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
	dbEntry, _, err := mapper.ModifyEntryToDBEntry(tx, newEntry)
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

func (r *Repository) updateRDN(tx *sqlx.Tx, oldDN, newDN *DN, oldRDN *RelativeDN, oldEntry *ModifyEntry) error {
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
	dbEntry, _, err := mapper.ModifyEntryToDBEntry(tx, newEntry)
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

func (r *Repository) moveTree(tx *sqlx.Tx, sourcePath, newParentPath string) error {
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
