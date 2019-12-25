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

func (r *Repository) UpdateDN(tx *sqlx.Tx, oldDN, newDN *DN) error {
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

		err = r.Update(tx, nil, modifyEntry)
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
