package main

import (
	"fmt"
	"log"
	"strconv"
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

	if oldEntry != nil {
		// TODO move to schema
		memberAttrs := []string{"member", "uniqueMember"}
		for _, ma := range memberAttrs {
			diff := calcDiffAttr(oldEntry, newEntry, ma)

			err := r.addMembers(tx, dbEntry.ID, ma, diff.add)
			if err != nil {
				return err
			}

			err = r.deleteMembers(tx, dbEntry.ID, ma, diff.del)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *Repository) addMembers(tx *sqlx.Tx, id int64, attrNameNorm string, dnNorms []string) error {
	nodeNormCache, err := collectAllNodeNorm()
	if err != nil {
		return err
	}

	where := make([]string, len(dnNorms))
	params := make(map[string]interface{}, len(dnNorms)*2+2)
	params["mamber_id"] = id
	params["attr_name_norm"] = attrNameNorm

	for i, dnNorm := range dnNorms {
		dn, err := r.server.NormalizeDN(dnNorm)
		if err != nil {
			return NewInvalidDNSyntax()
		}

		parentID, ok := nodeNormCache[dn.ParentDN().DNNormStr()]
		if !ok {
			return NewInvalidDNSyntax()
		}

		key1 := "parent_id_" + strconv.Itoa(i)
		key2 := "rdn_norm_" + strconv.Itoa(i)

		where[i] = fmt.Sprintf("(parent_id = :%s AND rdn_norm = :%s)", key1, key2)
		params[key1] = parentID
		params[key2] = dn.RDNNormStr()
	}

	q := fmt.Sprintf(`INSERT INTO ldap_member (member_id, attr_name_norm, member_of_id)
		SELECT %d::::BIGINT, '%s', id FROM ldap_entry WHERE %s`, strings.Join(where, " AND "))

	_, err = tx.NamedExec(q, params)
	if err != nil {
		return xerrors.Errorf("Failed to add member. id: %d, attr: %s, dnNorms: %v, err: %w", id, attrNameNorm, dnNorms, err)
	}
	return nil
}

func (r *Repository) deleteMembers(tx *sqlx.Tx, id int64, attrNameNorm string, dnNorms []string) error {
	nodeNormCache, err := collectAllNodeNorm()
	if err != nil {
		return err
	}

	where := make([]string, len(dnNorms))
	params := make(map[string]interface{}, len(dnNorms)*2+2)
	params["mamber_id"] = id
	params["attr_name_norm"] = attrNameNorm

	for i, dnNorm := range dnNorms {
		dn, err := r.server.NormalizeDN(dnNorm)
		if err != nil {
			return NewInvalidDNSyntax()
		}

		parentID, ok := nodeNormCache[dn.ParentDN().DNNormStr()]
		if !ok {
			return NewInvalidDNSyntax()
		}

		key1 := "parent_id_" + strconv.Itoa(i)
		key2 := "rdn_norm_" + strconv.Itoa(i)

		where[i] = fmt.Sprintf("(parent_id = :%s AND rdn_norm = :%s)", key1, key2)
		params[key1] = parentID
		params[key2] = dn.RDNNormStr()
	}

	q := fmt.Sprintf(`DELETE FROM ldap_member WHERE member_id = :member_id AND attr_name_norm = :attr_name_norm AND member_of_id IN (
		SELECT id FROM ldap_entry
			WHERE %s
	)`, strings.Join(where, " AND "))

	_, err = tx.NamedExec(q, params)
	if err != nil {
		return xerrors.Errorf("Failed to delete member. id: %d, attr: %s, dnNorms: %v, err: %w", id, attrNameNorm, dnNorms, err)
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

func (r *Repository) UpdateDN(oldDN, newDN *DN) error {
	tx := r.db.MustBegin()
	err := r.updateDN(tx, oldDN, newDN)
	if err != nil {
		tx.Rollback()
		return err
	}

	err = tx.Commit()

	return err
}

func (r *Repository) updateDN(tx *sqlx.Tx, oldDN, newDN *DN) error {
	oldEntry, err := r.FindByDNWithLock(tx, oldDN)
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
		return xerrors.Errorf("Failed to update entry DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
	}

	return nil
}
