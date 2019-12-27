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
		"id":         dbEntry.ID,
		"updated":    dbEntry.Updated,
		"attrs_norm": dbEntry.AttrsNorm,
		"attrs_orig": dbEntry.AttrsOrig,
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
	if len(dnNorms) == 0 {
		return nil
	}

	nodeNormCache, err := collectAllNodeNorm()
	if err != nil {
		return err
	}

	where := make([]string, len(dnNorms))
	params := make(map[string]interface{}, len(dnNorms)*2+2)
	params["member_id"] = id
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
		SELECT :member_id ::::BIGINT, :attr_name_norm, id FROM ldap_entry WHERE %s`, strings.Join(where, " OR "))

	log.Printf("addMemberQuery: %s, params: %v", q, params)

	_, err = tx.NamedExec(q, params)
	if err != nil {
		return xerrors.Errorf("Failed to add member. id: %d, attr: %s, dnNorms: %v, err: %w", id, attrNameNorm, dnNorms, err)
	}
	return nil
}

func (r *Repository) deleteMembers(tx *sqlx.Tx, id int64, attrNameNorm string, dnNorms []string) error {
	if len(dnNorms) == 0 {
		return nil
	}

	nodeNormCache, err := collectAllNodeNorm()
	if err != nil {
		return err
	}

	where := make([]string, len(dnNorms))
	params := make(map[string]interface{}, len(dnNorms)*2+2)
	params["member_id"] = id
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
	)`, strings.Join(where, " OR "))

	log.Printf("deleteMemberQuery: %s, params: %v", q, params)

	_, err = tx.NamedExec(q, params)
	if err != nil {
		return xerrors.Errorf("Failed to delete member. id: %d, attr: %s, dnNorms: %v, err: %w", id, attrNameNorm, dnNorms, err)
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
	oldEntry, err := r.FindByDNWithLock(tx, oldDN)
	if err != nil {
		return NewNoSuchObject()
	}

	parentID := oldEntry.dbParentID
	if !oldDN.ParentDN().Equal(newDN.ParentDN()) {
		p, err := r.FindByDNWithLock(tx, newDN.ParentDN())
		if err != nil {
			return NewNoSuchObject()
		}
		parentID = p.dbEntryId
	}

	newEntry := oldEntry.ModifyRDN(newDN)
	dbEntry, err := mapper.ModifyEntryToDBEntry(newEntry)
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(updateDNByIdStmt).Exec(map[string]interface{}{
		"id":           oldEntry.dbEntryId,
		"parent_id":    parentID,
		"updated":      dbEntry.Updated,
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
		_, err = r.Insert(add)
		if err != nil {
			return err
		}
	}

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			log.Printf("warn: Failed to update entry DN because of already exists. oldDN: %s newDN: %s err: %v", oldDN.DNNormStr(), newDN.DNNormStr(), err)
			return NewAlreadyExists()
		}
		return xerrors.Errorf("Failed to update entry DN. oldDN: %s, newDN: %s, err: %w", oldDN.DNNormStr(), newDN.DNNormStr(), err)
	}

	return nil
}
