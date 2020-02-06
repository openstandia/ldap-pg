package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func (r Repository) DeleteByDN(dn *DN) error {
	tx := r.db.MustBegin()

	if dn.IsContainer() {
		has, err := r.hasChildren(tx, dn)
		if err != nil {
			tx.Rollback()
			return err
		}
		if has {
			tx.Rollback()
			return NewNotAllowedOnNonLeaf()
		}
	}

	delID, err := r.deleteByDN(tx, dn)
	if err != nil {
		tx.Rollback()
		return err
	}

	if dn.IsContainer() {
		err := r.deleteTreeNodeByID(tx, delID)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	err = r.deleteMemberByID(tx, delID)
	if err != nil {
		tx.Rollback()
		return err
	}

	err = tx.Commit()

	return err
}

func (r *Repository) hasChildren(tx *sqlx.Tx, dn *DN) (bool, error) {
	pq, params := r.CreateFindByDNQuery(dn, &FindOption{Lock: true})

	q := fmt.Sprintf(`SELECT count(e.id)
		FROM (%s) p
			LEFT JOIN ldap_entry e ON e.parent_id = p.id`, pq)

	stmt, err := tx.PrepareNamed(q)
	if err != nil {
		return true, xerrors.Errorf("Failed to prepare query: %s, params: %v, err: %w", q, params, err)
	}

	var count int
	err = stmt.Get(&count, params)
	if err != nil {
		return true, xerrors.Errorf("Failed to execute query: %s, params: %v, err: %w", q, params, err)
	}

	if count == 0 {
		return false, nil
	}

	return true, nil
}

func (r *Repository) deleteByDN(tx *sqlx.Tx, dn *DN) (int64, error) {
	// DELETE FROM ldap_entry e WHERE e.id IN (
	//     SELECT e0.id
	//     FROM ldap_tree e3
	//     INNER JOIN ldap_tree e2 ON e2.parent_id = e3.id
	//     INNER JOIN ldap_tree e1 ON e1.parent_id = e2.id
	//     INNER JOIN ldap_entry e0 ON e0.parent_id = e1.id
	//     WHERE e3.rdn_norm = 'ou=mycompany' AND e2.rdn_norm = 'ou=mysection' AND e1.rdn_norm = 'ou=mydept' AND e0.rdn_norm = 'cn=mygroup';
	// )

	// TODO check it has children (or add constraint in the table...)

	if dn.IsDC() {
		return r.deleteDC(tx)
	}

	size := len(dn.dnNorm)
	last := size - 1
	params := make(map[string]interface{}, size)

	var fetchStmt *sqlx.NamedStmt
	var err error

	join := make([]string, size)
	where := make([]string, size)

	for i := last; i >= 0; i-- {
		if i == last {
			join[last-i] = fmt.Sprintf("ldap_tree e%d", i)
		} else if i > 0 {
			join[last-i] = fmt.Sprintf("INNER JOIN ldap_tree e%d ON e%d.parent_id = e%d.id", i, i, i+1)
		} else {
			join[last-i] = "INNER JOIN ldap_entry e0 ON e0.parent_id = e1.id"
		}
		where[last-i] = fmt.Sprintf("e%d.rdn_norm = :rdn_norm_%d", i, i)

		params[fmt.Sprintf("rdn_norm_%d", i)] = dn.dnNorm[i]
	}

	q := fmt.Sprintf(`DELETE FROM ldap_entry e WHERE e.id IN 
			(
				SELECT e0.id
					FROM %s
					WHERE %s
			) RETURNING e.id`,
		strings.Join(join, " "), strings.Join(where, " AND "))

	log.Printf("debug: deleteByDN query: %s, params: %v", q, params)

	fetchStmt, err = tx.PrepareNamed(q)
	if err != nil {
		return 0, xerrors.Errorf("Failed to prepare deleteByDN query. query: %s, err: %w", q, err)
	}

	var delID int64
	if tx != nil {
		err = tx.NamedStmt(fetchStmt).Get(&delID, params)
	} else {
		err = fetchStmt.Get(&delID, params)
	}
	if err != nil {
		if isNoResult(err) {
			return 0, NewNoSuchObject()
		}
		return 0, xerrors.Errorf("Failed to exec deleteByDN query. query: %s, params: %v, err: %w",
			fetchStmt.QueryString, fetchStmt.Params, err)
	}

	if delID == 0 {
		return 0, NewNoSuchObject()
	}

	return delID, nil
}

func (r *Repository) deleteDC(tx *sqlx.Tx) (int64, error) {
	// TODO check it has children (or add constraint in the table...)
	var id int64
	err := tx.NamedStmt(deleteDCStmt).Get(&id, map[string]interface{}{})
	if err != nil {
		if isNoResult(err) {
			return 0, NewNoSuchObject()
		}
		return 0, xerrors.Errorf("Failed to delete DC entry. err: %w", err)
	}
	if id == 0 {
		return 0, NewNoSuchObject()
	}

	return id, nil
}

func (r *Repository) deleteTreeNodeByID(tx *sqlx.Tx, id int64) error {
	var delID int64 = -1
	err := tx.NamedStmt(deleteTreeNodeByIDStmt).Get(&delID, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		if isNoResult(err) {
			return NewNoSuchObject()
		}
		return xerrors.Errorf("Failed to delete tree node. id: %d, err: %w", id, err)
	}
	if delID == 0 {
		return NewNoSuchObject()
	}

	return nil
}

func (r *Repository) deleteMemberByID(tx *sqlx.Tx, id int64) error {
	var delID int64 = -1
	err := tx.NamedStmt(deleteMemberByIDStmt).Get(&delID, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		if isNoResult(err) {
			// Ignore
			return nil
		}
		return xerrors.Errorf("Failed to delete member. id: %d, err: %w", id, err)
	}
	if delID == 0 {
		// Ignore
		return nil
	}

	return nil
}
