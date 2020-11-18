package main

import (
	"fmt"
	"log"

	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func (r *Repository) Insert(entry *AddEntry) (int64, error) {
	tx := r.db.MustBegin()
	return r.insertWithTx(tx, entry)
}

func (r *Repository) insertWithTx(tx *sqlx.Tx, entry *AddEntry) (int64, error) {
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

func (r *Repository) insertEntryAndTree(tx *sqlx.Tx, entry *AddEntry) (int64, int64, error) {
	if entry.DN().IsRoot() {
		return 0, 0, xerrors.Errorf("Invalid entry, it should not be root DN. DN: %v", entry.dn)
	}

	newID, parentId, err := r.insertEntry(tx, entry)
	if err != nil {
		return 0, 0, err
	}

	err = r.insertTree(tx, newID, parentId)
	if err != nil {
		return 0, 0, err
	}

	return newID, parentId, nil
}

func (r *Repository) insertEntry(tx *sqlx.Tx, entry *AddEntry) (int64, int64, error) {
	if entry.DN().IsRoot() {
		return 0, 0, xerrors.Errorf("Invalid entry, it should not be root DN. DN: %v", entry.dn)
	}

	dbEntry, err := mapper.AddEntryToDBEntry(tx, entry)
	if err != nil {
		return 0, 0, err
	}

	params := createFindTreePathByDNParams(entry.ParentDN())
	params["rdn_norm"] = entry.RDNNorm()
	params["rdn_orig"] = entry.RDNOrig()
	params["attrs_norm"] = dbEntry.AttrsNorm
	params["attrs_orig"] = dbEntry.AttrsOrig

	findParentDNByDN, err := createFindTreePathByDNSQL(entry.ParentDN())
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

	return id, parentId, nil
}

func (r *Repository) insertTree(tx *sqlx.Tx, newID, parentId int64) error {
	q := `
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
	params := map[string]interface{}{}
	params["id"] = parentId

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

	var id int64
	var path string
	if rows.Next() {
		err := rows.Scan(&id, &path)
		if err != nil {
			return xerrors.Errorf("Failed to scan. id: %d, err: %w", parentId, err)
		}
		log.Printf("debug: Inserted new tree entry. id: %d, path: %s", id, path)
	} else {
		log.Printf("debug: The tree entry already exists. id: %d", parentId)
	}

	return nil
}

func (r *Repository) insertRootEntry(tx *sqlx.Tx, entry *AddEntry) (int64, error) {
	if !entry.DN().IsRoot() {
		return 0, xerrors.Errorf("Invalid entry, it should be root DN. DN: %v", entry.dn)
	}

	dbEntry, err := mapper.AddEntryToDBEntry(tx, entry)
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

type nordNorm struct {
	ID     int64  `db:"id"`
	DNNorm string `db:"dn_norm"`
}

func collectNodeNormByParentID(tx *sqlx.Tx, parentID int64) ([]*nordNorm, error) {
	if parentID == ROOT_ID {
		return nil, xerrors.Errorf("Invalid parentID: %d", parentID)
	}

	var rows *sqlx.Rows
	var err error
	if tx != nil {
		rows, err = tx.NamedStmt(collectNodeNormByParentIDStmt).Queryx(map[string]interface{}{
			"parent_id": parentID,
		})
	} else {
		rows, err = collectNodeNormByParentIDStmt.Queryx(map[string]interface{}{
			"parent_id": parentID,
		})
	}
	if err != nil {
		return nil, xerrors.Errorf("Failed to fetch child ID by parentID: %s, err: %w", parentID, err)
	}
	defer rows.Close()

	list := []*nordNorm{}
	for rows.Next() {
		child := nordNorm{}
		rows.StructScan(&child)
		list = append(list, &child)
	}

	err = rows.Err()
	if err != nil {
		log.Printf("error: Search children error: %#v", err)
		return nil, err
	}

	return list, nil
}
