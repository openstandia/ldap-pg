package main

import (
	"strconv"

	"github.com/jmoiron/sqlx"
	"golang.org/x/xerrors"
)

func (r Repository) DeleteByDN(dn *DN) error {
	tx := r.db.MustBegin()

	// First, fetch the target entry with lock
	fetchedDN, err := r.FindDNByDNWithLock(tx, dn, true)
	if err != nil {
		rollback(tx)
		return err
	}

	// Not allowed error if the entry has children yet
	if fetchedDN.HasSub {
		rollback(tx)
		return NewNotAllowedOnNonLeaf()
	}

	// Delete entry
	delID, err := r.deleteByID(tx, fetchedDN.ID)
	if err != nil {
		rollback(tx)
		return err
	}

	// Delete tree entry if the parent doesn't have children
	hasSub, err := r.hasSub(tx, fetchedDN.ParentID)
	if err != nil {
		rollback(tx)
		return err
	}
	if !hasSub {
		if err := r.deleteTreeByID(tx, fetchedDN.ParentID); err != nil {
			rollback(tx)
			return err
		}
	}

	// Remove member and uniqueMember if the others have association for the target entry
	err = r.removeAssociationById(tx, delID)
	if err != nil {
		rollback(tx)
		return err
	}

	// Commit!
	err = tx.Commit()

	return err
}

func (r *Repository) hasSub(tx *sqlx.Tx, id int64) (bool, error) {
	var hasSub bool
	err := tx.NamedStmt(hasSubStmt).Get(&hasSub, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		return false, xerrors.Errorf("Failed to check existence. id: %d, err: %w", id, err)
	}

	return hasSub, nil
}

func (r *Repository) deleteByID(tx *sqlx.Tx, id int64) (int64, error) {
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

func (r *Repository) deleteTreeByID(tx *sqlx.Tx, id int64) error {
	var delID int64 = -1
	err := tx.NamedStmt(deleteTreeByIDStmt).Get(&delID, map[string]interface{}{
		"id": id,
	})
	if err != nil {
		if isNoResult(err) {
			return NewNoSuchObject()
		}
		return xerrors.Errorf("Failed to delete tree node. id: %d, err: %w", id, err)
	}

	// TODO need?
	if delID == -1 {
		return NewNoSuchObject()
	}

	return nil
}

func (r *Repository) removeAssociationById(tx *sqlx.Tx, id int64) error {
	if err := r.execRemoveAssociatio(tx, id, removeMemberByIDStmt, "member"); err != nil {
		return err
	}
	if err := r.execRemoveAssociatio(tx, id, removeUniqueMemberByIDStmt, "uniqueMember"); err != nil {
		return err
	}
	return nil
}

func (r *Repository) execRemoveAssociatio(tx *sqlx.Tx, id int64, stmt *sqlx.NamedStmt, attrName string) error {
	idStr := strconv.FormatInt(id, 10)

	var updatedID int64 = -1
	err := tx.NamedStmt(stmt).Get(&updatedID, map[string]interface{}{
		"cond_filter": `$ ? (@ != ` + idStr + `)`,
		"cond_where":  `$.` + attrName + ` == ` + idStr + ``,
	})
	if err != nil {
		if isNoResult(err) {
			// Ignore
			return nil
		}
		return xerrors.Errorf("Failed to delete association. query: %s, id: %d, err: %w", stmt.QueryString, id, err)
	}

	// TODO need?
	if updatedID == 0 {
		// Ignore
		return nil
	}

	return nil
}
