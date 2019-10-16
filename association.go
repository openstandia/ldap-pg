package main

import (
	"log"

	"github.com/jmoiron/sqlx"
)

type RenameSupport interface {
	renameMember(tx *sqlx.Tx, oldDN, newDN *DN, callback func() error) error
}

type DeleteSupport interface {
	deleteMember(tx *sqlx.Tx, dn *DN, callback func() error) error
}

type OneWaySupport interface {
	RenameSupport
	DeleteSupport
}

type TwoWaySupport interface {
	RenameSupport
	DeleteSupport
	updateMember(tx *sqlx.Tx, oldEntry, newEntry *Entry) error
	updateMembership(tx *sqlx.Tx, oldEntry, newEntry *Entry) error
}

type OneWay struct {
}

func (a *OneWay) renameMember(tx *sqlx.Tx, oldDN, newDN *DN, callback func() error) error {
	_, err := tx.NamedStmt(replaceMemberByMemberStmt).Queryx(map[string]interface{}{
		"oldMemberDN": oldDN.DN,
		"newMemberDN": newDN.DN,
		"dn":          oldDN.DN,
	})
	if err != nil {
		return err
	}

	err = callback()
	if err != nil {
		return err
	}

	return nil
}

func (a *OneWay) deleteMember(tx *sqlx.Tx, dn *DN, callback func() error) error {
	_, err := tx.NamedStmt(removeMemberByMemberStmt).Exec(map[string]interface{}{
		"memberDN": dn.DN,
		"dn":       dn.DN,
	})
	if err != nil {
		return err
	}

	err = callback()
	if err != nil {
		return err
	}

	return nil
}

func (a *OneWay) updateMember(tx *sqlx.Tx, oldEntry, newEntry *Entry) error {
	// Do nothing
	return nil
}

func (a *OneWay) updateMembership(tx *sqlx.Tx, oldEntry, newEntry *Entry) error {
	// Do nothing
	return nil
}

type TwoWay struct {
	OneWay
}

func (a *TwoWay) renameMember(tx *sqlx.Tx, oldDN, newDN *DN, callback func() error) error {
	_, err := tx.NamedStmt(replaceMemberByMemberStmt).Queryx(map[string]interface{}{
		"oldMemberDN": oldDN.DN,
		"newMemberDN": newDN.DN,
		"dn":          oldDN.DN,
	})
	if err != nil {
		return err
	}

	err = callback()
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(replaceMemberOfByMemberOfStmt).Queryx(map[string]interface{}{
		"oldMemberOfDN": oldDN.DN,
		"newMemberOfDN": newDN.DN,
		"dn":            oldDN.DN,
	})
	if err != nil {
		return err
	}
	return nil
}

func (a *TwoWay) deleteMember(tx *sqlx.Tx, dn *DN, callback func() error) error {
	_, err := tx.NamedStmt(removeMemberByMemberStmt).Exec(map[string]interface{}{
		"memberDN": dn.DN,
		"dn":       dn.DN,
	})
	if err != nil {
		return err
	}

	err = callback()
	if err != nil {
		return err
	}

	_, err = tx.NamedStmt(removeMemberOfByMemberOfStmt).Exec(map[string]interface{}{
		"memberOfDN": dn.DN,
		"dn":         dn.DN,
	})
	if err != nil {
		return err
	}
	return nil
}

func (a *TwoWay) updateMember(tx *sqlx.Tx, oldEntry, newEntry *Entry) error {
	// 1. Add member in the object entry
	// 2. Add memberOf in the subject entry

	diff := calcDiffAttr(oldEntry, newEntry, "member")

	log.Printf("Diff member: %#v", diff)
	log.Printf("oldEntry: %#v", oldEntry)

	for _, memberDN := range diff.add {
		err := addMemberOf(tx, memberDN, oldEntry.Dn)
		if err != nil {
			return err
		}
	}
	for _, memberDN := range diff.del {
		err := deleteMemberOf(tx, memberDN, oldEntry.Dn)
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *TwoWay) updateMembership(tx *sqlx.Tx, oldEntry, newEntry *Entry) error {
	// TODO
	return nil
}

// TODO configurable
var handler interface{} = &OneWay{}

func isSupportedFetchMemberOf() bool {
	_, ok := handler.(OneWaySupport)
	return ok
}

func renameAssociation(tx *sqlx.Tx, oldEntry, newEntry *DN, callback func() error) error {
	var err error
	if t, ok := handler.(RenameSupport); ok {
		err = t.renameMember(tx, oldEntry, newEntry, callback)
		if err != nil {
			return err
		}
	}
	return err
}

func deleteAssociation(tx *sqlx.Tx, dn *DN, callback func() error) error {
	var err error
	if t, ok := handler.(DeleteSupport); ok {
		err = t.deleteMember(tx, dn, callback)
		if err != nil {
			return err
		}
	} else {
		log.Printf("warn: Not supported DeleteSupport")
	}
	return err
}

func addAssociation(tx *sqlx.Tx, newEntry *Entry) error {
	return modifyAssociation(tx, nil, newEntry)
}

func modifyAssociation(tx *sqlx.Tx, oldEntry, newEntry *Entry) error {
	var err error
	if t, ok := handler.(TwoWaySupport); ok {
		if oldEntry.HasAttr("memberOf") || newEntry.HasAttr("memberOf") {
			err = t.updateMembership(tx, oldEntry, newEntry)
			if err != nil {
				return err
			}
		}
		if oldEntry.HasAttr("member") || newEntry.HasAttr("member") {
			err = t.updateMember(tx, oldEntry, newEntry)
		}
	}

	return err
}
