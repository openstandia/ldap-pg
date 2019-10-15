package main

import (
	"log"

	"github.com/jmoiron/sqlx"
)

type MembershipSupport interface {
	updateMembership(tx *sqlx.Tx, oldEntry, newEntry *Entry) error
	deleteMembership(tx *sqlx.Tx, dn *DN) error
	rename(tx *sqlx.Tx, oldDN, newDN *DN) error
}

type MemberSupport interface {
	updateMember(tx *sqlx.Tx, oldEntry, newEntry *Entry) error
	deleteMember(tx *sqlx.Tx, dn *DN) error
	rename(tx *sqlx.Tx, oldDN, newDN *DN) error
}

type Membership struct {
}

func (a *Membership) addMembership(tx *sqlx.Tx, entry *Entry, dn *DN) error {

	return nil
}

func (a *Membership) deleteMembership(tx *sqlx.Tx, dn *DN) error {

	return nil
}

func (a *Membership) rename(tx *sqlx.Tx, oldDN *DN, newDN *DN) error {

	return nil
}

type Member struct {
}

func (a *Member) updateMember(tx *sqlx.Tx, oldEntry, newEntry *Entry) error {
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

func (a *Member) deleteMember(tx *sqlx.Tx, dn *DN) error {
	// 1. Delete member in the object entry
	// 2. Delete memberOf in the subject entry

	return nil
}

func (a *Member) rename(tx *sqlx.Tx, oldDN, newDN *DN) error {
	// 1. Rename member in the parent entry
	// 2. Rename memberOf in the child entry

	return nil
}

// TODO configurable
var handler interface{} = &Member{}

func addAssociation(tx *sqlx.Tx, newEntry *Entry) error {
	var err error
	if t, ok := handler.(MembershipSupport); ok {
		err = t.updateMembership(tx, nil, newEntry)
	}

	if t, ok := handler.(MemberSupport); ok {
		err = t.updateMember(tx, nil, newEntry)
	}
	return err
}

func modifyAssociation(tx *sqlx.Tx, oldEntry, newEntry *Entry) error {
	var err error
	if t, ok := handler.(MembershipSupport); ok {
		err = t.updateMembership(tx, oldEntry, newEntry)
	}

	if t, ok := handler.(MemberSupport); ok {
		err = t.updateMember(tx, oldEntry, newEntry)
	}
	return err
}

func deleteAssociation(tx *sqlx.Tx, dn *DN) error {
	var err error
	if t, ok := handler.(MembershipSupport); ok {
		err = t.deleteMembership(tx, dn)
	}

	if t, ok := handler.(MemberSupport); ok {
		err = t.deleteMember(tx, dn)
	}
	return err
}

func renameAssociation(tx *sqlx.Tx, oldDN *DN, newDN *DN) error {
	var err error
	if t, ok := handler.(MembershipSupport); ok {
		err = t.rename(tx, oldDN, newDN)
	}

	if t, ok := handler.(MemberSupport); ok {
		err = t.rename(tx, oldDN, newDN)
	}
	return err
}
