package main

import (
	"github.com/jmoiron/sqlx"
)

type MembershipSupport interface {
	addMembership(tx *sqlx.Tx, entry *Entry, dn *DN) error
	deleteMembership(tx *sqlx.Tx, entry *Entry, dn *DN) error
}

type MemberSupport interface {
	addMember(tx *sqlx.Tx, entry *Entry, dn *DN) error
	deleteMember(tx *sqlx.Tx, entry *Entry, dn *DN) error
}

type MembershipWithID struct {
}

func (a *MembershipWithID) addMembership(tx *sqlx.Tx, entry *Entry, dn *DN) error {

	return nil
}

func (a *MembershipWithID) deleteMembership(tx *sqlx.Tx, entry *Entry, dn *DN) error {

	return nil
}

// TODO configurable
var handler interface{} = MembershipWithID{}

func addAssociation(tx *sqlx.Tx, entry *Entry, dn *DN) error {
	if entry.HasAttr("member") {

	}

	var err error
	if t, ok := handler.(MembershipSupport); ok {
		err = t.addMembership(tx, entry, dn)
	}

	if t, ok := handler.(MemberSupport); ok {
		err = t.addMember(tx, entry, dn)
	}
	return err
}

func deleteAssociation(tx *sqlx.Tx, entry *Entry, dn *DN) error {
	var err error
	if t, ok := handler.(MembershipSupport); ok {
		err = t.deleteMembership(tx, entry, dn)
	}

	if t, ok := handler.(MemberSupport); ok {
		err = t.deleteMember(tx, entry, dn)
	}
	return err
}
