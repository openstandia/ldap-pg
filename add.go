package main

import (
	"log"

	ldap "github.com/openstandia/ldapserver"
)

func handleAdd(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAddRequest()
	log.Printf("info: Adding entry: %s", r.Entry())
	//attributes values

	dn, err := normalizeDN(string(r.Entry()))
	if err != nil {
		log.Printf("warn: Invalid DN: %s err: %s", r.Entry(), err)

		// TODO return correct code
		res := ldap.NewAddResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	entry, err := mapper.ToEntry(dn, r.Attributes())

	tx := db.MustBegin()

	id, err := insert(tx, entry)
	if err != nil {
		tx.Rollback()

		responseAddError(w, err)
		return
	}

	// Resolve member/memberOf
	err = addAssociation(tx, entry, dn)
	if err != nil {
		tx.Rollback()

		responseAddError(w, err)
		return
	}

	tx.Commit()

	log.Printf("Added. %d", id)

	res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	log.Printf("info: End Adding entry: %s", r.Entry())
}

func responseAddError(w ldap.ResponseWriter, err error) {
	if ldapErr, ok := err.(*LDAPError); ok {
		res := ldap.NewAddResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		w.Write(res)
	} else {
		log.Printf("error: %s", err)
		// TODO
		res := ldap.NewAddResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
