package main

import (
	"log"
	"time"

	"github.com/google/uuid"
	ldap "github.com/openstandia/ldapserver"
)

func handleAdd(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAddRequest()
	log.Printf("info: Adding entry: %s", r.Entry())
	//attributes values

	dn, err := normalizeDN(string(r.Entry()))
	if err != nil {
		log.Printf("warn: Invalid DN: %s err: %s", r.Entry(), err)

		responseAddError(w, err)
		return
	}

	if !requiredAuthz(m, "add", dn) {
		responseAddError(w, NewInsufficientAccess())
		return
	}

	addEntry, err := mapper.LDAPMessageToAddEntry(dn, r.Attributes())
	if err != nil {
		responseAddError(w, err)
		return
	}

	// TODO strict mode
	if _, ok := addEntry.GetAttrNorm("entryUUID"); !ok {
		uuid, _ := uuid.NewRandom()
		addEntry.Add("entryUUID", []string{uuid.String()})
	}
	now := time.Now()
	if _, ok := addEntry.GetAttrNorm("createTimestamp"); !ok {
		addEntry.Add("createTimestamp", []string{now.Format(TIMESTAMP_FORMAT)})
	}
	if _, ok := addEntry.GetAttrNorm("modifyTimestamp"); !ok {
		addEntry.Add("modifyTimestamp", []string{now.Format(TIMESTAMP_FORMAT)})
	}

	tx := db.MustBegin()

	id, err := insert(tx, addEntry)
	if err != nil {
		tx.Rollback()

		responseAddError(w, err)
		return
	}

	tx.Commit()

	log.Printf("Added. Id: %d", id)

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
		log.Printf("error: %+v", err)
		// TODO
		res := ldap.NewAddResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
