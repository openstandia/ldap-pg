package main

import (
	"log"

	ldap "github.com/openstandia/ldapserver"
)

func handleModifyDN(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyDNRequest()
	dn, err := normalizeDN(string(r.Entry()))

	if err != nil {
		log.Printf("warn: Invalid dn: %s err: %s", r.Entry(), err)

		// TODO return correct error
		responseModifyDNError(w, err)
		return
	}

	newDN, err := dn.Modify(string(r.NewRDN()))

	if err != nil {
		// TODO return correct error
		log.Printf("info: Invalid newrdn. dn: %s newrdn: %s err: %#v", dn.DNNorm, r.NewRDN(), err)
		responseModifyDNError(w, err)
		return
	}

	log.Printf("info: Modify entry: %s", dn.DNNorm)

	tx := db.MustBegin()

	// TODO impl
	if r.NewSuperior() != nil {
		log.Printf("error: Not implemented NewSuperior. value: %s", *r.NewSuperior())
	}

	// TODO impl
	if r.DeleteOldRDN() {
		log.Printf("DeleteOldRDN")
	} else {
		log.Printf("error: Not implemented DeleteOldRDN false")
	}

	err = updateDNWithAssociationWithLock(tx, dn, newDN)
	if err != nil {
		tx.Rollback()

		log.Printf("warn: Failed to modify dn: %s err: %s", dn.DNNorm, err)
		// TODO error code
		responseModifyDNError(w, err)
		return
	}

	tx.Commit()

	res := ldap.NewModifyDNResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func responseModifyDNError(w ldap.ResponseWriter, err error) {
	if ldapErr, ok := err.(*LDAPError); ok {
		res := ldap.NewModifyDNResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		w.Write(res)
	} else {
		log.Printf("error: %s", err)
		// TODO
		res := ldap.NewModifyDNResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
