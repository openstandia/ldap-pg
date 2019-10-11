package main

import (
	"log"

	ldap "github.com/openstandia/ldapserver"
)

func handleDelete(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetDeleteRequest()
	dn, err := normalizeDN(string(r))
	if err != nil {
		log.Printf("warn: Invalid dn: %s err: %s", r, err)

		// TODO return correct error
		res := ldap.NewDeleteResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	log.Printf("info: Deleting entry: %s", dn.DN)

	tx := db.MustBegin()

	var id int64
	err = tx.Get(&id, "DELETE FROM ldap_entry WHERE dn = :dn RETURNING id", map[string]interface{}{"dn": dn.DN})

	if err != nil {
		log.Printf("info: Failed to delete entry: %#v", err)
		tx.Rollback()

		responseDeleteError(w, err)
		return
	}

	// TODO delete memberOf of entry which is fetched by member DN
	// TODO delete member of entry which is fetched by memberOf DN

	tx.Commit()

	log.Printf("info: Deleted. id: %d dn: %s", id, dn.DN)

	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func responseDeleteError(w ldap.ResponseWriter, err error) {
	if ldapErr, ok := err.(*LDAPError); ok {
		res := ldap.NewDeleteResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		w.Write(res)
	} else {
		log.Printf("error: %s", err)
		// TODO
		res := ldap.NewDeleteResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
