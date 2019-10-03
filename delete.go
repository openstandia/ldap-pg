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

	_, err = tx.NamedExec("DELETE FROM ldap_entry WHERE dn = :dn", map[string]interface{}{"dn": dn.DN})

	if err != nil {
		log.Printf("info: Failed to delete entry: %#v", err)
		tx.Rollback()

		res := ldap.NewDeleteResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	tx.Commit()

	log.Printf("info: Deleted dn: %s", dn.DN)

	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
