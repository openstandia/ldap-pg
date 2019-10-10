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

	entry, err := findByDN(tx, dn)
	if err != nil {
		tx.Rollback()

		// TODO return correct error
		log.Printf("info: Failed to fetch the entry. dn: %s err: %#v", dn.DN, err)
		res := ldap.NewDeleteResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	jsonMap := map[string]interface{}{}
	entry.Attrs.Unmarshal(&jsonMap)

	_, err = tx.NamedExec("DELETE FROM ldap_entry WHERE dn = :dn", map[string]interface{}{"dn": dn.DN})

	if err != nil {
		log.Printf("info: Failed to delete entry: %#v", err)
		tx.Rollback()

		res := ldap.NewDeleteResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	// TODO delete memberOf of entry which is fetched by member DN
	// TODO delete member of entry which is fetched by memberOf DN

	tx.Commit()

	log.Printf("info: Deleted dn: %s", dn.DN)

	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
