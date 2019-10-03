package main

import (
	"encoding/json"
	"log"

	"github.com/jmoiron/sqlx/types"
	ldap "github.com/openstandia/ldapserver"
)

func handleModifyDN(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyDNRequest()
	dn, err := normalizeDN(string(r.Entry()))

	if err != nil {
		log.Printf("warn: Invalid dn: %s err: %s", r.Entry(), err)

		// TODO return correct error
		res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	log.Printf("info: Modify entry: %s", dn.DN)

	tx := db.MustBegin()

	entry, err := findByDN(tx, dn)
	if err != nil {
		// TODO return correct error
		log.Printf("info: Failed to fetch the entry. dn: %s err: %#v", dn.DN, err)
		res := ldap.NewModifyDNResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	err = dn.Modify(string(r.NewRDN()))
	if err != nil {
		// TODO return correct error
		log.Printf("info: Invalid newrdn. dn: %s newrdn: %s err: %#v", dn.DN, r.NewRDN, err)
		res := ldap.NewModifyDNResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	jsonMap := map[string]interface{}{}
	entry.Attrs.Unmarshal(&jsonMap)

	newAttrs, err := json.Marshal(jsonMap)
	if err != nil {
		// TODO return correct error
		log.Printf("error: Failed to marshal entry: %#v", err)
		res := ldap.NewModifyDNResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	if r.DeleteOldRDN() {
		log.Printf("DeleteOldRDN")

	} else {
		log.Printf("Not DeleteOldRDN")

	}

	if r.NewSuperior() != nil {
		log.Printf("NewSuperior: %s", *r.NewSuperior())

	}
	jsonText := types.JSONText(string(newAttrs))
	_, err = tx.NamedExec(`UPDATE ldap_entry SET updated = now(), dn = :newdn, path = :newpath, attrs = :attrs WHERE id = :id`, map[string]interface{}{
		"id":      entry.Id,
		"newdn":   dn.DN,
		"newpath": dn.ReverseParentDN,
		"attrs":   jsonText,
	})

	if err != nil {
		tx.Rollback()

		log.Printf("warn: Failed to modify dn: %s err: %s", dn.DN, err)
		res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	tx.Commit()

	res := ldap.NewModifyDNResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
