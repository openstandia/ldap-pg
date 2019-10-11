package main

import (
	"database/sql"
	"fmt"
	"log"

	ldap "github.com/openstandia/ldapserver"
)

func handleModify(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyRequest()
	dn, err := normalizeDN(string(r.Object()))

	if err != nil {
		log.Printf("warn: Invalid dn: %s err: %s", r.Object(), err)

		// TODO return correct error
		res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	log.Printf("info: Modify entry: %s", dn.DN)

	// if err != nil {
	// 	log.Printf("warn: Invalid DN format for modify dn=%s", dn)
	// 	res := ldap.NewModifyResponse(ldap.LDAPResultNoSuchObject)
	// 	w.Write(res)
	// 	return
	// }

	tx := db.MustBegin()

	entry, err := findByDNWithLock(tx, dn)
	if err != nil {
		tx.Rollback()
		if err == sql.ErrNoRows {
			responseModifyError(w, NewNoSuchObject())
			return
		} else {
			responseModifyError(w, fmt.Errorf("Failed to fetch the entry. dn: %s err: %#v", dn.DN, err))
			return
		}
	}

	// TODO refactoring
	// deleteMembers := []interface{}{}

	for _, change := range r.Changes() {
		modification := change.Modification()
		attrName := string(modification.Type_())

		log.Printf("Modify operation: %d attribute: %s", change.Operation(), modification.Type_())

		var values []string
		for _, attributeValue := range modification.Vals() {
			values = append(values, string(attributeValue))
			log.Printf("--> value: %s", attributeValue)
		}

		var err error

		switch change.Operation() {
		case ldap.ModifyRequestChangeOperationAdd:
			err = entry.AddAttrs(attrName, values)

		case ldap.ModifyRequestChangeOperationDelete:
			err = entry.DeleteAttrs(attrName, values)

		case ldap.ModifyRequestChangeOperationReplace:
			err = entry.ReplaceAttrs(attrName, values)
		}

		if err != nil {
			tx.Rollback()

			log.Printf("warn: Failed to modify. dn: %s err: %s", dn.DN, err)
			responseModifyError(w, err)
			return
		}
	}

	log.Printf("Update entry with %#v", entry)

	err = update(tx, entry)

	if err != nil {
		tx.Rollback()

		// TODO error code
		responseModifyError(w, fmt.Errorf("Failed to modify the entry. dn: %s entry: %#v err: %#v", dn.DN, entry, err))
		return
	}
	// Resolve memberOf
	// TODO error handling
	// _ = updateAssociation(tx, dn, jsonMap)
	// _ = updateOwnerAssociation(tx, dn, jsonMap)

	// Clean deleted Members
	// for _, m := range deleteMembers {
	// 	var memberDN *DN
	// 	var err error
	// 	if memberDN, err = normalizeDN(m.(string)); err != nil {
	// 		log.Printf("error: Invalid member, can't normalize dn: %#v", err)
	// 		continue
	// 	}
	//
	// 	entry, err := findByDNWithLock(tx, memberDN)
	//
	// 	if err != nil {
	// 		log.Printf("error: Search member memberDN: %s error: %#v", memberDN.DN, err)
	// 		continue
	// 	}
	//
	// 	log.Printf("deleting memberOf: %+v deleteDN: %s", entry.Attrs, dn.DN)
	//
	// 	deleteMemberOf(entry, dn)
	//
	// 	_, err = tx.NamedExec(`UPDATE ldap_entry SET attrs = :attrs WHERE id = :id`, map[string]interface{}{
	// 		"id":    entry.Id,
	// 		"attrs": entry.Attrs,
	// 	})
	// 	if err != nil {
	// 		log.Printf("error: Faild to modify member dn: %s err: %#v", entry.Dn, err)
	// 		continue
	// 	}
	// }

	tx.Commit()

	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func responseModifyError(w ldap.ResponseWriter, err error) {
	if ldapErr, ok := err.(*LDAPError); ok {
		res := ldap.NewModifyResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		w.Write(res)
	} else {
		log.Printf("error: %s", err)
		// TODO
		res := ldap.NewModifyResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
