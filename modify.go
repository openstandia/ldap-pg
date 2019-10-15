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

	tx := db.MustBegin()

	oldEntry, err := findByDNWithLock(tx, dn)
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

	newEntry := oldEntry.Clone()

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
			err = newEntry.AddAttrs(attrName, values)

		case ldap.ModifyRequestChangeOperationDelete:
			err = newEntry.DeleteAttrs(attrName, values)

		case ldap.ModifyRequestChangeOperationReplace:
			err = newEntry.ReplaceAttrs(attrName, values)
		}

		if err != nil {
			tx.Rollback()

			log.Printf("warn: Failed to modify. dn: %s err: %s", dn.DN, err)
			responseModifyError(w, err)
			return
		}
	}

	log.Printf("Update entry. oldEntry: %#v newEntry: %#v", oldEntry, newEntry)

	err = update(tx, newEntry)

	if err != nil {
		tx.Rollback()

		// TODO error code
		responseModifyError(w, fmt.Errorf("Failed to modify the entry. dn: %s entry: %#v err: %#v", dn.DN, newEntry, err))
		return
	}

	// resolve member
	err = modifyAssociation(tx, oldEntry, newEntry)
	if err != nil {
		tx.Rollback()

		responseModifyError(w, err)
		return
	}

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
