package main

import (
	"encoding/json"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx/types"
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

	entryUUID, _ := uuid.NewRandom()
	createTimestamp := time.Now()
	modifyTimestamp := createTimestamp

	jsonMap := map[string]interface{}{}

	for _, attr := range r.Attributes() {
		k := attr.Type_()
		attrName := string(k)

		s, ok := schemaMap.Get(attrName)
		if !ok {
			// TODO check classObject and return error response
			log.Printf("error: Invalid attribute name %s", k)
			continue
		}

		var err error
		if s.Name == "entryUUID" {
			entryUUID, err = uuid.Parse(string(attr.Vals()[0]))
			if err != nil {
				log.Printf("warn: Invalid entryUUID %s", attr.Vals()[0])

				// TODO return correct code
				res := ldap.NewAddResponse(ldap.LDAPResultOperationsError)
				w.Write(res)
				return
			}
			continue
		}
		if s.Name == "createTimestamp" {
			createTimestamp, err = time.Parse(TIMESTAMP_FORMAT, string(attr.Vals()[0]))
			if err != nil {
				log.Printf("warn: Invalid createTimestamp %s, err: %s", attr.Vals()[0], err)

				// TODO return correct code
				res := ldap.NewAddResponse(ldap.LDAPResultOperationsError)
				w.Write(res)
				return
			}
			continue
		}
		if s.Name == "modifyTimestamp" {
			modifyTimestamp, err = time.Parse(TIMESTAMP_FORMAT, string(attr.Vals()[0]))
			if err != nil {
				log.Printf("warn: Invalid modifyTimestamp %s, err: %s", attr.Vals()[0], err)

				// TODO return correct code
				res := ldap.NewAddResponse(ldap.LDAPResultOperationsError)
				w.Write(res)
				return
			}
			continue
		}

		mapAttributeValue(s, attr, jsonMap)
	}

	attrs, err := json.Marshal(jsonMap)
	if err != nil {
		// TODO return correct error
		log.Printf("error: Failed to marshal entry: %#v", err)
		res := ldap.NewAddResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	jsonText := types.JSONText(string(attrs))

	tx := db.MustBegin()

	_, err = tx.NamedExec(`INSERT INTO ldap_entry (dn, path, uuid, created, updated, attrs)
VALUES (:dn, :path, :uuid, :created, :updated, :attrs)`, map[string]interface{}{
		"dn":      dn.DN,
		"path":    dn.ReverseParentDN,
		"uuid":    entryUUID,
		"created": createTimestamp,
		"updated": modifyTimestamp,
		"attrs":   jsonText,
	})
	if err != nil {
		log.Printf("Failed to add entry: %v", err)
		tx.Rollback()

		res := ldap.NewAddResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	// Resolve memberOf
	// TODO error handling
	_ = updateAssociation(tx, dn, jsonMap)

	tx.Commit()

	res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	log.Printf("info: End Adding entry: %s", r.Entry())
}
