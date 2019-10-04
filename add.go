package main

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
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

	// Resolve memberOf
	resolveMemberOf(tx, dn, jsonMap)

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

	tx.Commit()

	res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	log.Printf("info: End Adding entry: %s", r.Entry())
}

func resolveMemberOf(tx *sqlx.Tx, ownerDN *DN, jsonMap map[string]interface{}) {
	log.Printf("resolveMemberOf dn: %s", ownerDN)
	if members, ok := jsonMap["member"]; ok {
		log.Printf("members %#v", members)
		if marr, ok := members.([]interface{}); ok {
			for _, mem := range marr {
				log.Printf("memberDN %#v", mem)

				var memberDN *DN
				var err error
				if memDN, ok := mem.(string); ok {
					if memberDN, err = normalizeDN(memDN); err != nil {
						log.Printf("error: Invalid member, can't normalize dn: %#v", err)
						continue
					}
				} else {
					log.Printf("error: Invalid member, not string dn: %#v", err)
					continue
				}

				entry, err := findByDN(tx, memberDN)

				if err != nil {
					log.Printf("error: Search member memberDN: %s error: %#v", memberDN.DN, err)
					continue
				}

				err = mergeMemberOf(entry, ownerDN)
				if err != nil {
					log.Printf("error: Merge memberOf error: %#v", err)
					continue
				}

				log.Printf("merged memberOf: %+v", entry.Attrs)

				_, err = tx.NamedExec(`UPDATE ldap_entry SET attrs = :attrs WHERE id = :id`, map[string]interface{}{
					"id":    entry.Id,
					"attrs": entry.Attrs,
				})
				if err != nil {
					log.Printf("error: Faild to modify memberOf dn: %s err: %#v", entry.Dn, err)
					continue
				}
			}
		}
	}
}

func mergeMemberOf(entry *Entry, ownerDN *DN) error {
	jsonMap := map[string]interface{}{}
	entry.Attrs.Unmarshal(&jsonMap)

	if mos, ok := jsonMap["memberOf"]; ok {
		if mosarr, ok := mos.([]interface{}); ok {
			found := false
			for _, mos := range mosarr {
				if memberOf, ok := mos.(string); ok {
					if strings.ToLower(memberOf) == strings.ToLower(ownerDN.DN) {
						found = true
						break
					}
				}
			}
			if !found {
				mosarr = append(mosarr, ownerDN.DN)
			}
		}
	} else {
		// Nothing, add memberOf
		jsonMap["memberOf"] = []string{ownerDN.DN}
	}

	attrs, err := json.Marshal(jsonMap)

	if err != nil {
		return err
	}

	jsonText := types.JSONText(string(attrs))
	entry.Attrs = jsonText

	return nil
}
