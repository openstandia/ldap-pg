package main

import (
	"encoding/json"
	"log"

	"github.com/jmoiron/sqlx/types"
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

	entry, err := findByDN(tx, dn)
	if err != nil {
		tx.Rollback()

		// TODO return correct error
		log.Printf("info: Failed to fetch the entry. dn: %s err: %#v", dn.DN, err)
		res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	jsonMap := map[string]interface{}{}
	entry.Attrs.Unmarshal(&jsonMap)

	// TODO refactoring
	deleteMembers := []interface{}{}

	for _, change := range r.Changes() {
		modification := change.Modification()
		attrName := string(modification.Type_())

		s, ok := schemaMap.Get(attrName)
		if !ok {
			tx.Rollback()

			// TODO return correct error code
			log.Printf("warn: Failed to modify because of no schema, dn=%s", dn.DN)
			res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
			w.Write(res)
			return
		}

		var operationString string
		switch change.Operation() {
		case ldap.ModifyRequestChangeOperationAdd:
			operationString = "Add"

			var values []interface{}
			for _, attributeValue := range modification.Vals() {
				values = append(values, string(attributeValue))
			}

			if s.SingleValue {
				if len(values) > 1 {
					tx.Rollback()

					// TODO return correct error code
					log.Printf("warn: Failed to modify because of adding multiple values to single-value attribute dn=%s ", dn.DN)
					res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
					w.Write(res)
					return
				}
				// TODO override ok?
				jsonMap[s.Name] = values[0]
			} else {
				err := mergeMultipleValues(s, values, jsonMap)

				if lerr, ok := err.(*LDAPError); ok {
					tx.Rollback()

					log.Printf("warn: Failed to modify because of invalid modify/add data. dn: %s attrName: %s value: %#v", dn.DN, s.Name, jsonMap[s.Name])

					res := ldap.NewModifyResponse(lerr.Code)
					res.SetDiagnosticMessage(lerr.Msg)
					w.Write(res)
					return
				}
			}

		case ldap.ModifyRequestChangeOperationDelete:
			operationString = "Delete"

			if len(modification.Vals()) == 0 {
				// TODO
				if s.Name == "member" {
					deleteMembers = append(deleteMembers, jsonMap["member"].([]interface{})...)
					log.Printf("DeleteAll: deleteMembers: %v", deleteMembers)
				}
				delete(jsonMap, s.Name)
			} else {
				delVals := s.NewSchemaValueMap(len(modification.Vals()))
				for _, attributeValue := range modification.Vals() {
					log.Printf("attributeValue: %s", attributeValue)
					delVals.Put(string(attributeValue))
				}

				if s.SingleValue {
					// TODO test multiple delVals against single-value
					if cur, ok := jsonMap[s.Name].(string); ok {
						if delVals.Has(cur) {
							delete(jsonMap, s.Name)
						}
					} else {
						tx.Rollback()

						// TODO return correct error code
						log.Printf("error: Failed to modify because of invalid schema. Need to be single string value. dn: %s attrName: %s value: %#v", dn.DN, s.Name, jsonMap[s.Name])

						res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
						w.Write(res)
						return
					}
				} else {
					if cur, ok := jsonMap[s.Name].([]interface{}); ok {
						newVals := []string{}
						for _, v := range cur {
							if vv, ok := v.(string); ok {
								if !delVals.Has(vv) {
									newVals = append(newVals, vv)
								} else {
									if s.Name == "member" {
										deleteMembers = append(deleteMembers, vv)
										log.Printf("DeleteOne: deleteMembers: %v", deleteMembers)
									}
								}
							} else {
								tx.Rollback()

								// TODO return correct error code
								log.Printf("error: Failed to modify because of invalid schema. Need to be string in array. dn: %s attrName: %s value: %#v", dn.DN, s.Name, jsonMap[s.Name])

								res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
								w.Write(res)
								return
							}
						}
						jsonMap[s.Name] = newVals
					} else {
						tx.Rollback()

						// TODO return correct error code
						log.Printf("error: Failed to modify because of invalid schema. Need to be array. dn: %s attrName: %s value: %#v", dn.DN, s.Name, jsonMap[s.Name])

						res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
						w.Write(res)
						return
					}
				}
			}
		case ldap.ModifyRequestChangeOperationReplace:
			operationString = "Replace"

			if len(modification.Vals()) == 0 {
				// Replaceの値なしで削除するケース
				delete(jsonMap, s.Name)
			} else {
				if s.SingleValue {
					// TODO test multiple replace values against single-value
					jsonMap[s.Name] = string(modification.Vals()[0])
				} else {
					if s.Name == "member" {
						deleteMembers = append(deleteMembers, jsonMap[s.Name].([]interface{})...)
						log.Printf("Replace: deleteMembers: %v", deleteMembers)
					}
					var newVals []string
					for _, attributeValue := range modification.Vals() {
						newVals = append(newVals, string(attributeValue))
					}
					jsonMap[s.Name] = newVals
				}
			}
		}

		// For logging
		// TODO
		log.Printf("%s attribute '%s'", operationString, modification.Type_())
		for _, attributeValue := range modification.Vals() {
			log.Printf(" - value: %s", attributeValue)
		}
	}

	attrs, err := json.Marshal(jsonMap)
	if err != nil {
		tx.Rollback()

		// TODO return correct error
		log.Printf("error: Failed to marshal entry: %#v", err)
		res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	jsonText := types.JSONText(string(attrs))
	_, err = tx.NamedExec(`UPDATE ldap_entry SET updated = now(), attrs = :attrs WHERE id = :id`, map[string]interface{}{
		"id":    entry.Id,
		"attrs": jsonText,
	})

	if err != nil {
		tx.Rollback()

		log.Printf("warn: Failed to modify dn: %s err: %s", dn.DN, err)
		res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	// Resolve memberOf
	// TODO error handling
	_ = updateAssociation(tx, dn, jsonMap)
	_ = updateOwnerAssociation(tx, dn, jsonMap)

	// Clean deleted Members
	for _, m := range deleteMembers {
		var memberDN *DN
		var err error
		if memberDN, err = normalizeDN(m.(string)); err != nil {
			log.Printf("error: Invalid member, can't normalize dn: %#v", err)
			continue
		}

		entry, err := findByDN(tx, memberDN)

		if err != nil {
			log.Printf("error: Search member memberDN: %s error: %#v", memberDN.DN, err)
			continue
		}

		log.Printf("deleting memberOf: %+v deleteDN: %s", entry.Attrs, dn.DN)

		deleteMemberOf(entry, dn)

		_, err = tx.NamedExec(`UPDATE ldap_entry SET attrs = :attrs WHERE id = :id`, map[string]interface{}{
			"id":    entry.Id,
			"attrs": entry.Attrs,
		})
		if err != nil {
			log.Printf("error: Faild to modify member dn: %s err: %#v", entry.Dn, err)
			continue
		}
	}

	tx.Commit()

	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
