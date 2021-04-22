package main

import (
	"database/sql"
	"log"

	ldap "github.com/openstandia/ldapserver"
	"golang.org/x/xerrors"
)

func handleModify(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyRequest()
	dn, err := s.NormalizeDN(string(r.Object()))

	if err != nil {
		log.Printf("warn: Invalid dn: %s, err: %s", r.Object(), err)

		// TODO return correct error
		res := ldap.NewModifyResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	if !requiredAuthz(m, "modify", dn) {
		responseModifyError(w, NewInsufficientAccess())
		return
	}

	log.Printf("info: Modify entry: %s", dn.DNNormStr())

	err = s.Repo().Update(dn, func(newEntry *ModifyEntry) error {
		for _, change := range r.Changes() {
			modification := change.Modification()
			attrName := string(modification.Type_())

			log.Printf("Modify operation: %d, attribute: %s", change.Operation(), modification.Type_())

			var values []string
			for _, attributeValue := range modification.Vals() {
				values = append(values, string(attributeValue))
				log.Printf("--> value: %s", attributeValue)
			}

			var err error

			switch change.Operation() {
			case ldap.ModifyRequestChangeOperationAdd:
				err = newEntry.Add(attrName, values)

			case ldap.ModifyRequestChangeOperationDelete:
				err = newEntry.Delete(attrName, values)

			case ldap.ModifyRequestChangeOperationReplace:
				err = newEntry.Replace(attrName, values)
			}

			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		if err == sql.ErrNoRows {
			responseModifyError(w, NewNoSuchObject())
			return
		}
		responseModifyError(w, xerrors.Errorf("Failed to modify the entry. dn: %s, err: %w", dn.DNNormStr(), err))
		return
	}

	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func responseModifyError(w ldap.ResponseWriter, err error) {
	var ldapErr *LDAPError
	if ok := xerrors.As(err, &ldapErr); ok {
		log.Printf("warn: Modify LDAP error. err: %+v", err)

		res := ldap.NewModifyResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		w.Write(res)
	} else {
		log.Printf("error: Modify error. err: %+v", err)

		// TODO
		res := ldap.NewModifyResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
