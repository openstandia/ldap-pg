package main

import (
	"log"

	ldap "github.com/openstandia/ldapserver"
)

func handleDelete(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetDeleteRequest()
	dn, err := s.NormalizeDN(string(r))
	if err != nil {
		log.Printf("warn: Invalid dn: %s err: %s", r, err)

		// TODO return correct error
		res := ldap.NewDeleteResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	if !requiredAuthz(m, "delete", dn) {
		responseDeleteError(w, NewInsufficientAccess())
		return
	}

	log.Printf("info: Deleting entry: %s", dn.DNNormStr())

	err = s.Repo().DeleteByDN(dn)
	if err != nil {
		log.Printf("info: Failed to delete entry: %#v", err)

		responseDeleteError(w, err)
		return
	}

	log.Printf("info: Deleted. dn: %s", dn.DNNormStr())

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
