package main

import (
	"log"

	ldap "github.com/openstandia/ldapserver"
	"golang.org/x/xerrors"
)

func handleModifyDN(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyDNRequest()
	dn, err := s.NormalizeDN(string(r.Entry()))

	if err != nil {
		log.Printf("warn: Invalid dn: %s err: %s", r.Entry(), err)

		// TODO return correct error
		responseModifyDNError(w, err)
		return
	}

	if !requiredAuthz(m, "modrdn", dn) {
		responseModifyDNError(w, NewInsufficientAccess())
		return
	}

	newDN, oldRDN, err := dn.ModifyRDN(string(r.NewRDN()), bool(r.DeleteOldRDN()))

	if err != nil {
		// TODO return correct error
		log.Printf("info: Invalid newrdn. dn: %s newrdn: %s err: %#v", dn.DNNormStr(), r.NewRDN(), err)
		responseModifyDNError(w, err)
		return
	}

	log.Printf("info: Modify DN entry: %s", dn.DNNormStr())

	if r.NewSuperior() != nil {
		sup := string(*r.NewSuperior())
		newParentDN, err := s.NormalizeDN(sup)
		if err != nil {
			// TODO return correct error
			responseModifyDNError(w, NewInvalidDNSyntax())
			return
		}

		newDN, err = newDN.Move(newParentDN)
		if err != nil {
			// TODO return correct error
			responseModifyDNError(w, NewInvalidDNSyntax())
			return
		}
	}

	err = s.Repo().UpdateDN(dn, newDN, oldRDN)
	if err != nil {
		log.Printf("warn: Failed to modify dn: %s err: %+v", dn.DNNormStr(), err)
		// TODO error code
		responseModifyDNError(w, err)
		return
	}

	res := ldap.NewModifyDNResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func responseModifyDNError(w ldap.ResponseWriter, err error) {
	var ldapErr *LDAPError
	if ok := xerrors.As(err, &ldapErr); ok {
		log.Printf("warn: ModifyDN LDAP error. err: %+v", err)

		res := ldap.NewModifyDNResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		w.Write(res)
	} else {
		log.Printf("error: ModifyDN error. err: %+v", err)

		// TODO
		res := ldap.NewModifyDNResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
