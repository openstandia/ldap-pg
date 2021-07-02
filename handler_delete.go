package main

import (
	"context"
	"log"

	ldap "github.com/openstandia/ldapserver"
	"golang.org/x/xerrors"
)

func handleDelete(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	ctx := context.Background()

	r := m.GetDeleteRequest()
	dn, err := s.NormalizeDN(string(r))
	if err != nil {
		log.Printf("warn: Invalid dn: %s err: %s", r, err)

		// TODO return correct error
		res := ldap.NewDeleteResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	if !s.RequiredAuthz(m, DeleteOps, dn) {
		responseDeleteError(w, NewInsufficientAccess())
		return
	}

	log.Printf("info: Deleting entry: %s", dn.DNNormStr())

	i := 0
Retry:

	err = s.Repo().DeleteByDN(ctx, dn)
	if err != nil {
		var retryError *RetryError
		if ok := xerrors.As(err, &retryError); ok {
			if i < maxRetry {
				i++
				log.Printf("warn: Detect consistency error. Do retry. try_count: %d", i)
				goto Retry
			}
			log.Printf("error: Give up to retry. try_count: %d", i)
		}

		log.Printf("info: Failed to delete entry: %#v", err)

		responseDeleteError(w, err)
		return
	}

	log.Printf("info: Deleted. dn: %s", dn.DNNormStr())

	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func responseDeleteError(w ldap.ResponseWriter, err error) {
	var ldapErr *LDAPError
	if ok := xerrors.As(err, &ldapErr); ok {
		log.Printf("warn: Delete LDAP error. err: %+v", err)

		res := ldap.NewDeleteResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		w.Write(res)
	} else {
		log.Printf("error: Delete error. err: %+v", err)
		// TODO
		res := ldap.NewDeleteResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
