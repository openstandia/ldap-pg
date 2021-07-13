package main

import (
	"context"
	"log"

	ldap "github.com/openstandia/ldapserver"
	"golang.org/x/xerrors"
)

func handleAdd(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	ctx := SetSessionContext(context.Background(), m)

	r := m.GetAddRequest()

	dn, err := s.NormalizeDN(string(r.Entry()))
	if err != nil {
		log.Printf("warn: Invalid DN: %s err: %s", r.Entry(), err)
		responseAddError(w, err)
		return
	}

	if !s.RequiredAuthz(m, AddOps, dn) {
		// TODO return errror message
		// ldap_add: Insufficient access (50)
		// additional info: no write access to parent
		responseAddError(w, NewInsufficientAccess())
		return
	}

	// Invalid suffix
	if !dn.Equal(s.Suffix) && !dn.IsSubOf(s.Suffix) {
		responseAddError(w, NewNoGlobalSuperiorKnowledge())
		return
	}

	log.Printf("debug: Start adding DN: %v", dn)

	addEntry, err := mapper.LDAPMessageToAddEntry(dn, r.Attributes())
	if err != nil {
		responseAddError(w, err)
		return
	}

	log.Printf("info: Adding entry: %s", r.Entry())

	i := 0
Retry:

	id, err := s.Repo().Insert(ctx, addEntry)
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

		responseAddError(w, err)
		return
	}

	log.Printf("debug: Added. Id: %d, DN: %v", id, dn)

	res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	log.Printf("debug: End Adding entry: %s", r.Entry())
}

func responseAddError(w ldap.ResponseWriter, err error) {
	var ldapErr *LDAPError
	if ok := xerrors.As(err, &ldapErr); ok {
		log.Printf("warn: Add LDAP error. err: %+v", err)

		res := ldap.NewAddResponse(ldapErr.Code)
		if ldapErr.Msg != "" {
			res.SetDiagnosticMessage(ldapErr.Msg)
		}
		if ldapErr.MatchedDN != "" {
			res.SetMatchedDN(ldapErr.MatchedDN)
		}
		w.Write(res)
	} else {
		log.Printf("error: Add error. err: %+v", err)

		// TODO
		res := ldap.NewAddResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
