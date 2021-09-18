package main

import (
	"context"
	"log"

	"github.com/google/uuid"
	"github.com/openstandia/goldap/message"
	ldap "github.com/openstandia/ldapserver"
	"golang.org/x/xerrors"
)

func handleSearch(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	ctx := SetSessionContext(context.Background(), m)

	r := m.GetSearchRequest()

	var pageControl *message.SimplePagedResultsControl

	if m.Controls() != nil {
		for _, con := range *m.Controls() {
			log.Printf("info: req control: %v", con)
			if pc, ok := con.PagedResultsControl(); ok {
				pageControl = pc
			}
		}

		if pageControl != nil {
			log.Printf("info: req pageControl: size=%d, cookie=%s", pageControl.Size(), pageControl.Cookie())
		}
	}

	log.Printf("info: handleGenericSearch baseDN=%s, scope=%d, sizeLimit=%d, filter=%s, attributes=%s, timeLimit=%d",
		r.BaseObject(), r.Scope(), r.SizeLimit(), r.FilterString(), r.Attributes(), r.TimeLimit().Int())

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		log.Print("info: Leaving handleSearch...")
		return
	default:
	}

	scope := int(r.Scope())
	if scope < 0 || scope > 3 {
		log.Printf("warn: Invalid scope: %d", scope)

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	// Always return no such object
	if string(r.BaseObject()) == "" {
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	// Phase 1: normalize DN
	baseDN, err := s.NormalizeDN(string(r.BaseObject()))
	if err != nil {
		log.Printf("info: Invalid baseDN error: %#v", err)

		// # search result
		// search: 2
		// result: 34 Invalid DN syntax
		// text: invalid DN
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage("invalid DN")
		w.Write(res)
		return
	}

	// Phase 2: authorization
	if !s.RequiredAuthz(m, SearchOps, baseDN) {
		// Return 32 No such object
		responseSearchError(w, NewNoSuchObject())
		return
	}

	// Phase 4: execute SQL and return entries
	// TODO configurable default pageSize
	var pageSize int32 = 500
	if pageControl != nil {
		pageSize = pageControl.Size()
	}

	sessionMap := getPageSession(m)
	var offset int32
	if pageControl != nil {
		reqCookie := pageControl.Cookie()
		if reqCookie != "" {
			var ok bool
			if offset, ok = sessionMap[reqCookie]; ok {
				log.Printf("debug: paged results cookie is ok")

				// clear cookie
				delete(sessionMap, reqCookie)
			} else {
				log.Printf("debug: invalid paged results cookie")

				// Not found requested cookie
				// Return error
				res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultUnwillingToPerform)
				res.SetDiagnosticMessage("paged results cookie is invalid or old")
				w.Write(res)
				return
			}
		}
	}
	option := &SearchOption{
		Scope:                      scope,
		Filter:                     r.Filter(),
		PageSize:                   pageSize,
		Offset:                     offset,
		RequestedAssocation:        getRequestedMemberAttrs(r),
		IsMemberOfRequested:        isMemberOfRequested(r),
		IsHasSubordinatesRequested: isHasSubOrdinatesRequested(r),
	}

	maxCount, limittedCount, err := s.Repo().Search(ctx, baseDN, option, func(searchEntry *SearchEntry) error {
		responseEntry(s, w, m, r, searchEntry)
		return nil
	})
	if err != nil {
		responseSearchError(w, err)
		return
	}

	if maxCount == 0 {
		log.Printf("debug: Not found")

		// Must return success if no hit
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
		w.Write(res)
		return
	}

	var nextCookie string

	if limittedCount+offset < maxCount {
		uuid, _ := uuid.NewRandom()
		nextCookie = uuid.String()

		sessionMap := getPageSession(m)
		sessionMap[nextCookie] = offset + pageSize
	}

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)

	if pageControl != nil {
		// https://www.ietf.org/rfc/rfc2696.txt
		control := message.NewSimplePagedResultsControl(maxCount, false, nextCookie)
		var controls message.Controls = []message.Control{control}

		w.WriteControls(res, &controls)
	} else {
		w.Write(res)
	}
}

func responseEntry(s *Server, w ldap.ResponseWriter, m *ldap.Message, r message.SearchRequest, searchEntry *SearchEntry) {
	log.Printf("Response Entry: %+v", searchEntry)

	session := getAuthSession(m)

	dnOrig := searchEntry.DNOrig()
	e := ldap.NewSearchResultEntry(resolveSuffix(s, dnOrig))

	sentAttrs := map[string]struct{}{}

	if isAllAttributesRequested(r) {
		for k, v := range searchEntry.GetAttrsOrigWithoutOperationalAttrs() {
			if !s.simpleACL.CanVisible(session, k) {
				log.Printf("- Ignore Attribute %s", k)
				continue
			}

			log.Printf("- Attribute %s: %#v", k, v)

			av := make([]message.AttributeValue, len(v))
			for i, vv := range v {
				av[i] = message.AttributeValue(vv)
			}
			e.AddAttribute(message.AttributeDescription(k), av...)

			sentAttrs[k] = struct{}{}
		}
	}

	for _, attr := range r.Attributes() {
		a := string(attr)

		if !s.simpleACL.CanVisible(session, a) {
			log.Printf("- Ignore Attribute %s", a)
			continue
		}

		log.Printf("Requested attr: %s", a)

		if a != "+" {
			k, values, ok := searchEntry.GetAttrOrig(a)
			if !ok {
				log.Printf("No schema for requested attr, ignore. attr: %s", a)
				continue
			}

			if _, ok := sentAttrs[k]; ok {
				log.Printf("Already sent, ignore. attr: %s", a)
				continue
			}

			log.Printf("- Attribute %s=%#v", a, values)

			av := make([]message.AttributeValue, len(values))
			for i, vv := range values {
				av[i] = message.AttributeValue(vv)
			}
			e.AddAttribute(message.AttributeDescription(k), av...)

			sentAttrs[k] = struct{}{}
		}
	}

	if isOperationalAttributesRequested(r) {
		for k, v := range searchEntry.GetOperationalAttrsOrig() {
			if !s.simpleACL.CanVisible(session, k) {
				log.Printf("- Ignore Attribute %s", k)
				continue
			}

			if _, ok := sentAttrs[k]; !ok {
				for _, vv := range v {
					e.AddAttribute(message.AttributeDescription(k), message.AttributeValue(vv))
				}
			}
		}
	}

	w.Write(e)

	log.Printf("Response an entry. dn: %s", dnOrig)
}

func responseSearchError(w ldap.ResponseWriter, err error) {
	var ldapErr *LDAPError
	if ok := xerrors.As(err, &ldapErr); ok {
		if ldapErr.Code != ldap.LDAPResultSuccess && !ldapErr.IsNoSuchObjectError() {
			log.Printf("warn: Search LDAP error. err: %+v", err)
		}

		res := ldap.NewSearchResultDoneResponse(ldapErr.Code)
		w.Write(res)
	} else {
		log.Printf("error: Search error. err: %+v", err)

		// TODO
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}
