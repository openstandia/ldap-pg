package main

import (
	"log"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/openstandia/goldap/message"
	ldap "github.com/openstandia/ldapserver"
)

func handleSearch(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
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

	log.Printf("info: handleGenericSearch")
	log.Printf("info: Request baseDN=%s", r.BaseObject())
	log.Printf("info: Request Scope=%d", r.Scope())
	log.Printf("info: Request SizeLimit=%d", r.SizeLimit())
	log.Printf("info: Request Filter=%s", r.Filter())
	log.Printf("info: Request FilterString=%s", r.FilterString())
	log.Printf("info: Request Attributes=%s", r.Attributes())
	log.Printf("info: Request TimeLimit=%d", r.TimeLimit().Int())

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

	// Phase 1: normalize DN
	baseDN, err := s.NormalizeDN(string(r.BaseObject()))
	if err != nil {
		log.Printf("info: Invalid baseDN error: %#v", err)

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	// Phase 2: authorization
	if !requiredAuthz(m, "search", baseDN) {
		responseSearchError(w, NewInsufficientAccess())
		return
	}

	// Phase 3: filter converting
	q, err := ToQuery(schemaMap, r.Filter())
	if err != nil {
		log.Printf("info: query error: %#v", err)

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}
	// If the filter doesn't contain supported attributes, return success.
	if q.Query == "" && r.FilterString() != "" {
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
		w.Write(res)
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
			offset = sessionMap[reqCookie]
			// clear
			delete(sessionMap, reqCookie)
		}
	}

	q.Params["pageSize"] = pageSize
	q.Params["offset"] = offset

	maxCount, limittedCount, err := s.Repo().Search(baseDN, scope, q,
		getRequestedMemberAttrs(r), isMemberOfRequested(r), func(searchEntry *SearchEntry) error {
			responseEntry(s, w, r, searchEntry)
			return nil
		})
	if err != nil {
		if lerr, ok := err.(*LDAPError); ok {
			log.Printf("info: Search failed: %v", err)

			res := ldap.NewSearchResultDoneResponse(lerr.Code)
			w.Write(res)
			return
		}

		log.Printf("error: Search error: %v", err)

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
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

	// https://www.ietf.org/rfc/rfc2696.txt
	if nextCookie != "" {
		control := message.NewSimplePagedResultsControl(pageSize, false, nextCookie)
		var controls message.Controls = []message.Control{control}

		w.WriteControls(res, &controls)
	} else {
		w.Write(res)
	}

	return
}

func responseEntry(s *Server, w ldap.ResponseWriter, r message.SearchRequest, searchEntry *SearchEntry) {
	log.Printf("Response Entry: %+v", searchEntry)

	var dn string
	if searchEntry.DNOrigStr() == "" {
		dn = s.SuffixOrigStr()
	} else {
		dn = searchEntry.DNOrigStr() + "," + s.SuffixOrigStr()
	}
	e := ldap.NewSearchResultEntry(dn)

	sentAttrs := map[string]struct{}{}

	if isAllAttributesRequested(r) {
		for k, v := range searchEntry.GetAttrsOrigWithoutOperationalAttrs() {
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
			if _, ok := sentAttrs[k]; !ok {
				for _, vv := range v {
					e.AddAttribute(message.AttributeDescription(k), message.AttributeValue(vv))
				}
			}
		}
	}

	w.Write(e)

	log.Printf("Response an entry. dn: %s", searchEntry.DNOrigStr())
}

func responseSearchError(w ldap.ResponseWriter, err error) {
	if ldapErr, ok := err.(*LDAPError); ok {
		res := ldap.NewSearchResultDoneResponse(ldapErr.Code)
		w.Write(res)
	} else {
		log.Printf("error: %s", err)
		// TODO
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultProtocolError)
		w.Write(res)
	}
}

func expandIn(cid []int64) (string, map[string]int64) {
	s := make([]string, len(cid))
	m := make(map[string]int64, len(cid))

	for i, id := range cid {
		k := "parent_id_" + strconv.Itoa(i)
		s[i] = ":" + k
		m[k] = id
	}
	return strings.Join(s, ","), m
}
