package main

import (
	"log"

	"github.com/google/uuid"
	"github.com/openstandia/goldap/message"
	ldap "github.com/openstandia/ldapserver"
)

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
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

	baseDN, err := normalizeDN(string(r.BaseObject()))
	if err != nil {
		log.Printf("info: Invalid baseDN error: %#v", err)

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	scope := int(r.Scope())

	q, err := ToQuery(schemaMap, r.Filter())
	if err != nil {
		log.Printf("info: query error: %#v", err)

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	// Scope handling, one and sub need to includ base.
	// 0: base
	// 1: one
	// 2: sub
	// 3: children
	var pathQuery string
	path := baseDN.ToPath()
	if scope == 0 {
		pathQuery = "dn_norm = :baseDNNorm"
		q.Params["baseDNNorm"] = baseDN.DNNorm

	} else if scope == 1 {
		pathQuery = "(dn_norm = :baseDNNorm OR path = :path)"
		q.Params["baseDNNorm"] = baseDN.DNNorm
		q.Params["path"] = path

	} else if scope == 2 {
		pathQuery = "(dn_norm = :baseDNNorm OR path LIKE :path)"
		q.Params["baseDNNorm"] = baseDN.DNNorm
		q.Params["path"] = path + "%"

	} else if scope == 3 {
		pathQuery = "path LIKE :path"
		q.Params["path"] = path + "%"

	} else {
		log.Printf("warn: Invalid scope: %d", scope)

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	// TODO configurable default pageSize
	var pageSize int32 = 500
	if pageControl != nil {
		pageSize = pageControl.Size()
	}

	sessionMap := getSession(m)
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

	maxCount, limittedCount, err := findByFilter(pathQuery, q, isMemberOfAttributesRequested(r), func(searchEntry *SearchEntry) error {
		responseEntry(w, r, searchEntry)
		return nil
	})
	if err != nil {
		log.Printf("error: Search  error: %#v", err)

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}

	if maxCount == 0 {
		log.Printf("info: Not found")

		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	var nextCookie string

	if limittedCount+offset < maxCount {
		uuid, _ := uuid.NewRandom()
		nextCookie = uuid.String()

		sessionMap := getSession(m)
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

func responseEntry(w ldap.ResponseWriter, r message.SearchRequest, searchEntry *SearchEntry) {
	log.Printf("Response Entry: %+v", searchEntry)

	e := ldap.NewSearchResultEntry(searchEntry.GetDNNorm())

	sentAttrs := map[string]struct{}{}

	if isAllAttributesRequested(r) {
		for k, v := range searchEntry.GetAttrsOrig() {
			log.Printf("- Attribute %s: %#v", k, v)

			for _, vv := range v {
				e.AddAttribute(message.AttributeDescription(k), message.AttributeValue(vv))
			}
		}
	} else {
		for _, attr := range r.Attributes() {
			a := string(attr)

			log.Printf("Requested attr: %s", a)

			if a != "+" {
				k, values, ok := searchEntry.GetAttrOrig(a)
				if !ok {
					log.Printf("No schema for requested attr, ignore. attr: %s", a)
					continue
				}

				log.Printf("- Attribute %s=%#v", a, values)
				for _, v := range values {
					e.AddAttribute(message.AttributeDescription(k), message.AttributeValue(v))
				}
				sentAttrs[k] = struct{}{}
			}
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
		// e.AddAttribute("entryUUID", message.AttributeValue(entry.EntryUUID))
		// e.AddAttribute("createTimestamp", message.AttributeValue(entry.Created.Format(TIMESTAMP_FORMAT)))
		// e.AddAttribute("modifyTimestamp", message.AttributeValue(entry.Updated.Format(TIMESTAMP_FORMAT)))
	}

	w.Write(e)

	log.Printf("Response an entry. dn: %s", searchEntry.GetDNNorm())
}
