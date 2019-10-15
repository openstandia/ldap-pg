package main

import (
	"log"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
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
		pathQuery = "(LOWER(dn) = LOWER(:baseDN))"
		q.Params["baseDN"] = baseDN.DN

	} else if scope == 1 {
		pathQuery = "(LOWER(dn) = LOWER(:baseDN) OR path = :path)"
		q.Params["baseDN"] = baseDN.DN
		q.Params["path"] = path

	} else if scope == 2 {
		pathQuery = "(LOWER(dn) = LOWER(:baseDN) OR path LIKE :path)"
		q.Params["baseDN"] = baseDN.DN
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

	var rows *sqlx.Rows

	q.Params["pageSize"] = pageSize
	q.Params["offset"] = offset

	rows, err = findByFilter(pathQuery, q)
	if err != nil {
		log.Printf("info: Search  error: %#v", err)

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}
	defer rows.Close()

	entry := Entry{}
	var max int32 = 0
	var count int32 = 0
	for rows.Next() {
		err := rows.StructScan(&entry)
		if err != nil {
			log.Printf("error: Entry struct mapping error: %#v", err)

			// TODO return correct error code
			res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultOperationsError)
			w.Write(res)
			return
		}
		if max == 0 {
			max = entry.Count
		}
		responseEntry(w, r, &entry)

		count++
		entry.Clear()
	}

	if max == 0 {
		log.Printf("info: Not found")

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	err = rows.Err()
	if err != nil {
		log.Printf("error: Search error: %#v", err)

		// TODO return correct error code
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	var nextCookie string

	if count+offset < max {
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

func responseEntry(w ldap.ResponseWriter, r message.SearchRequest, entry *Entry) {

	log.Printf("get Entry: %+v", entry)

	e := ldap.NewSearchResultEntry(entry.Dn)

	if isAllAttributesRequested(r) {
		for k, _ := range entry.GetAttrs() {
			values, _ := entry.GetAttr(k)

			log.Printf("AddAttribute %s: %#v", k, values)

			for _, v := range values {
				e.AddAttribute(message.AttributeDescription(k), message.AttributeValue(v))
			}
		}

		// TODO
		if isSupportedFetchMemberOf() {
			values := entry.GetMemberOf()
			log.Printf("AddAttribute memberOf=%#v", values)
			for _, v := range values {
				e.AddAttribute(message.AttributeDescription("memberOf"), message.AttributeValue(v))
			}
		}
	} else {
		for _, attr := range r.Attributes() {
			a := string(attr)

			log.Printf("attr: %s", a)

			if a != "+" {
				s, ok := schemaMap.Get(a)
				if !ok {
					log.Printf("No schema for requested attr, ignore. attr: %s", a)
					continue
				}

				var values []string

				// TODO
				if s.Name == "memberOf" && isSupportedFetchMemberOf() {
					values = entry.GetMemberOf()
				} else {
					var ok bool
					values, ok = entry.GetAttr(s.Name)
					if !ok {
						log.Printf("No data for requested attr, ignore. attr: %s", a)
						continue
					}
				}

				log.Printf("AddAttribute %s=%#v", a, values)
				for _, v := range values {
					e.AddAttribute(message.AttributeDescription(s.Name), message.AttributeValue(v))
				}
			}
		}
	}

	if isOperationalAttributesRequested(r) {
		e.AddAttribute("entryUUID", message.AttributeValue(entry.EntryUUID))
		e.AddAttribute("createTimestamp", message.AttributeValue(entry.Created.Format(TIMESTAMP_FORMAT)))
		e.AddAttribute("modifyTimestamp", message.AttributeValue(entry.Updated.Format(TIMESTAMP_FORMAT)))
		// TODO Adding more operational attributes
	}

	w.Write(e)

	log.Printf("Wrote 1 entry dn: %s", entry.Dn)
}
