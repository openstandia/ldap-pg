package main

import (
	"log"

	"github.com/openstandia/goldap/message"
	ldap "github.com/openstandia/ldapserver"
)

type SearchDSEHandler struct {
	server *Server
}

func NewSearchDSEHandler(s *Server) *SearchDSEHandler {
	return &SearchDSEHandler{
		server: s,
	}
}

func (h SearchDSEHandler) HandleSearchDSE(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	log.Printf("info: handleSearchDSE")
	log.Printf("info: Request BaseDn=%s", r.BaseObject())
	log.Printf("info: Request Filter=%s", r.Filter())
	log.Printf("info: Request FilterString=%s", r.FilterString())
	log.Printf("info: Request Attributes=%s", r.Attributes())
	log.Printf("info: Request TimeLimit=%d", r.TimeLimit().Int())

	e := ldap.NewSearchResultEntry("")
	// e.AddAttribute("vendorName", "OpenStandia")
	// e.AddAttribute("vendorVersion", "0.0.1")
	e.AddAttribute("subschemaSubentry", "cn=Subschema")
	// e.AddAttribute("namingContexts", "ou=system", "ou=schema", "dc=example,dc=com", "ou=config")

	if isOperationalAttributesRequested(r) {
		e.AddAttribute("objectClass", "top", "extensibleObject")
		e.AddAttribute("namingContexts", message.AttributeValue(h.server.GetSuffix()))
		e.AddAttribute("supportedLDAPVersion", "3")
		e.AddAttribute("supportedFeatures",
			"1.3.6.1.4.1.4203.1.5.1",
		)
		e.AddAttribute("supportedControl",
			// "2.16.840.1.113730.3.4.3",
			// "1.3.6.1.4.1.4203.1.10.1",
			// "2.16.840.1.113730.3.4.2",
			// "1.3.6.1.4.1.4203.1.9.1.4",
			// "1.3.6.1.4.1.42.2.27.8.5.1",
			// "1.3.6.1.4.1.4203.1.9.1.1",
			// "1.3.6.1.4.1.4203.1.9.1.3",
			// "1.3.6.1.4.1.4203.1.9.1.2",
			// "1.3.6.1.4.1.18060.0.0.1",
			// "2.16.840.1.113730.3.4.7",
			"1.2.840.113556.1.4.319",
		)
	}

	// e.AddAttribute("supportedExtension", "1.3.6.1.4.1.1466.20036", "1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.18060.0.1.5", "1.3.6.1.4.1.18060.0.1.3", "1.3.6.1.4.1.1466.20037")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
