package main

import (
	"log"

	"github.com/openstandia/goldap/message"
	ldap "github.com/openstandia/ldapserver"
)

func handleSearchDSE(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
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
	// e.AddAttribute("objectClass", "top")
	// e.AddAttribute("namingContexts", "ou=system", "ou=schema", "dc=example,dc=com", "ou=config")

	searchEntry := NewSearchEntry(s.schemaMap, "", map[string][]string{
		"objectClass":          {"top"},
		"subschemaSubentry":    {"cn=Subschema"},
		"namingContexts":       {s.GetSuffix()},
		"supportedLDAPVersion": {"3"},
		"supportedFeatures": {
			"1.3.6.1.4.1.4203.1.5.1",
		},
		"supportedControl": {
			"1.2.840.113556.1.4.319",
		},
	})

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

	// e.AddAttribute("supportedExtension", "1.3.6.1.4.1.1466.20036", "1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.18060.0.1.5", "1.3.6.1.4.1.18060.0.1.3", "1.3.6.1.4.1.1466.20037")
	w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
