package main

import (
	"log"
	"strings"

	"github.com/openstandia/goldap/message"
	ldap "github.com/openstandia/ldapserver"
)

func handleSearchSubschema(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()

	log.Printf("handleSearchSubschema")
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		log.Print("info: Leaving handleSearchSubschema...")
		return
	default:
	}

	e := ldap.NewSearchResultEntry(string(r.BaseObject()))

	searchEntry := NewSearchEntry(nil, map[string][]string{
		"objectClass": []string{"top", "subentry", "subschema", "extensibleObject"},
		"cn":          []string{"Subschema"},
	})

	lines := strings.Split(schemaMap.Dump(), "\n")

	valuesMap := map[string][]string{}

	for _, line := range lines {
		tag := strings.Split(line, ": ")

		if len(tag) == 1 {
			continue
		}

		// log.Printf("attr: %s", string(attr))
		// log.Printf("attr: %s", tag)
		valuesMap[tag[0]] = append(valuesMap[tag[0]], line[len(tag[0])+2:])
	}

	// log.Printf("v: %v", valuesMap)

	// attrNames := []string{"ldapSyntaxes", "matchingRules", "matchingRuleUse", "attributeTypes", "objectClasses"}

	for k, v := range valuesMap {
		searchEntry.attributes[k] = v
	}

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

	// e.AddAttribute("mail", "valere.jeantet@gmail.com", "mail@vjeantet.fr")
	// e.AddAttribute("company", "SODADI")
	// e.AddAttribute("department", "DSI/SEC")
	// e.AddAttribute("l", "Ferrieres en brie")
	// e.AddAttribute("mobile", "0612324567")
	// e.AddAttribute("telephoneNumber", "0612324567")
	// e.AddAttribute("cn", "Valère JEANTET")
	// w.Write(e)
	//
	// e = ldap.NewSearchResultEntry("cn=Claire Thomas, " + string(r.BaseObject()))
	// e.AddAttribute("mail", "claire.thomas@gmail.com")
	// e.AddAttribute("cn", "Claire THOMAS")
	// w.Write(e)

	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
