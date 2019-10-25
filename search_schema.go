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

	attrMap := map[string]struct{}{}
	for _, attr := range r.Attributes() {
		attrMap[string(attr)] = struct{}{}
	}

	e := ldap.NewSearchResultEntry(string(r.BaseObject()))
	if _, ok := attrMap["objectclass"]; ok || (len(attrMap) == 0 && r.FilterString() == "(objectclass=*)") {
		e.AddAttribute("objectClass", "top")
		e.AddAttribute("objectClass", "subentry")
		e.AddAttribute("objectClass", "subschema")
		e.AddAttribute("objectClass", "extensibleObject")
		e.AddAttribute("cn", "Subschema")
	}

	lines := strings.Split(schemaMap.Dump(), "\n")

	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}

	valuesMap := map[string][]message.AttributeValue{}

	log.Printf("size: %d", len(lines))

	for _, line := range lines {
		tag := strings.Split(line, ": ")

		if len(tag) == 1 {
			continue
		}
		if _, ok := attrMap[tag[0]]; !ok {
			continue
		}

		// log.Printf("attr: %s", string(attr))
		// log.Printf("attr: %s", tag)
		valuesMap[tag[0]] = append(valuesMap[tag[0]], message.AttributeValue(line[len(tag[0])+2:]))
	}

	// log.Printf("v: %v", valuesMap)

	for k, v := range valuesMap {
		e.AddAttribute(message.AttributeDescription(k), v...)
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
