package main

import (
	"log"

	ldap "github.com/openstandia/ldapserver"
)

// The resultCode is set to compareTrue, compareFalse, or an appropriate
// error.  compareTrue indicates that the assertion value in the ava
// Comparerequest field matches a value of the attribute or subtype according to the
// attribute's EQUALITY matching rule.  compareFalse indicates that the
// assertion value in the ava field and the values of the attribute or
// subtype did not match.  Other result codes indicate either that the
// result of the comparison was Undefined, or that
// some error occurred.
func handleCompare(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetCompareRequest()
	log.Printf("[INFO] Comparing entry: %s", r.Entry())
	//attributes values
	log.Printf(" attribute name to compare : \"%s\"", r.Ava().AttributeDesc())
	log.Printf(" attribute value expected : \"%s\"", r.Ava().AssertionValue())

	res := ldap.NewCompareResponse(ldap.LDAPResultCompareTrue)

	w.Write(res)
}
