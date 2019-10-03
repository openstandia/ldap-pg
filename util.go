package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/openstandia/goldap/message"
	ldap "github.com/openstandia/ldapserver"
	goldap "gopkg.in/ldap.v3"
)

const TIMESTAMP_FORMAT string = "20060102150405Z"

type DN struct {
	DN              string
	ReverseParentDN string
}

func (d *DN) Equal(o *DN) bool {
	return d.DN == o.DN
}

func (d *DN) Modify(newRDN string) error {
	nd, err := goldap.ParseDN(newRDN)
	if err != nil {
		return err
	}

	dn, _ := goldap.ParseDN(d.DN)

	var n []string

	for _, v := range nd.RDNs {
		for _, a := range v.Attributes {
			n = append(n, fmt.Sprintf("%s=%s", a.Type, a.Value))
			// TODO multiple RDN using +
		}
	}

	for i := 1; i < len(dn.RDNs); i++ {
		for _, a := range dn.RDNs[i].Attributes {
			n = append(n, fmt.Sprintf("%s=%s", a.Type, a.Value))
			// TODO multiple RDN using +
		}
	}

	ndn := strings.Join(n, ",")
	reverse := toReverseDN(n)

	d.DN = ndn
	d.ReverseParentDN = reverse

	return nil
}

func (d *DN) ToPath() string {
	parts := strings.Split(d.DN, ",")

	var path string
	for i := len(parts) - 1; i >= 0; i-- {
		path += strings.ToLower(parts[i]) + "/"
	}
	return path
}

func normalizeDN(dn string) (*DN, error) {
	d, err := goldap.ParseDN(dn)
	if err != nil {
		return nil, err
	}
	var n []string
	for _, v := range d.RDNs {
		for _, a := range v.Attributes {
			n = append(n, fmt.Sprintf("%s=%s", a.Type, a.Value))
			// TODO multiple RDN using +
		}
	}

	ndn := strings.Join(n, ",")
	reverse := toReverseDN(n)

	return &DN{
		DN:              ndn,
		ReverseParentDN: reverse,
	}, nil
}

func toReverseDN(dn []string) string {
	var path string
	// ignore last rdn
	for i := len(dn) - 1; i > 0; i-- {
		path += strings.ToLower(dn[i]) + "/"
	}
	return path
}

func getSession(m *ldap.Message) map[string]int32 {
	store := m.Client.GetCustomData()
	if sessionMap, ok := store.(map[string]int32); ok {
		return sessionMap
	} else {
		sessionMap := map[string]int32{}
		m.Client.SetCustomData(sessionMap)
		return sessionMap
	}
}

func isOperationalAttributesRequested(r message.SearchRequest) bool {
	for _, attr := range r.Attributes() {
		if string(attr) == "+" {
			return true
		}
	}
	return false
}

func isAllAttributesRequested(r message.SearchRequest) bool {
	if len(r.Attributes()) == 0 {
		return true
	}
	for _, attr := range r.Attributes() {
		if string(attr) == "*" {
			return true
		}
	}
	return false
}

func responseUnsupportedSearch(w ldap.ResponseWriter, r message.SearchRequest) {
	log.Printf("warn: Unsupported search filter: %s", r.FilterString())
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	res.SetResultCode(ldap.LDAPResultOperationsError)
	w.Write(res)
}

func mapAttributeValue(s *Schema, attr message.Attribute, jsonMap map[string]interface{}) {
	if s.SingleValue {
		jsonMap[s.Name] = string(attr.Vals()[0])
	} else {
		arr := []interface{}{}
		for _, v := range attr.Vals() {
			arr = append(arr, string(v))
		}
		jsonMap[s.Name] = arr
	}
}

func mergeMultipleValues(s *Schema, vals []interface{}, jsonMap map[string]interface{}) error {
	if mv, ok := jsonMap[s.Name]; ok {
		if mvv, ok := mv.([]interface{}); ok {
			jsonMap[s.Name] = append(mvv, vals...)

			// TODO need to remove duplication??
		} else {
			// Value in DB isn't array
			return fmt.Errorf("%s is not array.", s.Name)
		}
	} else {
		// New
		jsonMap[s.Name] = vals
	}
	return nil
}
