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

func mergeMultipleValues(s *Schema, vals []interface{}, jsonMap map[string]interface{}) error {
	if mv, ok := jsonMap[s.Name]; ok {
		if mvv, ok := mv.([]interface{}); ok {
			mvvMap := arrayToMap(mvv)

			for i, v := range vals {
				if _, ok := mvvMap[v]; ok {
					// Duplicate error
					return NewTypeOrValueExists("modify/add", s.Name, i)
				}
				mvv = append(mvv, v)
			}

			jsonMap[s.Name] = mvv
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

func arrayToMap(arr []interface{}) map[interface{}]struct{} {
	// TODO schema aware
	m := map[interface{}]struct{}{}
	for _, v := range arr {
		m[v] = struct{}{}
	}
	return m
}

func arrayContains(arr []string, str string) (int, bool) {
	for i, v := range arr {
		if v == str {
			return i, true
		}
	}
	return -1, false
}

func hasDuplicate(s *Schema, arr []string) (int, bool) {
	m := make(map[string]int, len(arr))

	for i, v := range arr {
		// TODO Schema aware
		if j, ok := m[v]; ok {
			return j, true
		}
		m[v] = i
	}
	return -1, false
}
