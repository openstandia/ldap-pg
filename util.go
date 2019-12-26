package main

import (
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openstandia/goldap/message"
	ldap "github.com/openstandia/ldapserver"
	goldap "gopkg.in/ldap.v3"
)

const TIMESTAMP_FORMAT string = "20060102150405Z"

func getSession(m *ldap.Message) map[string]interface{} {
	store := m.Client.GetCustomData()
	if sessionMap, ok := store.(map[string]interface{}); ok {
		return sessionMap
	} else {
		sessionMap := map[string]interface{}{}
		m.Client.SetCustomData(sessionMap)
		return sessionMap
	}
}

func getAuthSession(m *ldap.Message) map[string]*DN {
	session := getSession(m)
	if authSession, ok := session["auth"]; ok {
		return authSession.(map[string]*DN)
	} else {
		authSession := map[string]*DN{}
		session["auth"] = authSession
		return authSession
	}
}

func requiredAuthz(m *ldap.Message, operation string, targetDN *DN) bool {
	session := getAuthSession(m)
	var ok bool
	if _, ok = session["dn"]; !ok {
		return false
	}

	// TODO authz
	return true
}

func getPageSession(m *ldap.Message) map[string]int32 {
	session := getSession(m)
	if pageSession, ok := session["page"]; ok {
		return pageSession.(map[string]int32)
	} else {
		pageSession := map[string]int32{}
		session["page"] = pageSession
		return pageSession
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

func isMemberOfRequested(r message.SearchRequest) bool {
	for _, attr := range r.Attributes() {
		if strings.ToLower(string(attr)) == "memberof" {
			return true
		}
	}
	return false
}

func getRequestedMemberAttrs(r message.SearchRequest) []string {
	if len(r.Attributes()) == 0 {
		return []string{"member", "uniqueMember"}
	}
	list := []string{}
	for _, attr := range r.Attributes() {
		if string(attr) == "*" {
			// TODO move to schema
			return []string{"member", "uniqueMember"}
		}
		a := strings.ToLower(string(attr))

		// TODO move to schema
		if a == "member" {
			list = append(list, "member")
		}
		if a == "uniquemember" {
			list = append(list, "uniqueMember")
		}
	}
	return list
}

func isMemberRequested(r message.SearchRequest) bool {
	if len(r.Attributes()) == 0 {
		return true
	}
	for _, attr := range r.Attributes() {
		if string(attr) == "*" {
			return true
		}
		a := strings.ToLower(string(attr))

		// TODO move to schema
		if a == "member" ||
			a == "uniqueMember" {
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

func arrayDiff(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

func normalize(s *Schema, value string) (string, error) {
	switch s.Equality {
	case "caseExactMatch":
		return normalizeSpace(value), nil
	case "caseIgnoreMatch":
		return strings.ToLower(normalizeSpace(value)), nil
	case "distinguishedNameMatch":
		return normalizeDistinguishedName(value)
	case "caseExactIA5Match":
		return normalizeSpace(value), nil
	case "caseIgnoreIA5Match":
		return strings.ToLower(normalizeSpace(value)), nil
	case "generalizedTimeMatch":
		return normalizeGeneralizedTime(value)
	case "objectIdentifierMatch":
		return strings.ToLower(value), nil
	case "numericStringMatch":
		return removeAllSpace(value), nil
	case "integerMatch":
		return value, nil
	case "UUIDMatch":
		return normalizeUUID(value)
	}

	switch s.Substr {
	case "caseExactSubstringsMatch":
		return normalizeSpace(value), nil
	case "caseIgnoreSubstringsMatch":
		return strings.ToLower(normalizeSpace(value)), nil
	case "caseExactIA5SubstringsMatch":
		return normalizeSpace(value), nil
	case "caseIgnoreIA5SubstringsMatch":
		return strings.ToLower(normalizeSpace(value)), nil
	}

	return value, nil
}

var SPACE_PATTERN = regexp.MustCompile(`\s+`)

func normalizeSpace(value string) string {
	str := SPACE_PATTERN.ReplaceAllString(value, " ")
	str = strings.Trim(str, " ")
	return str
}

func removeAllSpace(value string) string {
	str := SPACE_PATTERN.ReplaceAllString(value, "")
	return str
}

func parseDN(value string) (*goldap.DN, []string, []string, error) {
	d, err := goldap.ParseDN(value)
	if err != nil {
		log.Printf("warn: Invalid DN syntax. dn: %s", value)
		return nil, nil, nil, NewInvalidDNSyntax()
	}

	n := make([]string, len(d.RDNs))
	no := make([]string, len(d.RDNs))
	for i, v := range d.RDNs {
		nn := make([]string, len(v.Attributes))
		nno := make([]string, len(v.Attributes))
		for j, a := range v.Attributes {
			sv, err := NewSchemaValue(a.Type, []string{a.Value})
			if err != nil {
				log.Printf("warn: Invalid DN syntax. Not found in schema. dn: %s err: %+v", value, err)
				return nil, nil, nil, NewInvalidDNSyntax()
			}

			vv, err := sv.Normalize()
			if err != nil {
				log.Printf("warn: Invalid RDN of DN syntax. dn: %s", value)
				return nil, nil, nil, NewInvalidDNSyntax()
			}

			// TODO normalize type
			nn[j] = fmt.Sprintf("%s=%s", strings.ToLower(a.Type), vv[0])
			nno[j] = fmt.Sprintf("%s=%s", strings.ToLower(a.Type), a.Value)
		}
		n[i] = strings.Join(nn, ",")
		no[i] = strings.Join(nno, ",")
	}
	return d, n, no, nil
}

func normalizeDistinguishedName(value string) (string, error) {
	_, dnNorm, _, err := parseDN(value)
	if err != nil {
		return "", err
	}

	return strings.Join(dnNorm, ","), nil
}

func normalizeGeneralizedTime(value string) (string, error) {
	_, err := time.Parse(TIMESTAMP_FORMAT, value)
	if err != nil {
		return "", err
	}
	return value, nil
}

func normalizeUUID(value string) (string, error) {
	u, err := uuid.Parse(value)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func isNoResult(err error) bool {
	// see https://golang.org/pkg/database/sql/#pkg-variables
	return err == sql.ErrNoRows
}
