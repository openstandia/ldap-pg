package main

import (
	"bytes"
	"database/sql"
	enchex "encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/openstandia/goldap/message"
	ldap "github.com/openstandia/ldapserver"
	"golang.org/x/xerrors"
	ber "gopkg.in/asn1-ber.v1"
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
	if dn, ok := session["dn"]; ok {
		log.Printf("info: Authorized. authorizedDN: %s, targetDN: %s", dn.DNNormStr(), targetDN.DNNormStr())

		// TODO authz

		return true
	}

	log.Printf("warn: Not Authorized for anonymous. targetDN: %s", targetDN.DNNormStr())

	return false
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
		if strings.EqualFold(string(attr), "memberof") || string(attr) == "+" {
			return true
		}
	}
	return false
}

func isHasSubOrdinatesRequested(r message.SearchRequest) bool {
	for _, attr := range r.Attributes() {
		if strings.EqualFold(string(attr), "hassubordinates") || string(attr) == "+" {
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
		a := string(attr)

		// TODO move to schema
		if strings.EqualFold(a, "member") {
			list = append(list, "member")
		}
		if strings.EqualFold(a, "uniquemember") {
			list = append(list, "uniqueMember")
		}
	}
	return list
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
	case "uniqueMemberMatch":
		nv, err := normalizeDistinguishedName(value)
		if err != nil {
			// fallback
			return strings.ToLower(normalizeSpace(value)), nil
		}
		return nv, nil
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

// ParseDN returns a distinguishedName or an error.
// The function respects https://tools.ietf.org/html/rfc4514
// This function based on go-ldap/ldap/v3.
func ParseDN(str string) (*DN, error) {
	dn := new(DN)
	dn.RDNs = make([]*RelativeDN, 0)
	rdn := new(RelativeDN)
	rdn.Attributes = make([]*AttributeTypeAndValue, 0)
	buffer := bytes.Buffer{}
	attribute := new(AttributeTypeAndValue)
	escaping := false

	unescapedTrailingSpaces := 0
	stringTypeFromBuffer := func() string {
		s := buffer.String()
		s = s[0 : len(s)-unescapedTrailingSpaces]
		buffer.Reset()
		unescapedTrailingSpaces = 0
		return s
	}
	stringValueFromBuffer := func(t string) (string, string, error) {
		orig := stringTypeFromBuffer()

		sv, err := NewSchemaValue(t, []string{orig})
		if err != nil {
			log.Printf("warn: Invalid DN syntax. Not found in schema. dn: %s err: %+v", str, err)
			return "", "", NewInvalidDNSyntax()
		}

		norm, err := sv.Normalize()
		if err != nil {
			log.Printf("warn: Invalid RDN of DN syntax. dn: %s", str)
			return "", "", NewInvalidDNSyntax()
		}

		return orig, norm[0], nil
	}

	for i := 0; i < len(str); i++ {
		char := str[i]
		switch {
		case escaping:
			unescapedTrailingSpaces = 0
			escaping = false
			switch char {
			case ' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\':
				buffer.WriteByte(char)
				continue
			}
			// Not a special character, assume hex encoded octet
			if len(str) == i+1 {
				return nil, xerrors.New("got corrupted escaped character")
			}

			dst := []byte{0}
			n, err := enchex.Decode([]byte(dst), []byte(str[i:i+2]))
			if err != nil {
				return nil, fmt.Errorf("failed to decode escaped character: %s", err)
			} else if n != 1 {
				return nil, fmt.Errorf("expected 1 byte when un-escaping, got %d", n)
			}
			buffer.WriteByte(dst[0])
			i++
		case char == '\\':
			unescapedTrailingSpaces = 0
			escaping = true
		case char == '=':
			attribute.TypeOrig = stringTypeFromBuffer()
			attribute.TypeNorm = strings.ToLower(attribute.TypeOrig)
			// Special case: If the first character in the value is # the
			// following data is BER encoded so we can just fast forward
			// and decode.
			if len(str) > i+1 && str[i+1] == '#' {
				i += 2
				index := strings.IndexAny(str[i:], ",+")
				data := str
				if index > 0 {
					data = str[i : i+index]
				} else {
					data = str[i:]
				}
				rawBER, err := enchex.DecodeString(data)
				if err != nil {
					return nil, fmt.Errorf("failed to decode BER encoding: %s", err)
				}
				packet, err := ber.DecodePacketErr(rawBER)
				if err != nil {
					return nil, fmt.Errorf("failed to decode BER packet: %s", err)
				}
				buffer.WriteString(packet.Data.String())
				i += len(data) - 1
			}
		case char == ',' || char == '+':
			// We're done with this RDN or value, push it
			if len(attribute.TypeOrig) == 0 {
				return nil, errors.New("incomplete type, value pair")
			}
			orig, norm, err := stringValueFromBuffer(attribute.TypeNorm)
			if err != nil {
				return nil, xerrors.Errorf("failed to normalize dn: %w", err)
			}
			attribute.ValueOrig = orig
			attribute.ValueNorm = norm
			rdn.Attributes = append(rdn.Attributes, attribute)
			attribute = new(AttributeTypeAndValue)
			if char == ',' {
				dn.RDNs = append(dn.RDNs, rdn)
				rdn = new(RelativeDN)
				rdn.Attributes = make([]*AttributeTypeAndValue, 0)
			}
		case char == ' ' && buffer.Len() == 0:
			// ignore unescaped leading spaces
			continue
		default:
			if char == ' ' {
				// Track unescaped spaces in case they are trailing and we need to remove them
				unescapedTrailingSpaces++
			} else {
				// Reset if we see a non-space char
				unescapedTrailingSpaces = 0
			}
			buffer.WriteByte(char)
		}
	}
	if buffer.Len() > 0 {
		if len(attribute.TypeOrig) == 0 {
			return nil, errors.New("DN ended with incomplete type, value pair")
		}
		orig, norm, err := stringValueFromBuffer(attribute.TypeNorm)
		if err != nil {
			return nil, xerrors.Errorf("failed to normalize dn: %w", err)
		}
		attribute.ValueOrig = orig
		attribute.ValueNorm = norm
		rdn.Attributes = append(rdn.Attributes, attribute)
		dn.RDNs = append(dn.RDNs, rdn)
	}
	return dn, nil
}

func normalizeDistinguishedName(value string) (string, error) {
	dn, err := NormalizeDN(value)
	if err != nil {
		return "", err
	}

	return dn.DNNormStr(), nil
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

func namedStmt(tx *sqlx.Tx, stmt *sqlx.NamedStmt) *sqlx.NamedStmt {
	if tx != nil {
		return tx.NamedStmt(stmt)
	}
	return stmt
}

func txLabel(tx *sqlx.Tx) string {
	if tx == nil {
		return "non-tx"
	}
	return "tx"
}

func rollback(tx *sqlx.Tx) {
	err := tx.Rollback()
	if err != nil {
		log.Printf("warn: Detect error when rollback, ignore it. err: %v", err)
	}
}

func commit(tx *sqlx.Tx) error {
	err := tx.Commit()
	if err != nil {
		log.Printf("warn: Detect error when commit, do rollback. err: %v", err)
		rollback(tx)
	}
	return err
}
