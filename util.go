package main

import (
	"bytes"
	"database/sql"
	enchex "encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/jmoiron/sqlx/types"
	"github.com/lib/pq"
	"github.com/openstandia/goldap/message"
	ldap "github.com/openstandia/ldapserver"
	"golang.org/x/xerrors"
	ber "gopkg.in/asn1-ber.v1"
)

const TIMESTAMP_FORMAT string = "20060102150405Z"
const TIMESTAMP_NANO_FORMAT string = "20060102150405.000000Z"

type AuthSession struct {
	DN     *DN
	Groups []*DN
	IsRoot bool
}

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

func getAuthSession(m *ldap.Message) *AuthSession {
	session := getSession(m)
	if authSession, ok := session["auth"]; ok {
		return authSession.(*AuthSession)
	} else {
		authSession := &AuthSession{}
		session["auth"] = authSession
		return authSession
	}
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

func mergeMultipleValues(s *AttributeType, vals []interface{}, jsonMap map[string]interface{}) error {
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

func hasDuplicate(s *AttributeType, arr []string) (int, bool) {
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

func normalize(s *AttributeType, value string, index int) (interface{}, error) {
	switch s.Equality {
	case "caseExactMatch":
		return normalizeSpace(value), nil
	case "caseIgnoreMatch":
		return strings.ToLower(normalizeSpace(value)), nil
	case "distinguishedNameMatch":
		return normalizeDistinguishedName(s, value, index)
	case "caseExactIA5Match":
		return normalizeSpace(value), nil
	case "caseIgnoreIA5Match":
		return strings.ToLower(normalizeSpace(value)), nil
	case "generalizedTimeMatch":
		return normalizeGeneralizedTime(s, value, index)
	case "objectIdentifierMatch":
		return strings.ToLower(value), nil
	case "numericStringMatch":
		return removeAllSpace(value), nil
	case "integerMatch":
		i, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			// Invalid syntax (21)
			// additional info: pwdLockoutDuration: value #0 invalid per syntax
			return 0, NewInvalidPerSyntax(s.Name, index)
		}
		return i, nil
	case "booleanMatch":
		return normalizeBoolean(s, value, index)
	case "UUIDMatch":
		return normalizeUUID(value)
	case "uniqueMemberMatch":
		nv, err := normalizeDistinguishedName(s, value, index)
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
func ParseDN(schemaMap *SchemaMap, str string) (*DN, error) {
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

		sv, err := NewSchemaValue(schemaMap, t, []string{orig})
		if err != nil {
			log.Printf("warn: Invalid DN syntax. dn_orig: %s err: %v", str, err)
			return "", "", NewInvalidDNSyntax()
		}

		return orig, sv.NormStr()[0], nil
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
			attribute.ValueOrigEncoded = encodeDN(orig)
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
		attribute.ValueOrigEncoded = encodeDN(orig)
		attribute.ValueNorm = norm
		rdn.Attributes = append(rdn.Attributes, attribute)
		dn.RDNs = append(dn.RDNs, rdn)
	}
	return dn, nil
}

func normalizeDistinguishedName(s *AttributeType, value string, index int) (*DN, error) {
	dn, err := NormalizeDN(s.schemaDef, value)
	if err != nil {
		return nil, NewInvalidPerSyntax(s.Name, index)
	}

	// Return original DN
	return dn, nil
}

func normalizeGeneralizedTime(s *AttributeType, value string, index int) (int64, error) {
	t, err := time.Parse(TIMESTAMP_FORMAT, value)
	if err != nil {
		return 0, NewInvalidPerSyntax(s.Name, index)
	}
	return t.Unix(), nil
}

func normalizeBoolean(s *AttributeType, value string, index int) (string, error) {
	// The spec says Boolean = "TRUE" / "FALSE"
	// https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.3
	if value != "TRUE" && value != "FALSE" {
		return "", NewInvalidPerSyntax(s.Name, index)
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

func isDuplicateKeyError(err error) bool {
	// The error code is 23505.
	// see https://www.postgresql.org/docs/13/errcodes-appendix.html
	if err, ok := err.(*pq.Error); ok {
		return err.Code == pq.ErrorCode("23505")
	}
	return false
}

func isForeignKeyError(err error) bool {
	// The error code is 23503.
	// see https://www.postgresql.org/docs/13/errcodes-appendix.html
	if err, ok := err.(*pq.Error); ok {
		return err.Code == pq.ErrorCode("23503")
	}
	return false
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

func resolveSuffix(s *Server, dnOrig string) string {
	// Suffix DN or Level 1 DN have comma with end
	if strings.HasSuffix(dnOrig, ",") {
		// Detect whether the dnOrig is Suffix DN (The DN should have same RDN)
		if s.Suffix.RDNNormStr() == strings.ToLower(strings.TrimSuffix(dnOrig, ",")) {
			dnOrig = s.SuffixOrigStr()
		} else {
			dnOrig += s.SuffixOrigStr()
		}
	} else {
		dnOrig += "," + s.SuffixOrigStr()
	}
	return dnOrig
}

func sortObjectClasses(s *SchemaMap, objectClasses []*ObjectClass) {
	sort.Slice(objectClasses, func(i, j int) bool {
		sup := objectClasses[i].Sup

		for {
			// Top level
			if sup == "" {
				return false
			}

			oc, _ := s.ObjectClass(sup)
			if oc.Name == objectClasses[j].Name {
				return true
			}
			// next
			sup = oc.Sup
		}
	})
}

func verifyChainedObjectClasses(s *SchemaMap, objectClasses []*ObjectClass) *LDAPError {
	for i := range objectClasses {
		if i > 0 {
			prev := objectClasses[i-1]
			cur := objectClasses[i]

			sup := prev.Sup

			for {
				if sup == "" {
					// e.g.
					// ldap_add: Object class violation (65)
					//   additional info: invalid structural object class chain (person/groupOfUniqueNames)
					return NewObjectClassViolationInvalidStructualChain(objectClasses[0].Name, objectClasses[i].Name)
				}
				supOC, _ := s.ObjectClass(sup)
				if supOC.Name == cur.Name {
					break
				}

				// next
				sup = supOC.Sup
			}
		}
	}

	return nil
}

type StringSet map[string]struct{}

func NewStringSet(str ...string) StringSet {
	set := StringSet{}
	for _, v := range str {
		set.Add(v)
	}
	return set
}

func (s StringSet) Add(str string) {
	s[str] = struct{}{}
}

func (s StringSet) Size() int {
	return len(s)
}

func (s StringSet) First() string {
	// TODO Store the order of the map
	for k, _ := range s {
		return k
	}
	return ""
}

func (s StringSet) Contains(str string) bool {
	_, ok := s[str]
	return ok
}

func (s StringSet) Values() []string {
	rtn := make([]string, s.Size())
	i := 0
	for k, _ := range s {
		rtn[i] = k
		i++
	}
	return rtn
}

func timeToJSONAttrs(format string, t *time.Time) (types.JSONText, types.JSONText) {
	norm := []int64{t.Unix()}
	orig := []string{t.In(time.UTC).Format(format)}

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	return types.JSONText(bNorm), types.JSONText(bOrig)
}

func nowTimeToJSONAttrs(format string) (types.JSONText, types.JSONText) {
	now := time.Now()

	norm := []int64{now.Unix()}
	orig := []string{now.In(time.UTC).Format(format)}

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	return types.JSONText(bNorm), types.JSONText(bOrig)
}

func emptyJSONArray() (types.JSONText, types.JSONText) {
	norm := make([]string, 0)
	orig := make([]string, 0)

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	return types.JSONText(bNorm), types.JSONText(bOrig)
}

func timesToJSONAttrs(format string, t []*time.Time) (types.JSONText, types.JSONText) {
	norm := make([]int64, len(t))
	orig := make([]string, len(t))

	for i, v := range t {
		norm[i] = v.Unix()
		orig[i] = v.In(time.UTC).Format(format)
	}

	bNorm, _ := json.Marshal(norm)
	bOrig, _ := json.Marshal(orig)

	return types.JSONText(bNorm), types.JSONText(bOrig)
}

func mergeIndex(m1, m2 map[string]struct{}) map[string]struct{} {
	m := make(map[string]struct{}, len(m1)+len(m2))
	for k, v := range m1 {
		m[k] = v
	}
	for k, v := range m2 {
		m[k] = v
	}
	return m
}
