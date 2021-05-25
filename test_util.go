// +build integration

package main

import (
	"database/sql"
	"fmt"
	"log"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jsimonetti/pwscheme/ssha"
	"github.com/jsimonetti/pwscheme/ssha256"
	"github.com/jsimonetti/pwscheme/ssha512"
	_ "github.com/lib/pq"
	"golang.org/x/xerrors"
)

func IntegrationTestRunner(m *testing.M) int {
	// shutdown := SetupDBConn()
	// defer shutdown()

	s := setupLDAPServer()
	defer func() {
		s.Stop()

		i := 0
		for {
			if i > 10 {
				log.Fatalf("error: Failed to stop test ldap server within 10 seconds.")
			}

			_, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "localhost", 8389))
			if err != nil {
				break
			}
			time.Sleep(1 * time.Second)
			i++
		}
	}()

	// truncateTables()

	// SetupDefaultFixtures()

	// resetTimer := MockTimeNow()
	// defer resetTimer()

	return m.Run()
}

func runTestCases(t *testing.T, tcs []Command) {
	truncateTables()

	var conn *ldap.Conn
	var err error
	for i, tc := range tcs {
		conn, err = tc.Run(t, conn)
		if err != nil {
			t.Errorf("Unexpected error on testcase: %d %v, got error: %+v", i, tc, err)
			break
		}
	}
	time.Sleep(1 * time.Second)
	conn.Close()
}

type Command interface {
	Run(t *testing.T, conn *ldap.Conn) (*ldap.Conn, error)
}

type Parallel struct {
	count int
	ops   [][]Command
}

func (c Parallel) Run(t *testing.T, unused *ldap.Conn) (*ldap.Conn, error) {
	wg := &sync.WaitGroup{}

	for _, commands := range c.ops {
		cms := commands
		wg.Add(1)
		go func() {
			defer wg.Done()

			var conn *ldap.Conn
			var err error
			for i := 0; i < c.count; i++ {
				for i, tc := range cms {
					conn, err = tc.Run(t, conn)
					if err != nil {
						t.Errorf("Unexpected error on testcase: %d %v, got error: %+v", i, tc, err)
						break
					}
				}
			}
			time.Sleep(1 * time.Second)
			conn.Close()
		}()
	}
	wg.Wait()

	return unused, nil
}

type Conn struct{}

func (c Conn) Run(t *testing.T, conn *ldap.Conn) (*ldap.Conn, error) {
	var err error
	connect := func() {
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", "localhost", 8389))
	}
	if conn == nil {
		connect()
	} else {
		conn.Close()
		connect()
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type Bind struct {
	rdn      string
	password string
	assert   *AssertResponse
}

func (c Bind) Run(t *testing.T, conn *ldap.Conn) (*ldap.Conn, error) {
	err := conn.Bind(c.rdn+","+testServer.GetSuffix(), c.password)
	err = c.assert.AssertResponse(conn, err)
	return conn, err
}

func AddDC(dc string, parents ...string) Add {
	type A []string
	type M map[string][]string

	parentDN := strings.Join(parents, ",")

	return Add{
		"dc=" + dc,
		parentDN,
		M{
			"objectClass": A{"top", "dcObject", "organization"},
			"o":           A{dc},
		},
		nil,
	}
}

func AddOU(ou string, parents ...string) Add {
	type A []string
	type M map[string][]string

	parentDN := strings.Join(parents, ",")

	return Add{
		"ou=" + ou,
		parentDN,
		M{
			"objectClass": A{"organizationalUnit"},
		},
		&AssertEntry{},
	}
}

type Add struct {
	rdn    string
	baseDN string
	attrs  map[string][]string
	assert Assert
}

func (a Add) SetAssert(assert Assert) Add {
	a.assert = assert
	return a
}

type ModifyAdd struct {
	rdn    string
	baseDN string
	attrs  map[string][]string
	assert *AssertEntry
}

type ModifyReplace struct {
	rdn    string
	baseDN string
	attrs  map[string][]string
	assert *AssertEntry
}

type ModifyDelete struct {
	rdn    string
	baseDN string
	attrs  map[string][]string
	assert *AssertEntry
}

type ModifyDN struct {
	rdn           string
	baseDN        string
	newRDN        string
	delOld        bool
	newSup        string
	moveContainer bool
	assert        *AssertRename
}

type Delete struct {
	rdn    string
	baseDN string
	assert *AssertNoEntry
}

type Search struct {
	baseDN string
	filter string
	scope  int
	attrs  []string
	assert *AssertEntries
}

func (s Search) Run(t *testing.T, conn *ldap.Conn) (*ldap.Conn, error) {
	search := ldap.NewSearchRequest(
		s.baseDN,
		s.scope,
		ldap.NeverDerefAliases,
		0, // Size Limit
		0, // Time Limit
		false,
		"("+s.filter+")", // The filter to apply
		s.attrs,          // A list attributes to retrieve
		nil,
	)
	sr, err := conn.Search(search)
	if err != nil {
		return conn, err
	}

	if s.assert != nil {
		err = s.assert.AssertEntries(conn, err, sr)
		if err != nil {
			return conn, err
		}
	}

	return conn, nil
}

func resolveDN(rdn, baseDN string) string {
	dn := rdn
	if baseDN != "" {
		dn = rdn + `,` + baseDN
	}
	if !strings.HasPrefix(strings.ToLower(rdn), "dc=") {
		dn = dn + `,` + testServer.GetSuffix()
	}
	return dn
}

func (a Add) Run(t *testing.T, conn *ldap.Conn) (*ldap.Conn, error) {
	dn := resolveDN(a.rdn, a.baseDN)

	add := ldap.NewAddRequest(dn, nil)
	for k, v := range a.attrs {
		add.Attribute(k, v)
	}

	log.Printf("info: Exec add operation: %v", add)

	err := conn.Add(add)

	if a.assert != nil {
		err = a.assert.AssertEntry(conn, err, a.rdn, a.baseDN, a.attrs)
	}
	return conn, err
}

func (m ModifyAdd) Run(t *testing.T, conn *ldap.Conn) (*ldap.Conn, error) {
	dn := resolveDN(m.rdn, m.baseDN)

	modify := ldap.NewModifyRequest(dn, nil)
	for k, v := range m.attrs {
		modify.Add(k, v)
	}

	log.Printf("info: Exec modify(add) operation: %v", modify)

	err := conn.Modify(modify)

	if m.assert != nil {
		err = m.assert.AssertEntry(conn, err, m.rdn, m.baseDN, m.attrs)
	}
	return conn, err
}

func (m ModifyReplace) Run(t *testing.T, conn *ldap.Conn) (*ldap.Conn, error) {
	dn := resolveDN(m.rdn, m.baseDN)

	modify := ldap.NewModifyRequest(dn, nil)
	for k, v := range m.attrs {
		modify.Replace(k, v)
	}

	log.Printf("info: Exec modify(replace) operation: %v", modify)

	err := conn.Modify(modify)

	if m.assert != nil {
		err = m.assert.AssertEntry(conn, err, m.rdn, m.baseDN, m.attrs)
	}
	return conn, err
}

func (m ModifyDelete) Run(t *testing.T, conn *ldap.Conn) (*ldap.Conn, error) {
	dn := resolveDN(m.rdn, m.baseDN)

	modify := ldap.NewModifyRequest(dn, nil)
	for k, v := range m.attrs {
		modify.Delete(k, v)
	}

	log.Printf("info: Exec modify(delete) operation: %v", modify)

	err := conn.Modify(modify)

	if m.assert != nil {
		err = m.assert.AssertEntry(conn, err, m.rdn, m.baseDN, m.attrs)
	}
	return conn, err
}

func (m ModifyDN) Run(t *testing.T, conn *ldap.Conn) (*ldap.Conn, error) {
	dn := resolveDN(m.rdn, m.baseDN)
	var newSup = m.newSup
	if newSup != "" {
		newSup = newSup + "," + testServer.GetSuffix()
	}

	modifyDN := ldap.NewModifyDNRequest(dn, m.newRDN, m.delOld, newSup)

	log.Printf("info: Exec modifyDN operation: %v", modifyDN)

	err := conn.ModifyDN(modifyDN)

	if m.assert != nil {
		err = m.assert.AssertRename(conn, err, m.rdn, m.newRDN, m.baseDN, m.delOld, m.newSup, m.moveContainer)
	}
	return conn, err
}

func (d Delete) Run(t *testing.T, conn *ldap.Conn) (*ldap.Conn, error) {
	dn := resolveDN(d.rdn, d.baseDN)

	del := ldap.NewDelRequest(dn, nil)

	log.Printf("info: Exec delete operation: %v", del)

	err := conn.Del(del)

	if d.assert != nil {
		err = d.assert.AssertNoEntry(conn, err, d.rdn, d.baseDN)
	}
	return conn, err
}

type AssertResponse struct {
	expect uint16
}

func (a AssertResponse) AssertResponse(conn *ldap.Conn, err error) error {
	if a.expect == 0 {
		if err != nil {
			return xerrors.Errorf("Unexpected error response code. want: no error got: %w", err)
		}
	} else {
		if !ldap.IsErrorWithCode(err, a.expect) {
			return xerrors.Errorf("Unexpected error response code. want: %d got: %w", a.expect, err)
		}
	}
	return nil
}

func (a AssertResponse) AssertEntry(conn *ldap.Conn, err error, rdn, baseDN string, attrs map[string][]string) error {
	return a.AssertResponse(conn, err)
}

type Assert interface {
	AssertEntry(conn *ldap.Conn, err error, rdn, baseDN string, attrs map[string][]string) error
}

type AssertLDAPError struct {
	expectErrorCode uint16
}

func (a AssertLDAPError) AssertEntry(conn *ldap.Conn, err error, rdn, baseDN string, attrs map[string][]string) error {
	if ldap.IsErrorWithCode(err, a.expectErrorCode) {
		return nil
	}
	return xerrors.Errorf("Unexpected LDAP error response when previous operation. rdn: %s, want: %d  err: %w",
		rdn, a.expectErrorCode, err)
}

type AssertEntry struct {
	expectAttrs map[string][]string
}

func (a AssertEntry) AssertEntry(conn *ldap.Conn, err error, rdn, baseDN string, attrs map[string][]string) error {
	if err != nil {
		return xerrors.Errorf("Unexpected error response when previous operation. rdn: %s, err: %w", rdn, err)
	}
	sr, err := searchEntry(conn, "", baseDN, ldap.ScopeWholeSubtree, fmt.Sprintf("(%s)", rdn), nil)
	if err != nil {
		return xerrors.Errorf("Unexpected error when searching the entry. err: %w", err)
	}
	if len(sr.Entries) != 1 {
		return xerrors.Errorf("Unexpected entry count. want = [1] got = %d. searched by baseDN: %s", len(sr.Entries), baseDN)
	}
	var expectAttrs map[string][]string
	if len(a.expectAttrs) > 0 {
		expectAttrs = a.expectAttrs
	} else {
		expectAttrs = attrs
	}
	for k, expect := range expectAttrs {
		actual := sr.Entries[0].GetAttributeValues(k)
		if !reflect.DeepEqual(expect, actual) {
			return xerrors.Errorf("Unexpected entry attr [%s]. want = [%v] got = %d", k, expect, actual)
		}
	}
	return nil
}

type AssertEntries []ExpectEntry

func (e AssertEntries) AssertEntries(conn *ldap.Conn, err error, sr *ldap.SearchResult) error {
	if len(sr.Entries) != len(e) {
		return xerrors.Errorf("Unexpected entry size. want = [%d] got = %d", len(e), len(sr.Entries))
	}
	m := make(map[string]ExpectEntry, len(sr.Entries))
	for _, expect := range e {
		var dn string
		if expect.rdn == "" && expect.baseDN == "" {
			dn = ""
		} else if expect.rdn != "" && expect.baseDN == "" {
			dn = fmt.Sprintf("%s,%s", expect.rdn, testServer.GetSuffix())
		} else if expect.rdn == "" && expect.baseDN != "" {
			dn = fmt.Sprintf("%s", expect.baseDN)
		} else {
			dn = fmt.Sprintf("%s,%s,%s", expect.rdn, expect.baseDN, testServer.GetSuffix())
		}
		m[strings.ToLower(dn)] = expect
	}

	for _, v := range sr.Entries {
		expect, ok := m[strings.ToLower(v.DN)]
		if !ok {
			return xerrors.Errorf("Unexpected entry. want = [%v] got = dn: %s, entry: %v", m, v.DN, *v)
		}

		for k, expectAttrs := range expect.attrs {
			actual := v.GetAttributeValues(k)
			if !reflect.DeepEqual(expectAttrs, actual) {
				return xerrors.Errorf("Unexpected entry attr [%s]. want = [%v] got = %v", k, expectAttrs, actual)
			}
		}
	}
	return nil
}

type ExpectEntry struct {
	rdn    string
	baseDN string
	attrs  map[string][]string
}

type AssertSearchOne struct {
	baseDN      string
	filter      string
	reqAttrs    []string
	expectAttrs map[string][]string
}

func (s AssertSearchOne) AssertSearch(conn *ldap.Conn, err error) error {
	if err != nil {
		return xerrors.Errorf("Unexpected error response when previous operation. err: %w", err)
	}
	sr, err := searchEntry(conn, "", s.baseDN, ldap.ScopeWholeSubtree, fmt.Sprintf("(%s)", s.filter), s.reqAttrs)
	if err != nil {
		return xerrors.Errorf("Unexpected error when searching the entry. err: %w", err)
	}
	if len(sr.Entries) != 1 {
		return xerrors.Errorf("Unexpected entry count. want = [1] got = %d", len(sr.Entries))
	}
	for k, expect := range s.expectAttrs {
		actual := sr.Entries[0].GetAttributeValues(k)
		if !reflect.DeepEqual(expect, actual) {
			return xerrors.Errorf("Unexpected entry attr [%s]. want = [%v] got = %d", k, expect, actual)
		}
	}
	return nil
}

type AssertRename struct {
}

func (s AssertRename) AssertRename(conn *ldap.Conn, err error, oldRDN, newRDN, baseDN string, delOld bool, newSup string, moveContainer bool) error {
	if err != nil {
		return xerrors.Errorf("Unexpected error response when previous operation. err: %w", err)
	}

	// Fetch old entry with full dn (baseDN = target old DN)
	sr, err := searchEntry(conn, oldRDN, baseDN, ldap.ScopeWholeSubtree, "(objectClass=*)", nil)

	if newSup == "" {
		// No move case
		if oldRDN == newRDN {
			// No RDN change case, should returns 1 entry
			if err != nil {
				return xerrors.Errorf("Unexpected error when searching the renamed entry. err: %w", err)
			}
			if len(sr.Entries) != 1 {
				return xerrors.Errorf("Unexpected new renamed count. want = [1] got = %d", len(sr.Entries))
			}
		} else {
			// RDN change case, should returns no search result (0) for old entry
			if err != nil {
				return xerrors.Errorf("Unexpected error when searching the old entry. err: %w", err)
			}
			if len(sr.Entries) != 0 {
				return xerrors.Errorf("Unexpected search result for old RDN. Should returns no search result (0). oldRDN: %v, newRDN: %v",
					oldRDN, newRDN)
			}
		}

		// Fetch new entry with full dn (baseDN = target new DN)
		sr, err = searchEntry(conn, newRDN, baseDN, ldap.ScopeWholeSubtree, "(objectClass=*)", nil)
		if err != nil {
			return xerrors.Errorf("Unexpected error when searching the renamed entry. err: %w", err)
		}
		if len(sr.Entries) != 1 {
			return xerrors.Errorf("Unexpected new renamed count. want = [1] got = %d", len(sr.Entries))
		}

		or := strings.Split(oldRDN, "=")
		actualRDNs := sr.Entries[0].GetAttributeValues(or[0])
		for _, v := range actualRDNs {
			if v == or[1] {
				if oldRDN != newRDN && delOld {
					return xerrors.Errorf("Unexpected old rdn. want deleted got = %s", v)
				}
			}
		}
	} else {
		// Move case, should returns no search result (0) for old entry
		if err != nil {
			return xerrors.Errorf("Unexpected error when searching the old entry. err: %w", err)
		}
		if len(sr.Entries) != 0 {
			return xerrors.Errorf("Unexpected search result for old RDN. Should returns no search result (0). oldRDN: %v, newRDN: %v",
				oldRDN, newRDN)
		}

		// Fetch new entry with full dn (baseDN = target new DN)
		sr, err = searchEntry(conn, newRDN, newSup, ldap.ScopeWholeSubtree, "(objectClass=*)", nil)
		if err != nil {
			return xerrors.Errorf("Unexpected error when searching the renamed entry. err: %w", err)
		}

		if !moveContainer {
			if len(sr.Entries) != 1 {
				return xerrors.Errorf("Unexpected new renamed count. want = [1] got = %d", len(sr.Entries))
			}
			or := strings.Split(oldRDN, "=")
			actualRDNs := sr.Entries[0].GetAttributeValues(or[0])
			for _, v := range actualRDNs {
				if v == or[1] {
					if oldRDN != newRDN && delOld {
						return xerrors.Errorf("Unexpected old rdn. want deleted got = %s", v)
					}
				}
			}
		} else {
			if len(sr.Entries) == 0 {
				return xerrors.Errorf("Unexpected new renamed count. want >= [1] got = %d", len(sr.Entries))
			}
		}
	}
	// TODO support newSup
	return nil
}

type AssertNoEntry struct {
}

func (n AssertNoEntry) AssertNoEntry(conn *ldap.Conn, err error, rdn, baseDN string) error {
	if err != nil {
		return xerrors.Errorf("Unexpected error response when previous operation. err: %w", err)
	}

	sr, err := searchEntry(conn, "", baseDN, ldap.ScopeWholeSubtree, fmt.Sprintf("(%s)", rdn), nil)
	// expected return success
	if err != nil {
		return xerrors.Errorf("Unexpected error when searching the deleted entry. err: %w", err)
	}
	if len(sr.Entries) != 0 {
		return xerrors.Errorf("Unexpected error when searching the deleted entry. Hit count: %d", len(sr.Entries))
	}

	return nil
}

func SSHA(p string) string {
	h, _ := ssha.Generate(p, 8)
	return h
}

func SSHA256(p string) string {
	h, _ := ssha256.Generate(p, 8)
	return h
}

func SSHA512(p string) string {
	h, _ := ssha512.Generate(p, 8)
	return h
}

func deleteEntry(c *ldap.Conn, rdn string) error {
	del := ldap.NewDelRequest(rdn+","+testServer.GetSuffix(), nil)
	return c.Del(del)
}

func searchEntry(c *ldap.Conn, rdn, baseDN string, scope int, filter string, attrs []string) (*ldap.SearchResult, error) {
	bd := testServer.GetSuffix()
	if baseDN != "" {
		bd = baseDN + "," + bd
	}
	if rdn != "" {
		bd = rdn + "," + bd
	}

	log.Printf("info: searchEntry. baseDN: %s, scope: %d, filter: %s, reqAttrs: %v", bd, scope, filter, attrs)

	search := ldap.NewSearchRequest(
		bd,
		scope,
		ldap.NeverDerefAliases,
		0, // Size Limit
		0, // Time Limit
		false,
		filter, // The filter to apply
		attrs,  // A list attributes to retrieve
		nil,
	)
	sr, err := c.Search(search)
	if err != nil {
		if !ldap.IsErrorWithCode(err, 32) {
			log.Printf("error: search error: baseDN: %s, filter: %s", bd, filter)
		}
		return nil, err
	}

	return sr, nil
}

// You can boot the postgres server for tests using docker.
//
/*
docker run --rm -e POSTGRES_DB=ldap -e POSTGRES_USER=dev  -e POSTGRES_PASSWORD=dev -p 35432:5432 -v (pwd)/misc:/docker-entrypoint-initdb.d postgres:12-alpine \
  -c log_destination=stderr \
  -c log_statement=all \
  -c log_connections=on \
  -c log_disconnections=on \
  -c jit=off
*/

var testPGPort int = 35432

func setupLDAPServer() *Server {
	go func() {
		testServer = NewServer(&ServerConfig{
			DBHostName:      "localhost",
			DBPort:          testPGPort,
			DBName:          "ldap",
			DBSchema:        "public",
			DBUser:          "dev",
			DBPassword:      "dev",
			DBMaxOpenConns:  2,
			DBMaxIdleConns:  1,
			Suffix:          "dc=example,dc=com",
			RootDN:          "cn=Manager,dc=example,dc=com",
			RootPW:          "secret",
			BindAddress:     "127.0.0.1:8389",
			LogLevel:        "warn",
			PProfServer:     "127.0.0.1:10000",
			GoMaxProcs:      0,
			QueryTranslator: "default",
		})
		testServer.Start()
	}()

	i := 0
	for {
		if i > 10 {
			log.Fatalf("Failed to start test ldap server within 10 seconds.")
		}

		_, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "localhost", 8389))
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
		i++
	}
	return testServer
}

func truncateTables() {
	log.Printf("info: Truncate tables")

	db, err := sql.Open("postgres", fmt.Sprintf("host=127.0.0.1 port=%d user=dev password=dev dbname=ldap sslmode=disable search_path=public", testPGPort))
	if err != nil {
		log.Fatal("db connection error:", err)
	}
	defer db.Close()

	_, err = db.Exec("TRUNCATE ldap_entry, ldap_container, ldap_association")
	if err != nil {
		log.Fatal("truncate table error:", err)
	}
}
