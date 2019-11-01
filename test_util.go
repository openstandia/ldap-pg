// +build integration

package main

import (
	"database/sql"
	"fmt"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/jsimonetti/pwscheme/ssha"
	"github.com/jsimonetti/pwscheme/ssha256"
	"github.com/jsimonetti/pwscheme/ssha512"
	_ "github.com/lib/pq"
	"golang.org/x/xerrors"
	"gopkg.in/ldap.v3"
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
				log.Fatalf("error: Faild to stop test ldap server within 10 seconds.")
			}

			_, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "localhost", 8389))
			if err != nil {
				break
			}
			time.Sleep(1 * time.Second)
			i++
		}
	}()

	// createTablesIfNotExist()
	//truncateTables()

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
		conn, err = tc.Run(conn)
		if err != nil {
			t.Errorf("Unexpected error on testcase: %d, got error: %+v", i, err)
			break
		}
	}
	time.Sleep(1 * time.Second)
	conn.Close()
}

type Command interface {
	Run(conn *ldap.Conn) (*ldap.Conn, error)
}

type Conn struct{}

func (c Conn) Run(conn *ldap.Conn) (*ldap.Conn, error) {
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

func (c Bind) Run(conn *ldap.Conn) (*ldap.Conn, error) {
	err := conn.Bind(c.rdn+","+server.GetSuffix(), c.password)
	err = c.assert.AssertResponse(conn, err)
	return conn, err
}

type Add struct {
	rdn    string
	baseDN string
	attrs  map[string][]string
	assert *AssertEntry
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
	rdn    string
	baseDN string
	newRDN string
	delOld bool
	newSup string
	assert *AssertRename
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
}

func (s Search) Run(conn *ldap.Conn) (*ldap.Conn, error) {
	sr, err := searchEntry(conn, "", s.baseDN, s.scope, fmt.Sprintf("(%s)", s.filter), nil)
	if err != nil {
		return conn, err
	}
	for _, v := range sr.Entries {
		v.PrettyPrint(4)
	}
	return conn, nil
}

func (a Add) Run(conn *ldap.Conn) (*ldap.Conn, error) {
	var dn string
	if a.baseDN != "" {
		dn = fmt.Sprintf("%s,%s,%s", a.rdn, a.baseDN, server.GetSuffix())
	} else {
		dn = fmt.Sprintf("%s,%s", a.rdn, server.GetSuffix())
	}
	add := ldap.NewAddRequest(dn, nil)
	for k, v := range a.attrs {
		add.Attribute(k, v)
	}
	err := conn.Add(add)

	if a.assert != nil {
		err = a.assert.AssertEntry(conn, err, a.rdn, a.baseDN, a.attrs)
	}
	return conn, err
}

func (m ModifyAdd) Run(conn *ldap.Conn) (*ldap.Conn, error) {
	var dn string
	if m.baseDN != "" {
		dn = fmt.Sprintf("%s,%s,%s", m.rdn, m.baseDN, server.GetSuffix())
	} else {
		dn = fmt.Sprintf("%s,%s", m.rdn, server.GetSuffix())
	}
	modify := ldap.NewModifyRequest(dn, nil)
	for k, v := range m.attrs {
		modify.Add(k, v)
	}
	err := conn.Modify(modify)

	if m.assert != nil {
		err = m.assert.AssertEntry(conn, err, m.rdn, m.baseDN, m.attrs)
	}
	return conn, err
}

func (m ModifyReplace) Run(conn *ldap.Conn) (*ldap.Conn, error) {
	var dn string
	if m.baseDN != "" {
		dn = fmt.Sprintf("%s,%s,%s", m.rdn, m.baseDN, server.GetSuffix())
	} else {
		dn = fmt.Sprintf("%s,%s", m.rdn, server.GetSuffix())
	}
	modify := ldap.NewModifyRequest(dn, nil)
	for k, v := range m.attrs {
		modify.Replace(k, v)
	}
	err := conn.Modify(modify)

	if m.assert != nil {
		err = m.assert.AssertEntry(conn, err, m.rdn, m.baseDN, m.attrs)
	}
	return conn, err
}

func (m ModifyDelete) Run(conn *ldap.Conn) (*ldap.Conn, error) {
	var dn string
	if m.baseDN != "" {
		dn = fmt.Sprintf("%s,%s,%s", m.rdn, m.baseDN, server.GetSuffix())
	} else {
		dn = fmt.Sprintf("%s,%s", m.rdn, server.GetSuffix())
	}
	modify := ldap.NewModifyRequest(dn, nil)
	for k, v := range m.attrs {
		modify.Delete(k, v)
	}
	err := conn.Modify(modify)

	if m.assert != nil {
		err = m.assert.AssertEntry(conn, err, m.rdn, m.baseDN, m.attrs)
	}
	return conn, err
}

func (m ModifyDN) Run(conn *ldap.Conn) (*ldap.Conn, error) {
	var dn string
	if m.baseDN != "" {
		dn = fmt.Sprintf("%s,%s,%s", m.rdn, m.baseDN, server.GetSuffix())
	} else {
		dn = fmt.Sprintf("%s,%s", m.rdn, server.GetSuffix())
	}
	modifyDN := ldap.NewModifyDNRequest(dn, m.newRDN, m.delOld, m.newSup)
	err := conn.ModifyDN(modifyDN)

	if m.assert != nil {
		err = m.assert.AssertRename(conn, err, m.rdn, m.newRDN, m.baseDN, m.delOld, m.newSup)
	}
	return conn, err
}

func (d Delete) Run(conn *ldap.Conn) (*ldap.Conn, error) {
	var dn string
	if d.baseDN != "" {
		dn = fmt.Sprintf("%s,%s,%s", d.rdn, d.baseDN, server.GetSuffix())
	} else {
		dn = fmt.Sprintf("%s,%s", d.rdn, server.GetSuffix())
	}
	del := ldap.NewDelRequest(dn, nil)
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
		return xerrors.Errorf("Unexpected entry count. want = [1] got = %d", len(sr.Entries))
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

func (s AssertRename) AssertRename(conn *ldap.Conn, err error, oldRDN, newRDN, baseDN string, delOld bool, newSup string) error {
	if err != nil {
		return xerrors.Errorf("Unexpected error response when previous operation. err: %w", err)
	}

	sr, err := searchEntry(conn, "", baseDN, ldap.ScopeWholeSubtree, fmt.Sprintf("(%s)", oldRDN), nil)
	if delOld {
		if err != nil && !ldap.IsErrorWithCode(err, 32) {
			return xerrors.Errorf("Unexpected error when searching the old entry. err: %w", err)
		}
	} else {
		if len(sr.Entries) != 1 {
			return xerrors.Errorf("Unexpected old entry count. want = [1] got = %d", len(sr.Entries))
		}
	}

	sr, err = searchEntry(conn, "", baseDN, ldap.ScopeWholeSubtree, fmt.Sprintf("(%s)", newRDN), nil)
	if err != nil {
		return xerrors.Errorf("Unexpected error when searching the renamed entry. err: %w", err)
	}
	if len(sr.Entries) != 1 {
		return xerrors.Errorf("Unexpected new renamed count. want = [1] got = %d", len(sr.Entries))
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

	_, err = searchEntry(conn, "", baseDN, ldap.ScopeWholeSubtree, fmt.Sprintf("(%s)", rdn), nil)
	if !ldap.IsErrorWithCode(err, 32) {
		return xerrors.Errorf("Unexpected error when searching the deleted entry. err: %w", err)
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
	del := ldap.NewDelRequest(rdn+","+server.GetSuffix(), nil)
	return c.Del(del)
}

func searchEntry(c *ldap.Conn, rdn, baseDN string, scope int, filter string, attrs []string) (*ldap.SearchResult, error) {
	bd := server.GetSuffix()
	if baseDN != "" {
		bd = baseDN + "," + bd
	}

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
		return nil, err
	}

	return sr, nil
}

func setupLDAPServer() *Server {
	go func() {
		server = NewServer(&ServerConfig{
			DBHostName:     "localhost",
			DBPort:         5432,
			DBName:         "ldap",
			DBUser:         "dev",
			DBPassword:     "dev",
			DBMaxOpenConns: 2,
			DBMaxIdleConns: 1,
			Suffix:         "dc=example,dc=com",
			RootDN:         "cn=Manager,dc=example,dc=com",
			RootPW:         "secret",
			BindAddress:    "127.0.0.1.8389",
			LogLevel:       "debug",
			PProfServer:    "",
			GoMaxProcs:     0,
		})
		server.Start()
	}()

	i := 0
	for {
		if i > 10 {
			log.Fatalf("Faild to start test ldap server within 10 seconds.")
		}

		_, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "localhost", 8389))
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
		i++
	}
	return server
}

func truncateTables() {
	db, err := sql.Open("postgres", "host=127.0.0.1 port=5432 user=dev password=dev dbname=ldap sslmode=disable")
	if err != nil {
		log.Fatal("db connection error:", err)
	}
	defer db.Close()

	_, err = db.Exec("TRUNCATE ldap_entry")
	if err != nil {
		log.Fatal("truncate table error:", err)
	}
}
