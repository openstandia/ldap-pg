// +build integration

package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jsimonetti/pwscheme/ssha"
	"github.com/jsimonetti/pwscheme/ssha256"
	"github.com/jsimonetti/pwscheme/ssha512"
	_ "github.com/lib/pq"
	"gopkg.in/ldap.v3"
)

var server *Server

func TestMain(m *testing.M) {
	os.Exit(IntegrationTestRunner(m))
}

func IntegrationTestRunner(m *testing.M) int {
	// shutdown := SetupDBConn()
	// defer shutdown()

	setupLDAPServer()

	// createTablesIfNotExist()
	truncateTables()

	// SetupDefaultFixtures()

	// resetTimer := MockTimeNow()
	// defer resetTimer()

	return m.Run()
}

func TestLDAPBind(t *testing.T) {
	c, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "localhost", 8389))
	if err != nil {
		t.Fatalf("Can't connect: %v", err)
	}
	defer c.Close()

	err = c.Bind("cn=Manager", "invalid")
	if !ldap.IsErrorWithCode(err, 49) {
		t.Fatalf("want = %d, got = %v", 49, err)
	}

	err = c.Bind("cn=Manager", "secret")
	if err != nil {
		t.Fatalf("want = nil, got = %v", err)
	}
}

func TestLDAPCRUD(t *testing.T) {
	c, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", "localhost", 8389))
	if err != nil {
		t.Fatalf("Can't connect: %v", err)
	}
	defer c.Close()

	err = c.Bind("cn=Manager", "secret")
	if err != nil {
		t.Fatalf("Can't bind: %v", err)
	}

	err = addEntry(c, "ou=Users", map[string][]string{
		"objectClass": []string{"organizationalUnit"},
	})
	if err != nil {
		t.Fatalf("Can't add: %v", err)
	}
	err = addEntry(c, "ou=Groups", map[string][]string{
		"objectClass": []string{"organizationalUnit"},
	})
	if err != nil {
		t.Fatalf("Can't add: %v", err)
	}
	err = addEntry(c, "uid=user1,ou=Users", map[string][]string{
		"objectClass":  []string{"inetOrgPerson"},
		"sn":           []string{"user1"},
		"userPassword": []string{toSsha("password")},
	})
	if err != nil {
		t.Fatalf("Can't add: %v", err)
	}
	err = addEntry(c, "uid=user2,ou=Users", map[string][]string{
		"objectClass":  []string{"inetOrgPerson"},
		"sn":           []string{"user2"},
		"userPassword": []string{toSsha256("password")},
	})
	if err != nil {
		t.Fatalf("Can't add: %v", err)
	}
	err = addEntry(c, "cn=top,ou=Groups", map[string][]string{
		"objectClass": []string{"groupOfNames"},
		"member":      []string{"cn=A,ou=Groups," + server.GetSuffix()},
	})
	if err != nil {
		t.Fatalf("Can't add: %v", err)
	}
	err = addEntry(c, "cn=A,ou=Groups", map[string][]string{
		"objectClass": []string{"groupOfNames"},
		"member": []string{
			"cn=A_1,ou=Groups," + server.GetSuffix(),
			"cn=A_2,ou=Groups," + server.GetSuffix(),
		},
	})
	if err != nil {
		t.Fatalf("Can't add: %v", err)
	}
	err = addEntry(c, "cn=A_1,ou=Groups", map[string][]string{
		"objectClass": []string{"groupOfNames"},
		"member":      []string{"uid=user1,ou=Users," + server.GetSuffix()},
	})
	if err != nil {
		t.Fatalf("Can't add: %v", err)
	}
	err = addEntry(c, "cn=A_2,ou=Groups", map[string][]string{
		"objectClass": []string{"groupOfNames"},
		"member":      []string{"uid=user2,ou=Users," + server.GetSuffix()},
	})
	if err != nil {
		t.Fatalf("Can't add: %v", err)
	}
	err = modifyEntry(c, "uid=user1,ou=Users", []change{
		{
			changetype: "add",
			attrName:   "givenName",
			attrValue:  []string{"foo"},
		},
	})
	if err != nil {
		t.Fatalf("Can't modify/add: %v", err)
	}

	sr, err := searchEntry(c, "", ldap.ScopeWholeSubtree, "(uid=user1)", nil)
	if err != nil {
		t.Fatalf("Can't search: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Fatalf("Can't search: %v", sr)
	}
	for _, entry := range sr.Entries {
		if entry.DN != "uid=user1,ou=users,"+server.GetSuffix() {
			t.Fatalf("want = uid=user1,ou=users,"+server.GetSuffix()+" got = %v", entry.DN)
		}
		gn := entry.GetAttributeValues("givenName")
		if !reflect.DeepEqual(gn, []string{"foo"}) {
			t.Fatalf("want = [foo] got = %v", gn)
		}
	}

	err = modifyEntry(c, "uid=user1,ou=Users", []change{
		{
			changetype: "add",
			attrName:   "givenName",
			attrValue:  []string{"bar"},
		},
	})
	if err != nil {
		t.Fatalf("Can't modify/add: %v", err)
	}

	sr, err = searchEntry(c, "", ldap.ScopeWholeSubtree, "(uid=user1)", nil)
	if err != nil {
		t.Fatalf("Can't search: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Fatalf("Can't search: %v", sr)
	}
	for _, entry := range sr.Entries {
		if entry.DN != "uid=user1,ou=users,"+server.GetSuffix() {
			t.Fatalf("want = uid=user1,ou=users,"+server.GetSuffix()+" got = %v", entry.DN)
		}
		entry.PrettyPrint(2)
		gn := entry.GetAttributeValues("givenName")
		log.Printf("gn: %v\n", gn)
		if !reflect.DeepEqual(gn, []string{"foo", "bar"}) {
			t.Fatalf("want = [foo bar] got = %v", gn)
		}
	}

	err = modifyEntry(c, "uid=user1,ou=Users", []change{
		{
			changetype: "replace",
			attrName:   "givenName",
			attrValue:  []string{"hoge"},
		},
	})
	if err != nil {
		t.Fatalf("Can't modify/replace: %v", err)
	}

	sr, err = searchEntry(c, "", ldap.ScopeWholeSubtree, "(uid=user1)", nil)
	if err != nil {
		t.Fatalf("Can't search: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Fatalf("Can't search: %v", sr)
	}
	for _, entry := range sr.Entries {
		if entry.DN != "uid=user1,ou=users,"+server.GetSuffix() {
			t.Fatalf("want = uid=user1,ou=users,"+server.GetSuffix()+" got = %v", entry.DN)
		}
		gn := entry.GetAttributeValues("givenName")
		if !reflect.DeepEqual(gn, []string{"hoge"}) {
			t.Fatalf("want = [hoge] got = %v", gn)
		}
	}

	err = modifyEntry(c, "uid=user1,ou=Users", []change{
		{
			changetype: "delete",
			attrName:   "givenName",
			attrValue:  []string{},
		},
	})
	if err != nil {
		t.Fatalf("Can't modify/delete: %v", err)
	}

	sr, err = searchEntry(c, "", ldap.ScopeWholeSubtree, "(uid=user1)", nil)
	if err != nil {
		t.Fatalf("Can't search: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Fatalf("Can't search: %v", sr)
	}
	for _, entry := range sr.Entries {
		if entry.DN != "uid=user1,ou=users,"+server.GetSuffix() {
			t.Fatalf("want = uid=user1,ou=users,"+server.GetSuffix()+" got = %v", entry.DN)
		}
		gn := entry.GetAttributeValues("givenName")
		if !reflect.DeepEqual(gn, []string{}) {
			t.Fatalf("want = [] got = %v", gn)
		}
	}

	err = modifyDNEntry(c, "uid=user1,ou=Users", "uid=user1-rename")
	if err != nil {
		t.Fatalf("Can't modifydn: %v", err)
	}

	sr, err = searchEntry(c, "", ldap.ScopeWholeSubtree, "(cn=A_1)", nil)
	if err != nil {
		t.Fatalf("Can't search: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Fatalf("Can't search: %v", sr)
	}
	for _, entry := range sr.Entries {
		if entry.DN != "cn=a_1,ou=groups,"+server.GetSuffix() {
			t.Fatalf("want = cn=a_1,ou=groups,"+server.GetSuffix()+" got = %v", entry.DN)
		}
		entry.PrettyPrint(2)
		av := entry.GetAttributeValues("member")
		if !reflect.DeepEqual(av, []string{"uid=user1-rename,ou=Users," + server.GetSuffix()}) {
			t.Fatalf("want = [] got = %v", av)
		}
	}

	err = deleteEntry(c, "uid=user1,ou=Users")
	if !ldap.IsErrorWithCode(err, 32) {
		t.Fatalf("want = 32, got = %v", err)
	}

	err = deleteEntry(c, "uid=user1-rename,ou=Users")
	if err != nil {
		t.Fatalf("Can't delete: %v", err)
	}

	sr, err = searchEntry(c, "", ldap.ScopeWholeSubtree, "(uid=user1-rename)", nil)
	if !ldap.IsErrorWithCode(err, 32) {
		t.Fatalf("want = 32, got = %v", err)
	}

	sr, err = searchEntry(c, "", ldap.ScopeWholeSubtree, "(cn=A_1)", nil)
	if err != nil {
		t.Fatalf("Can't search: %v", err)
	}
	if len(sr.Entries) != 1 {
		t.Fatalf("Can't search: %v", sr)
	}
	for _, entry := range sr.Entries {
		if entry.DN != "cn=a_1,ou=groups,"+server.GetSuffix() {
			t.Fatalf("want = cn=a_1,ou=groups,"+server.GetSuffix()+" got = %v", entry.DN)
		}
		entry.PrettyPrint(2)
		av := entry.GetAttributeValues("member")
		if !reflect.DeepEqual(av, []string{}) {
			t.Fatalf("want = [] got = %v", av)
		}
	}
}

func toSsha(p string) string {
	h, _ := ssha.Generate(p, 8)
	return h
}

func toSsha256(p string) string {
	h, _ := ssha256.Generate(p, 8)
	return h
}

func toSsha512(p string) string {
	h, _ := ssha512.Generate(p, 8)
	return h
}

func addEntry(c *ldap.Conn, rdn string, attrs map[string][]string) error {
	add := ldap.NewAddRequest(rdn+","+server.GetSuffix(), nil)
	for k, v := range attrs {
		add.Attribute(k, v)
	}
	return c.Add(add)
}

type change struct {
	changetype string
	attrName   string
	attrValue  []string
}

func modifyEntry(c *ldap.Conn, rdn string, changes []change) error {
	modify := ldap.NewModifyRequest(rdn+","+server.GetSuffix(), nil)
	for _, change := range changes {
		switch change.changetype {
		case "add":
			modify.Add(change.attrName, change.attrValue)
		case "replace":
			modify.Replace(change.attrName, change.attrValue)
		case "delete":
			modify.Delete(change.attrName, change.attrValue)
		}
	}
	return c.Modify(modify)
}

func modifyDNEntry(c *ldap.Conn, rdn, newRDN string) error {
	modifyDN := ldap.NewModifyDNRequest(rdn+","+server.GetSuffix(), newRDN, true, "")
	return c.ModifyDN(modifyDN)
}

func deleteEntry(c *ldap.Conn, rdn string) error {
	del := ldap.NewDelRequest(rdn+","+server.GetSuffix(), nil)
	return c.Del(del)
}

func searchEntry(c *ldap.Conn, rdn string, scope int, filter string, attrs []string) (*ldap.SearchResult, error) {
	baseDN := server.GetSuffix()
	if rdn != "" {
		baseDN = rdn + "," + baseDN
	}

	search := ldap.NewSearchRequest(
		baseDN,
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

func setupLDAPServer() {
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
			RootDN:         "cn=Manager",
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
