// +build integration

package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

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
}

func addEntry(c *ldap.Conn, rdn string, attrs map[string][]string) error {
	add := ldap.NewAddRequest(rdn+","+server.GetSuffix(), nil)
	for k, v := range attrs {
		add.Attribute(k, v)
	}
	return c.Add(add)
}

func modifyEntry(c *ldap.Conn, rdn string, operations []map[string][]string) error {
	modify := ldap.NewModifyRequest(rdn+","+server.GetSuffix(), nil)
	for _, op := range operations {
		switch op["changetype"][0] {
		case "add":
		case "modify":

		case "delete":

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

func searchEntry(c *ldap.Conn, rdn string, attrs map[string][]string) error {
	add := ldap.NewAddRequest(rdn+","+server.GetSuffix(), nil)
	for k, v := range attrs {
		add.Attribute(k, v)
	}
	return c.Add(add)
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
