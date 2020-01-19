// +build integration

package main

import (
	"os"
	"testing"

	"gopkg.in/ldap.v3"
)

var server *Server

func TestMain(m *testing.M) {

	rtn := IntegrationTestRunner(m)

	os.Exit(rtn + rtn)
}

func TestRootDSE(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		// Not need bind
		Search{
			"",
			"objectclass=*",
			ldap.ScopeBaseObject,
			A{"*", "+"},
			&AssertEntries{
				ExpectEntry{
					"",
					"",
					M{
						"objectClass":          A{"top"},
						"subschemaSubentry":    A{"cn=Subschema"},
						"namingContexts":       A{server.GetSuffix()},
						"supportedLDAPVersion": A{"3"},
						"supportedFeatures":    A{"1.3.6.1.4.1.4203.1.5.1"},
						"supportedControl":     A{"1.2.840.113556.1.4.319"},
					},
				},
			},
		},
	}

	runTestCases(t, tcs)
}

func TestSearchSchema(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		// Not need bind
		Search{
			"cn=Subschema",
			"objectclass=*",
			ldap.ScopeBaseObject,
			A{"*", "+"},
			&AssertEntries{
				ExpectEntry{
					"",
					"cn=Subschema",
					M{
						"objectClass": A{"top", "subentry", "subschema", "extensibleObject"},
						// TODO add more
					},
				},
			},
		},
	}

	runTestCases(t, tcs)
}

func TestBind(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC(),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"sn":           A{"user1"},
				"userPassword": A{SSHA("password1")},
			},
			&AssertEntry{},
		},
		Add{
			"uid=user2", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"sn":           A{"user2"},
				"userPassword": A{SSHA256("password2")},
			},
			&AssertEntry{},
		},
		Add{
			"uid=user3", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"sn":           A{"user3"},
				"userPassword": A{SSHA512("password3")},
			},
			&AssertEntry{},
		},
		Add{
			"uid=user4", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"sn":           A{"user4"},
				"userPassword": A{"password4"},
			},
			&AssertEntry{},
		},
		Bind{
			"uid=user1,ou=Users",
			"invalid",
			&AssertResponse{49},
		},
		Bind{
			"uid=user1,ou=Users",
			"password1",
			&AssertResponse{},
		},
		Bind{
			"uid=user2,ou=Users",
			"password2",
			&AssertResponse{},
		},
		Bind{
			"uid=user2,ou=Users",
			"invalid",
			&AssertResponse{49},
		},
		Bind{
			"uid=user3,ou=Users",
			"password3",
			&AssertResponse{},
		},
		Bind{
			"uid=user3,ou=Users",
			"invalid",
			&AssertResponse{49},
		},
		Bind{
			"uid=user4,ou=Users",
			"password4",
			&AssertResponse{},
		},
		Bind{
			"uid=user4,ou=Users",
			"invalid",
			&AssertResponse{49},
		},
	}

	runTestCases(t, tcs)
}

func TestSearch(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC(),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":    A{"inetOrgPerson"},
				"sn":             A{"user1"},
				"userPassword":   A{SSHA("password1")},
				"employeeNumber": A{"emp1"},
			},
			&AssertEntry{},
		},
		Add{
			"uid=user2", "ou=Users",
			M{
				"objectClass":    A{"inetOrgPerson"},
				"sn":             A{"user2"},
				"userPassword":   A{SSHA("password2")},
				"employeeNumber": A{"emp2"},
			},
			&AssertEntry{},
		},
		// Equal by Multi-value
		Search{
			"ou=Users," + server.GetSuffix(),
			"uid=user1",
			ldap.ScopeWholeSubtree,
			A{"*"},
			&AssertEntries{
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"sn": A{"user1"},
					},
				},
			},
		},
		// Equal by Single-value
		Search{
			"ou=Users," + server.GetSuffix(),
			"employeeNumber=emp1",
			ldap.ScopeWholeSubtree,
			A{"*"},
			&AssertEntries{
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"sn": A{"user1"},
					},
				},
			},
		},
		// Substr by Multi-value
		Search{
			"ou=Users," + server.GetSuffix(),
			"uid=user*",
			ldap.ScopeWholeSubtree,
			A{"*"},
			&AssertEntries{
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"sn": A{"user1"},
					},
				},
				ExpectEntry{
					"uid=user2",
					"ou=Users",
					M{
						"sn": A{"user2"},
					},
				},
			},
		},
		// Substr by Single-value
		Search{
			"ou=Users," + server.GetSuffix(),
			"employeeNumber=emp*",
			ldap.ScopeWholeSubtree,
			A{"*"},
			&AssertEntries{
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"sn": A{"user1"},
					},
				},
				ExpectEntry{
					"uid=user2",
					"ou=Users",
					M{
						"sn": A{"user2"},
					},
				},
			},
		},
	}

	runTestCases(t, tcs)
}

func TestBasicCRUD(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC(),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"sn":           A{"user1"},
				"userPassword": A{SSHA("password1")},
			},
			&AssertEntry{},
		},
		ModifyAdd{
			"uid=user1", "ou=Users",
			M{
				"givenName": A{"foo"},
			},
			&AssertEntry{},
		},
		ModifyAdd{
			"uid=user1", "ou=Users",
			M{
				"givenName": A{"bar"},
			},
			&AssertEntry{
				M{
					"givenName": A{"foo", "bar"},
				},
			},
		},
		ModifyReplace{
			"uid=user1", "ou=Users",
			M{
				"givenName": A{"hoge"},
			},
			&AssertEntry{},
		},
		ModifyReplace{
			"uid=user1", "ou=Users",
			M{
				"givenName": A{"hoge", "foo"},
			},
			&AssertEntry{},
		},
		// Delete attr using modify/replace
		ModifyReplace{
			"uid=user1", "ou=Users",
			M{
				"givenName": A{},
			},
			&AssertEntry{},
		},
		// Delete attr using modify/delete
		ModifyAdd{
			"uid=user1", "ou=Users",
			M{
				"givenName": A{"foo", "bar", "hoge"},
			},
			&AssertEntry{},
		},
		ModifyDelete{
			"uid=user1", "ou=Users",
			M{
				"givenName": A{"bar"},
			},
			&AssertEntry{
				M{
					"givenName": A{"foo", "hoge"},
				},
			},
		},
		ModifyDelete{
			"uid=user1", "ou=Users",
			M{
				"givenName": A{},
			},
			&AssertEntry{},
		},
		ModifyDN{
			"uid=user1", "ou=Users",
			"uid=user1-rename",
			true,
			"",
			&AssertRename{},
		},
		Delete{
			"uid=user1-rename", "ou=Users",
			&AssertNoEntry{},
		},
	}

	runTestCases(t, tcs)
}

func TestOperationalAttributes(t *testing.T) {
	type A []string
	type M map[string][]string

	server.config.MigrationEnabled = false
	server.LoadSchema()

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC(),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"sn":           A{"user1"},
				"userPassword": A{SSHA("password1")},
				"entryUUID":    A{"0b05df74-1219-495d-9d95-dc0c05e00aa9"},
			},
			&AssertLDAPError{
				expectErrorCode: ldap.LDAPResultConstraintViolation,
			},
		},
	}

	runTestCases(t, tcs)
}

func TestOperationalAttributesMigration(t *testing.T) {
	type A []string
	type M map[string][]string

	server.config.MigrationEnabled = true
	server.LoadSchema()

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC(),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"sn":           A{"user1"},
				"userPassword": A{SSHA("password1")},
				"entryUUID":    A{"0b05df74-1219-495d-9d95-dc0c05e00aa9"},
			},
			nil,
		},
		Search{
			"ou=Users," + server.GetSuffix(),
			"uid=user1",
			ldap.ScopeWholeSubtree,
			A{"entryUUID"},
			&AssertEntries{
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"entryUUID": A{"0b05df74-1219-495d-9d95-dc0c05e00aa9"},
					},
				},
			},
		},
	}

	runTestCases(t, tcs)
}

func TestMemberOf(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC(),
		AddOU("Groups"),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"sn":           A{"user1"},
				"userPassword": A{SSHA("password1")},
			},
			&AssertEntry{},
		},
		Add{
			"cn=A1", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member": A{
					"uid=user1,ou=Users," + server.GetSuffix(),
				},
			},
			&AssertEntry{},
		},
		Add{
			"cn=A", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member": A{
					"cn=A1,ou=Groups," + server.GetSuffix(),
				},
			},
			&AssertEntry{},
		},
		Add{
			"cn=top", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member":      A{"cn=A,ou=Groups," + server.GetSuffix()},
			},
			&AssertEntry{},
		},
		Search{
			"ou=Users," + server.GetSuffix(),
			"uid=user1",
			ldap.ScopeWholeSubtree,
			A{"memberOf"},
			&AssertEntries{
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"memberOf": A{"cn=A1,ou=Groups," + server.GetSuffix()},
					},
				},
			},
		},
	}

	runTestCases(t, tcs)
}
