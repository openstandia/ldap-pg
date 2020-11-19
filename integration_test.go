// +build integration

package main

import (
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

var server *Server

func TestMain(m *testing.M) {

	rtn := IntegrationTestRunner(m)

	os.Exit(rtn + rtn)
}

func TestParallel(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC("com"),
		AddDC("example", "dc=com"),
		AddOU("Users"),
		Parallel{
			100,
			[][]Command{
				[]Command{
					Conn{},
					Bind{"cn=Manager", "secret", &AssertResponse{}},
					Add{
						"uid=user1", "ou=Users",
						M{
							"objectClass": A{"inetOrgPerson"},
							"sn":          A{"user1"},
						},
						&AssertEntry{},
					},
					ModifyAdd{
						"uid=user1", "ou=Users",
						M{
							"givenName": A{"user1"},
						},
						&AssertEntry{},
					},
					Delete{
						"uid=user1", "ou=Users",
						&AssertNoEntry{},
					},
				},
				[]Command{
					Conn{},
					Bind{"cn=Manager", "secret", &AssertResponse{}},
					Add{
						"uid=user2", "ou=Users",
						M{
							"objectClass": A{"inetOrgPerson"},
							"sn":          A{"user2"},
						},
						&AssertEntry{},
					},
					ModifyAdd{
						"uid=user2", "ou=Users",
						M{
							"givenName": A{"user2"},
						},
						&AssertEntry{},
					},
					Delete{
						"uid=user2", "ou=Users",
						&AssertNoEntry{},
					},
				},
			},
		},
	}

	runTestCases(t, tcs)
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
		AddDC("com"),
		AddDC("example", "dc=com"),
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
		AddDC("com"),
		AddDC("example", "dc=com"),
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

func TestScopeSearch(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC("com"),
		AddDC("example", "dc=com"),
		AddOU("Users"),
		AddOU("SubUsers", "ou=Users"),
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
		Add{
			"uid=user3", "ou=SubUsers,ou=Users",
			M{
				"objectClass":    A{"inetOrgPerson"},
				"sn":             A{"user3"},
				"userPassword":   A{SSHA("password3")},
				"employeeNumber": A{"emp3"},
			},
			&AssertEntry{},
		},
		Add{
			"uid=user4", "ou=SubUsers,ou=Users",
			M{
				"objectClass":    A{"inetOrgPerson"},
				"sn":             A{"user4"},
				"userPassword":   A{SSHA("password4")},
				"employeeNumber": A{"emp4"},
			},
			&AssertEntry{},
		},
		// base for container
		Search{
			"ou=Users," + server.GetSuffix(),
			"objectclass=*",
			ldap.ScopeBaseObject,
			A{"*", "+"},
			&AssertEntries{
				ExpectEntry{
					"ou=Users",
					"",
					M{
						"hasSubordinates": A{"TRUE"},
					},
				},
			},
		},
		// sub for container
		Search{
			"ou=Users," + server.GetSuffix(),
			"objectclass=*",
			ldap.ScopeWholeSubtree,
			A{"*", "+"},
			&AssertEntries{
				ExpectEntry{
					"ou=Users",
					"",
					M{
						"hasSubordinates": A{"TRUE"},
					},
				},
				ExpectEntry{
					"ou=SubUsers",
					"ou=Users",
					M{
						"hasSubordinates": A{"TRUE"},
					},
				},
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"hasSubordinates": A{"FALSE"},
					},
				},
				ExpectEntry{
					"uid=user2",
					"ou=Users",
					M{
						"hasSubordinates": A{"FALSE"},
					},
				},
				ExpectEntry{
					"uid=user3",
					"ou=SubUsers,ou=Users",
					M{
						"hasSubordinates": A{"FALSE"},
					},
				},
				ExpectEntry{
					"uid=user4",
					"ou=SubUsers,ou=Users",
					M{
						"hasSubordinates": A{"FALSE"},
					},
				},
			},
		},
		// one for container
		Search{
			"ou=Users," + server.GetSuffix(),
			"objectclass=*",
			ldap.ScopeSingleLevel,
			A{"*", "+"},
			&AssertEntries{
				ExpectEntry{
					"ou=SubUsers",
					"ou=Users",
					M{
						"hasSubordinates": A{"TRUE"},
					},
				},
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"hasSubordinates": A{"FALSE"},
					},
				},
				ExpectEntry{
					"uid=user2",
					"ou=Users",
					M{
						"hasSubordinates": A{"FALSE"},
					},
				},
			},
		},
		// children for container
		Search{
			"ou=Users," + server.GetSuffix(),
			"objectclass=*",
			3,
			A{"*", "+"},
			&AssertEntries{
				ExpectEntry{
					"ou=SubUsers",
					"ou=Users",
					M{
						"hasSubordinates": A{"TRUE"},
					},
				},
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"hasSubordinates": A{"FALSE"},
					},
				},
				ExpectEntry{
					"uid=user2",
					"ou=Users",
					M{
						"hasSubordinates": A{"FALSE"},
					},
				},
				ExpectEntry{
					"uid=user3",
					"ou=SubUsers,ou=Users",
					M{
						"hasSubordinates": A{"FALSE"},
					},
				},
				ExpectEntry{
					"uid=user4",
					"ou=SubUsers,ou=Users",
					M{
						"hasSubordinates": A{"FALSE"},
					},
				},
			},
		},
		// base for not container(admin virtual entry)
		Search{
			"cn=Manager," + server.GetSuffix(),
			"objectClass=*",
			ldap.ScopeBaseObject,
			A{"*", "+"},
			&AssertEntries{
				ExpectEntry{
					"cn=Manager",
					"",
					M{
						"description":     A{"LDAP administrator"},
						"hasSubordinates": A{"FALSE"},
					},
				},
			},
		},
		// base for not container
		Search{
			"uid=user1,ou=Users," + server.GetSuffix(),
			"uid=user1",
			ldap.ScopeBaseObject,
			A{"*", "+"},
			&AssertEntries{
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"sn":              A{"user1"},
						"hasSubordinates": A{"FALSE"},
					},
				},
			},
		},
		// sub for not container
		Search{
			"uid=user1,ou=Users," + server.GetSuffix(),
			"uid=user1",
			ldap.ScopeWholeSubtree,
			A{"*", "+"},
			&AssertEntries{
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"sn":              A{"user1"},
						"hasSubordinates": A{"FALSE"},
					},
				},
			},
		},
		// one for not container
		Search{
			"uid=user1,ou=Users," + server.GetSuffix(),
			"uid=user1",
			ldap.ScopeSingleLevel,
			A{"*", "+"},
			&AssertEntries{},
		},
		// children for not container
		Search{
			"uid=user1,ou=Users," + server.GetSuffix(),
			"uid=user1",
			3,
			A{"*", "+"},
			&AssertEntries{},
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
		AddDC("com"),
		AddDC("example", "dc=com"),
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
		ModifyDN{
			"uid=user1-rename", "ou=Users",
			"uid=user1-rename2",
			false,
			"",
			&AssertRename{},
		},
		Delete{
			"uid=user1-rename2", "ou=Users",
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
		AddDC("com"),
		AddDC("example", "dc=com"),
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
		AddDC("com"),
		AddDC("example", "dc=com"),
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
		AddDC("com"),
		AddDC("example", "dc=com"),
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
