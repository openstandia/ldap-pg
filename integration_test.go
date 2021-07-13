// +build integration

package main

import (
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

var testServer *Server

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
		AddDC("com").SetAssert(&AssertResponse{53}),
		AddDC("example", "dc=com"),
		AddOU("Users"),
		Parallel{
			100,
			[][]Command{
				{
					Conn{},
					Bind{"cn=Manager", "secret", &AssertResponse{}},
					Add{
						"uid=user1", "ou=Users",
						M{
							"objectClass": A{"inetOrgPerson"},
							"cn":          A{"user1"},
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
				{
					Conn{},
					Bind{"cn=Manager", "secret", &AssertResponse{}},
					Add{
						"uid=user2", "ou=Users",
						M{
							"objectClass": A{"inetOrgPerson"},
							"cn":          A{"user2"},
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
						"namingContexts":       A{testServer.GetSuffix()},
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
		AddDC("example", "dc=com"),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user1"},
				"sn":           A{"user1"},
				"userPassword": A{SSHA("password1")},
			},
			&AssertEntry{},
		},
		Add{
			"uid=user2", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user2"},
				"sn":           A{"user2"},
				"userPassword": A{SSHA256("password2")},
			},
			&AssertEntry{},
		},
		Add{
			"uid=user3", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user3"},
				"sn":           A{"user3"},
				"userPassword": A{SSHA512("password3")},
			},
			&AssertEntry{},
		},
		Add{
			"uid=user4", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user4"},
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

func TestSearchSpecialCharacters(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC("example", "dc=com"),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":    A{"inetOrgPerson"},
				"cn":             A{"user1"},
				"sn":             A{"!@#$%^&*()_+|~{}:;'<>?`-=\\[]'/.,\""},
				"userPassword":   A{SSHA("password1")},
				"employeeNumber": A{"emp1"},
			},
			&AssertEntry{},
		},
		Add{
			// TODO Need to escape '='? (OpenLDAP doesn't need it)
			"uid=!@#$%^&*()_\\+|~{}:\\;'\\<\\>?`-\\=[]'/.\\,\"\\\\", "ou=Users",
			M{
				"objectClass":    A{"inetOrgPerson"},
				"cn":             A{"user2"},
				"sn":             A{"user2"},
				"userPassword":   A{SSHA("password1")},
				"employeeNumber": A{"emp2"},
			},
			nil,
		},
		Search{
			"ou=Users," + testServer.GetSuffix(),
			"uid=!@#$%^&\\2A\\28\\29_\\2B|~{}:;'<>?`-=[]'/.,\"\\5C",
			ldap.ScopeWholeSubtree,
			A{"*"},
			&AssertEntries{
				ExpectEntry{
					"uid=!@#$%^&*()_\\2B|~{}:\\3B'\\3C\\3E?`-\\3D[]'/.\\2C\\22\\5C",
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

func TestSearch(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC("example", "dc=com"),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":    A{"inetOrgPerson"},
				"cn":             A{"user1"},
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
				"cn":             A{"user2"},
				"sn":             A{"user2"},
				"userPassword":   A{SSHA("password2")},
				"employeeNumber": A{"emp2"},
			},
			&AssertEntry{},
		},
		// Equal by Multi-value
		Search{
			"ou=Users," + testServer.GetSuffix(),
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
			"ou=Users," + testServer.GetSuffix(),
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
			"ou=Users," + testServer.GetSuffix(),
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
			"ou=Users," + testServer.GetSuffix(),
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
		AddDC("example", "dc=com"),
		AddOU("Users"),
		AddOU("SubUsers", "ou=Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":    A{"inetOrgPerson"},
				"cn":             A{"user1"},
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
				"cn":             A{"user2"},
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
				"cn":             A{"user3"},
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
				"cn":             A{"user4"},
				"sn":             A{"user4"},
				"userPassword":   A{SSHA("password4")},
				"employeeNumber": A{"emp4"},
			},
			&AssertEntry{},
		},
		// base for container
		Search{
			"ou=Users," + testServer.GetSuffix(),
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
			"ou=Users," + testServer.GetSuffix(),
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
			"ou=Users," + testServer.GetSuffix(),
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
			"ou=Users," + testServer.GetSuffix(),
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
			"cn=Manager," + testServer.GetSuffix(),
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
			"uid=user1,ou=Users," + testServer.GetSuffix(),
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
			"uid=user1,ou=Users," + testServer.GetSuffix(),
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
			"uid=user1,ou=Users," + testServer.GetSuffix(),
			"uid=user1",
			ldap.ScopeSingleLevel,
			A{"*", "+"},
			&AssertEntries{},
		},
		// children for not container
		Search{
			"uid=user1,ou=Users," + testServer.GetSuffix(),
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
		AddDC("example", "dc=com"),
		AddOU("Users"),
		AddOU("Groups"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user1"},
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
		Delete{
			"uid=user1", "ou=Users",
			&AssertNoEntry{},
		},
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user1"},
				"sn":           A{"user1"},
				"userPassword": A{SSHA("password1")},
			},
			&AssertEntry{},
		},
	}

	runTestCases(t, tcs)
}

func TestModRDN(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC("example", "dc=com"),
		AddOU("Users"),
		AddOU("Groups"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user1"},
				"sn":           A{"user1"},
				"userPassword": A{SSHA("password1")},
			},
			&AssertEntry{},
		},
		// Rename RDN
		ModifyDN{
			"uid=user1", "ou=Users",
			"uid=user1-rename",
			true,
			"",
			false,
			&AssertRename{},
		},
		// Rename with old RDN
		ModifyDN{
			"uid=user1-rename", "ou=Users",
			"uid=user1-rename2",
			false,
			"",
			false,
			&AssertRename{},
		},
		// No rename with old RDN
		ModifyDN{
			"uid=user1-rename2", "ou=Users",
			"uid=user1-rename2",
			false,
			"",
			false,
			&AssertRename{},
		},
		// No rename
		ModifyDN{
			"uid=user1-rename2", "ou=Users",
			"uid=user1-rename2",
			true,
			"",
			false,
			&AssertRename{},
		},
		// Change parent of the leaf case
		ModifyDN{
			"uid=user1-rename2", "ou=Users",
			"uid=user1-rename2",
			true,
			"ou=Groups",
			false,
			&AssertRename{},
		},
		// Change parent of the leaf case with old same RDN
		ModifyDN{
			"uid=user1-rename2", "ou=Groups",
			"uid=user1-rename2",
			false,
			"ou=Users",
			false,
			&AssertRename{},
		},
		// Rename and change parent of the leaf case
		ModifyDN{
			"uid=user1-rename2", "ou=Users",
			"uid=user1",
			true,
			"ou=Groups",
			false,
			&AssertRename{},
		},
		// Rename with old RDN and change parent of the leaf case
		ModifyDN{
			"uid=user1", "ou=Groups",
			"uid=user1-rename",
			false,
			"ou=Users",
			false,
			&AssertRename{},
		},
		// Move tree case
		ModifyDN{
			"ou=Users", "",
			"ou=Users",
			true,
			"ou=Groups",
			true,
			&AssertRename{},
		},
		// Add sub entry of the user
		Add{
			"uid=subuser1", "uid=user1-rename,ou=Users,ou=Groups",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"subuser1"},
				"sn":           A{"subuser1"},
				"userPassword": A{SSHA("password1")},
			},
			&AssertEntry{},
		},
		// Move tree case for more deep level
		ModifyDN{
			"uid=user1-rename", "ou=Users,ou=Groups",
			"uid=user1-rename",
			true,
			"ou=Groups",
			true,
			&AssertRename{},
		},
	}

	runTestCases(t, tcs)
}

func TestOperationalAttributes(t *testing.T) {
	type A []string
	type M map[string][]string

	testServer.config.MigrationEnabled = false
	testServer.LoadSchema()

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC("example", "dc=com"),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user1"},
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

	testServer.config.MigrationEnabled = true
	testServer.LoadSchema()

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		AddDC("example", "dc=com"),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user1"},
				"sn":           A{"user1"},
				"userPassword": A{SSHA("password1")},
				"entryUUID":    A{"0b05df74-1219-495d-9d95-dc0c05e00aa9"},
			},
			nil,
		},
		Search{
			"ou=Users," + testServer.GetSuffix(),
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
		AddDC("example", "dc=com"),
		AddOU("Groups"),
		AddOU("Users"),
		Add{
			"uid=user1", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user1"},
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
					"uid=user1,ou=Users," + testServer.GetSuffix(),
				},
			},
			&AssertEntry{},
		},
		Add{
			"cn=A", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member": A{
					"cn=A1,ou=Groups," + testServer.GetSuffix(),
				},
			},
			&AssertEntry{},
		},
		Add{
			"cn=top", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member":      A{"cn=A,ou=Groups," + testServer.GetSuffix()},
			},
			&AssertEntry{},
		},
		Search{
			"ou=Users," + testServer.GetSuffix(),
			"uid=user1",
			ldap.ScopeWholeSubtree,
			A{"memberOf"},
			&AssertEntries{
				ExpectEntry{
					"uid=user1",
					"ou=Users",
					M{
						"memberOf": A{"cn=A1,ou=Groups," + testServer.GetSuffix()},
					},
				},
			},
		},
		Add{
			"uid=user2", "ou=Users",
			M{
				"objectClass":  A{"inetOrgPerson"},
				"cn":           A{"user2"},
				"sn":           A{"user2"},
				"userPassword": A{SSHA("password1")},
			},
			&AssertEntry{},
		},
		// Test case for duplicate members
		Add{
			"cn=A1", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member": A{
					"uid=user2,ou=Users," + testServer.GetSuffix(),
					"uid=user2,ou=Users," + testServer.GetSuffix(),
				},
			},
			&AssertLDAPError{
				expectErrorCode: ldap.LDAPResultAttributeOrValueExists,
			},
		},
		// Test case for adding a non-existent member
		Add{
			"cn=A1", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member": A{
					"uid=notfound,ou=Users," + testServer.GetSuffix(),
				},
			},
			&AssertLDAPError{
				expectErrorCode: ldap.LDAPResultInvalidAttributeSyntax,
			},
		},
		Add{
			"cn=A1", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member": A{
					"uid=user2,ou=Users," + testServer.GetSuffix(),
					"uid=notfound,ou=Users," + testServer.GetSuffix(),
				},
			},
			&AssertLDAPError{
				expectErrorCode: ldap.LDAPResultInvalidAttributeSyntax,
			},
		},
	}

	runTestCases(t, tcs)
}
