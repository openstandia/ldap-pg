// +build integration

package main

import (
	"os"
	"testing"
)

var server *Server

func TestMain(m *testing.M) {

	*twowayEnabled = false
	rtn := IntegrationTestRunner(m)

	*twowayEnabled = true
	rtn = IntegrationTestRunner(m)

	os.Exit(rtn + rtn)
}

func TestBind(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
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

func TestBasicCRUD(t *testing.T) {
	type A []string
	type M map[string][]string

	tcs := []Command{
		Conn{},
		Bind{"cn=Manager", "secret", &AssertResponse{}},
		Add{
			"ou=Groups",
			"",
			M{
				"objectClass": A{"organizationalUnit"},
			},
			&AssertEntry{},
		},
		Add{
			"ou=Users", "",
			M{
				"objectClass": A{"organizationalUnit"},
			},
			&AssertEntry{},
		},
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
			"cn=top", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member":      A{"cn=A,ou=Groups," + server.GetSuffix()},
			},
			&AssertEntry{},
		},
		Add{
			"cn=A", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member": A{
					"cn=A1,ou=Groups," + server.GetSuffix(),
					"cn=A2,ou=Groups," + server.GetSuffix(),
				},
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
			"cn=A2", "ou=Groups",
			M{
				"objectClass": A{"groupOfNames"},
				"member": A{
					"uid=user2,ou=Users," + server.GetSuffix(),
				},
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
