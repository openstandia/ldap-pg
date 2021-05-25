// +build test

package main

import (
	"testing"
)

func TestAddEntryValidate(t *testing.T) {
	testcases := []struct {
		DN            string
		Attrs         map[string][]string
		ExpectedError error
	}{
		{
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"cn": {"abc"},
				"sn": {"efg"},
			},
			NewObjectClassViolation(),
		},
		{
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"inetOrgPerson"},
				"cn":          {"abc"},
			},
			NewObjectClassViolationRequiresAttribute("inetOrgPerson", "sn"),
		},
		{
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"inetOrgPerson"},
				"cn":          {"abc"},
				"sn":          {"efg"},
				"displayName": {"hij"},
			},
			nil,
		},
		{
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass":  {"inetOrgPerson"},
				"cn":           {"abc"},
				"sn":           {"efg"},
				"userPassword": {"hij"},
			},
			nil,
		},
		{
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"person"},
				"cn":          {"abc"},
				"sn":          {"efg"},
				"displayName": {"hij"},
			},
			NewObjectClassViolationNotAllowed("displayName"),
		},
		{
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"uknown"},
				"cn":          {"abc"},
			},
			NewInvalidPerSyntax("objectClass", 0),
		},
		{
			"cn=abc,ou=Users,dc=example,dc=com",
			map[string][]string{
				"objectClass": {"person", "uknown"},
				"cn":          {"abc"},
				"sn":          {"efg"},
			},
			NewInvalidPerSyntax("objectClass", 1),
		},
	}
	server := NewServer(&ServerConfig{
		Suffix: "dc=example,dc=com",
	})
	schemaMap := InitSchemaMap(server)

	for i, tc := range testcases {
		dn, err := ParseDN(schemaMap, tc.DN)
		if err != nil {
			t.Errorf("Unexpected error on %d:\nParse DN: %s, got error [%v]\n", i, tc.DN, err)
			continue
		}
		entry := NewAddEntry(schemaMap, dn)
		for k, v := range tc.Attrs {
			err = entry.Add(k, v)
			if err != nil {
				break
			}
		}
		if err != nil {
			if tc.ExpectedError.Error() != err.Error() {
				t.Errorf("Unexpected error on %d:\nError: [%v] expected, got error [%v]\n", i, tc.ExpectedError, err)
			}
			continue
		}

		err = entry.Validate()
		if tc.ExpectedError == nil {
			if err != nil {
				t.Errorf("Unexpected error on %d:\nError: [%v] expected, got error [%v]\n", i, tc.ExpectedError, err)
			}
			continue
		} else {
			if tc.ExpectedError.Error() != err.Error() {
				t.Errorf("Unexpected error on %d:\nError: [%v] expected, got error [%v]\n", i, tc.ExpectedError, err)
			}
		}
	}
}
