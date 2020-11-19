// +build !integration

package main

import (
	"strings"
	"testing"
)

func TestDNNormalize(t *testing.T) {
	testcases := []struct {
		Value        string
		ExpectedNorm string
		ExpectedOrig string
	}{
		{
			"cn   =   te      St   , ou=People, DC=EXAMPLE, DC=COM",
			"cn=te st,ou=people,dc=example,dc=com",
			"cn=te      St,ou=People,DC=EXAMPLE,DC=COM",
		},
		{
			"ou=People,DC=example,DC=com",
			"ou=people,dc=example,dc=com",
			"ou=People,DC=example,DC=com",
		},
		{
			"DC=example,DC=com",
			"dc=example,dc=com",
			"DC=example,DC=com",
		},
		{
			"DC=com",
			"dc=com",
			"DC=com",
		},
		{
			"DC=example,DC=org",
			"dc=example,dc=org",
			"DC=example,DC=org",
		},
		{
			"",
			"",
			"",
		},
	}
	server := NewServer(&ServerConfig{
		Suffix: "dc=example,dc=com",
	})
	schemaMap = InitSchemaMap(server)

	for i, tc := range testcases {
		dn, err := NormalizeDN(tc.Value)
		if err != nil {
			t.Errorf("Unexpected error on %d:\n'%s' -> '%s' expected, got err: %+v\n", i, tc.Value, tc.ExpectedNorm, err)
			continue
		}
		if dn.DNNormStr() != tc.ExpectedNorm {
			t.Errorf("Unexpected error on %d:\nDNNorm:\n'%s' -> %s' expected, got '%s'\n", i, tc.Value, tc.ExpectedNorm, dn.DNNormStr())
			continue
		}
		if dn.DNOrigStr() != tc.ExpectedOrig {
			t.Errorf("Unexpected error on %d:\nDNOrig:\n'%s' expected, got '%s'\n", i, tc.ExpectedOrig, dn.DNOrigStr())
			continue
		}
		if strings.HasSuffix(dn.DNOrigStr(), "dc=example,dc=com") {
			t.Errorf("Unexpected error on %d:\nDNOrig:\n'%s' doesn't have %s as suffix' expected, but not\n", i, tc.Value, dn.DNOrigStr())
			continue
		}
	}
}
