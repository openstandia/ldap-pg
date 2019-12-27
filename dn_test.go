// +build !integration

package main

import (
	"strings"
	"testing"
)

func TestDNNormalize(t *testing.T) {
	testcases := []struct {
		Value    string
		Expected string
	}{
		{
			"cn = test , ou=People, DC=example, DC=com",
			"cn=test,ou=people",
		},
	}
	server := NewServer(&ServerConfig{
		Suffix: "dc=example,dc=com",
	})
	schemaMap = InitSchemaMap(server)

	for i, tc := range testcases {
		dn, err := NormalizeDN([]string{"dc=example", "dc=com"}, tc.Value)
		if err != nil {
			t.Errorf("Unexpected error on %d:\n'%s' -> '%s' expected, got err: %+v\n", i, tc.Value, tc.Expected, err)
			continue
		}
		if dn.DNNormStr() != tc.Expected {
			t.Errorf("Unexpected error on %d:\nDNNorm:\n'%s' -> %s' expected, got '%s'\n", i, tc.Value, tc.Expected, dn.DNNormStr())
			continue
		}
		if strings.HasPrefix(tc.Value, dn.DNOrigStr()) {
			t.Errorf("Unexpected error on %d:\nDNOrig:\n'%s' -> %s' expected, got '%s'\n", i, tc.Value, tc.Value, dn.DNOrigStr())
			continue
		}
	}
}
