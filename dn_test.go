// +build !integration

package main

import (
	"testing"
)

func TestDNNormalize(t *testing.T) {
	testcases := []struct {
		Value    string
		Expected string
	}{
		{
			"cn = test , ou=People, DC=example, DC=com",
			"cn=test,ou=people,dc=example,dc=com",
		},
	}

	schemaMap = InitSchemaMap()

	for i, tc := range testcases {
		dn, err := normalizeDN(tc.Value)
		if err != nil {
			t.Errorf("Unexpected error on %d:\n'%s' -> '%s' expected, got err: %+v\n", i, tc.Value, tc.Expected, err)
			continue
		}
		if dn.DNNorm != tc.Expected {
			t.Errorf("Unexpected error on %d:\nDNNorm:\n'%s' -> %s' expected, got '%s'\n", i, tc.Value, tc.Expected, dn.DNNorm)
			continue
		}
		if dn.DNOrig != tc.Value {
			t.Errorf("Unexpected error on %d:\nDNOrig:\n'%s' -> %s' expected, got '%s'\n", i, tc.Value, tc.Value, dn.DNNorm)
			continue
		}
	}
}
