// +build !integration

package main

import (
	"testing"
)

func TestNormalize(t *testing.T) {
	testcases := []struct {
		Name     string
		Value    string
		Expected string
	}{
		{
			"cn",
			"abc",
			"abc",
		},
		{
			"cn",
			"aBc",
			"abc",
		},
		{
			"cn",
			"  a  B c  ",
			"a b c",
		},
		{
			"vendorName",
			"foobar",
			"foobar",
		},
		{
			"vendorName",
			"  f oo  Bar  ",
			"f oo Bar",
		},
	}

	schemaMap := InitSchemaMap(nil)

	for i, tc := range testcases {
		s, ok := schemaMap.Get(tc.Name)
		if !ok {
			t.Errorf("Unexpected error on %d:\n'%s' -> '%s' expected, got no schema\n", i, tc.Value, tc.Expected)
			continue
		}
		v, err := normalize(s, tc.Value)
		if err != nil {
			t.Errorf("Unexpected error on %d:\nSchema: %v\n'%s' -> '%s' expected, got error %s\n", i, s, tc.Value, tc.Expected, err)
			continue
		}

		if v != tc.Expected {
			t.Errorf("Unexpected error on %d:\nSchema: %v\n'%s' -> %s' expected, got '%s'\n", i, s, tc.Value, tc.Expected, v)
			continue
		}
	}
}
