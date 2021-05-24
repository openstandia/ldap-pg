// +build test

package main

import (
	"reflect"
	"testing"
)

func TestNewSchemaValue(t *testing.T) {
	testcases := []struct {
		Name         string
		Value        []string
		ExpectedNorm []string
	}{
		{
			"cn",
			[]string{"abc"},
			[]string{"abc"},
		},
		{
			"cn",
			[]string{"aBc"},
			[]string{"abc"},
		},
		{
			"cn",
			[]string{" a  B c "},
			[]string{"a b c"},
		},
	}
	server := NewServer(&ServerConfig{
		Suffix: "dc=example,dc=com",
	})
	schemaMap := InitSchemaMap(server)

	for i, tc := range testcases {
		sv, err := NewSchemaValue(schemaMap, tc.Name, tc.Value)
		if err != nil {
			t.Errorf("Unexpected error on %d:\nSchema: %s\n'%s' -> '%s' expected, got error %v\n", i, tc.Name, tc.Value, tc.ExpectedNorm, err)
			continue
		}

		if !reflect.DeepEqual(sv.Norm(), tc.ExpectedNorm) {
			t.Errorf("Unexpected error on %d:\nSchema: %v\n'%s' -> %s' expected, got '%v'\n", i, tc.Name, tc.Value, tc.ExpectedNorm, sv)
			continue
		}
	}
}

func TestSchemaValueOp(t *testing.T) {
	testcases := []struct {
		Op           string
		Name         string
		Value        []string
		ExpectedNorm []string
		ExpectedOrig []string
	}{
		{
			"",
			"sn",
			[]string{"  a  B  c  "},
			[]string{"a b c"},
			[]string{"  a  B  c  "},
		},
		{
			"Add",
			"sn",
			[]string{"FOO"},
			[]string{"a b c", "foo"},
			[]string{"  a  B  c  ", "FOO"},
		},
		{
			"Delete",
			"sn",
			[]string{" A b   C  "},
			[]string{"foo"},
			[]string{"FOO"},
		},
	}

	server := NewServer(&ServerConfig{
		Suffix: "dc=example,dc=com",
	})
	schemaMap := InitSchemaMap(server)

	var sv *SchemaValue
	var err error

	for i, tc := range testcases {
		if sv == nil {
			sv, err = NewSchemaValue(schemaMap, tc.Name, tc.Value)
			if err != nil {
				t.Errorf("Unexpected error on %d:\nSchema: %s\n'%v' -> '%v' / '%v' expected, got error %v\n", i, tc.Name, tc.Value, tc.ExpectedNorm, tc.ExpectedOrig, err)
				continue
			}
		} else {
			op, err := NewSchemaValue(schemaMap, tc.Name, tc.Value)
			if err != nil {
				t.Errorf("Unexpected error on %d:\nSchema: %s\n'%v' -> '%v' / '%v' expected, got error %v\n", i, tc.Name, tc.Value, tc.ExpectedNorm, tc.ExpectedOrig, err)
				continue
			}

			switch tc.Op {
			case "Add":
				err = sv.Add(op)
				if err != nil {
					t.Errorf("Unexpected error on %d:\nSchema: %s\n'%v' -> '%v' / '%v' expected, got error %v\n", i, tc.Name, tc.Value, tc.ExpectedNorm, tc.ExpectedOrig, err)
					continue
				}
			case "Delete":
				err = sv.Delete(op)
				if err != nil {
					t.Errorf("Unexpected error on %d:\nSchema: %v\n'%v' -> '%v' / '%v' expected, got error %v\n", i, tc.Name, tc.Value, tc.ExpectedNorm, tc.ExpectedOrig, err)
					continue
				}
			}
			if !reflect.DeepEqual(sv.Norm(), tc.ExpectedNorm) {
				t.Errorf("Unexpected error on %d:\nSchema: %v\n'%v' -> %v' expected, got '%v'\n", i, tc.Name, tc.Value, tc.ExpectedNorm, sv.Norm())
				continue
			}
			if !reflect.DeepEqual(sv.Orig(), tc.ExpectedOrig) {
				t.Errorf("Unexpected error on %d:\nSchema: %v\n'%v' -> %v' expected, got '%v'\n", i, tc.Name, tc.Value, tc.ExpectedOrig, sv.Orig())
				continue
			}
		}
	}
}

func TestObjectClassContains(t *testing.T) {
	server := NewServer(&ServerConfig{
		Suffix: "dc=example,dc=com",
	})
	schemaDef := InitSchemaMap(server)

	oc := &ObjectClass{
		schemaDef:  schemaDef,
		Oid:        "",
		Name:       "user",
		Structural: true,
		must:       []string{"cn", "UID"},
		may:        []string{"sn", "GIVENNAME"},
	}
	testcases := []struct {
		Attr     string
		Expected bool
	}{
		{
			"cn",
			true,
		},
		{
			"UID",
			true,
		},
		{
			"sn",
			true,
		},
		{
			"CN",
			true,
		},
		{
			"uid",
			true,
		},
		{
			"SN",
			true,
		},
		{
			"givenName",
			true,
		},
		{
			"email",
			false,
		},
	}

	for i, tc := range testcases {
		result := oc.Contains(tc.Attr)
		if result != tc.Expected {
			t.Errorf("Unexpected error on %d: Contains %s -> '%v' expected, got '%v'\n", i, tc.Attr, tc.Expected, result)
		}
	}
}

func TestObjectClassNormalization(t *testing.T) {
	server := NewServer(&ServerConfig{
		Suffix: "dc=example,dc=com",
	})
	schemaDef := InitSchemaMap(server)

	testcases := []struct {
		Name     string
		Value    []string
		Expected []string
	}{
		{
			"objectClass",
			[]string{"top", "dcObject", "organization"},
			[]string{"organization", "top", "dcobject"},
		},
		{
			"objectClass",
			[]string{"inetOrgPerson"},
			[]string{"inetorgperson", "organizationalperson", "person", "top"},
		},
		{
			"objectClass",
			[]string{"organizationalPerson"},
			[]string{"organizationalperson", "person", "top"},
		},
		// Auxiliary case
		// Note: Auxiliary is NOT supported fully yet
		//   The superior of the auxiliary objectClass is not resolved
		{
			"objectClass",
			[]string{"mailAccount", "inetOrgPerson"},
			[]string{"inetorgperson", "organizationalperson", "person", "top", "mailaccount"},
		},
	}

	for i, tc := range testcases {
		sv, err := NewSchemaValue(schemaDef, tc.Name, tc.Value)
		if err != nil {
			t.Errorf("Unexpected error on %d:\nValue: %v\nExpected: %v\ngot error %v\n", i, tc.Value, tc.Expected, err)
			continue
		}
		if !reflect.DeepEqual(sv.Norm(), tc.Expected) {
			t.Errorf("Unexpected error on %d:\nValue: %v\nExpected: %v\ngot '%v'\n", i, tc.Value, tc.Expected, sv.Norm())
			continue
		}
	}
}
