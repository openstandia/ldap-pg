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

	schemaMap = InitSchemaMap()

	for i, tc := range testcases {
		sv, err := NewSchemaValue(tc.Name, tc.Value)
		if err != nil {
			t.Errorf("Unexpected error on %d:\nSchema: %s\n'%s' -> '%s' expected, got error %v\n", i, tc.Name, tc.Value, tc.ExpectedNorm, err)
			continue
		}

		if !reflect.DeepEqual(sv.GetNorm(), tc.ExpectedNorm) {
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

	schemaMap = InitSchemaMap()

	var sv *SchemaValue
	var err error

	for i, tc := range testcases {
		if sv == nil {
			sv, err = NewSchemaValue(tc.Name, tc.Value)
			if err != nil {
				t.Errorf("Unexpected error on %d:\nSchema: %s\n'%v' -> '%v' / '%v' expected, got error %v\n", i, tc.Name, tc.Value, tc.ExpectedNorm, tc.ExpectedOrig, err)
				continue
			}
		} else {
			op, err := NewSchemaValue(tc.Name, tc.Value)
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
			if !reflect.DeepEqual(sv.GetNorm(), tc.ExpectedNorm) {
				t.Errorf("Unexpected error on %d:\nSchema: %v\n'%v' -> %v' expected, got '%v'\n", i, tc.Name, tc.Value, tc.ExpectedNorm, sv.GetNorm())
				continue
			}
			if !reflect.DeepEqual(sv.GetOrig(), tc.ExpectedOrig) {
				t.Errorf("Unexpected error on %d:\nSchema: %v\n'%v' -> %v' expected, got '%v'\n", i, tc.Name, tc.Value, tc.ExpectedOrig, sv.GetOrig())
				continue
			}
		}
	}
}
