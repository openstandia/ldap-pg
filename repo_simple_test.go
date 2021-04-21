// +build !integration

package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestCreateFindTreePathSQL(t *testing.T) {
	testcases := []struct {
		DN            string
		ExpectedSQL   string
		ExpectedError string
	}{
		{
			"ou=Users,dc=example,dc=com",
			"SELECT e2.rdn_orig || ',' || e1.rdn_orig || ',' || e0.rdn_orig as dn_orig, e2.id, e2.parent_id, e0.id || '.' || e1.id || '.' || e2.id as path, COALESCE((SELECT true FROM ldap_tree t WHERE t.id = e2.id), false) as has_sub FROM ldap_entry e0, ldap_entry e1, ldap_entry e2 WHERE e0.rdn_norm = :rdn_norm0 AND e1.rdn_norm = :rdn_norm1 AND e2.rdn_norm = :rdn_norm2 AND e0.parent_id is NULL AND e1.parent_id = e0.id AND e2.parent_id = e1.id",
			"",
		},
		{
			"ou=g000001,ou=Group,dc=example,dc=com",
			"SELECT e3.rdn_orig || ',' || e2.rdn_orig || ',' || e1.rdn_orig || ',' || e0.rdn_orig as dn_orig, e3.id, e3.parent_id, e0.id || '.' || e1.id || '.' || e2.id || '.' || e3.id as path, COALESCE((SELECT true FROM ldap_tree t WHERE t.id = e3.id), false) as has_sub FROM ldap_entry e0, ldap_entry e1, ldap_entry e2, ldap_entry e3 WHERE e0.rdn_norm = :rdn_norm0 AND e1.rdn_norm = :rdn_norm1 AND e2.rdn_norm = :rdn_norm2 AND e3.rdn_norm = :rdn_norm3 AND e0.parent_id is NULL AND e1.parent_id = e0.id AND e2.parent_id = e1.id AND e3.parent_id = e2.id",
			"",
		},
		{
			"dc=example,dc=com",
			"SELECT e1.rdn_orig || ',' || e0.rdn_orig as dn_orig, e1.id, e1.parent_id, e0.id || '.' || e1.id as path, COALESCE((SELECT true FROM ldap_tree t WHERE t.id = e1.id), false) as has_sub FROM ldap_entry e0, ldap_entry e1 WHERE e0.rdn_norm = :rdn_norm0 AND e1.rdn_norm = :rdn_norm1 AND e0.parent_id is NULL AND e1.parent_id = e0.id",
			"",
		},
		{
			"dc=com",
			"SELECT e0.rdn_orig as dn_orig, e0.id, e0.parent_id, e0.id as path, COALESCE((SELECT true FROM ldap_tree t WHERE t.id = e0.id), false) as has_sub FROM ldap_entry e0 WHERE e0.rdn_norm = :rdn_norm0 AND e0.parent_id is NULL",
			"",
		},
		{
			"",
			"",
			"Invalid DN, it's anonymous",
		},
	}
	server := NewServer(&ServerConfig{
		Suffix: "dc=example,dc=com",
	})
	schemaMap = InitSchemaMap(server)

	for i, tc := range testcases {
		baseDN, err := NormalizeDN(tc.DN)
		if err != nil {
			t.Errorf("Unexpected error on %d:\ngot error '%s'\n", i, err)
		}
		sql, err := createFindBasePathByDNSQL(baseDN, &FindOption{})
		if err != nil {
			if tc.ExpectedError == "" {
				t.Errorf("Unexpected error on %d:\n'%s' expected, got error '%s'\n", i, tc.ExpectedSQL, err)
				continue
			}
			if err.Error() != tc.ExpectedError {
				t.Errorf("Unexpected error on %d:\n'%s' expected, got error '%s'\n", i, tc.ExpectedError, err)
				continue
			}
		}
		sql = strings.ReplaceAll(sql, "\n", "")
		rep := regexp.MustCompile(`\s+`)
		sql = rep.ReplaceAllString(sql, " ")
		sql = strings.Trim(sql, " ")

		if sql != tc.ExpectedSQL {
			t.Errorf("Unexpected error on %d:\n'%s' expected, got\n'%s'\n", i, tc.ExpectedSQL, sql)
			continue
		}
	}
}
