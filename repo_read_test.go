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
			"SELECT e2.rdn_orig || ',' || e1.rdn_orig || ',' || e0.rdn_orig as dn_orig, e2.id, t1.path as parent_path, (CASE WHEN ex.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub FROM ldap_tree t0, ldap_entry e0, ldap_tree t1, ldap_entry e1, ldap_entry e2 LEFT JOIN ldap_tree ex ON e2.id = ex.id WHERE e0.rdn_norm = :rdn_norm0 AND e1.rdn_norm = :rdn_norm1 AND e2.rdn_norm = :rdn_norm2 AND t0.parent_id is NULL AND t0.id = e0.id AND t1.parent_id = t0.id AND t1.id = e1.id AND e2.parent_id = t1.id",
			"",
		},
		{
			"ou=g000001,ou=Group,dc=example,dc=com",
			"SELECT e3.rdn_orig || ',' || e2.rdn_orig || ',' || e1.rdn_orig || ',' || e0.rdn_orig as dn_orig, e3.id, t2.path as parent_path, (CASE WHEN ex.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub FROM ldap_tree t0, ldap_entry e0, ldap_tree t1, ldap_entry e1, ldap_tree t2, ldap_entry e2, ldap_entry e3 LEFT JOIN ldap_tree ex ON e3.id = ex.id WHERE e0.rdn_norm = :rdn_norm0 AND e1.rdn_norm = :rdn_norm1 AND e2.rdn_norm = :rdn_norm2 AND e3.rdn_norm = :rdn_norm3 AND t0.parent_id is NULL AND t0.id = e0.id AND t1.parent_id = t0.id AND t1.id = e1.id AND t2.parent_id = t1.id AND t2.id = e2.id AND e3.parent_id = t2.id",
			"",
		},
		{
			"dc=example,dc=com",
			"SELECT e1.rdn_orig || ',' || e0.rdn_orig as dn_orig, e1.id, t0.path as parent_path, (CASE WHEN ex.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub FROM ldap_tree t0, ldap_entry e0, ldap_entry e1 LEFT JOIN ldap_tree ex ON e1.id = ex.id WHERE e0.rdn_norm = :rdn_norm0 AND e1.rdn_norm = :rdn_norm1 AND t0.parent_id is NULL AND t0.id = e0.id AND e1.parent_id = t0.id",
			"",
		},
		{
			"dc=com",
			"SELECT e0.rdn_orig as dn_orig, e0.id, '' as parent_path, (CASE WHEN ex.id IS NOT NULL THEN 1 ELSE 0 END) as has_sub FROM ldap_entry e0 LEFT JOIN ldap_tree ex ON e0.id = ex.id WHERE e0.rdn_norm = :rdn_norm0 AND e0.parent_id is NULL",
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
		baseDN, err := NormalizeDN([]string{"dc=example", "dc=com"}, tc.DN)
		if err != nil {
			t.Errorf("Unexpected error on %d:\ngot error '%s'\n", i, err)
		}
		sql, err := createFindTreePathByDNSQL(baseDN, &FindOption{})
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
