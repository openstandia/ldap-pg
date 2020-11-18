package main

import (
	"fmt"
	"log"

	"github.com/openstandia/goldap/message"
)

type SubJsonQueryTranslator struct {
}

func (t *SubJsonQueryTranslator) Translate(schemaMap SchemaMap, packet message.Filter, q *Query) (err error) {
	err = nil

	switch f := packet.(type) {
	case message.FilterAnd:
		q.Query += "("
		for i, child := range f {
			err = t.Translate(schemaMap, child, q)

			if err != nil {
				return
			}
			if i < len(f)-1 {
				q.Query += " AND "
			}
		}
		q.Query += ")"
	case message.FilterOr:
		q.Query += "("
		for i, child := range f {
			err = t.Translate(schemaMap, child, q)

			if err != nil {
				return
			}
			if i < len(f)-1 {
				q.Query += " OR "
			}
		}
		q.Query += ")"
	case message.FilterNot:
		q.Query += "NOT "

		q.Query += "("
		err = t.Translate(schemaMap, f.Filter, q)
		q.Query += ")"

		if err != nil {
			return
		}
	case message.FilterSubstrings:
		for i, fs := range f.Substrings() {
			attrName := string(f.Type_())

			var s *Schema
			s, ok := schemaMap.Get(attrName)
			if !ok {
				log.Printf("Unsupported filter attribute: %s", attrName)
				return
			}

			switch fsv := fs.(type) {
			case message.SubstringInitial:
				// TODO Need escape?
				t.StartsWithMatch(s, q, string(fsv), i)
			case message.SubstringAny:
				if i > 0 {
					q.Query += " AND "
				}
				// TODO Need escape?
				t.AnyMatch(s, q, string(fsv), i)
			case message.SubstringFinal:
				if i > 0 {
					q.Query += " AND "
				}
				// TODO Need escape?
				t.EndsMatch(s, q, string(fsv), i)
			}
		}
	case message.FilterEqualityMatch:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.EqualityMatch(s, q, string(f.AssertionValue()))
		}
	case message.FilterGreaterOrEqual:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.GreaterOrEqualMatch(s, q, string(f.AssertionValue()))
		}
	case message.FilterLessOrEqual:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.LessOrEqualMatch(s, q, string(f.AssertionValue()))
		}
	case message.FilterPresent:
		if s, ok := findSchema(schemaMap, string(f)); ok {
			t.PresentMatch(s, q)
		}
	case message.FilterApproxMatch:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.ApproxMatch(s, q, string(f.AssertionValue()))
		}
	}

	return
}

func (t *SubJsonQueryTranslator) StartsWithMatch(s *Schema, q *Query, val string, i int) {
	paramKey := q.nextParamKey(s.Name)

	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	q.Query += fmt.Sprintf("e.attrs_norm->'%s' @@ :%s", s.Name, paramKey)

	// attrs_norm->'cn' @@ '$ starts with "foo"';
	q.Params[paramKey] = `$ starts with "` + escape(sv.Norm()[0]) + `"`
}

func (t *SubJsonQueryTranslator) AnyMatch(s *Schema, q *Query, val string, i int) {
	paramKey := q.nextParamKey(s.Name)

	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	q.Query += fmt.Sprintf("e.attrs_norm->'%s' @@ :%s", s.Name, paramKey)

	// attrs_norm->'cn' @@ '$ like_regex ".*foo.*"';
	q.Params[paramKey] = `$ like_regex ".*` + escapeRegex(sv.Norm()[0]) + `.*"`
}

func (t *SubJsonQueryTranslator) EndsMatch(s *Schema, q *Query, val string, i int) {
	paramKey := q.nextParamKey(s.Name)

	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	q.Query += fmt.Sprintf("e.attrs_norm->'%s' @@ :%s", s.Name, paramKey)

	// attrs_norm->'cn' @@ '$ like_regex ".*foo$"';
	q.Params[paramKey] = `$ like_regex ".*` + escapeRegex(sv.Norm()[0]) + `$"`
}

func (t *SubJsonQueryTranslator) EqualityMatch(s *Schema, q *Query, val string) {
	paramKey := q.nextParamKey(s.Name)

	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		// TODO error no entry response
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s, err: %+v", s.Name, val, err)
		return
	}
	log.Printf("s: %+v", s)

	if s.IsUseMemberTable {
		reqDN, err := s.server.NormalizeDN(val)
		if err != nil {
			log.Printf("warn: Ignore filter due to invalid DN syntax of member. attrName: %s, value: %s, err: %+v", s.Name, val, err)
			return
		}

		paramKeyName := paramKey + "_name"
		paramKeyParentID := paramKey + "_parent_id"

		// Stroe into pendig params since we need to resolve the parent DN as id later
		q.PendingParams[reqDN.ParentDN()] = paramKeyParentID

		q.Query += fmt.Sprintf(`EXISTS
			(
				SELECT 1 FROM ldap_member lm
					LEFT JOIN ldap_entry le ON le.id = lm.member_of_id
				WHERE lm.attr_name_norm = :%s AND lm.member_id = e.id AND le.parent_id = :%s AND le.rdn_norm = :%s
			)`, paramKeyName, paramKeyParentID, paramKey)
		q.Params[paramKeyName] = s.Name
		q.Params[paramKeyParentID] = -1 // unresolved yet
		q.Params[paramKey] = reqDN.RDNNormStr()
		return
	} else if s.IsUseMemberOfTable {
		reqDN, err := s.server.NormalizeDN(val)
		if err != nil {
			log.Printf("warn: Ignore filter due to invalid DN syntax of memberOf. attrName: %s, value: %s, err: %+v", s.Name, val, err)
			return
		}

		paramKeyParentID := paramKey + "_parent_id"

		// Stroe into pendig params since we need to resolve the parent DN as id later
		q.PendingParams[reqDN.ParentDN()] = paramKeyParentID

		q.Query += fmt.Sprintf(`EXISTS
			(
				SELECT 1 FROM ldap_member lm
					LEFT JOIN ldap_entry le ON le.id = lm.member_id
				WHERE lm.member_of_id = e.id AND le.parent_id = :%s AND le.rdn_norm = :%s
			)`, paramKeyParentID, paramKey)
		q.Params[paramKeyParentID] = -1 // unresolved yet
		q.Params[paramKey] = reqDN.RDNNormStr()
		return
	} else {
		// attrs_norm->'cn' @@ '$ == "foo"'
		q.Query += fmt.Sprintf("e.attrs_norm->'%s' @@ :%s", s.Name, paramKey)
	}
	q.Params[paramKey] = `$ == "` + escape(sv.Norm()[0]) + `"`
}

func (t *SubJsonQueryTranslator) GreaterOrEqualMatch(s *Schema, q *Query, val string) {
	paramKey := q.nextParamKey(s.Name)

	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	// attrs_norm->'cn' @@ '$ >= 3'
	q.Query += fmt.Sprintf("e.attrs_norm->'%s' @@ :%s", s.Name, paramKey)
	q.Params[paramKey] = `$ >= ` + sv.Norm()[0]
}

func (t *SubJsonQueryTranslator) LessOrEqualMatch(s *Schema, q *Query, val string) {
	paramKey := q.nextParamKey(s.Name)

	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	// attrs_norm->'cn' @@ '$ <= 3'
	q.Query += fmt.Sprintf("e.attrs_norm->'%s' @@ :%s", s.Name, paramKey)
	q.Params[paramKey] = `$ <= ` + sv.Norm()[0]
}

func (t *SubJsonQueryTranslator) PresentMatch(s *Schema, q *Query) {
	paramKey := q.nextParamKey(s.Name)

	sv, err := NewSchemaValue(s.Name, []string{s.Name})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s", s.Name)
		return
	}
	// attrs_norm ? 'cn';
	q.Query += "e.attrs_norm ? :" + paramKey
	q.Params[paramKey] = sv.Norm()[0]
}

func (t *SubJsonQueryTranslator) ApproxMatch(s *Schema, q *Query, val string) {
	paramKey := q.nextParamKey(s.Name)

	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	// TODO
	q.Query += fmt.Sprintf("e.attrs_norm->'%s' @@ :%s", s.Name, paramKey)
	q.Params[paramKey] = `$ like_reges ".*` + escapeRegex(sv.Norm()[0]) + `.*"`
}
