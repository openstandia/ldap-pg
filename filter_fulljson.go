package main

import (
	"log"

	"github.com/openstandia/goldap/message"
)

// FullJsonQueryTranslator is an implementation for searching with full jsonpath query.
type FullJsonQueryTranslator struct {
}

func (t *FullJsonQueryTranslator) Translate(schemaMap SchemaMap, packet message.Filter, q *Query) error {

	paramKey := "filter"
	q.Query += "e.attrs_norm @@ :" + paramKey

	jsonpath := make([]byte, 0, 128)

	err := t.internalTranslate(schemaMap, packet, q, &jsonpath)
	if err != nil {
		return err
	}

	q.Params[paramKey] = string(jsonpath)

	return nil
}

func (t *FullJsonQueryTranslator) internalTranslate(schemaMap SchemaMap, packet message.Filter, q *Query, jsonpath *[]byte) (err error) {
	err = nil

	switch f := packet.(type) {
	case message.FilterAnd:
		*jsonpath = append(*jsonpath, "("...)
		for i, child := range f {
			err = t.internalTranslate(schemaMap, child, q, jsonpath)

			if err != nil {
				return
			}
			if i < len(f)-1 {
				*jsonpath = append(*jsonpath, " && "...)
			}
		}
		*jsonpath = append(*jsonpath, ")"...)
	case message.FilterOr:
		*jsonpath = append(*jsonpath, "("...)
		for i, child := range f {
			err = t.internalTranslate(schemaMap, child, q, jsonpath)

			if err != nil {
				return
			}
			if i < len(f)-1 {
				*jsonpath = append(*jsonpath, " || "...)
			}
		}
		*jsonpath = append(*jsonpath, ")"...)
	case message.FilterNot:
		*jsonpath = append(*jsonpath, "(!("...)
		err = t.internalTranslate(schemaMap, f.Filter, q, jsonpath)

		if err != nil {
			return
		}
		*jsonpath = append(*jsonpath, "))"...)
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
				t.StartsWithMatch(s, q, jsonpath, string(fsv), i)
			case message.SubstringAny:
				if i > 0 {
					*jsonpath = append(*jsonpath, " && "...)
				}
				t.AnyMatch(s, q, jsonpath, string(fsv), i)
			case message.SubstringFinal:
				if i > 0 {
					*jsonpath = append(*jsonpath, " || "...)
				}
				t.EndsMatch(s, q, jsonpath, string(fsv), i)
			}
		}
	case message.FilterEqualityMatch:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.EqualityMatch(s, q, jsonpath, string(f.AssertionValue()))
		}
	case message.FilterGreaterOrEqual:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.GreaterOrEqualMatch(s, q, jsonpath, string(f.AssertionValue()))
		}
	case message.FilterLessOrEqual:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.LessOrEqualMatch(s, q, jsonpath, string(f.AssertionValue()))
		}
	case message.FilterPresent:
		if s, ok := findSchema(schemaMap, string(f)); ok {
			t.PresentMatch(s, q, jsonpath)
		}
	case message.FilterApproxMatch:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			t.ApproxMatch(s, q, jsonpath, string(f.AssertionValue()))
		}
	}

	return
}

func (t *FullJsonQueryTranslator) StartsWithMatch(s *Schema, q *Query, jsonpath *[]byte, val string, i int) {
	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	// attrs_norm @@ '$.cn starts with "foo"';
	*jsonpath = append(*jsonpath, `$.`...)
	*jsonpath = append(*jsonpath, s.Name...)
	*jsonpath = append(*jsonpath, ` starts with "`...)
	*jsonpath = append(*jsonpath, escape(sv.Norm()[0])...)
	*jsonpath = append(*jsonpath, `"`...)
}

func (t *FullJsonQueryTranslator) AnyMatch(s *Schema, q *Query, jsonpath *[]byte, val string, i int) {
	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	// attrs_norm @@ '$.cn like_regex ".*foo.*"';
	*jsonpath = append(*jsonpath, `$.`...)
	*jsonpath = append(*jsonpath, s.Name...)
	*jsonpath = append(*jsonpath, ` like_regex ".*`...)
	*jsonpath = append(*jsonpath, escapeRegex(sv.Norm()[0])...)
	*jsonpath = append(*jsonpath, `".*`...)
}

func (t *FullJsonQueryTranslator) EndsMatch(s *Schema, q *Query, jsonpath *[]byte, val string, i int) {
	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	// attrs_norm @@ '$.cn like_regex ".*foo.*"';
	*jsonpath = append(*jsonpath, `$.`...)
	*jsonpath = append(*jsonpath, s.Name...)
	*jsonpath = append(*jsonpath, ` like_regex ".*`...)
	*jsonpath = append(*jsonpath, escapeRegex(sv.Norm()[0])...)
	*jsonpath = append(*jsonpath, `"$`...)
}

func (t *FullJsonQueryTranslator) EqualityMatch(s *Schema, q *Query, jsonpath *[]byte, val string) {
	paramKey := q.nextParamKey(s.Name)

	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		// TODO error no entry response
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s, err: %+v", s.Name, val, err)
		return
	}

	if s.IsUseMemberTable {
		reqDN, err := s.server.NormalizeDN(val)
		if err != nil {
			log.Printf("warn: Ignore filter due to invalid DN syntax of member. attrName: %s, value: %s, err: %+v", s.Name, val, err)
			return
		}

		// Stroe into pendig params since we need to resolve the parent DN as id later
		q.PendingParams[reqDN] = paramKey

		// attrs_norm @@ '$.member[*] == "uid=u000001,ou=Users,dc=example,dc=com"';
		*jsonpath = append(*jsonpath, `$.`...)
		*jsonpath = append(*jsonpath, s.Name...)
		*jsonpath = append(*jsonpath, ` == :`...)
		*jsonpath = append(*jsonpath, paramKey...) // replace using pending params later before executing query
		*jsonpath = append(*jsonpath, ``...)
	} else if s.IsUseMemberOfTable {
		reqDN, err := s.server.NormalizeDN(val)
		if err != nil {
			log.Printf("warn: Ignore filter due to invalid DN syntax of memberOf. attrName: %s, value: %s, err: %+v", s.Name, val, err)
			return
		}

		// Stroe into pendig params since we need to resolve the parent DN as id later
		q.PendingParams[reqDN] = paramKey

		// attrs_norm @@ '$.memberof[*] == "cn=g000001,ou=Groups,dc=example,dc=com"';
		*jsonpath = append(*jsonpath, `$.`...)
		*jsonpath = append(*jsonpath, s.Name...)
		*jsonpath = append(*jsonpath, ` == :`...)
		*jsonpath = append(*jsonpath, paramKey...) // replace using pending params later before executing query
		*jsonpath = append(*jsonpath, ``...)
	} else {
		// attrs_norm @@ '$.cn == "foo"';
		*jsonpath = append(*jsonpath, `$.`...)
		*jsonpath = append(*jsonpath, s.Name...)
		*jsonpath = append(*jsonpath, ` == "`...)
		*jsonpath = append(*jsonpath, escape(sv.Norm()[0])...)
		*jsonpath = append(*jsonpath, `"`...)
	}
}

func (t *FullJsonQueryTranslator) GreaterOrEqualMatch(s *Schema, q *Query, jsonpath *[]byte, val string) {
	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	// TODO escape check

	// attrs_norm @@ '$.cn == "foo"';
	*jsonpath = append(*jsonpath, `$.`...)
	*jsonpath = append(*jsonpath, s.Name...)
	*jsonpath = append(*jsonpath, ` >= `...)
	*jsonpath = append(*jsonpath, escape(sv.Norm()[0])...)
	*jsonpath = append(*jsonpath, ``...)
}

func (t *FullJsonQueryTranslator) LessOrEqualMatch(s *Schema, q *Query, jsonpath *[]byte, val string) {
	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	// TODO escape check

	// attrs_norm @@ '$.cn == "foo"';
	*jsonpath = append(*jsonpath, `$.`...)
	*jsonpath = append(*jsonpath, s.Name...)
	*jsonpath = append(*jsonpath, ` <= `...)
	*jsonpath = append(*jsonpath, escape(sv.Norm()[0])...)
	*jsonpath = append(*jsonpath, ``...)
}

func (t *FullJsonQueryTranslator) PresentMatch(s *Schema, q *Query, jsonpath *[]byte) {
	// attrs_norm @@ '$.cn == "foo"';
	*jsonpath = append(*jsonpath, `exists($.`...)
	*jsonpath = append(*jsonpath, escape(s.Name)...)
	*jsonpath = append(*jsonpath, `)`...)
}

func (t *FullJsonQueryTranslator) ApproxMatch(s *Schema, q *Query, jsonpath *[]byte, val string) {
	sv, err := NewSchemaValue(s.Name, []string{val})
	if err != nil {
		log.Printf("warn: Ignore filter due to invalid syntax. attrName: %s, value: %s", s.Name, val)
		return
	}

	// TODO
	// attrs_norm @@ '$.cn like_regex ".*foo.*"';
	*jsonpath = append(*jsonpath, `$.`...)
	*jsonpath = append(*jsonpath, s.Name...)
	*jsonpath = append(*jsonpath, ` like_regex ".*`...)
	*jsonpath = append(*jsonpath, escapeRegex(sv.Norm()[0])...)
	*jsonpath = append(*jsonpath, `"$`...)
}
