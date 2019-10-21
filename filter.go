package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/openstandia/goldap/message"
	"github.com/pkg/errors"
)

func (s *Schema) SubstringMatch(q *Query, val string, i int) {
	paramKey := q.nextParamKey(s.Name)

	if s.IndexType == "fts" {
		q.Query += fmt.Sprintf("attrs_norm->>'%s' ILIKE :%s", s.Name, paramKey)
	} else {
		if s.IsCaseIgnoreSubstr() {
			q.Query += fmt.Sprintf("attrs_norm->>'%s' LIKE :%s", s.Name, paramKey)
		} else {
			q.Query += fmt.Sprintf("attrs_norm->>'%s' LIKE :%s", s.Name, paramKey)
		}
	}
	q.Params[paramKey] = val
}

func (s *Schema) EqualityMatch(q *Query, val string) {
	paramKey := q.nextParamKey(s.Name)

	if s.IndexType == "fts" {
		// TODO Escapse %
		q.Query += fmt.Sprintf("attrs_norm->>'%s' ILIKE :%s", s.Name, paramKey)
	} else {
		if s.IsCaseIgnore() {
			if s.SingleValue {
				q.Query += fmt.Sprintf("attrs_norm->>'%s' = :%s", s.Name, paramKey)
			} else {
				q.Query += fmt.Sprintf("attrs_norm->'%s' @> jsonb_build_array(CAST(:%s AS text))", s.Name, paramKey)
			}
		} else {
			if s.SingleValue {
				q.Query += fmt.Sprintf("attrs_norm->>'%s' = :%s", s.Name, paramKey)
			} else {
				q.Query += fmt.Sprintf("attrs_norm->'%s' @> jsonb_build_array(CAST(:%s AS TEXT))", s.Name, paramKey)
			}
		}
	}
	q.Params[paramKey] = val
}

func (s *Schema) GreaterOrEqualMatch(q *Query, val string) {
	paramKey := q.nextParamKey(s.Name)

	q.Query += fmt.Sprintf("(attrs_norm->>'%s')::numeric >= :%s", s.Name, paramKey)
	q.Params[paramKey] = val
}

func (s *Schema) LessOrEqualMatch(q *Query, val string) {
	paramKey := q.nextParamKey(s.Name)

	q.Query += fmt.Sprintf("(attrs_norm->>'%s')::numeric <= :%s", s.Name, paramKey)
	q.Params[paramKey] = val
}

func (s *Schema) PresentMatch(q *Query) {
	if s.IndexType == "jsonb_ops" {
		q.Query += fmt.Sprintf("attrs_norm ? '%s'", s.Name)
	} else {
		q.Query += fmt.Sprintf("(attrs_norm->>'%s') IS NOT NULL", s.Name)
	}
}

func (s *Schema) ApproxMatch(q *Query, val string) {
	paramKey := q.nextParamKey(s.Name)

	q.Query += fmt.Sprintf("attrs_norm->>'%s' ILIKE :%s", s.Name, paramKey)
	q.Params[paramKey] = val
}

type Query struct {
	hasOr  bool
	Query  string
	Params map[string]interface{}
}

func (q *Query) nextParamKey(name string) string {
	return fmt.Sprintf("%d_%s", len(q.Params), name)
}

func ToQuery(schemaMap SchemaMap, packet message.Filter) (*Query, error) {
	q := &Query{
		Query:  "",
		Params: map[string]interface{}{},
	}

	err := translateFilter(schemaMap, packet, q)
	if err != nil {
		return nil, errors.Wrap(err, "Query translating error")
	}

	log.Printf("Translated query: %s\n  Bind: %#v", q.Query, q.Params)

	return q, nil
}

func translateFilter(schemaMap SchemaMap, packet message.Filter, q *Query) (err error) {
	err = nil

	switch f := packet.(type) {
	case message.FilterAnd:
		q.Query += "("
		for i, child := range f {
			err = translateFilter(schemaMap, child, q)

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
			err = translateFilter(schemaMap, child, q)

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
		err = translateFilter(schemaMap, f.Filter, q)
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
				// TODO Escapse %
				s.SubstringMatch(q, string(fsv)+"%", i)
			case message.SubstringAny:
				if i > 0 {
					q.Query += " AND "
				}
				// TODO Escapse %
				s.SubstringMatch(q, "%"+string(fsv)+"%", i)
			case message.SubstringFinal:
				if i > 0 {
					q.Query += " AND "
				}
				// TODO Escapse %
				s.SubstringMatch(q, "%"+string(fsv), i)
			}
		}
	case message.FilterEqualityMatch:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			s.EqualityMatch(q, string(f.AssertionValue()))
		}
	case message.FilterGreaterOrEqual:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			s.GreaterOrEqualMatch(q, string(f.AssertionValue()))
		}
	case message.FilterLessOrEqual:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			s.LessOrEqualMatch(q, string(f.AssertionValue()))
		}
	case message.FilterPresent:
		if s, ok := findSchema(schemaMap, string(f)); ok {
			s.PresentMatch(q)
		}
	case message.FilterApproxMatch:
		if s, ok := findSchema(schemaMap, string(f.AttributeDesc())); ok {
			s.ApproxMatch(q, string(f.AssertionValue()))
		}
	}

	return
}

func findSchema(schemaMap SchemaMap, attrName string) (*Schema, bool) {
	var s *Schema
	s, ok := schemaMap.Get(attrName)
	if !ok {
		log.Printf("Unsupported filter attribute: %s", attrName)
		return nil, false
	}
	return s, true
}

func resolveKeyTable(baseObject string) string {
	keyTable := strings.Split(strings.Split(baseObject, ",")[0], "=")[1]
	return keyTable
}
