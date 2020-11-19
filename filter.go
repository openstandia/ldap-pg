package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/openstandia/goldap/message"
	"github.com/pkg/errors"
)

// TODO Need more escape?
func escapeRegex(s string) string {
	s = escape(s)
	s = strings.ReplaceAll(s, `*`, `\*`)
	return s
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `(`, `\(`)
	s = strings.ReplaceAll(s, `)`, `\)`)
	s = strings.ReplaceAll(s, `.`, `\.`)
	return s
}

type Query struct {
	Query           string
	Params          map[string]interface{}
	PendingParams   map[*DN]string   // dn => paramsKey
	IdToDNOrigCache map[int64]string // id => dn_orig
	DNNormToIdCache map[string]int64 // dn_norm => id
}

func (q *Query) nextParamKey(name string) string {
	return fmt.Sprintf("%d_%s", len(q.Params), name)
}

func ToQuery(s *Server, schemaMap SchemaMap, packet message.Filter) (*Query, error) {
	q := &Query{
		Query:           "",
		Params:          map[string]interface{}{},
		PendingParams:   map[*DN]string{},
		IdToDNOrigCache: map[int64]string{},
		DNNormToIdCache: map[string]int64{},
	}

	var f QueryTranslator
	if s.config.QueryTranslator == "default" {
		f = &FullJsonQueryTranslator{}
	}

	err := f.Translate(schemaMap, packet, q)
	if err != nil {
		return nil, errors.Wrap(err, "Query translating error")
	}

	log.Printf("Translated query: %s\n  Bind: %#v", q.Query, q.Params)

	return q, nil
}

type QueryTranslator interface {
	Translate(schemaMap SchemaMap, packet message.Filter, q *Query) error
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
