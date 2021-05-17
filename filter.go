package main

import (
	"log"
	"regexp"
	"strings"
)

func escapeRegex(s string) string {
	return regexp.QuoteMeta(s)
}

// escape escapes meta characters used in PostgreSQL jsonpath name.
// See https://www.postgresql.org/docs/12/datatype-json.html#DATATYPE-JSONPATH
func escapeName(s string) string {
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `'`, `''`) // Write two adjacent single quotes
	s = strings.ReplaceAll(s, `[`, `\[`)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `*`, `\*`)
	return s
}

// escapeValue escapes meta characters used in PostgreSQL jsonpath value.
// See https://www.postgresql.org/docs/12/datatype-json.html#DATATYPE-JSONPATH
func escapeValue(s string) string {
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `'`, `''`)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return s
}

func findSchema(schemaMap *SchemaMap, attrName string) (*Schema, bool) {
	var s *Schema
	s, ok := schemaMap.Get(attrName)
	if !ok {
		log.Printf("Unsupported filter attribute: %s", attrName)
		return nil, false
	}
	return s, true
}
