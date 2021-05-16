package main

import (
	"log"
	"strings"
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

func findSchema(schemaMap *SchemaMap, attrName string) (*Schema, bool) {
	var s *Schema
	s, ok := schemaMap.Get(attrName)
	if !ok {
		log.Printf("Unsupported filter attribute: %s", attrName)
		return nil, false
	}
	return s, true
}
