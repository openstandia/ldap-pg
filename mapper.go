package main

import (
	// "fmt"

	"log"
	"strconv"

	"github.com/openstandia/goldap/message"
)

type Mapper struct {
	server *Server
}

func NewMapper(server *Server) *Mapper {
	return &Mapper{
		server: server,
	}
}

func (m *Mapper) LDAPMessageToAddEntry(dn *DN, ldapAttrs message.AttributeList) (*AddEntry, error) {
	entry := NewAddEntry(m.server.schemaMap, dn)

	for _, attr := range ldapAttrs {
		k := attr.Type_()
		attrName := string(k)

		arr := make([]string, len(attr.Vals()))
		for i, v := range attr.Vals() {
			arr[i] = string(v)
		}

		err := entry.Add(attrName, arr)
		if err != nil {
			log.Printf("warn: Invalid attribute. attrName: %s, err: %s", k, err)
			return nil, err
		}
	}

	err := entry.Validate()
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func uniqueIDs(target []int64) []string {
	m := map[int64]bool{}
	result := []string{}

	for _, v := range target {
		if !m[v] {
			m[v] = true
			result = append(result, strconv.FormatInt(v, 10))
		}
	}

	return result
}

func unique(target []int64) []int64 {
	m := map[int64]bool{}
	result := []int64{}

	for _, v := range target {
		if !m[v] {
			m[v] = true
			result = append(result, v)
		}
	}

	return result
}
