package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/openstandia/goldap/message"
)

type Mapper struct {
	schemaMap SchemaMap
}

func NewMapper(s SchemaMap) *Mapper {
	return &Mapper{
		schemaMap: s,
	}
}

func (m *Mapper) ToEntry(dn *DN, ldapAttrs message.AttributeList) (*Entry, error) {
	entryUUID, _ := uuid.NewRandom()
	createTimestamp := time.Now()
	modifyTimestamp := createTimestamp

	jsonAttrs := JSONAttrs{}

	// Store RDN into attrs
	rdn := dn.GetRDN()
	for k, v := range rdn {
		s, ok := m.schemaMap.Get(k)
		if !ok {
			log.Printf("warn: Invalid rdn. attrName: %s", k)
			return nil, NewInvalidDNSyntax()
		}
		if s.SingleValue {
			jsonAttrs[s.Name] = v
		} else {
			jsonAttrs[s.Name] = []interface{}{v}
		}
	}

	for _, attr := range ldapAttrs {
		k := attr.Type_()
		attrName := string(k)

		s, ok := m.schemaMap.Get(attrName)
		if !ok {
			// TODO check classObject and return error response
			log.Printf("warn: Invalid attribute name %s", k)
			return nil, fmt.Errorf("Unsupported attribute name: %s", k)
		}

		var err error
		// TODO strict mode
		if s.Name == "entryUUID" {
			entryUUID, err = uuid.Parse(string(attr.Vals()[0]))
			if err != nil {
				log.Printf("warn: Invalid entryUUID %s", attr.Vals()[0])
				return nil, err
			}
			continue
		}
		// TODO strict mode
		if s.Name == "createTimestamp" {
			createTimestamp, err = time.Parse(TIMESTAMP_FORMAT, string(attr.Vals()[0]))
			if err != nil {
				log.Printf("warn: Invalid createTimestamp %s, err: %s", attr.Vals()[0], err)
				return nil, err
			}
			continue
		}
		// TODO strict mode
		if s.Name == "modifyTimestamp" {
			modifyTimestamp, err = time.Parse(TIMESTAMP_FORMAT, string(attr.Vals()[0]))
			if err != nil {
				log.Printf("warn: Invalid modifyTimestamp %s, err: %s", attr.Vals()[0], err)
				return nil, err
			}
			continue
		}

		mapAttributeValue(s, attr, jsonAttrs)
	}

	entry := NewEntry(dn, jsonAttrs)
	entry.EntryUUID = entryUUID.String()
	entry.Created = createTimestamp
	entry.Updated = modifyTimestamp

	return entry, nil
}

func mapAttributeValue(s *Schema, attr message.Attribute, jsonAttrs JSONAttrs) {
	if s.SingleValue {
		jsonAttrs[s.Name] = string(attr.Vals()[0])
	} else {
		arr := []interface{}{}
		for _, v := range attr.Vals() {
			arr = append(arr, string(v))
		}
		jsonAttrs[s.Name] = arr
	}
}
