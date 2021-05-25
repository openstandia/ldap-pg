package main

type SearchEntry struct {
	schemaMap  *SchemaMap
	dnOrig     string
	attributes map[string][]string
}

func NewSearchEntry(schemaMap *SchemaMap, dnOrig string, valuesOrig map[string][]string) *SearchEntry {
	readEntry := &SearchEntry{
		schemaMap:  schemaMap,
		dnOrig:     dnOrig,
		attributes: valuesOrig,
	}
	return readEntry
}

func (j *SearchEntry) DNOrigStr() string {
	return j.dnOrig
}

func (j *SearchEntry) GetAttrsOrig() map[string][]string {
	return j.attributes
}

func (j *SearchEntry) GetAttrOrig(attrName string) (string, []string, bool) {
	s, ok := j.schemaMap.AttributeType(attrName)
	if !ok {
		return "", nil, false
	}

	v, ok := j.attributes[s.Name]
	if !ok {
		return "", nil, false
	}
	return s.Name, v, true
}

func (j *SearchEntry) GetAttrsOrigWithoutOperationalAttrs() map[string][]string {
	m := map[string][]string{}
	for k, v := range j.attributes {
		if s, ok := j.schemaMap.AttributeType(k); ok {
			if !s.IsOperationalAttribute() {
				m[k] = v
			}
		}
	}
	return m
}

func (j *SearchEntry) GetOperationalAttrsOrig() map[string][]string {
	m := map[string][]string{}
	for k, v := range j.attributes {
		if s, ok := j.schemaMap.AttributeType(k); ok {
			if s.IsOperationalAttribute() {
				m[k] = v
			}
		}
	}
	return m
}
