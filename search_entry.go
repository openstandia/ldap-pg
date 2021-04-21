package main

type SearchEntry struct {
	schemaMap  *SchemaMap
	dn         *DN
	attributes map[string][]string
}

func NewSearchEntry(schemaMap *SchemaMap, dn *DN, valuesOrig map[string][]string) *SearchEntry {
	readEntry := &SearchEntry{
		schemaMap:  schemaMap,
		dn:         dn,
		attributes: valuesOrig,
	}
	return readEntry
}

func (j *SearchEntry) DNNormStr() string {
	return j.dn.DNNormStr()
}

func (j *SearchEntry) DNOrigStr() string {
	return j.dn.DNOrigStr()
}

func (j *SearchEntry) GetAttrsOrig() map[string][]string {
	return j.attributes
}

func (j *SearchEntry) GetAttrOrig(attrName string) (string, []string, bool) {
	s, ok := j.schemaMap.Get(attrName)
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
		if s, ok := j.schemaMap.Get(k); ok {
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
		if s, ok := j.schemaMap.Get(k); ok {
			if s.IsOperationalAttribute() {
				m[k] = v
			}
		}
	}
	return m
}
