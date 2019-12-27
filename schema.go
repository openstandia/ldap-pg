package main

import (
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strings"
	"time"
)

type SchemaMap map[string]*Schema

func (s SchemaMap) Get(k string) (*Schema, bool) {
	schema, ok := s[strings.ToLower(k)]
	return schema, ok
}

func (s SchemaMap) Put(k string, schema *Schema) {
	s[strings.ToLower(k)] = schema
}

// TODO
var mergedSchema string = ""

func (s SchemaMap) Dump() string {
	return mergedSchema
}

func (s SchemaMap) resolve() error {
	for _, v := range s {
		// log.Printf("Schema resolve %s", v.Name)
		vv := reflect.ValueOf(v)

		for _, f := range []string{"Equality", "Ordering", "Substr"} {
			// log.Printf("Checking %s", f)
			field := vv.Elem().FieldByName(f)
			val := field.Interface().(string)

			if val == "" {
				cur := v
				var parent *Schema
				for {
					if cur.Sup == "" {
						break
					}
					var ok bool
					parent, ok = s.Get(cur.Sup)
					if !ok {
						return fmt.Errorf("Not found '%s' in schema.", cur.Sup)
					}
					// log.Printf("Finding parent: %s", cur.Sup)

					pval := reflect.ValueOf(parent).Elem().FieldByName(f).Interface().(string)
					if pval != "" {
						// log.Printf("Found %s: %s", f, pval)
						field.SetString(pval)
						break
					}
					// find next parent
					cur = parent
				}
			}
		}
	}
	return nil
}

type Schema struct {
	server             *Server
	Name               string
	AName              []string
	Oid                string
	Equality           string
	Ordering           string
	Substr             string
	Syntax             string
	Sup                string
	Usage              string
	IndexType          string
	ColumnName         string
	SingleValue        bool
	NoUserModification bool
}

func InitSchemaMap(server *Server) SchemaMap {
	m := SchemaMap{}

	mergedSchema = mergeSchema(SCHEMA_OPENLDAP24, customSchema)
	parseSchema(server, m, mergedSchema)

	err := m.resolve()
	if err != nil {
		log.Printf("error: Resolving schema error. %v", err)
	}

	return m
}

var (
	oidPattern      = regexp.MustCompile("(^.*?): \\( (.*?) ")
	namePattern     = regexp.MustCompile("^.*?: \\( .*? NAME '(.*?)' ")
	namesPattern    = regexp.MustCompile("^.*?: \\( .*? NAME \\( (.*?) \\) ")
	equalityPattern = regexp.MustCompile(" EQUALITY (.*?) ")
	syntaxPattern   = regexp.MustCompile(" SYNTAX (.*?) ")
	substrPattern   = regexp.MustCompile(" SUBSTR (.*?) ")
	orderingPattern = regexp.MustCompile(" ORDERING (.*?) ")
	supPattern      = regexp.MustCompile(" SUP (.*?) ")
	usagePattern    = regexp.MustCompile(" USAGE (.*?) ")
)

func parseSchema(server *Server, m SchemaMap, schemaDef string) {
	for _, line := range strings.Split(strings.TrimSuffix(schemaDef, "\n"), "\n") {
		if strings.HasPrefix(line, "attributeTypes") {
			stype, oid := parseOid(line)
			name := parseName(line)

			eg := equalityPattern.FindStringSubmatch(line)
			syng := syntaxPattern.FindStringSubmatch(line)
			subg := substrPattern.FindStringSubmatch(line)
			og := orderingPattern.FindStringSubmatch(line)
			supg := supPattern.FindStringSubmatch(line)
			usag := usagePattern.FindStringSubmatch(line)

			if stype == "" || oid == "" || len(name) == 0 {
				log.Printf("warn: Unsupported schema. %s", line)
				continue
			}

			s := &Schema{
				server:      server,
				IndexType:   "", // TODO configurable
				SingleValue: false,
			}
			s.Oid = oid
			if len(name) == 1 {
				s.Name = name[0]
			} else {
				s.Name = name[0]
				s.AName = name[1:]
			}

			// log.Printf("schema: %+v", s)

			if eg != nil {
				s.Equality = eg[1]
			}
			if syng != nil {
				s.Syntax = syng[1]
			}
			if subg != nil {
				s.Substr = subg[1]
			}
			if og != nil {
				s.Ordering = og[1]
			}
			if supg != nil {
				s.Sup = supg[1]
			}
			if usag != nil {
				s.Usage = usag[1]
			}

			if strings.Contains(line, "SINGLE-VALUE") {
				s.SingleValue = true
			}
			if !*migrationEnabled && strings.Contains(line, "NO-USER-MODIFICATION") {
				s.NoUserModification = true
			}

			m.Put(s.Name, s)
		}
	}

	// Add dn schema
	// if dn, ok := m.Get("distinguishedName"); ok {
	// 	m.Put("dn", dn)
	// }
}

func parseOid(line string) (string, string) {
	og := oidPattern.FindStringSubmatch(line)

	stype := og[1]
	oid := og[2]

	return stype, oid
}

func parseName(line string) []string {
	ng := namePattern.FindStringSubmatch(line)
	nsg := namesPattern.FindStringSubmatch(line)

	var name []string
	if ng != nil {
		name = []string{ng[1]}
	} else {
		name = strings.Split(strings.ReplaceAll(nsg[1], "'", ""), " ")
	}

	return name
}

func mergeSchema(a string, b []string) string {
	used := make(map[string]struct{}, len(b))

	lsResult := []string{}
	mrResult := []string{}
	mruResult := []string{}
	atResult := []string{}
	ocResult := []string{}

	for _, line1 := range strings.Split(strings.TrimSuffix(a, "\n"), "\n") {
		if line1 == "" {
			continue
		}
		stype1, oid1 := parseOid(line1)

		overwriting := false
		for _, line2 := range b {
			if line2 == "" {
				continue
			}
			stype2, oid2 := parseOid(line2)
			if stype1 == stype2 && oid1 == oid2 {
				log.Printf("info: Overwriting schema: %s", line2)

				switch strings.ToLower(stype1) {
				case "ldapsyntaxes":
					lsResult = append(lsResult, line2)
				case "matchingrules":
					mrResult = append(mrResult, line2)
				case "matchingruleuse":
					mruResult = append(mruResult, line2)
				case "attributetypes":
					atResult = append(atResult, line2)
				case "objectclasses":
					ocResult = append(ocResult, line2)
				}

				used[stype2+"/"+oid2] = struct{}{}
				overwriting = true
				break
			}
		}
		if !overwriting {
			switch strings.ToLower(stype1) {
			case "ldapsyntaxes":
				lsResult = append(lsResult, line1)
			case "matchingrules":
				mrResult = append(mrResult, line1)
			case "matchingruleuse":
				mruResult = append(mruResult, line1)
			case "attributetypes":
				atResult = append(atResult, line1)
			case "objectclasses":
				ocResult = append(ocResult, line1)
			}
		}
	}

	// Additional custom schema
	for _, line2 := range b {
		if line2 == "" {
			continue
		}
		stype2, oid2 := parseOid(line2)
		if _, ok := used[stype2+"/"+oid2]; !ok {
			log.Printf("info: Adding schema: %s", line2)

			switch strings.ToLower(stype2) {
			case "ldapsyntaxes":
				lsResult = append(lsResult, line2)
			case "matchingrules":
				mrResult = append(mrResult, line2)
			case "matchingruleuse":
				mruResult = append(mruResult, line2)
			case "attributetypes":
				atResult = append(atResult, line2)
			case "objectclasses":
				ocResult = append(ocResult, line2)
			}
		}
	}

	all := []string{}
	all = append(all, lsResult...)
	all = append(all, mrResult...)
	all = append(all, mruResult...)
	all = append(all, atResult...)
	all = append(all, ocResult...)

	return strings.Join(all, "\n")
}

func (s *Schema) NewSchemaValueMap(size int) SchemaValueMap {
	valMap := SchemaValueMap{
		schema:   s,
		valueMap: make(map[string]struct{}, size),
	}
	return valMap
}

type SchemaValueMap struct {
	schema   *Schema
	valueMap map[string]struct{}
}

func (m SchemaValueMap) Put(val string) {
	if m.schema.IsCaseIgnore() {
		m.valueMap[strings.ToLower(val)] = struct{}{}
	} else {
		m.valueMap[val] = struct{}{}
	}
}

func (m SchemaValueMap) Has(val string) bool {
	if m.schema.IsCaseIgnore() {
		_, ok := m.valueMap[strings.ToLower(val)]
		return ok
	} else {
		_, ok := m.valueMap[val]
		return ok
	}
}

type SchemaValue struct {
	schema          *Schema
	value           []string
	cachedNorm      []string
	cachedNormIndex map[string]struct{}
}

func NewSchemaValue(attrName string, attrValue []string) (*SchemaValue, error) {
	// TODO refactoring
	s, ok := schemaMap.Get(attrName)
	if !ok {
		return nil, NewUndefinedType(attrName)
	}

	if s.SingleValue && len(attrValue) > 1 {
		return nil, NewMultipleValuesProvidedError(attrName)
	}

	sv := &SchemaValue{
		schema: s,
		value:  attrValue,
	}

	_, err := sv.Normalize()
	if err != nil {
		return nil, err
	}

	// Check if it contains duplicate value
	if !s.SingleValue && len(sv.value) != len(sv.cachedNormIndex) {
		// TODO index
		return nil, NewMoreThanOnceError(attrName, 0)
	}

	return sv, nil
}

func (s *SchemaValue) Name() string {
	return s.schema.Name
}

func (s *SchemaValue) HasDuplicate(value *SchemaValue) bool {
	s.Normalize()

	for _, v := range value.Norm() {
		if _, ok := s.cachedNormIndex[v]; ok {
			return true
		}
	}
	return false
}

func (s *SchemaValue) Validate() string {

	//return NewInvalidPerSyntax(attrName, 0)
	return s.schema.Name
}

func (s *SchemaValue) IsSingle() bool {
	return s.schema.SingleValue
}

func (s *SchemaValue) IsNoUserModification() bool {
	return s.schema.NoUserModification
}

func (s *SchemaValue) IsEmpty() bool {
	return len(s.value) == 0
}

func (s *SchemaValue) IsMemberAttribute() bool {
	return s.schema.IsMemberAttribute()
}

func (s *SchemaValue) Clone() *SchemaValue {
	newValue := make([]string, len(s.value))
	copy(newValue, s.value)

	return &SchemaValue{
		schema: s.schema,
		value:  newValue,
	}
}

func (s *SchemaValue) Equals(value *SchemaValue) bool {
	if s.IsSingle() != value.IsSingle() {
		return false
	}
	if s.IsSingle() {
		return s.Norm()[0] == value.Norm()[0]
	} else {
		if len(s.value) != len(value.value) {
			return false
		}

		s.Normalize()

		for _, v := range value.Norm() {
			if _, ok := s.cachedNormIndex[v]; !ok {
				return false
			}
		}
		return true
	}
}

func (s *SchemaValue) Add(value *SchemaValue) error {
	if s.IsSingle() {
		return NewMultipleValuesConstraintViolation(value.Name())

	} else {
		if s.HasDuplicate(value) {
			// TODO index
			return NewTypeOrValueExists("modify/add", value.Name(), 0)
		}
	}
	s.value = append(s.value, value.value...)
	s.cachedNorm = nil
	s.cachedNormIndex = nil

	return nil
}

func (s *SchemaValue) Delete(value *SchemaValue) error {
	s.Normalize()
	value.Normalize()

	// TODO Duplicate delete error

	// Check the values
	for _, v := range value.Norm() {
		if _, ok := s.cachedNormIndex[v]; !ok {
			// Not found the value
			return NewNoSuchAttribute("modify/delete", value.Name())
		}
	}

	// Create new values
	newValue := make([]string, len(s.value)-len(value.value))
	newValueNorm := make([]string, len(newValue))

	i := 0
	for j, v := range s.Norm() {
		if _, ok := value.cachedNormIndex[v]; !ok {
			newValue[i] = s.value[j]
			newValueNorm[i] = s.cachedNorm[j]
			i++
		}
	}

	s.value = newValue
	s.cachedNorm = newValueNorm
	s.cachedNormIndex = nil

	return nil
}

func (s *SchemaValue) Orig() []string {
	return s.value
}

func (s *SchemaValue) AsTime() []time.Time {
	t := make([]time.Time, len(s.value))
	for i, _ := range s.value {
		// Already validated, ignore error
		t[i], _ = time.Parse(TIMESTAMP_FORMAT, s.value[i])
	}
	return t
}

func (s *SchemaValue) Norm() []string {
	s.Normalize()
	return s.cachedNorm
}

func (s *SchemaValue) GetForJSON() interface{} {
	s.Normalize()
	if s.schema.SingleValue {
		return s.cachedNorm[0]
	}
	return s.cachedNorm
}

// Normalize the value using schema definition.
// The value is expected as a valid value. It means you need to validte the value in advance.
func (s *SchemaValue) Normalize() ([]string, error) {
	if len(s.cachedNorm) > 0 {
		return s.cachedNorm, nil
	}

	rtn := make([]string, len(s.value))
	m := make(map[string]struct{}, len(s.value))
	for i, v := range s.value {
		var err error
		rtn[i], err = normalize(s.schema, v)
		if err != nil {
			return nil, err
		}
		m[rtn[i]] = struct{}{}
	}
	s.cachedNorm = rtn
	s.cachedNormIndex = m

	return rtn, nil
}

func (s *Schema) IsCaseIgnore() bool {
	if strings.HasPrefix(s.Equality, "caseIgnore") ||
		s.Equality == "objectIdentifierMatch" {
		return true
	}
	return false
}

func (s *Schema) IsCaseIgnoreSubstr() bool {
	if strings.HasPrefix(s.Substr, "caseIgnore") ||
		s.Substr == "numericStringSubstringsMatch" {
		return true
	}
	return false
}

func (s *Schema) IsOperationalAttribute() bool {
	if s.Usage == "directoryOperation" ||
		s.Usage == "dSAOperation" {
		return true
	}
	// TODO check other case
	return false
}

func (s *Schema) IsMemberAttribute() bool {
	if s.Name == "member" ||
		s.Name == "uniqueMember" {
		return true
	}
	return false
}

func (s *Schema) IsIndependentColumn() bool {
	return s.ColumnName != ""
}

func (s *Schema) UseIndependentColumn(c string) {
	s.ColumnName = c
}
