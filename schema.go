package main

import (
	"fmt"
	"log"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

func NewSchema(server *Server) *SchemaMap {
	return &SchemaMap{
		server:         server,
		ObjectClasses:  map[string]*ObjectClass{},
		AttributeTypes: map[string]*AttributeType{},
	}
}

type SchemaMap struct {
	server         *Server
	ObjectClasses  map[string]*ObjectClass
	AttributeTypes map[string]*AttributeType
}

func (s *SchemaMap) ObjectClass(k string) (*ObjectClass, bool) {
	schema, ok := s.ObjectClasses[strings.ToLower(k)]
	return schema, ok
}

func (s *SchemaMap) PutObjectClass(k string, objectClass *ObjectClass) {
	s.ObjectClasses[strings.ToLower(k)] = objectClass
}

func (s *SchemaMap) AttributeType(k string) (*AttributeType, bool) {
	schema, ok := s.AttributeTypes[strings.ToLower(k)]
	return schema, ok
}

func (s *SchemaMap) PutAttributeType(k string, attributeType *AttributeType) {
	s.AttributeTypes[strings.ToLower(k)] = attributeType
}

func (s *SchemaMap) ValidateObjectClass(ocs []string, attrs map[string]*SchemaValue) *LDAPError {
	stoc := []*ObjectClass{}
	for i, v := range ocs {
		oc, ok := s.ObjectClass(v)
		if !ok {
			log.Printf("error: not found objectClass: %s", v)
			// Not found objectClass
			// e.g.
			// ldap_add: Invalid syntax (21)
			//   additional info: objectClass: value #0 invalid per syntax
			return NewInvalidPerSyntax("objectClass", i)
		}

		if oc.Structural {
			stoc = append(stoc, oc)
		}

		for _, mv := range oc.Must() {
			_, ok := attrs[mv]
			if !ok {
				// e.g.
				// ldap_add: Object class violation (65)
				//   additional info: object class 'inetOrgPerson' requires attribute 'sn'
				return NewObjectClassViolationRequiresAttribute(oc.Name, mv)
			}
		}
	}
	if len(stoc) == 0 {
		return NewObjectClassViolationNoStructural()
	}

	// Validate structural objectClass chain
	sortObjectClasses(s, stoc)
	if err := verifyChainedObjectClasses(s, stoc); err != nil {
		return err
	}

	for k, sv := range attrs {
		if k == "objectClass" {
			continue
		}
		if sv.IsNoUserModification() {
			continue
		}
		contains := false
		for i, v := range ocs {
			oc, ok := s.ObjectClass(v)
			if !ok {
				// Not found objectClass
				// e.g.
				// ldap_add: Invalid syntax (21)
				//   additional info: objectClass: value #0 invalid per syntax
				return NewInvalidPerSyntax("objectClass", i)
			}

			if oc.Contains(k) {
				contains = true
				break
			}
		}
		// Using unknown attribute
		if !contains {
			// e.g.
			// ldap_add: Object class violation (65)
			//   additional info: attribute 'uniqueMember' not allowed
			return NewObjectClassViolationNotAllowed(k)
		}
	}

	return nil
}

// TODO
var mergedSchema string = ""

func (s *SchemaMap) Dump() string {
	return mergedSchema
}

func (s *SchemaMap) resolve() error {
	for _, v := range s.AttributeTypes {
		// log.Printf("Schema resolve %s", v.Name)
		vv := reflect.ValueOf(v)

		for _, f := range []string{"Equality", "Ordering", "Substr"} {
			// log.Printf("Checking %s", f)
			field := vv.Elem().FieldByName(f)
			val := field.Interface().(string)

			if val == "" {
				cur := v
				var parent *AttributeType
				for {
					if cur.Sup == "" {
						break
					}
					var ok bool
					parent, ok = s.AttributeType(cur.Sup)
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

type AttributeType struct {
	schemaDef          *SchemaMap
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

type ObjectClass struct {
	schemaDef  *SchemaMap
	Name       string
	Oid        string
	Sup        string
	Structural bool
	Abstruct   bool
	Auxiliary  bool
	must       []string
	may        []string
}

func (o *ObjectClass) Must() []string {
	m := []string{}
	m = append(m, o.must...)

	if p, ok := o.schemaDef.ObjectClass(o.Sup); ok {
		m = append(m, p.Must()...)
	}
	return m
}

func (o *ObjectClass) May() []string {
	m := []string{}
	m = append(m, o.may...)

	if p, ok := o.schemaDef.ObjectClass(o.Sup); ok {
		m = append(m, p.May()...)
	}
	return m
}

func (o *ObjectClass) Contains(a string) bool {
	for _, v := range o.Must() {
		if strings.ToLower(v) == strings.ToLower(a) {
			return true
		}
	}
	for _, v := range o.May() {
		if strings.ToLower(v) == strings.ToLower(a) {
			return true
		}
	}
	return false
}

func InitSchemaMap(server *Server) *SchemaMap {
	m := NewSchema(server)

	mergedSchema = mergeSchema(SCHEMA_OPENLDAP24, customSchema)
	parseSchema(server, m, mergedSchema)
	err := parseObjectClass(server, m, mergedSchema)
	if err != nil {
		log.Fatalf("error: Failed to parse objectClass: %v", err)
	}

	err = m.resolve()
	if err != nil {
		log.Printf("error: Resolving schema error. %+v", err)
	}

	return m
}

var (
	oidPattern        = regexp.MustCompile("(^.*?): \\( (.*?) ")
	namePattern       = regexp.MustCompile("^.*?: \\( .*? NAME '(.*?)' ")
	namesPattern      = regexp.MustCompile("^.*?: \\( .*? NAME \\( (.*?) \\) ")
	equalityPattern   = regexp.MustCompile(" EQUALITY (.*?) ")
	syntaxPattern     = regexp.MustCompile(" SYNTAX (.*?) ")
	substrPattern     = regexp.MustCompile(" SUBSTR (.*?) ")
	orderingPattern   = regexp.MustCompile(" ORDERING (.*?) ")
	supPattern        = regexp.MustCompile(" SUP (.*?) ")
	usagePattern      = regexp.MustCompile(" USAGE (.*?) ")
	structuralPattern = regexp.MustCompile(" STRUCTURAL ")
	abstractPattern   = regexp.MustCompile(" ABSTRACT ")
	auxiliaryPattern  = regexp.MustCompile(" AUXILIARY ")
	mustPattern       = regexp.MustCompile(" MUST (.*?) ")
	multiMustPattern  = regexp.MustCompile(" MUST \\( (.*?) \\) ")
	mayPattern        = regexp.MustCompile(" MAY (.*?) ")
	multiMayPattern   = regexp.MustCompile(" MAY \\( (.*?) \\) ")
)

func parseSchema(server *Server, m *SchemaMap, schemaDef string) {
	for _, line := range strings.Split(strings.TrimSuffix(schemaDef, "\n"), "\n") {
		stype, oid := parseOid(line)

		if strings.ToLower(stype) == "attributetypes" {
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

			s := &AttributeType{
				schemaDef:   m,
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
			if strings.Contains(line, "NO-USER-MODIFICATION") {
				s.NoUserModification = true
			}

			m.PutAttributeType(s.Name, s)
		}
	}

	// Add dn schema
	// if dn, ok := m.Get("distinguishedName"); ok {
	// 	m.Put("dn", dn)
	// }
}

func parseObjectClass(server *Server, schemaDef *SchemaMap, rawSchemaDef string) error {
	isDefined := func(a string) bool {
		_, ok := schemaDef.AttributeType(a)
		return ok
	}
	for _, line := range strings.Split(strings.TrimSuffix(rawSchemaDef, "\n"), "\n") {
		stype, oid := parseOid(line)

		if strings.ToLower(stype) == "objectclasses" {
			name := parseName(line)
			supg := supPattern.FindStringSubmatch(line)
			stru := structuralPattern.MatchString(line)
			abst := abstractPattern.MatchString(line)
			auxi := auxiliaryPattern.MatchString(line)
			must := mustPattern.FindStringSubmatch(line)
			mmust := multiMustPattern.FindStringSubmatch(line)
			may := mayPattern.FindStringSubmatch(line)
			mmay := multiMayPattern.FindStringSubmatch(line)

			// TODO define schemas defined as hidden schema in OpenLDAP
			oc := &ObjectClass{
				schemaDef:  schemaDef,
				Oid:        oid,
				Name:       name[0],
				Structural: stru,
				Abstruct:   abst,
				Auxiliary:  auxi,
				must:       []string{},
				may:        []string{},
			}
			if supg != nil {
				oc.Sup = supg[1]
			}
			if mmust != nil {
				for _, v := range strings.Split(mmust[1], "$") {
					v = strings.TrimSpace(v)
					if !isDefined(v) {
						// log.Printf("warn: %s of %s isn't defined as attributeType in the schema", v, name)
						// return xerrors.Errorf("%s of %s isn't defined as attributeType in the schema", v, name)
					}
					oc.must = append(oc.must, strings.TrimSpace(v))
				}
			} else if must != nil {
				if !isDefined(must[1]) {
					// log.Printf("warn: %s of %s isn't defined as attributeType in the schema", must[1], name)
					// return xerrors.Errorf("%s of %s isn't defined as attributeType in the schema", must[1], name)
				}
				oc.must = append(oc.must, must[1])
			}
			if mmay != nil {
				for _, v := range strings.Split(mmay[1], "$") {
					v = strings.TrimSpace(v)
					if !isDefined(v) {
						// log.Printf("warn: %s of %s isn't defined as attributeType in the schema", v, name)
						// return xerrors.Errorf("%s of %s isn't defined as attributeType in the schema", v, name)
					}
					oc.may = append(oc.may, strings.TrimSpace(v))
				}
			} else if may != nil {
				if !isDefined(may[1]) {
					// log.Printf("warn: %s of %s isn't defined as attributeType in the schema", may[1], name)
					// return xerrors.Errorf("%s of %s isn't defined as attributeType in the schema", may[1], name)
				}
				oc.may = append(oc.may, may[1])
			}

			schemaDef.PutObjectClass(oc.Name, oc)
		}
	}

	return nil
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

func (s *AttributeType) NewSchemaValueMap(size int) SchemaValueMap {
	valMap := SchemaValueMap{
		schema:   s,
		valueMap: make(map[string]struct{}, size),
	}
	return valMap
}

type SchemaValueMap struct {
	schema   *AttributeType
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
	schema    *AttributeType
	value     []string
	norm      []interface{}
	normStr   []string
	normIndex map[string]struct{}
}

func NewSchemaValue(schemaMap *SchemaMap, attrName string, attrValue []string) (*SchemaValue, error) {
	// TODO refactoring
	s, ok := schemaMap.AttributeType(attrName)
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

	err := sv.normalize()
	if err != nil {
		return nil, err
	}

	return sv, nil
}

func (s *SchemaValue) Name() string {
	return s.schema.Name
}

func (s *SchemaValue) HasDuplicate(value *SchemaValue) bool {
	for _, v := range value.NormStr() {
		if _, ok := s.normIndex[v]; ok {
			return true
		}
	}
	return false
}

func (s *SchemaValue) IsSingle() bool {
	return s.schema.SingleValue
}

func (s *SchemaValue) IsNoUserModification() bool {
	return s.schema.NoUserModification
}

func (s *SchemaValue) IsNoUserModificationWithMigrationDisabled() bool {
	return !s.schema.schemaDef.server.config.MigrationEnabled && s.schema.NoUserModification
}

func (s *SchemaValue) IsEmpty() bool {
	return len(s.value) == 0
}

func (s *SchemaValue) IsAssociationAttribute() bool {
	return s.schema.IsAssociationAttribute()
}

func (s *SchemaValue) Clone() *SchemaValue {
	newValue := make([]string, len(s.value))
	copy(newValue, s.value)

	nsv := &SchemaValue{
		schema: s.schema,
		value:  newValue,
	}

	err := nsv.normalize()
	if err != nil {
		log.Printf("Unexpected normalization error when cloning. err: %+v", err)
		return nil
	}

	return nsv
}

func (s *SchemaValue) Equals(value *SchemaValue) bool {
	if s.IsSingle() != value.IsSingle() {
		return false
	}
	if s.IsSingle() {
		return s.NormStr()[0] == value.NormStr()[0]
	} else {
		if len(s.value) != len(value.value) {
			return false
		}

		for _, v := range value.NormStr() {
			if _, ok := s.normIndex[v]; !ok {
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
	s.norm = append(s.norm, value.norm...)
	s.normStr = append(s.normStr, value.normStr...)
	s.normIndex = mergeIndex(s.normIndex, value.normIndex)

	return nil
}

func (s *SchemaValue) Delete(value *SchemaValue) error {
	// TODO Duplicate delete error

	// Check the values
	for _, v := range value.NormStr() {
		if _, ok := s.normIndex[v]; !ok {
			// Not found the value
			return NewNoSuchAttribute("modify/delete", value.Name())
		}
	}

	// Create new values
	newValue := make([]string, len(s.value)-len(value.value))
	newValueNorm := make([]interface{}, len(newValue))
	newValueNormStr := make([]string, len(newValue))
	newNormIndex := make(map[string]struct{}, len(newValue))

	i := 0
	for j, v := range s.NormStr() {
		if _, ok := value.normIndex[v]; !ok {
			newValue[i] = s.value[j]
			newValueNorm[i] = s.norm[j]
			newValueNormStr[i] = s.normStr[j]
			newNormIndex[s.normStr[j]] = struct{}{}
			i++
		}
	}

	s.value = newValue
	s.norm = newValueNorm
	s.normStr = newValueNormStr
	s.normIndex = newNormIndex

	return nil
}

func (s *SchemaValue) Orig() []string {
	return s.value
}

func (s *SchemaValue) Norm() interface{} {
	return s.norm
}

func (s *SchemaValue) NormStr() []string {
	return s.normStr
}

// normalize the value using schema definition.
// The value is expected as a valid value. It means you need to validte the value in advance.
func (s *SchemaValue) normalize() error {
	if len(s.normStr) > 0 {
		return nil
	}

	// objectClasses need additional nomalization
	// - Sort structural objectClasses by chain
	// - Expand sup objectClasses to search by sup objectClass later
	if s.Name() == "objectClass" {
		stocs := []*ObjectClass{}
		dup := map[string]struct{}{}
		resolved := map[string]struct{}{}
		nstocs := []*ObjectClass{}
		for i, v := range s.value {
			oc, ok := s.schema.schemaDef.ObjectClass(v)
			if !ok {
				return NewInvalidPerSyntax("objectClass", i)
			}

			// Check if it contains duplicate value
			if _, ok := dup[oc.Name]; ok {
				return NewMoreThanOnceError(s.Name(), i)
			}
			dup[oc.Name] = struct{}{}

			if oc.Structural || oc.Abstruct {
				// Already resolve?
				if _, ok := resolved[oc.Name]; ok {
					continue
				}
				stocs = append(stocs, oc)
				resolved[oc.Name] = struct{}{}

				// Expand sup
				sup := oc.Sup
				for {
					if sup == "" {
						break
					}
					// Already resolve?
					if _, ok := resolved[sup]; ok {
						break
					}

					if soc, ok := s.schema.schemaDef.ObjectClass(sup); ok {
						stocs = append(stocs, soc)
						// Recored the sup is resolved already
						resolved[soc.Name] = struct{}{}

						// next
						sup = soc.Sup
					} else {
						log.Printf("warn: Can't resolve superior objectClass when normalizing. objectClass: %s", oc.Sup)
						break
					}
				}
			} else {
				nstocs = append(nstocs, oc)
			}
		}

		sortObjectClasses(s.schema.schemaDef, stocs)
		if err := verifyChainedObjectClasses(s.schema.schemaDef, stocs); err != nil {
			return err
		}

		norm := make([]interface{}, len(stocs)+len(nstocs))
		normStr := make([]string, len(norm))
		m := make(map[string]struct{}, len(norm))

		for i := range stocs {
			normStr[i] = strings.ToLower(stocs[i].Name)
			m[normStr[i]] = struct{}{}
		}
		for i := range nstocs {
			j := i + len(stocs)
			normStr[j] = strings.ToLower(nstocs[i].Name)
			m[normStr[j]] = struct{}{}
		}
		s.norm = norm
		s.normStr = normStr
		s.normIndex = m

		return nil

	} else {
		norm := make([]interface{}, len(s.value))
		normStr := make([]string, len(norm))
		m := make(map[string]struct{}, len(norm))
		for i, v := range s.value {
			var err error
			norm[i], err = normalize(s.schema, v, i)
			if err != nil {
				return err
			}
			normStr[i] = toNormStr(norm[i])

			// Check if it contains duplicate value
			if _, ok := m[normStr[i]]; ok {
				return NewMoreThanOnceError(s.Name(), i)
			}
			m[normStr[i]] = struct{}{}
		}
		s.norm = norm
		s.normStr = normStr
		s.normIndex = m

		return nil
	}
}

func toNormStr(norm interface{}) string {
	switch v := norm.(type) {
	case string:
		return v
	case int64:
		return strconv.FormatInt(v, 10)
	case *DN:
		return v.DNNormStr()
	default:
		log.Printf("error: Unexpected type for converting norm value: %v", v)
		return ""
	}
}

func (s *AttributeType) IsCaseIgnore() bool {
	if strings.HasPrefix(s.Equality, "caseIgnore") ||
		s.Equality == "objectIdentifierMatch" {
		return true
	}
	return false
}

func (s *AttributeType) IsCaseIgnoreSubstr() bool {
	if strings.HasPrefix(s.Substr, "caseIgnore") ||
		s.Substr == "numericStringSubstringsMatch" {
		return true
	}
	return false
}

func (s *AttributeType) IsOperationalAttribute() bool {
	if s.Usage == "directoryOperation" ||
		s.Usage == "dSAOperation" ||
		s.Usage == "distributedOperation" {
		return true
	}
	// TODO check other case
	return false
}

func (s *AttributeType) IsAssociationAttribute() bool {
	if s.Name == "member" ||
		s.Name == "uniqueMember" {
		return true
	}
	return false
}

func (s *AttributeType) IsReverseAssociationAttribute() bool {
	return s.Name == "memberOf"
}

func (s *AttributeType) IsNumberOrdering() bool {
	return s.Ordering == "generalizedTimeOrderingMatch" ||
		s.Ordering == "integerOrderingMatch" ||
		s.Ordering == "numericStringOrderingMatch" ||
		s.Ordering == "UUIDOrderingMatch"
}
