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

func (s SchemaMap) Resolve() error {
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
	Name        string
	AName       string
	Oid         string
	Equality    string
	Ordering    string
	Substr      string
	Syntax      string
	Sup         string
	Usage       string
	IndexType   string
	SingleValue bool
}

func InitSchemaMap() SchemaMap {
	m := SchemaMap{}

	namePattern := regexp.MustCompile("attributeTypes: \\( (.*?) NAME '(.*?)' ")
	namesPattern := regexp.MustCompile("attributeTypes: \\( (.*?) NAME \\( (.*?) \\) ")
	equalityPattern := regexp.MustCompile(" EQUALITY (.*?) ")
	syntaxPattern := regexp.MustCompile(" SYNTAX (.*?) ")
	substrPattern := regexp.MustCompile(" SUBSTR (.*?) ")
	orderingPattern := regexp.MustCompile(" ORDERING (.*?) ")
	supPattern := regexp.MustCompile(" SUP (.*?) ")
	usagePattern := regexp.MustCompile(" USAGE (.*?) ")

	for _, line := range strings.Split(strings.TrimSuffix(SCHEMA, "\n"), "\n") {
		if strings.HasPrefix(line, "attributeTypes") {
			ng := namePattern.FindStringSubmatch(line)
			nsg := namesPattern.FindStringSubmatch(line)
			eg := equalityPattern.FindStringSubmatch(line)
			syng := syntaxPattern.FindStringSubmatch(line)
			subg := substrPattern.FindStringSubmatch(line)
			og := orderingPattern.FindStringSubmatch(line)
			supg := supPattern.FindStringSubmatch(line)
			usag := usagePattern.FindStringSubmatch(line)

			if ng == nil && nsg == nil {
				log.Printf("warn: Unsupported schema. %s", line)
				continue
			}

			s := &Schema{
				IndexType:   "", // TODO configurable
				SingleValue: false,
			}
			if ng != nil {
				s.Oid = ng[1]
				s.Name = ng[2]
			} else {
				s.Oid = nsg[1]
				names := strings.Split(nsg[2], " ")
				s.Name = strings.Trim(names[0], "'")
				// TODO more alias
				s.AName = strings.Trim(names[1], "'")
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

			m.Put(s.Name, s)
		}
	}

	err := m.Resolve()
	if err != nil {
		log.Printf("error: Resolving schema error. %v", err)
	}

	return m
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

	for _, v := range value.GetNorm() {
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

func (s *SchemaValue) IsEmpty() bool {
	return len(s.value) == 0
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
		return s.GetNorm()[0] == value.GetNorm()[0]
	} else {
		if len(s.value) != len(value.value) {
			return false
		}

		s.Normalize()

		for _, v := range value.GetNorm() {
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
	for _, v := range value.GetNorm() {
		if _, ok := s.cachedNormIndex[v]; !ok {
			// Not found the value
			return NewNoSuchAttribute("modify/delete", value.Name())
		}
	}

	// Create new values
	newValue := make([]string, len(s.value)-len(value.value))
	newValueNorm := make([]string, len(newValue))

	i := 0
	for j, v := range s.GetNorm() {
		if _, ok := value.cachedNormIndex[v]; !ok {
			newValue[i] = s.value[j]
			newValueNorm[i] = s.cachedNorm[j]
		}
	}

	s.value = newValue
	s.cachedNorm = newValueNorm
	s.cachedNormIndex = nil

	return nil
}

func (s *SchemaValue) Replace(value *SchemaValue) {
	s.value = value.value
	s.cachedNorm = nil
	s.cachedNormIndex = nil
}

func (s *SchemaValue) GetOrig() []string {
	return s.value
}

func (s *SchemaValue) GetAsTime() []time.Time {
	t := make([]time.Time, len(s.value))
	for i, _ := range s.value {
		// Already validated, ignore error
		t[i], _ = time.Parse(TIMESTAMP_FORMAT, s.value[i])
	}
	return t
}

func (s *SchemaValue) GetNorm() []string {
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
	if s.Usage == "directoryOperation" {
		return true
	}
	// TODO check other case
	return false
}

// ldapsearch -H ldap://... -x -D "cn=..." -b "cn=Subschema" -v -s base attributeTypes comparators ditContentRules ditStructureRules ldapSyntaxes matchingRules matchingRuleUse nameForms normalizers objectClasses syntaxCheckers
var SCHEMA string = `
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio' X-NOT-HUMAN-READABLE 'TRUE' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' X-NOT-HUMAN-READABLE 'TRUE' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.9 DESC 'Certificate List' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.10 DESC 'Certificate Pair' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )
ldapSyntaxes: ( 1.3.6.1.4.1.4203.666.11.10.2.1 DESC 'X.509 AttributeCertificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'Distinguished Name' )
ldapSyntaxes: ( 1.2.36.79672281.1.5.0 DESC 'RDN' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.14 DESC 'Delivery Method' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.22 DESC 'Facsimile Telephone Number' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' X-NOT-HUMAN-READABLE 'TRUE' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.34 DESC 'Name And Optional UID' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.36 DESC 'Numeric String' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.39 DESC 'Other Mailbox' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'Octet String' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.41 DESC 'Postal Address' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.44 DESC 'Printable String' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.11 DESC 'Country String' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.45 DESC 'SubtreeSpecification' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.49 DESC 'Supported Algorithm' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.50 DESC 'Telephone Number' )
ldapSyntaxes: ( 1.3.6.1.4.1.1466.115.121.1.52 DESC 'Telex Number' )
ldapSyntaxes: ( 1.3.6.1.1.1.0.0 DESC 'RFC2307 NIS Netgroup Triple' )
ldapSyntaxes: ( 1.3.6.1.1.1.0.1 DESC 'RFC2307 Boot Parameter' )
ldapSyntaxes: ( 1.3.6.1.1.16.1 DESC 'UUID' )
matchingRules: ( 1.3.6.1.1.16.3 NAME 'UUIDOrderingMatch' SYNTAX 1.3.6.1.1.16.1 )
matchingRules: ( 1.3.6.1.1.16.2 NAME 'UUIDMatch' SYNTAX 1.3.6.1.1.16.1 )
matchingRules: ( 1.2.840.113556.1.4.804 NAME 'integerBitOrMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
matchingRules: ( 1.2.840.113556.1.4.803 NAME 'integerBitAndMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
matchingRules: ( 1.3.6.1.4.1.4203.1.2.1 NAME 'caseExactIA5SubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
matchingRules: ( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
matchingRules: ( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
matchingRules: ( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
matchingRules: ( 2.5.13.38 NAME 'certificateListExactMatch' SYNTAX 1.3.6.1.1.15.5 )
matchingRules: ( 2.5.13.34 NAME 'certificateExactMatch' SYNTAX 1.3.6.1.1.15.1 )
matchingRules: ( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
matchingRules: ( 2.5.13.29 NAME 'integerFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
matchingRules: ( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )
matchingRules: ( 2.5.13.27 NAME 'generalizedTimeMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )
matchingRules: ( 2.5.13.23 NAME 'uniqueMemberMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )
matchingRules: ( 2.5.13.21 NAME 'telephoneNumberSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
matchingRules: ( 2.5.13.20 NAME 'telephoneNumberMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
matchingRules: ( 2.5.13.19 NAME 'octetStringSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
matchingRules: ( 2.5.13.18 NAME 'octetStringOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
matchingRules: ( 2.5.13.17 NAME 'octetStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
matchingRules: ( 2.5.13.16 NAME 'bitStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )
matchingRules: ( 2.5.13.15 NAME 'integerOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
matchingRules: ( 2.5.13.14 NAME 'integerMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
matchingRules: ( 2.5.13.13 NAME 'booleanMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )
matchingRules: ( 2.5.13.11 NAME 'caseIgnoreListMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
matchingRules: ( 2.5.13.10 NAME 'numericStringSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
matchingRules: ( 2.5.13.9 NAME 'numericStringOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
matchingRules: ( 2.5.13.8 NAME 'numericStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
matchingRules: ( 2.5.13.7 NAME 'caseExactSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
matchingRules: ( 2.5.13.6 NAME 'caseExactOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
matchingRules: ( 2.5.13.5 NAME 'caseExactMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
matchingRules: ( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )
matchingRules: ( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
matchingRules: ( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
matchingRules: ( 1.2.36.79672281.1.13.3 NAME 'rdnMatch' SYNTAX 1.2.36.79672281.1.5.0 )
matchingRules: ( 2.5.13.1 NAME 'distinguishedNameMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
matchingRules: ( 2.5.13.0 NAME 'objectIdentifierMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
matchingRuleUse: ( 1.2.840.113556.1.4.804 NAME 'integerBitOrMatch' APPLIES ( supportedLDAPVersion $ entryTtl $ uidNumber $ gidNumber $ olcConcurrency $ olcConnMaxPending $ olcConnMaxPendingAuth $ olcIdleTimeout $ olcIndexSubstrIfMinLen $ olcIndexSubstrIfMaxLen $ olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcIndexIntLen $ olcListenerThreads $ olcLocalSSF $ olcMaxDerefDepth $ olcReplicationInterval $ olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcThreads $ olcToolThreads $ olcWriteTimeout $ olcDbCacheFree $ olcDbCacheSize $ olcDbDNcacheSize $ olcDbIDLcacheSize $ olcDbSearchStack $ olcDbShmKey $ olcDbProtocolVersion $ olcDbConnectionPoolMax $ olcChainMaxReferralDepth $ olcSssVlvMax $ olcSssVlvMaxKeys $ olcSssVlvMaxPerConn $ mailPreferenceOption $ shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ shadowInactive $ shadowExpire $ shadowFlag $ ipServicePort $ ipProtocolNumber $ oncRpcNumber $ pwdMinAge $ pwdMaxAge $ pwdInHistory $ pwdCheckQuality $ pwdMinLength $ pwdExpireWarning $ pwdGraceAuthNLimit $ pwdLockoutDuration $ pwdMaxFailure $ pwdFailureCountInterval $ pwdMaxRecordedFailure ) )
matchingRuleUse: ( 1.2.840.113556.1.4.803 NAME 'integerBitAndMatch' APPLIES ( supportedLDAPVersion $ entryTtl $ uidNumber $ gidNumber $ olcConcurrency $ olcConnMaxPending $ olcConnMaxPendingAuth $ olcIdleTimeout $ olcIndexSubstrIfMinLen $ olcIndexSubstrIfMaxLen $ olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcIndexIntLen $ olcListenerThreads $ olcLocalSSF $ olcMaxDerefDepth $ olcReplicationInterval $ olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcThreads $ olcToolThreads $ olcWriteTimeout $ olcDbCacheFree $ olcDbCacheSize $ olcDbDNcacheSize $ olcDbIDLcacheSize $ olcDbSearchStack $ olcDbShmKey $ olcDbProtocolVersion $ olcDbConnectionPoolMax $ olcChainMaxReferralDepth $ olcSssVlvMax $ olcSssVlvMaxKeys $ olcSssVlvMaxPerConn $ mailPreferenceOption $ shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ shadowInactive $ shadowExpire $ shadowFlag $ ipServicePort $ ipProtocolNumber $ oncRpcNumber $ pwdMinAge $ pwdMaxAge $ pwdInHistory $ pwdCheckQuality $ pwdMinLength $ pwdExpireWarning $ pwdGraceAuthNLimit $ pwdLockoutDuration $ pwdMaxFailure $ pwdFailureCountInterval $ pwdMaxRecordedFailure ) )
matchingRuleUse: ( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' APPLIES ( altServer $ olcDbConfig $ c $ mail $ dc $ associatedDomain $ email $ aRecord $ mDRecord $ mXRecord $ nSRecord $ sOARecord $ cNAMERecord $ janetMailbox $ gecos $ homeDirectory $ loginShell $ memberUid $ memberNisNetgroup $ ipHostNumber $ ipNetworkNumber $ ipNetmaskNumber $ macAddress $ bootFile $ nisMapEntry $ pwdCheckModule $ x-devnetPassword ) )
matchingRuleUse: ( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' APPLIES ( altServer $ olcDbConfig $ c $ mail $ dc $ associatedDomain $ email $ aRecord $ mDRecord $ mXRecord $ nSRecord $ sOARecord $ cNAMERecord $ janetMailbox $ gecos $ homeDirectory $ loginShell $ memberUid $ memberNisNetgroup $ ipHostNumber $ ipNetworkNumber $ ipNetmaskNumber $ macAddress $ bootFile $ nisMapEntry $ pwdCheckModule $ x-devnetPassword ) )
matchingRuleUse: ( 2.5.13.38 NAME 'certificateListExactMatch' APPLIES ( authorityRevocationList $ certificateRevocationList $ deltaRevocationList ) )
matchingRuleUse: ( 2.5.13.34 NAME 'certificateExactMatch' APPLIES ( userCertificate $ cACertificate ) )
matchingRuleUse: ( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' APPLIES ( supportedControl $ supportedExtension $ supportedFeatures $ ldapSyntaxes $ supportedApplicationContext ) )
matchingRuleUse: ( 2.5.13.29 NAME 'integerFirstComponentMatch' APPLIES ( supportedLDAPVersion $ entryTtl $ uidNumber $ gidNumber $ olcConcurrency $ olcConnMaxPending $ olcConnMaxPendingAuth $ olcIdleTimeout $ olcIndexSubstrIfMinLen $ olcIndexSubstrIfMaxLen $ olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcIndexIntLen $ olcListenerThreads $ olcLocalSSF $ olcMaxDerefDepth $ olcReplicationInterval $ olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcThreads $ olcToolThreads $ olcWriteTimeout $ olcDbCacheFree $ olcDbCacheSize $ olcDbDNcacheSize $ olcDbIDLcacheSize $ olcDbSearchStack $ olcDbShmKey $ olcDbProtocolVersion $ olcDbConnectionPoolMax $ olcChainMaxReferralDepth $ olcSssVlvMax $ olcSssVlvMaxKeys $ olcSssVlvMaxPerConn $ mailPreferenceOption $ shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ shadowInactive $ shadowExpire $ shadowFlag $ ipServicePort $ ipProtocolNumber $ oncRpcNumber $ pwdMinAge $ pwdMaxAge $ pwdInHistory $ pwdCheckQuality $ pwdMinLength $ pwdExpireWarning $ pwdGraceAuthNLimit $ pwdLockoutDuration $ pwdMaxFailure $ pwdFailureCountInterval $ pwdMaxRecordedFailure ) )
matchingRuleUse: ( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' APPLIES ( createTimestamp $ modifyTimestamp $ pwdChangedTime $ pwdAccountLockedTime $ pwdFailureTime $ pwdGraceUseTime ) )
matchingRuleUse: ( 2.5.13.27 NAME 'generalizedTimeMatch' APPLIES ( createTimestamp $ modifyTimestamp $ pwdChangedTime $ pwdAccountLockedTime $ pwdFailureTime $ pwdGraceUseTime ) )
matchingRuleUse: ( 2.5.13.24 NAME 'protocolInformationMatch' APPLIES protocolInformation )
matchingRuleUse: ( 2.5.13.23 NAME 'uniqueMemberMatch' APPLIES uniqueMember )
matchingRuleUse: ( 2.5.13.22 NAME 'presentationAddressMatch' APPLIES presentationAddress )
matchingRuleUse: ( 2.5.13.20 NAME 'telephoneNumberMatch' APPLIES ( telephoneNumber $ homePhone $ mobile $ pager ) )
matchingRuleUse: ( 2.5.13.18 NAME 'octetStringOrderingMatch' APPLIES ( userPassword $ olcDbCryptKey $ pwdHistory ) )
matchingRuleUse: ( 2.5.13.17 NAME 'octetStringMatch' APPLIES ( userPassword $ olcDbCryptKey $ pwdHistory ) )
matchingRuleUse: ( 2.5.13.16 NAME 'bitStringMatch' APPLIES x500UniqueIdentifier )
matchingRuleUse: ( 2.5.13.15 NAME 'integerOrderingMatch' APPLIES ( supportedLDAPVersion $ entryTtl $ uidNumber $ gidNumber $ olcConcurrency $ olcConnMaxPending $ olcConnMaxPendingAuth $ olcIdleTimeout $ olcIndexSubstrIfMinLen $ olcIndexSubstrIfMaxLen $ olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcIndexIntLen $ olcListenerThreads $ olcLocalSSF $ olcMaxDerefDepth $ olcReplicationInterval $ olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcThreads $ olcToolThreads $ olcWriteTimeout $ olcDbCacheFree $ olcDbCacheSize $ olcDbDNcacheSize $ olcDbIDLcacheSize $ olcDbSearchStack $ olcDbShmKey $ olcDbProtocolVersion $ olcDbConnectionPoolMax $ olcChainMaxReferralDepth $ olcSssVlvMax $ olcSssVlvMaxKeys $ olcSssVlvMaxPerConn $ mailPreferenceOption $ shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ shadowInactive $ shadowExpire $ shadowFlag $ ipServicePort $ ipProtocolNumber $ oncRpcNumber $ pwdMinAge $ pwdMaxAge $ pwdInHistory $ pwdCheckQuality $ pwdMinLength $ pwdExpireWarning $ pwdGraceAuthNLimit $ pwdLockoutDuration $ pwdMaxFailure $ pwdFailureCountInterval $ pwdMaxRecordedFailure ) )
matchingRuleUse: ( 2.5.13.14 NAME 'integerMatch' APPLIES ( supportedLDAPVersion $ entryTtl $ uidNumber $ gidNumber $ olcConcurrency $ olcConnMaxPending $ olcConnMaxPendingAuth $ olcIdleTimeout $ olcIndexSubstrIfMinLen $ olcIndexSubstrIfMaxLen $ olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcIndexIntLen $ olcListenerThreads $ olcLocalSSF $ olcMaxDerefDepth $ olcReplicationInterval $ olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcThreads $ olcToolThreads $ olcWriteTimeout $ olcDbCacheFree $ olcDbCacheSize $ olcDbDNcacheSize $ olcDbIDLcacheSize $ olcDbSearchStack $ olcDbShmKey $ olcDbProtocolVersion $ olcDbConnectionPoolMax $ olcChainMaxReferralDepth $ olcSssVlvMax $ olcSssVlvMaxKeys $ olcSssVlvMaxPerConn $ mailPreferenceOption $ shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ shadowInactive $ shadowExpire $ shadowFlag $ ipServicePort $ ipProtocolNumber $ oncRpcNumber $ pwdMinAge $ pwdMaxAge $ pwdInHistory $ pwdCheckQuality $ pwdMinLength $ pwdExpireWarning $ pwdGraceAuthNLimit $ pwdLockoutDuration $ pwdMaxFailure $ pwdFailureCountInterval $ pwdMaxRecordedFailure ) )
matchingRuleUse: ( 2.5.13.13 NAME 'booleanMatch' APPLIES ( hasSubordinates $ olcAddContentAcl $ olcGentleHUP $ olcHidden $ olcLastMod $ olcMirrorMode $ olcMonitoring $ olcReadOnly $ olcReverseLookup $ olcSyncUseSubentry $ olcDbChecksum $ olcDbNoSync $ olcDbDirtyRead $ olcDbLinearIndex $ olcDbRebindAsUser $ olcDbChaseReferrals $ olcDbSingleConn $ olcDbUseTemporaryConn $ olcDbSessionTrackingRequest $ olcDbNoRefs $ olcDbNoUndefFilter $ olcDbPseudoRootBindDefer $ olcDbProxyWhoAmI $ olcDbRemoveUnknownSchema $ olcChainCacheURI $ olcChainReturnError $ olcMemberOfRefInt $ pwdReset $ olcPPolicyHashCleartext $ olcPPolicyForwardUpdates $ olcPPolicyUseLockout $ pwdLockout $ pwdMustChange $ pwdAllowUserChange $ pwdSafeModify ) )
matchingRuleUse: ( 2.5.13.11 NAME 'caseIgnoreListMatch' APPLIES ( postalAddress $ registeredAddress $ homePostalAddress ) )
matchingRuleUse: ( 2.5.13.9 NAME 'numericStringOrderingMatch' APPLIES ( x121Address $ internationaliSDNNumber ) )
matchingRuleUse: ( 2.5.13.8 NAME 'numericStringMatch' APPLIES ( x121Address $ internationaliSDNNumber ) )
matchingRuleUse: ( 2.5.13.7 NAME 'caseExactSubstringsMatch' APPLIES ( serialNumber $ c $ telephoneNumber $ destinationIndicator $ dnQualifier $ homePhone $ mobile $ pager ) )
matchingRuleUse: ( 2.5.13.6 NAME 'caseExactOrderingMatch' APPLIES ( supportedSASLMechanisms $ vendorName $ vendorVersion $ ref $ name $ cn $ uid $ labeledURI $ description $ olcConfigFile $ olcConfigDir $ olcAccess $ olcAllows $ olcArgsFile $ olcAttributeOptions $ olcAttributeTypes $ olcAuthIDRewrite $ olcAuthzPolicy $ olcAuthzRegexp $ olcBackend $ olcDatabase $ olcDisallows $ olcDitContentRules $ olcExtraAttrs $ olcInclude $ olcLdapSyntaxes $ olcLimits $ olcLogFile $ olcLogLevel $ olcModuleLoad $ olcModulePath $ olcObjectClasses $ olcObjectIdentifier $ olcOverlay $ olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ olcPlugin $ olcPluginLogFile $ olcReferral $ olcReplica $ olcReplicaArgsFile $ olcReplicaPidFile $ olcReplogFile $ olcRequires $ olcRestrict $ olcRootDSE $ olcRootPW $ olcSaslAuxprops $ olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ olcSecurity $ olcServerID $ olcSizeLimit $ olcSortVals $ olcSubordinate $ olcSyncrepl $ olcTCPBuffer $ olcTimeLimit $ olcTLSCACertificateFile $ olcTLSCACertificatePath $ olcTLSCertificateFile $ olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ olcTLSCRLFile $ olcTLSRandFile $ olcTLSVerifyClient $ olcTLSDHParamFile $ olcTLSProtocolMin $ olcUpdateRef $ olcDbDirectory $ olcDbCheckpoint $ olcDbCryptFile $ olcDbPageSize $ olcDbIndex $ olcDbLockDetect $ olcDbMode $ olcDbURI $ olcDbStartTLS $ olcDbACLPasswd $ olcDbIDAssertBind $ olcDbIDAssertAuthzFrom $ olcDbTFSupport $ olcDbTimeout $ olcDbIdleTimeout $ olcDbConnTtl $ olcDbNetworkTimeout $ olcDbCancel $ olcDbQuarantine $ olcDbRewrite $ olcDbMap $ olcDbSubtreeExclude $ olcDbSubtreeInclude $ olcDbDefaultTarget $ olcDbDnCacheTtl $ olcDbBindTimeout $ olcDbOnErr $ olcDbNretries $ olcDbClientPr $ olcMetaSub $ olcDbKeepalive $ olcDbFilter $ olcDbACLBind $ olcDbIDAssertPasswd $ olcDbIDAssertMode $ olcDbIDAssertPassThru $ olcChainingBehavior $ olcMemberOfDangling $ olcMemberOfGroupOC $ olcMemberOfMemberAD $ olcMemberOfMemberOfAD $ olcMemberOfDanglingError $ knowledgeInformation $ sn $ serialNumber $ c $ l $ st $ street $ o $ ou $ title $ businessCategory $ postalCode $ postOfficeBox $ physicalDeliveryOfficeName $ telephoneNumber $ destinationIndicator $ givenName $ initials $ generationQualifier $ dnQualifier $ houseIdentifier $ dmdName $ pseudonym $ textEncodedORAddress $ info $ drink $ roomNumber $ userClass $ host $ documentIdentifier $ documentTitle $ documentVersion $ documentLocation $ homePhone $ personalTitle $ mobile $ pager $ co $ uniqueIdentifier $ organizationalStatus $ buildingName $ documentPublisher $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ preferredLanguage $ ipServiceProtocol $ nisMapName ) )
matchingRuleUse: ( 2.5.13.5 NAME 'caseExactMatch' APPLIES ( supportedSASLMechanisms $ vendorName $ vendorVersion $ ref $ name $ cn $ uid $ labeledURI $ description $ olcConfigFile $ olcConfigDir $ olcAccess $ olcAllows $ olcArgsFile $ olcAttributeOptions $ olcAttributeTypes $ olcAuthIDRewrite $ olcAuthzPolicy $ olcAuthzRegexp $ olcBackend $ olcDatabase $ olcDisallows $ olcDitContentRules $ olcExtraAttrs $ olcInclude $ olcLdapSyntaxes $ olcLimits $ olcLogFile $ olcLogLevel $ olcModuleLoad $ olcModulePath $ olcObjectClasses $ olcObjectIdentifier $ olcOverlay $ olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ olcPlugin $ olcPluginLogFile $ olcReferral $ olcReplica $ olcReplicaArgsFile $ olcReplicaPidFile $ olcReplogFile $ olcRequires $ olcRestrict $ olcRootDSE $ olcRootPW $ olcSaslAuxprops $ olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ olcSecurity $ olcServerID $ olcSizeLimit $ olcSortVals $ olcSubordinate $ olcSyncrepl $ olcTCPBuffer $ olcTimeLimit $ olcTLSCACertificateFile $ olcTLSCACertificatePath $ olcTLSCertificateFile $ olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ olcTLSCRLFile $ olcTLSRandFile $ olcTLSVerifyClient $ olcTLSDHParamFile $ olcTLSProtocolMin $ olcUpdateRef $ olcDbDirectory $ olcDbCheckpoint $ olcDbCryptFile $ olcDbPageSize $ olcDbIndex $ olcDbLockDetect $ olcDbMode $ olcDbURI $ olcDbStartTLS $ olcDbACLPasswd $ olcDbIDAssertBind $ olcDbIDAssertAuthzFrom $ olcDbTFSupport $ olcDbTimeout $ olcDbIdleTimeout $ olcDbConnTtl $ olcDbNetworkTimeout $ olcDbCancel $ olcDbQuarantine $ olcDbRewrite $ olcDbMap $ olcDbSubtreeExclude $ olcDbSubtreeInclude $ olcDbDefaultTarget $ olcDbDnCacheTtl $ olcDbBindTimeout $ olcDbOnErr $ olcDbNretries $ olcDbClientPr $ olcMetaSub $ olcDbKeepalive $ olcDbFilter $ olcDbACLBind $ olcDbIDAssertPasswd $ olcDbIDAssertMode $ olcDbIDAssertPassThru $ olcChainingBehavior $ olcMemberOfDangling $ olcMemberOfGroupOC $ olcMemberOfMemberAD $ olcMemberOfMemberOfAD $ olcMemberOfDanglingError $ knowledgeInformation $ sn $ serialNumber $ c $ l $ st $ street $ o $ ou $ title $ businessCategory $ postalCode $ postOfficeBox $ physicalDeliveryOfficeName $ telephoneNumber $ destinationIndicator $ givenName $ initials $ generationQualifier $ dnQualifier $ houseIdentifier $ dmdName $ pseudonym $ textEncodedORAddress $ info $ drink $ roomNumber $ userClass $ host $ documentIdentifier $ documentTitle $ documentVersion $ documentLocation $ homePhone $ personalTitle $ mobile $ pager $ co $ uniqueIdentifier $ organizationalStatus $ buildingName $ documentPublisher $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ preferredLanguage $ ipServiceProtocol $ nisMapName ) )
matchingRuleUse: ( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' APPLIES ( serialNumber $ c $ telephoneNumber $ destinationIndicator $ dnQualifier $ homePhone $ mobile $ pager ) )
matchingRuleUse: ( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' APPLIES ( supportedSASLMechanisms $ vendorName $ vendorVersion $ ref $ name $ cn $ uid $ labeledURI $ description $ olcConfigFile $ olcConfigDir $ olcAccess $ olcAllows $ olcArgsFile $ olcAttributeOptions $ olcAttributeTypes $ olcAuthIDRewrite $ olcAuthzPolicy $ olcAuthzRegexp $ olcBackend $ olcDatabase $ olcDisallows $ olcDitContentRules $ olcExtraAttrs $ olcInclude $ olcLdapSyntaxes $ olcLimits $ olcLogFile $ olcLogLevel $ olcModuleLoad $ olcModulePath $ olcObjectClasses $ olcObjectIdentifier $ olcOverlay $ olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ olcPlugin $ olcPluginLogFile $ olcReferral $ olcReplica $ olcReplicaArgsFile $ olcReplicaPidFile $ olcReplogFile $ olcRequires $ olcRestrict $ olcRootDSE $ olcRootPW $ olcSaslAuxprops $ olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ olcSecurity $ olcServerID $ olcSizeLimit $ olcSortVals $ olcSubordinate $ olcSyncrepl $ olcTCPBuffer $ olcTimeLimit $ olcTLSCACertificateFile $ olcTLSCACertificatePath $ olcTLSCertificateFile $ olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ olcTLSCRLFile $ olcTLSRandFile $ olcTLSVerifyClient $ olcTLSDHParamFile $ olcTLSProtocolMin $ olcUpdateRef $ olcDbDirectory $ olcDbCheckpoint $ olcDbCryptFile $ olcDbPageSize $ olcDbIndex $ olcDbLockDetect $ olcDbMode $ olcDbURI $ olcDbStartTLS $ olcDbACLPasswd $ olcDbIDAssertBind $ olcDbIDAssertAuthzFrom $ olcDbTFSupport $ olcDbTimeout $ olcDbIdleTimeout $ olcDbConnTtl $ olcDbNetworkTimeout $ olcDbCancel $ olcDbQuarantine $ olcDbRewrite $ olcDbMap $ olcDbSubtreeExclude $ olcDbSubtreeInclude $ olcDbDefaultTarget $ olcDbDnCacheTtl $ olcDbBindTimeout $ olcDbOnErr $ olcDbNretries $ olcDbClientPr $ olcMetaSub $ olcDbKeepalive $ olcDbFilter $ olcDbACLBind $ olcDbIDAssertPasswd $ olcDbIDAssertMode $ olcDbIDAssertPassThru $ olcChainingBehavior $ olcMemberOfDangling $ olcMemberOfGroupOC $ olcMemberOfMemberAD $ olcMemberOfMemberOfAD $ olcMemberOfDanglingError $ knowledgeInformation $ sn $ serialNumber $ c $ l $ st $ street $ o $ ou $ title $ businessCategory $ postalCode $ postOfficeBox $ physicalDeliveryOfficeName $ telephoneNumber $ destinationIndicator $ givenName $ initials $ generationQualifier $ dnQualifier $ houseIdentifier $ dmdName $ pseudonym $ textEncodedORAddress $ info $ drink $ roomNumber $ userClass $ host $ documentIdentifier $ documentTitle $ documentVersion $ documentLocation $ homePhone $ personalTitle $ mobile $ pager $ co $ uniqueIdentifier $ organizationalStatus $ buildingName $ documentPublisher $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ preferredLanguage $ ipServiceProtocol $ nisMapName ) )
matchingRuleUse: ( 2.5.13.2 NAME 'caseIgnoreMatch' APPLIES ( supportedSASLMechanisms $ vendorName $ vendorVersion $ ref $ name $ cn $ uid $ labeledURI $ description $ olcConfigFile $ olcConfigDir $ olcAccess $ olcAllows $ olcArgsFile $ olcAttributeOptions $ olcAttributeTypes $ olcAuthIDRewrite $ olcAuthzPolicy $ olcAuthzRegexp $ olcBackend $ olcDatabase $ olcDisallows $ olcDitContentRules $ olcExtraAttrs $ olcInclude $ olcLdapSyntaxes $ olcLimits $ olcLogFile $ olcLogLevel $ olcModuleLoad $ olcModulePath $ olcObjectClasses $ olcObjectIdentifier $ olcOverlay $ olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ olcPlugin $ olcPluginLogFile $ olcReferral $ olcReplica $ olcReplicaArgsFile $ olcReplicaPidFile $ olcReplogFile $ olcRequires $ olcRestrict $ olcRootDSE $ olcRootPW $ olcSaslAuxprops $ olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ olcSecurity $ olcServerID $ olcSizeLimit $ olcSortVals $ olcSubordinate $ olcSyncrepl $ olcTCPBuffer $ olcTimeLimit $ olcTLSCACertificateFile $ olcTLSCACertificatePath $ olcTLSCertificateFile $ olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ olcTLSCRLFile $ olcTLSRandFile $ olcTLSVerifyClient $ olcTLSDHParamFile $ olcTLSProtocolMin $ olcUpdateRef $ olcDbDirectory $ olcDbCheckpoint $ olcDbCryptFile $ olcDbPageSize $ olcDbIndex $ olcDbLockDetect $ olcDbMode $ olcDbURI $ olcDbStartTLS $ olcDbACLPasswd $ olcDbIDAssertBind $ olcDbIDAssertAuthzFrom $ olcDbTFSupport $ olcDbTimeout $ olcDbIdleTimeout $ olcDbConnTtl $ olcDbNetworkTimeout $ olcDbCancel $ olcDbQuarantine $ olcDbRewrite $ olcDbMap $ olcDbSubtreeExclude $ olcDbSubtreeInclude $ olcDbDefaultTarget $ olcDbDnCacheTtl $ olcDbBindTimeout $ olcDbOnErr $ olcDbNretries $ olcDbClientPr $ olcMetaSub $ olcDbKeepalive $ olcDbFilter $ olcDbACLBind $ olcDbIDAssertPasswd $ olcDbIDAssertMode $ olcDbIDAssertPassThru $ olcChainingBehavior $ olcMemberOfDangling $ olcMemberOfGroupOC $ olcMemberOfMemberAD $ olcMemberOfMemberOfAD $ olcMemberOfDanglingError $ knowledgeInformation $ sn $ serialNumber $ c $ l $ st $ street $ o $ ou $ title $ businessCategory $ postalCode $ postOfficeBox $ physicalDeliveryOfficeName $ telephoneNumber $ destinationIndicator $ givenName $ initials $ generationQualifier $ dnQualifier $ houseIdentifier $ dmdName $ pseudonym $ textEncodedORAddress $ info $ drink $ roomNumber $ userClass $ host $ documentIdentifier $ documentTitle $ documentVersion $ documentLocation $ homePhone $ personalTitle $ mobile $ pager $ co $ uniqueIdentifier $ organizationalStatus $ buildingName $ documentPublisher $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ preferredLanguage $ ipServiceProtocol $ nisMapName ) )
matchingRuleUse: ( 2.5.13.1 NAME 'distinguishedNameMatch' APPLIES ( creatorsName $ modifiersName $ subschemaSubentry $ entryDN $ namingContexts $ aliasedObjectName $ dynamicSubtrees $ distinguishedName $ seeAlso $ olcDefaultSearchBase $ olcRootDN $ olcSchemaDN $ olcSuffix $ olcUpdateDN $ olcDbACLAuthcDn $ olcDbIDAssertAuthcDn $ memberOf $ olcMemberOfDN $ pwdPolicySubentry $ olcPPolicyDefault $ member $ owner $ roleOccupant $ manager $ documentAuthor $ secretary $ associatedName $ dITRedirect ) )
matchingRuleUse: ( 2.5.13.0 NAME 'objectIdentifierMatch' APPLIES ( supportedControl $ supportedExtension $ supportedFeatures $ supportedApplicationContext ) )
attributeTypes: ( 2.5.4.0 NAME 'objectClass' DESC 'RFC4512: object classes of the entity' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
attributeTypes: ( 2.5.21.9 NAME 'structuralObjectClass' DESC 'RFC4512: structural object class of entry' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 2.5.18.1 NAME 'createTimestamp' DESC 'RFC4512: time which object was created' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 2.5.18.2 NAME 'modifyTimestamp' DESC 'RFC4512: time which object was last modified' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 2.5.18.3 NAME 'creatorsName' DESC 'RFC4512: name of creator' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 2.5.18.4 NAME 'modifiersName' DESC 'RFC4512: name of last modifier' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 2.5.18.9 NAME 'hasSubordinates' DESC 'X.501: entry has children' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 2.5.18.10 NAME 'subschemaSubentry' DESC 'RFC4512: name of controlling subschema entry' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.1.20 NAME 'entryDN' DESC 'DN of the entry' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.1.16.4 NAME 'entryUUID' DESC 'UUID of the entry' EQUALITY UUIDMatch ORDERING UUIDOrderingMatch SYNTAX 1.3.6.1.1.16.1 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.4.1.1466.101.120.6 NAME 'altServer' DESC 'RFC4512: alternative servers' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 USAGE dSAOperation )
attributeTypes: ( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts' DESC 'RFC4512: naming contexts' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 USAGE dSAOperation )
attributeTypes: ( 1.3.6.1.4.1.1466.101.120.13 NAME 'supportedControl' DESC 'RFC4512: supported controls' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )
attributeTypes: ( 1.3.6.1.4.1.1466.101.120.7 NAME 'supportedExtension' DESC 'RFC4512: supported extended operations' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )
attributeTypes: ( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion' DESC 'RFC4512: supported LDAP versions' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 USAGE dSAOperation )
attributeTypes: ( 1.3.6.1.4.1.1466.101.120.14 NAME 'supportedSASLMechanisms' DESC 'RFC4512: supported SASL mechanisms' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE dSAOperation )
attributeTypes: ( 1.3.6.1.4.1.4203.1.3.5 NAME 'supportedFeatures' DESC 'RFC4512: features supported by the server' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )
attributeTypes: ( 1.3.6.1.1.4 NAME 'vendorName' DESC 'RFC3045: name of implementation vendor' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )
attributeTypes: ( 1.3.6.1.1.5 NAME 'vendorVersion' DESC 'RFC3045: version of implementation' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )
attributeTypes: ( 2.5.21.4 NAME 'matchingRules' DESC 'RFC4512: matching rules' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )
attributeTypes: ( 2.5.21.5 NAME 'attributeTypes' DESC 'RFC4512: attribute types' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )
attributeTypes: ( 2.5.21.6 NAME 'objectClasses' DESC 'RFC4512: object classes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )
attributeTypes: ( 2.5.21.8 NAME 'matchingRuleUse' DESC 'RFC4512: matching rule uses' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' DESC 'RFC4512: LDAP syntaxes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )
attributeTypes: ( 2.5.4.1 NAME ( 'aliasedObjectName' 'aliasedEntryName' ) DESC 'RFC4512: name of aliased object' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributeTypes: ( 2.16.840.1.113730.3.1.34 NAME 'ref' DESC 'RFC3296: subordinate referral URL' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE distributedOperation )
attributeTypes: ( 1.3.6.1.4.1.1466.101.119.3 NAME 'entryTtl' DESC 'RFC2589: entry time-to-live' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )
attributeTypes: ( 1.3.6.1.4.1.1466.101.119.4 NAME 'dynamicSubtrees' DESC 'RFC2589: dynamic subtrees' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 NO-USER-MODIFICATION USAGE dSAOperation )
attributeTypes: ( 2.5.4.49 NAME 'distinguishedName' DESC 'RFC4519: common supertype of DN attributes' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeTypes: ( 2.5.4.41 NAME 'name' DESC 'RFC4519: common supertype of name attributes' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )
attributeTypes: ( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s) for which the entity is known by' SUP name SINGLE-VALUE )
attributeTypes: ( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) DESC 'RFC4519: user identifier' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.0 NAME 'uidNumber' DESC 'RFC2307: An integer uniquely identifying a user in an administrative domain' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.1 NAME 'gidNumber' DESC 'RFC2307: An integer uniquely identifying a group in an administrative domain' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 2.5.4.35 NAME 'userPassword' DESC 'RFC4519/2307: password of user' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.250.1.57 NAME 'labeledURI' DESC 'RFC2079: Uniform Resource Identifier with optional label' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 2.5.4.13 NAME 'description' DESC 'RFC4519: descriptive information' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024} )
attributeTypes: ( 2.5.4.34 NAME 'seeAlso' DESC 'RFC4519: DN of related object' SUP distinguishedName )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.78 NAME 'olcConfigFile' DESC 'File for slapd configuration directives' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.79 NAME 'olcConfigDir' DESC 'Directory for slapd configuration backend' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.1 NAME 'olcAccess' DESC 'Access Control List' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.86 NAME 'olcAddContentAcl' DESC 'Check ACLs against content of Add ops' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.2 NAME 'olcAllows' DESC 'Allowed set of deprecated features' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.3 NAME 'olcArgsFile' DESC 'File for slapd command line options' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.5 NAME 'olcAttributeOptions' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.4 NAME 'olcAttributeTypes' DESC 'OpenLDAP attributeTypes' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.6 NAME 'olcAuthIDRewrite' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.7 NAME 'olcAuthzPolicy' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.8 NAME 'olcAuthzRegexp' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.9 NAME 'olcBackend' DESC 'A type of backend' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORDERED 'SIBLINGS' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.10 NAME 'olcConcurrency' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.11 NAME 'olcConnMaxPending' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.12 NAME 'olcConnMaxPendingAuth' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.13 NAME 'olcDatabase' DESC 'The backend type for a database instance' SUP olcBackend SINGLE-VALUE X-ORDERED 'SIBLINGS' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.14 NAME 'olcDefaultSearchBase' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.15 NAME 'olcDisallows' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.16 NAME 'olcDitContentRules' DESC 'OpenLDAP DIT content rules' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.20 NAME 'olcExtraAttrs' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.17 NAME 'olcGentleHUP' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.17 NAME 'olcHidden' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.18 NAME 'olcIdleTimeout' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.19 NAME 'olcInclude' SUP labeledURI )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.20 NAME 'olcIndexSubstrIfMinLen' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.21 NAME 'olcIndexSubstrIfMaxLen' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.22 NAME 'olcIndexSubstrAnyLen' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.23 NAME 'olcIndexSubstrAnyStep' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.84 NAME 'olcIndexIntLen' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.4 NAME 'olcLastMod' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.85 NAME 'olcLdapSyntaxes' DESC 'OpenLDAP ldapSyntax' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.5 NAME 'olcLimits' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.93 NAME 'olcListenerThreads' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.26 NAME 'olcLocalSSF' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.27 NAME 'olcLogFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.28 NAME 'olcLogLevel' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.6 NAME 'olcMaxDerefDepth' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.16 NAME 'olcMirrorMode' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.30 NAME 'olcModuleLoad' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.31 NAME 'olcModulePath' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.18 NAME 'olcMonitoring' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.32 NAME 'olcObjectClasses' DESC 'OpenLDAP object classes' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.33 NAME 'olcObjectIdentifier' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.34 NAME 'olcOverlay' SUP olcDatabase SINGLE-VALUE X-ORDERED 'SIBLINGS' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.35 NAME 'olcPasswordCryptSaltFormat' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.36 NAME 'olcPasswordHash' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.37 NAME 'olcPidFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.38 NAME 'olcPlugin' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.39 NAME 'olcPluginLogFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.40 NAME 'olcReadOnly' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.41 NAME 'olcReferral' SUP labeledURI SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.7 NAME 'olcReplica' SUP labeledURI EQUALITY caseIgnoreMatch X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.43 NAME 'olcReplicaArgsFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.44 NAME 'olcReplicaPidFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.45 NAME 'olcReplicationInterval' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.46 NAME 'olcReplogFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.47 NAME 'olcRequires' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.48 NAME 'olcRestrict' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.49 NAME 'olcReverseLookup' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.8 NAME 'olcRootDN' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.51 NAME 'olcRootDSE' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.9 NAME 'olcRootPW' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.89 NAME 'olcSaslAuxprops' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.53 NAME 'olcSaslHost' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.54 NAME 'olcSaslRealm' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.56 NAME 'olcSaslSecProps' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.58 NAME 'olcSchemaDN' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.59 NAME 'olcSecurity' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.81 NAME 'olcServerID' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.60 NAME 'olcSizeLimit' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.61 NAME 'olcSockbufMaxIncoming' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.62 NAME 'olcSockbufMaxIncomingAuth' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.83 NAME 'olcSortVals' DESC 'Attributes whose values will always be sorted' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.15 NAME 'olcSubordinate' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.10 NAME 'olcSuffix' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.19 NAME 'olcSyncUseSubentry' DESC 'Store sync context in a subentry' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.11 NAME 'olcSyncrepl' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.90 NAME 'olcTCPBuffer' DESC 'Custom TCP buffer size' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.66 NAME 'olcThreads' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.67 NAME 'olcTimeLimit' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.68 NAME 'olcTLSCACertificateFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.69 NAME 'olcTLSCACertificatePath' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.70 NAME 'olcTLSCertificateFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.71 NAME 'olcTLSCertificateKeyFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.72 NAME 'olcTLSCipherSuite' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.73 NAME 'olcTLSCRLCheck' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.82 NAME 'olcTLSCRLFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.74 NAME 'olcTLSRandFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.75 NAME 'olcTLSVerifyClient' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.77 NAME 'olcTLSDHParamFile' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.87 NAME 'olcTLSProtocolMin' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.80 NAME 'olcToolThreads' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.12 NAME 'olcUpdateDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.13 NAME 'olcUpdateRef' SUP labeledURI EQUALITY caseIgnoreMatch )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.0.88 NAME 'olcWriteTimeout' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.1 NAME 'olcDbDirectory' DESC 'Directory for database content' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.11 NAME 'olcDbCacheFree' DESC 'Number of extra entries to free when max is reached' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.1 NAME 'olcDbCacheSize' DESC 'Entry cache size in entries' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.2 NAME 'olcDbCheckpoint' DESC 'Database checkpoint interval in kbytes and minutes' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.16 NAME 'olcDbChecksum' DESC 'Enable database checksum validation' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.13 NAME 'olcDbCryptFile' DESC 'Pathname of file containing the DB encryption key' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.14 NAME 'olcDbCryptKey' DESC 'DB encryption key' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.3 NAME 'olcDbConfig' DESC 'BerkeleyDB DB_CONFIG configuration directives' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.4 NAME 'olcDbNoSync' DESC 'Disable synchronous database writes' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.15 NAME 'olcDbPageSize' DESC 'Page size of specified DB, in Kbytes' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.5 NAME 'olcDbDirtyRead' DESC 'Allow reads of uncommitted data' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.12 NAME 'olcDbDNcacheSize' DESC 'DN cache size' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.6 NAME 'olcDbIDLcacheSize' DESC 'IDL cache size in IDLs' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.2 NAME 'olcDbIndex' DESC 'Attribute index parameters' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.7 NAME 'olcDbLinearIndex' DESC 'Index attributes one at a time' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.8 NAME 'olcDbLockDetect' DESC 'Deadlock detection algorithm' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.3 NAME 'olcDbMode' DESC 'Unix permissions of database files' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.9 NAME 'olcDbSearchStack' DESC 'Depth of search stack in IDLs' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.1.10 NAME 'olcDbShmKey' DESC 'Key for shared memory region' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.0.14 NAME 'olcDbURI' DESC 'URI (list) for remote DSA' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.1 NAME 'olcDbStartTLS' DESC 'StartTLS' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.2 NAME 'olcDbACLAuthcDn' DESC 'Remote ACL administrative identity' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.3 NAME 'olcDbACLPasswd' DESC 'Remote ACL administrative identity credentials' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.7 NAME 'olcDbIDAssertBind' DESC 'Remote Identity Assertion administrative identity auth bind configuration' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.9 NAME 'olcDbIDAssertAuthzFrom' DESC 'Remote Identity Assertion authz rules' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.10 NAME 'olcDbRebindAsUser' DESC 'Rebind as user' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.11 NAME 'olcDbChaseReferrals' DESC 'Chase referrals' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.12 NAME 'olcDbTFSupport' DESC 'Absolute filters support' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.14 NAME 'olcDbTimeout' DESC 'Per-operation timeouts' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.15 NAME 'olcDbIdleTimeout' DESC 'connection idle timeout' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.16 NAME 'olcDbConnTtl' DESC 'connection ttl' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.17 NAME 'olcDbNetworkTimeout' DESC 'connection network timeout' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.18 NAME 'olcDbProtocolVersion' DESC 'protocol version' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.19 NAME 'olcDbSingleConn' DESC 'cache a single connection per identity' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.20 NAME 'olcDbCancel' DESC 'abandon/ignore/exop operations when appropriate' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.21 NAME 'olcDbQuarantine' DESC 'Quarantine database if connection fails and retry according to rule' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.22 NAME 'olcDbUseTemporaryConn' DESC 'Use temporary connections if the cached one is busy' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.23 NAME 'olcDbConnectionPoolMax' DESC 'Max size of privileged connections pool' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.24 NAME 'olcDbSessionTrackingRequest' DESC 'Add session tracking control to proxied requests' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.25 NAME 'olcDbNoRefs' DESC 'Do not return search reference responses' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.26 NAME 'olcDbNoUndefFilter' DESC 'Do not propagate undefined search filters' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.101 NAME 'olcDbRewrite' DESC 'DN rewriting rules' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.102 NAME 'olcDbMap' DESC 'Map attribute and objectclass names' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.103 NAME 'olcDbSubtreeExclude' DESC 'DN of subtree to exclude from target' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.104 NAME 'olcDbSubtreeInclude' DESC 'DN of subtree to include in target' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.105 NAME 'olcDbDefaultTarget' DESC 'Specify the default target' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.106 NAME 'olcDbDnCacheTtl' DESC 'dncache ttl' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.107 NAME 'olcDbBindTimeout' DESC 'bind timeout' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.108 NAME 'olcDbOnErr' DESC 'error handling' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.109 NAME 'olcDbPseudoRootBindDefer' DESC 'error handling' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.110 NAME 'olcDbNretries' DESC 'retry handling' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.111 NAME 'olcDbClientPr' DESC 'PagedResults handling' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.100 NAME 'olcMetaSub' DESC 'Placeholder to name a Target entry' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE X-ORDERED 'SIBLINGS' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.29 NAME 'olcDbKeepalive' DESC 'TCP keepalive' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.112 NAME 'olcDbFilter' DESC 'Filter regex pattern to include in target' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.4 NAME 'olcDbACLBind' DESC 'Remote ACL administrative identity auth bind configuration' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.5 NAME 'olcDbIDAssertAuthcDn' DESC 'Remote Identity Assertion administrative identity' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.6 NAME 'olcDbIDAssertPasswd' DESC 'Remote Identity Assertion administrative identity credentials' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.8 NAME 'olcDbIDAssertMode' DESC 'Remote Identity Assertion mode' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.13 NAME 'olcDbProxyWhoAmI' DESC 'Proxy whoAmI exop' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.27 NAME 'olcDbIDAssertPassThru' DESC 'Remote Identity Assertion passthru rules' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.2.3.28 NAME 'olcDbRemoveUnknownSchema' DESC 'Omit unknown schema when returning search results' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.3.1 NAME 'olcChainingBehavior' DESC 'Chaining behavior control parameters (draft-sermersheim-ldap-chaining)' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.3.2 NAME 'olcChainCacheURI' DESC 'Enables caching of URIs not present in configuration' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.3.3 NAME 'olcChainMaxReferralDepth' DESC 'max referral depth' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.3.4 NAME 'olcChainReturnError' DESC 'Errors are returned instead of the original referral' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.2.840.113556.1.2.102 NAME 'memberOf' DESC 'Group that the entry belongs to' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 USAGE dSAOperation X-ORIGIN 'iPlanet Delegated Administrator' )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.18.0 NAME 'olcMemberOfDN' DESC 'DN to be used as modifiersName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.18.1 NAME 'olcMemberOfDangling' DESC 'Behavior with respect to dangling members, constrained to ignore, drop, error' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.18.2 NAME 'olcMemberOfRefInt' DESC 'Take care of referential integrity' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.18.3 NAME 'olcMemberOfGroupOC' DESC 'Group objectClass' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.18.4 NAME 'olcMemberOfMemberAD' DESC 'member attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.18.5 NAME 'olcMemberOfMemberOfAD' DESC 'memberOf attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.18.7 NAME 'olcMemberOfDanglingError' DESC 'Error code returned in case of dangling back reference' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.21.1 NAME 'olcSssVlvMax' DESC 'Maximum number of concurrent Sort requests' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.21.2 NAME 'olcSssVlvMaxKeys' DESC 'Maximum number of Keys in a Sort request' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.21.3 NAME 'olcSssVlvMaxPerConn' DESC 'Maximum number of concurrent paged search requests per connection' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.16 NAME 'pwdChangedTime' DESC 'The time the password was last changed' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.17 NAME 'pwdAccountLockedTime' DESC 'The time an user account was locked' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.19 NAME 'pwdFailureTime' DESC 'The timestamps of the last consecutive authentication failures' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.20 NAME 'pwdHistory' DESC 'The history of users passwords' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.21 NAME 'pwdGraceUseTime' DESC 'The timestamps of the grace login once the password has expired' EQUALITY generalizedTimeMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 NO-USER-MODIFICATION USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.22 NAME 'pwdReset' DESC 'The indication that the password has been reset' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.23 NAME 'pwdPolicySubentry' DESC 'The pwdPolicy subentry in effect for this object' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE USAGE directoryOperation )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.12.1 NAME 'olcPPolicyDefault' DESC 'DN of a pwdPolicy object for uncustomized objects' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.12.2 NAME 'olcPPolicyHashCleartext' DESC 'Hash passwords on add or modify' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.12.4 NAME 'olcPPolicyForwardUpdates' DESC 'Allow policy state updates to be forwarded via updateref' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4203.1.12.2.3.3.12.3 NAME 'olcPPolicyUseLockout' DESC 'Warn clients with AccountLocked' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 2.5.4.2 NAME 'knowledgeInformation' DESC 'RFC2256: knowledge information' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )
attributeTypes: ( 2.5.4.4 NAME ( 'sn' 'surname' ) DESC 'RFC2256: last (family) name(s) for which the entity is known by' SUP name )
attributeTypes: ( 2.5.4.5 NAME 'serialNumber' DESC 'RFC2256: serial number of the entity' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.44{64} )
attributeTypes: ( 2.5.4.6 NAME ( 'c' 'countryName' ) DESC 'RFC4519: two-letter ISO-3166 country code' SUP name SYNTAX 1.3.6.1.4.1.1466.115.121.1.11 SINGLE-VALUE )
attributeTypes: ( 2.5.4.7 NAME ( 'l' 'localityName' ) DESC 'RFC2256: locality which this object resides in' SUP name )
attributeTypes: ( 2.5.4.8 NAME ( 'st' 'stateOrProvinceName' ) DESC 'RFC2256: state or province which this object resides in' SUP name )
attributeTypes: ( 2.5.4.9 NAME ( 'street' 'streetAddress' ) DESC 'RFC2256: street address of this object' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )
attributeTypes: ( 2.5.4.10 NAME ( 'o' 'organizationName' ) DESC 'RFC2256: organization this object belongs to' SUP name )
attributeTypes: ( 2.5.4.11 NAME ( 'ou' 'organizationalUnitName' ) DESC 'RFC2256: organizational unit this object belongs to' SUP name )
attributeTypes: ( 2.5.4.12 NAME 'title' DESC 'RFC2256: title associated with the entity' SUP name )
attributeTypes: ( 2.5.4.14 NAME 'searchGuide' DESC 'RFC2256: search guide, deprecated by enhancedSearchGuide' SYNTAX 1.3.6.1.4.1.1466.115.121.1.25 )
attributeTypes: ( 2.5.4.15 NAME 'businessCategory' DESC 'RFC2256: business category' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )
attributeTypes: ( 2.5.4.16 NAME 'postalAddress' DESC 'RFC2256: postal address' EQUALITY caseIgnoreListMatch SUBSTR caseIgnoreListSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
attributeTypes: ( 2.5.4.17 NAME 'postalCode' DESC 'RFC2256: postal code' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{40} )
attributeTypes: ( 2.5.4.18 NAME 'postOfficeBox' DESC 'RFC2256: Post Office Box' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{40} )
attributeTypes: ( 2.5.4.19 NAME 'physicalDeliveryOfficeName' DESC 'RFC2256: Physical Delivery Office Name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )
attributeTypes: ( 2.5.4.20 NAME 'telephoneNumber' DESC 'RFC2256: Telephone Number' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50{32} )
attributeTypes: ( 2.5.4.21 NAME 'telexNumber' DESC 'RFC2256: Telex Number' SYNTAX 1.3.6.1.4.1.1466.115.121.1.52 )
attributeTypes: ( 2.5.4.22 NAME 'teletexTerminalIdentifier' DESC 'RFC2256: Teletex Terminal Identifier' SYNTAX 1.3.6.1.4.1.1466.115.121.1.51 )
attributeTypes: ( 2.5.4.23 NAME ( 'facsimileTelephoneNumber' 'fax' ) DESC 'RFC2256: Facsimile (Fax) Telephone Number' SYNTAX 1.3.6.1.4.1.1466.115.121.1.22 )
attributeTypes: ( 2.5.4.24 NAME 'x121Address' DESC 'RFC2256: X.121 Address' EQUALITY numericStringMatch SUBSTR numericStringSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.36{15} )
attributeTypes: ( 2.5.4.25 NAME 'internationaliSDNNumber' DESC 'RFC2256: international ISDN number' EQUALITY numericStringMatch SUBSTR numericStringSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.36{16} )
attributeTypes: ( 2.5.4.26 NAME 'registeredAddress' DESC 'RFC2256: registered postal address' SUP postalAddress SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
attributeTypes: ( 2.5.4.27 NAME 'destinationIndicator' DESC 'RFC2256: destination indicator' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.44{128} )
attributeTypes: ( 2.5.4.28 NAME 'preferredDeliveryMethod' DESC 'RFC2256: preferred delivery method' SYNTAX 1.3.6.1.4.1.1466.115.121.1.14 SINGLE-VALUE )
attributeTypes: ( 2.5.4.29 NAME 'presentationAddress' DESC 'RFC2256: presentation address' EQUALITY presentationAddressMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.43 SINGLE-VALUE )
attributeTypes: ( 2.5.4.30 NAME 'supportedApplicationContext' DESC 'RFC2256: supported application context' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
attributeTypes: ( 2.5.4.31 NAME 'member' DESC 'RFC2256: member of a group' SUP distinguishedName )
attributeTypes: ( 2.5.4.32 NAME 'owner' DESC 'RFC2256: owner (of the object)' SUP distinguishedName )
attributeTypes: ( 2.5.4.33 NAME 'roleOccupant' DESC 'RFC2256: occupant of role' SUP distinguishedName )
attributeTypes: ( 2.5.4.36 NAME 'userCertificate' DESC 'RFC2256: X.509 user certificate, use ;binary' EQUALITY certificateExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )
attributeTypes: ( 2.5.4.37 NAME 'cACertificate' DESC 'RFC2256: X.509 CA certificate, use ;binary' EQUALITY certificateExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )
attributeTypes: ( 2.5.4.38 NAME 'authorityRevocationList' DESC 'RFC2256: X.509 authority revocation list, use ;binary' SYNTAX 1.3.6.1.4.1.1466.115.121.1.9 )
attributeTypes: ( 2.5.4.39 NAME 'certificateRevocationList' DESC 'RFC2256: X.509 certificate revocation list, use ;binary' SYNTAX 1.3.6.1.4.1.1466.115.121.1.9 )
attributeTypes: ( 2.5.4.40 NAME 'crossCertificatePair' DESC 'RFC2256: X.509 cross certificate pair, use ;binary' SYNTAX 1.3.6.1.4.1.1466.115.121.1.10 )
attributeTypes: ( 2.5.4.42 NAME ( 'givenName' 'gn' ) DESC 'RFC2256: first name(s) for which the entity is known by' SUP name )
attributeTypes: ( 2.5.4.43 NAME 'initials' DESC 'RFC2256: initials of some or all of names, but not the surname(s).' SUP name )
attributeTypes: ( 2.5.4.44 NAME 'generationQualifier' DESC 'RFC2256: name qualifier indicating a generation' SUP name )
attributeTypes: ( 2.5.4.45 NAME 'x500UniqueIdentifier' DESC 'RFC2256: X.500 unique identifier' EQUALITY bitStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )
attributeTypes: ( 2.5.4.46 NAME 'dnQualifier' DESC 'RFC2256: DN qualifier' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
attributeTypes: ( 2.5.4.47 NAME 'enhancedSearchGuide' DESC 'RFC2256: enhanced search guide' SYNTAX 1.3.6.1.4.1.1466.115.121.1.21 )
attributeTypes: ( 2.5.4.48 NAME 'protocolInformation' DESC 'RFC2256: protocol information' EQUALITY protocolInformationMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.42 )
attributeTypes: ( 2.5.4.50 NAME 'uniqueMember' DESC 'RFC2256: unique member of a group' EQUALITY uniqueMemberMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )
attributeTypes: ( 2.5.4.51 NAME 'houseIdentifier' DESC 'RFC2256: house identifier' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )
attributeTypes: ( 2.5.4.52 NAME 'supportedAlgorithms' DESC 'RFC2256: supported algorithms' SYNTAX 1.3.6.1.4.1.1466.115.121.1.49 )
attributeTypes: ( 2.5.4.53 NAME 'deltaRevocationList' DESC 'RFC2256: delta revocation list; use ;binary' SYNTAX 1.3.6.1.4.1.1466.115.121.1.9 )
attributeTypes: ( 2.5.4.54 NAME 'dmdName' DESC 'RFC2256: name of DMD' SUP name )
attributeTypes: ( 2.5.4.65 NAME 'pseudonym' DESC 'X.520(4th): pseudonym for the object' SUP name )
attributeTypes: ( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) DESC 'RFC1274: RFC822 Mailbox' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} SINGLE-VALUE )
attributeTypes: ( 0.9.2342.19200300.100.1.25 NAME ( 'dc' 'domainComponent' ) DESC 'RFC1274/2247: domain component' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributeTypes: ( 0.9.2342.19200300.100.1.37 NAME 'associatedDomain' DESC 'RFC1274: domain associated with object' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 1.2.840.113549.1.9.1 NAME ( 'email' 'emailAddress' 'pkcs9email' ) DESC 'RFC3280: legacy attribute for email addresses in DNs' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{128} )
attributeTypes: ( 0.9.2342.19200300.100.1.2 NAME 'textEncodedORAddress' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.4 NAME 'info' DESC 'RFC1274: general information' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{2048} )
attributeTypes: ( 0.9.2342.19200300.100.1.5 NAME ( 'drink' 'favouriteDrink' ) DESC 'RFC1274: favorite drink' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.6 NAME 'roomNumber' DESC 'RFC1274: room number' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.7 NAME 'photo' DESC 'RFC1274: photo (G3 fax)' SYNTAX 1.3.6.1.4.1.1466.115.121.1.23{25000} )
attributeTypes: ( 0.9.2342.19200300.100.1.8 NAME 'userClass' DESC 'RFC1274: category of user' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.9 NAME 'host' DESC 'RFC1274: host computer' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.10 NAME 'manager' DESC 'RFC1274: DN of manager' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeTypes: ( 0.9.2342.19200300.100.1.11 NAME 'documentIdentifier' DESC 'RFC1274: unique identifier of document' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.12 NAME 'documentTitle' DESC 'RFC1274: title of document' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.13 NAME 'documentVersion' DESC 'RFC1274: version of document' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.14 NAME 'documentAuthor' DESC 'RFC1274: DN of author of document' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeTypes: ( 0.9.2342.19200300.100.1.15 NAME 'documentLocation' DESC 'RFC1274: location of document original' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.20 NAME ( 'homePhone' 'homeTelephoneNumber' ) DESC 'RFC1274: home telephone number' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
attributeTypes: ( 0.9.2342.19200300.100.1.21 NAME 'secretary' DESC 'RFC1274: DN of secretary' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeTypes: ( 0.9.2342.19200300.100.1.22 NAME 'otherMailbox' SYNTAX 1.3.6.1.4.1.1466.115.121.1.39 )
attributeTypes: ( 0.9.2342.19200300.100.1.26 NAME 'aRecord' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 0.9.2342.19200300.100.1.27 NAME 'mDRecord' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 0.9.2342.19200300.100.1.28 NAME 'mXRecord' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 0.9.2342.19200300.100.1.29 NAME 'nSRecord' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 0.9.2342.19200300.100.1.30 NAME 'sOARecord' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 0.9.2342.19200300.100.1.31 NAME 'cNAMERecord' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 0.9.2342.19200300.100.1.38 NAME 'associatedName' DESC 'RFC1274: DN of entry associated with domain' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeTypes: ( 0.9.2342.19200300.100.1.39 NAME 'homePostalAddress' DESC 'RFC1274: home postal address' EQUALITY caseIgnoreListMatch SUBSTR caseIgnoreListSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
attributeTypes: ( 0.9.2342.19200300.100.1.40 NAME 'personalTitle' DESC 'RFC1274: personal title' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.41 NAME ( 'mobile' 'mobileTelephoneNumber' ) DESC 'RFC1274: mobile telephone number' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
attributeTypes: ( 0.9.2342.19200300.100.1.42 NAME ( 'pager' 'pagerTelephoneNumber' ) DESC 'RFC1274: pager telephone number' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
attributeTypes: ( 0.9.2342.19200300.100.1.43 NAME ( 'co' 'friendlyCountryName' ) DESC 'RFC1274: friendly country name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 0.9.2342.19200300.100.1.44 NAME 'uniqueIdentifier' DESC 'RFC1274: unique identifer' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.45 NAME 'organizationalStatus' DESC 'RFC1274: organizational status' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.46 NAME 'janetMailbox' DESC 'RFC1274: Janet mailbox' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.47 NAME 'mailPreferenceOption' DESC 'RFC1274: mail preference option' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
attributeTypes: ( 0.9.2342.19200300.100.1.48 NAME 'buildingName' DESC 'RFC1274: name of building' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )
attributeTypes: ( 0.9.2342.19200300.100.1.49 NAME 'dSAQuality' DESC 'RFC1274: DSA Quality' SYNTAX 1.3.6.1.4.1.1466.115.121.1.19 SINGLE-VALUE )
attributeTypes: ( 0.9.2342.19200300.100.1.50 NAME 'singleLevelQuality' DESC 'RFC1274: Single Level Quality' SYNTAX 1.3.6.1.4.1.1466.115.121.1.13 SINGLE-VALUE )
attributeTypes: ( 0.9.2342.19200300.100.1.51 NAME 'subtreeMinimumQuality' DESC 'RFC1274: Subtree Mininum Quality' SYNTAX 1.3.6.1.4.1.1466.115.121.1.13 SINGLE-VALUE )
attributeTypes: ( 0.9.2342.19200300.100.1.52 NAME 'subtreeMaximumQuality' DESC 'RFC1274: Subtree Maximun Quality' SYNTAX 1.3.6.1.4.1.1466.115.121.1.13 SINGLE-VALUE )
attributeTypes: ( 0.9.2342.19200300.100.1.53 NAME 'personalSignature' DESC 'RFC1274: Personal Signature (G3 fax)' SYNTAX 1.3.6.1.4.1.1466.115.121.1.23 )
attributeTypes: ( 0.9.2342.19200300.100.1.54 NAME 'dITRedirect' DESC 'RFC1274: DIT Redirect' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
attributeTypes: ( 0.9.2342.19200300.100.1.55 NAME 'audio' DESC 'RFC1274: audio (u-law)' SYNTAX 1.3.6.1.4.1.1466.115.121.1.4{25000} )
attributeTypes: ( 0.9.2342.19200300.100.1.56 NAME 'documentPublisher' DESC 'RFC1274: publisher of document' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 2.16.840.1.113730.3.1.1 NAME 'carLicense' DESC 'RFC2798: vehicle license or registration plate' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 2.16.840.1.113730.3.1.2 NAME 'departmentNumber' DESC 'RFC2798: identifies a department within an organization' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 2.16.840.1.113730.3.1.241 NAME 'displayName' DESC 'RFC2798: preferred name to be used when displaying entries' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 2.16.840.1.113730.3.1.3 NAME 'employeeNumber' DESC 'RFC2798: numerically identifies an employee within an organization' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 2.16.840.1.113730.3.1.4 NAME 'employeeType' DESC 'RFC2798: type of employment for a person' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
attributeTypes: ( 0.9.2342.19200300.100.1.60 NAME 'jpegPhoto' DESC 'RFC2798: a JPEG image' SYNTAX 1.3.6.1.4.1.1466.115.121.1.28 )
attributeTypes: ( 2.16.840.1.113730.3.1.39 NAME 'preferredLanguage' DESC 'RFC2798: preferred written or spoken language for a person' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributeTypes: ( 2.16.840.1.113730.3.1.40 NAME 'userSMIMECertificate' DESC 'RFC2798: PKCS#7 SignedData used to support S/MIME' SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 )
attributeTypes: ( 2.16.840.1.113730.3.1.216 NAME 'userPKCS12' DESC 'RFC2798: personal identity information, a PKCS #12 PFX' SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 )
attributeTypes: ( 1.3.6.1.1.1.1.2 NAME 'gecos' DESC 'The GECOS field; the common name' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' DESC 'The absolute path to the home directory' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.4 NAME 'loginShell' DESC 'The path to the login shell' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.5 NAME 'shadowLastChange' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.6 NAME 'shadowMin' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.7 NAME 'shadowMax' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.8 NAME 'shadowWarning' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.9 NAME 'shadowInactive' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.10 NAME 'shadowExpire' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.11 NAME 'shadowFlag' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.12 NAME 'memberUid' EQUALITY caseExactIA5Match SUBSTR caseExactIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 1.3.6.1.1.1.1.13 NAME 'memberNisNetgroup' EQUALITY caseExactIA5Match SUBSTR caseExactIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 1.3.6.1.1.1.1.14 NAME 'nisNetgroupTriple' DESC 'Netgroup triple' SYNTAX 1.3.6.1.1.1.0.0 )
attributeTypes: ( 1.3.6.1.1.1.1.15 NAME 'ipServicePort' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.16 NAME 'ipServiceProtocol' SUP name )
attributeTypes: ( 1.3.6.1.1.1.1.17 NAME 'ipProtocolNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.18 NAME 'oncRpcNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.19 NAME 'ipHostNumber' DESC 'IP address' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{128} )
attributeTypes: ( 1.3.6.1.1.1.1.20 NAME 'ipNetworkNumber' DESC 'IP network' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{128} SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.21 NAME 'ipNetmaskNumber' DESC 'IP netmask' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{128} SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.1.1.1.22 NAME 'macAddress' DESC 'MAC address' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{128} )
attributeTypes: ( 1.3.6.1.1.1.1.23 NAME 'bootParameter' DESC 'rpc.bootparamd parameter' SYNTAX 1.3.6.1.1.1.0.1 )
attributeTypes: ( 1.3.6.1.1.1.1.24 NAME 'bootFile' DESC 'Boot image name' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
attributeTypes: ( 1.3.6.1.1.1.1.26 NAME 'nisMapName' SUP name )
attributeTypes: ( 1.3.6.1.1.1.1.27 NAME 'nisMapEntry' EQUALITY caseExactIA5Match SUBSTR caseExactIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{1024} SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.1 NAME 'pwdAttribute' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.2 NAME 'pwdMinAge' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.3 NAME 'pwdMaxAge' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.4 NAME 'pwdInHistory' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.5 NAME 'pwdCheckQuality' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.6 NAME 'pwdMinLength' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.7 NAME 'pwdExpireWarning' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.8 NAME 'pwdGraceAuthNLimit' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.9 NAME 'pwdLockout' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.10 NAME 'pwdLockoutDuration' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.11 NAME 'pwdMaxFailure' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.12 NAME 'pwdFailureCountInterval' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.13 NAME 'pwdMustChange' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.14 NAME 'pwdAllowUserChange' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.15 NAME 'pwdSafeModify' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.42.2.27.8.1.30 NAME 'pwdMaxRecordedFailure' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
attributeTypes: ( 1.3.6.1.4.1.4754.1.99.1 NAME 'pwdCheckModule' DESC 'Loadable module that instantiates check_password() function' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
objectClasses: ( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )
objectClasses: ( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' DESC 'RFC4512: extensible object' SUP top AUXILIARY )
objectClasses: ( 2.5.6.1 NAME 'alias' DESC 'RFC4512: an alias' SUP top STRUCTURAL MUST aliasedObjectName )
objectClasses: ( 2.16.840.1.113730.3.2.6 NAME 'referral' DESC 'namedref: named subordinate referral' SUP top STRUCTURAL MUST ref )
objectClasses: ( 1.3.6.1.4.1.4203.1.4.1 NAME ( 'OpenLDAProotDSE' 'LDAProotDSE' ) DESC 'OpenLDAP Root DSE object' SUP top STRUCTURAL MAY cn )
objectClasses: ( 2.5.17.0 NAME 'subentry' DESC 'RFC3672: subentry' SUP top STRUCTURAL MUST ( cn $ subtreeSpecification ) )
objectClasses: ( 2.5.20.1 NAME 'subschema' DESC 'RFC4512: controlling subschema (sub)entry' AUXILIARY MAY ( dITStructureRules $ nameForms $ dITContentRules $ objectClasses $ attributeTypes $ matchingRules $ matchingRuleUse ) )
objectClasses: ( 1.3.6.1.4.1.1466.101.119.2 NAME 'dynamicObject' DESC 'RFC2589: Dynamic Object' SUP top AUXILIARY )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.0.0 NAME 'olcConfig' DESC 'OpenLDAP configuration object' SUP top ABSTRACT )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.0.1 NAME 'olcGlobal' DESC 'OpenLDAP Global configuration options' SUP olcConfig STRUCTURAL MAY ( cn $ olcConfigFile $ olcConfigDir $ olcAllows $ olcArgsFile $ olcAttributeOptions $ olcAuthIDRewrite $ olcAuthzPolicy $ olcAuthzRegexp $ olcConcurrency $ olcConnMaxPending $ olcConnMaxPendingAuth $ olcDisallows $ olcGentleHUP $ olcIdleTimeout $ olcIndexSubstrIfMaxLen $ olcIndexSubstrIfMinLen $ olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcIndexIntLen $ olcListenerThreads $ olcLocalSSF $ olcLogFile $ olcLogLevel $ olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ olcPluginLogFile $ olcReadOnly $ olcReferral $ olcReplogFile $ olcRequires $ olcRestrict $ olcReverseLookup $ olcRootDSE $ olcSaslAuxprops $ olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ olcSecurity $ olcServerID $ olcSizeLimit $ olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcTCPBuffer $ olcThreads $ olcTimeLimit $ olcTLSCACertificateFile $ olcTLSCACertificatePath $ olcTLSCertificateFile $ olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ olcTLSRandFile $ olcTLSVerifyClient $ olcTLSDHParamFile $ olcTLSCRLFile $ olcTLSProtocolMin $ olcToolThreads $ olcWriteTimeout $ olcObjectIdentifier $ olcAttributeTypes $ olcObjectClasses $ olcDitContentRules $ olcLdapSyntaxes ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.0.2 NAME 'olcSchemaConfig' DESC 'OpenLDAP schema object' SUP olcConfig STRUCTURAL MAY ( cn $ olcObjectIdentifier $ olcLdapSyntaxes $ olcAttributeTypes $ olcObjectClasses $ olcDitContentRules ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.0.3 NAME 'olcBackendConfig' DESC 'OpenLDAP Backend-specific options' SUP olcConfig STRUCTURAL MUST olcBackend )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.0.4 NAME 'olcDatabaseConfig' DESC 'OpenLDAP Database-specific options' SUP olcConfig STRUCTURAL MUST olcDatabase MAY ( olcHidden $ olcSuffix $ olcSubordinate $ olcAccess $ olcAddContentAcl $ olcLastMod $ olcLimits $ olcMaxDerefDepth $ olcPlugin $ olcReadOnly $ olcReplica $ olcReplicaArgsFile $ olcReplicaPidFile $ olcReplicationInterval $ olcReplogFile $ olcRequires $ olcRestrict $ olcRootDN $ olcRootPW $ olcSchemaDN $ olcSecurity $ olcSizeLimit $ olcSyncUseSubentry $ olcSyncrepl $ olcTimeLimit $ olcUpdateDN $ olcUpdateRef $ olcMirrorMode $ olcMonitoring $ olcExtraAttrs ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.0.5 NAME 'olcOverlayConfig' DESC 'OpenLDAP Overlay-specific options' SUP olcConfig STRUCTURAL MUST olcOverlay )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.0.6 NAME 'olcIncludeFile' DESC 'OpenLDAP configuration include file' SUP olcConfig STRUCTURAL MUST olcInclude MAY ( cn $ olcRootDSE ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.0.7 NAME 'olcFrontendConfig' DESC 'OpenLDAP frontend configuration' AUXILIARY MAY ( olcDefaultSearchBase $ olcPasswordHash $ olcSortVals ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.0.8 NAME 'olcModuleList' DESC 'OpenLDAP dynamic module info' SUP olcConfig STRUCTURAL MAY ( cn $ olcModulePath $ olcModuleLoad ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.2.2.1 NAME 'olcLdifConfig' DESC 'LDIF backend configuration' SUP olcDatabaseConfig STRUCTURAL MUST olcDbDirectory )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.2.1.2 NAME 'olcHdbConfig' DESC 'HDB backend configuration' SUP olcDatabaseConfig STRUCTURAL MUST olcDbDirectory MAY ( olcDbCacheSize $ olcDbCheckpoint $ olcDbChecksum $ olcDbConfig $ olcDbCryptFile $ olcDbCryptKey $ olcDbNoSync $ olcDbDirtyRead $ olcDbIDLcacheSize $ olcDbIndex $ olcDbLinearIndex $ olcDbLockDetect $ olcDbMode $ olcDbSearchStack $ olcDbShmKey $ olcDbCacheFree $ olcDbDNcacheSize $ olcDbPageSize ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.2.3.2 NAME 'olcMetaConfig' DESC 'Meta backend configuration' SUP olcDatabaseConfig STRUCTURAL MAY ( olcDbConnTtl $ olcDbDnCacheTtl $ olcDbIdleTimeout $ olcDbOnErr $ olcDbPseudoRootBindDefer $ olcDbSingleConn $ olcDbUseTemporaryConn $ olcDbConnectionPoolMax $ olcDbBindTimeout $ olcDbCancel $ olcDbChaseReferrals $ olcDbClientPr $ olcDbDefaultTarget $ olcDbNetworkTimeout $ olcDbNoRefs $ olcDbNoUndefFilter $ olcDbNretries $ olcDbProtocolVersion $ olcDbQuarantine $ olcDbRebindAsUser $ olcDbSessionTrackingRequest $ olcDbStartTLS $ olcDbTFSupport ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.2.3.3 NAME 'olcMetaTargetConfig' DESC 'Meta target configuration' SUP olcConfig STRUCTURAL MUST ( olcMetaSub $ olcDbURI ) MAY ( olcDbACLAuthcDn $ olcDbACLPasswd $ olcDbIDAssertAuthzFrom $ olcDbIDAssertBind $ olcDbMap $ olcDbRewrite $ olcDbSubtreeExclude $ olcDbSubtreeInclude $ olcDbTimeout $ olcDbKeepalive $ olcDbFilter $ olcDbBindTimeout $ olcDbCancel $ olcDbChaseReferrals $ olcDbClientPr $ olcDbDefaultTarget $ olcDbNetworkTimeout $ olcDbNoRefs $ olcDbNoUndefFilter $ olcDbNretries $ olcDbProtocolVersion $ olcDbQuarantine $ olcDbRebindAsUser $ olcDbSessionTrackingRequest $ olcDbStartTLS $ olcDbTFSupport ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.2.3.1 NAME 'olcLDAPConfig' DESC 'LDAP backend configuration' SUP olcDatabaseConfig STRUCTURAL MAY ( olcDbURI $ olcDbStartTLS $ olcDbACLAuthcDn $ olcDbACLPasswd $ olcDbACLBind $ olcDbIDAssertAuthcDn $ olcDbIDAssertPasswd $ olcDbIDAssertBind $ olcDbIDAssertMode $ olcDbIDAssertAuthzFrom $ olcDbIDAssertPassThru $ olcDbRebindAsUser $ olcDbChaseReferrals $ olcDbTFSupport $ olcDbProxyWhoAmI $ olcDbTimeout $ olcDbIdleTimeout $ olcDbConnTtl $ olcDbNetworkTimeout $ olcDbProtocolVersion $ olcDbSingleConn $ olcDbCancel $ olcDbQuarantine $ olcDbUseTemporaryConn $ olcDbConnectionPoolMax $ olcDbSessionTrackingRequest $ olcDbNoRefs $ olcDbNoUndefFilter $ olcDbOnErr $ olcDbKeepalive ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.3.3.1 NAME 'olcChainConfig' DESC 'Chain configuration' SUP olcOverlayConfig STRUCTURAL MAY ( olcChainingBehavior $ olcChainCacheURI $ olcChainMaxReferralDepth $ olcChainReturnError ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.3.3.2 NAME 'olcChainDatabase' DESC 'Chain remote server configuration' AUXILIARY )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.3.3.3 NAME 'olcPBindConfig' DESC 'Proxy Bind configuration' SUP olcOverlayConfig STRUCTURAL MUST olcDbURI MAY ( olcDbStartTLS $ olcDbNetworkTimeout $ olcDbQuarantine ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.3.7.1 NAME 'olcDistProcConfig' DESC 'Distributed procedures <draft-sermersheim-ldap-distproc> configuration' SUP olcOverlayConfig STRUCTURAL MAY ( olcChainingBehavior $ olcChainCacheURI ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.3.7.2 NAME 'olcDistProcDatabase' DESC 'Distributed procedure remote server configuration' AUXILIARY )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.3.18.1 NAME 'olcMemberOf' DESC 'Member-of configuration' SUP olcOverlayConfig STRUCTURAL MAY ( olcMemberOfDN $ olcMemberOfDangling $ olcMemberOfDanglingError $ olcMemberOfRefInt $ olcMemberOfGroupOC $ olcMemberOfMemberAD $ olcMemberOfMemberOfAD ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.3.21.1 NAME 'olcSssVlvConfig' DESC 'SSS VLV configuration' SUP olcOverlayConfig STRUCTURAL MAY ( olcSssVlvMax $ olcSssVlvMaxKeys $ olcSssVlvMaxPerConn ) )
objectClasses: ( 1.3.6.1.4.1.4203.1.12.2.4.3.12.1 NAME 'olcPPolicyConfig' DESC 'Password Policy configuration' SUP olcOverlayConfig STRUCTURAL MAY ( olcPPolicyDefault $ olcPPolicyHashCleartext $ olcPPolicyUseLockout $ olcPPolicyForwardUpdates ) )
objectClasses: ( 2.5.6.2 NAME 'country' DESC 'RFC2256: a country' SUP top STRUCTURAL MUST c MAY ( searchGuide $ description ) )
objectClasses: ( 2.5.6.3 NAME 'locality' DESC 'RFC2256: a locality' SUP top STRUCTURAL MAY ( street $ seeAlso $ searchGuide $ st $ l $ description ) )
objectClasses: ( 2.5.6.4 NAME 'organization' DESC 'RFC2256: an organization' SUP top STRUCTURAL MUST o MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $ x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ st $ l $ description ) )
objectClasses: ( 2.5.6.5 NAME 'organizationalUnit' DESC 'RFC2256: an organizational unit' SUP top STRUCTURAL MUST ou MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $ x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ st $ l $ description ) )
objectClasses: ( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )
objectClasses: ( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC2256: an organizational person' SUP person STRUCTURAL MAY ( title $ x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ ou $ st $ l ) )
objectClasses: ( 2.5.6.8 NAME 'organizationalRole' DESC 'RFC2256: an organizational role' SUP top STRUCTURAL MUST cn MAY ( x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $ seeAlso $ roleOccupant $ preferredDeliveryMethod $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ ou $ st $ l $ description ) )
objectClasses: ( 2.5.6.9 NAME 'groupOfNamesOrig' DESC 'RFC2256: a group of names (DNs)' SUP top STRUCTURAL MUST ( member $ cn ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )
objectClasses: ( 2.5.6.10 NAME 'residentialPerson' DESC 'RFC2256: an residential person' SUP person STRUCTURAL MUST l MAY ( businessCategory $ x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $ preferredDeliveryMethod $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ st $ l ) )
objectClasses: ( 2.5.6.11 NAME 'applicationProcess' DESC 'RFC2256: an application process' SUP top STRUCTURAL MUST cn MAY ( seeAlso $ ou $ l $ description ) )
objectClasses: ( 2.5.6.12 NAME 'applicationEntity' DESC 'RFC2256: an application entity' SUP top STRUCTURAL MUST ( presentationAddress $ cn ) MAY ( supportedApplicationContext $ seeAlso $ ou $ o $ l $ description ) )
objectClasses: ( 2.5.6.13 NAME 'dSA' DESC 'RFC2256: a directory system agent (a server)' SUP applicationEntity STRUCTURAL MAY knowledgeInformation )
objectClasses: ( 2.5.6.14 NAME 'device' DESC 'RFC2256: a device' SUP top STRUCTURAL MUST cn MAY ( serialNumber $ seeAlso $ owner $ ou $ o $ l $ description ) )
objectClasses: ( 2.5.6.15 NAME 'strongAuthenticationUser' DESC 'RFC2256: a strong authentication user' SUP top AUXILIARY MUST userCertificate )
objectClasses: ( 2.5.6.16 NAME 'certificationAuthority' DESC 'RFC2256: a certificate authority' SUP top AUXILIARY MUST ( authorityRevocationList $ certificateRevocationList $ cACertificate ) MAY crossCertificatePair )
objectClasses: ( 2.5.6.17 NAME 'groupOfUniqueNamesOrig' DESC 'RFC2256: a group of unique names (DN and Unique Identifier)' SUP top STRUCTURAL MUST ( uniqueMember $ cn ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )
objectClasses: ( 2.5.6.18 NAME 'userSecurityInformation' DESC 'RFC2256: a user security information' SUP top AUXILIARY MAY supportedAlgorithms )
objectClasses: ( 2.5.6.16.2 NAME 'certificationAuthority-V2' SUP certificationAuthority AUXILIARY MAY deltaRevocationList )
objectClasses: ( 2.5.6.19 NAME 'cRLDistributionPoint' SUP top STRUCTURAL MUST cn MAY ( certificateRevocationList $ authorityRevocationList $ deltaRevocationList ) )
objectClasses: ( 2.5.6.20 NAME 'dmd' SUP top STRUCTURAL MUST dmdName MAY ( userPassword $ searchGuide $ seeAlso $ businessCategory $ x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ st $ l $ description ) )
objectClasses: ( 2.5.6.21 NAME 'pkiUser' DESC 'RFC2587: a PKI user' SUP top AUXILIARY MAY userCertificate )
objectClasses: ( 2.5.6.22 NAME 'pkiCA' DESC 'RFC2587: PKI certificate authority' SUP top AUXILIARY MAY ( authorityRevocationList $ certificateRevocationList $ cACertificate $ crossCertificatePair ) )
objectClasses: ( 2.5.6.23 NAME 'deltaCRL' DESC 'RFC2587: PKI user' SUP top AUXILIARY MAY deltaRevocationList )
objectClasses: ( 1.3.6.1.4.1.250.3.15 NAME 'labeledURIObject' DESC 'RFC2079: object that contains the URI attribute type' SUP top AUXILIARY MAY labeledURI )
objectClasses: ( 0.9.2342.19200300.100.4.19 NAME 'simpleSecurityObject' DESC 'RFC1274: simple security object' SUP top AUXILIARY MUST userPassword )
objectClasses: ( 1.3.6.1.4.1.1466.344 NAME 'dcObject' DESC 'RFC2247: domain component object' SUP top AUXILIARY MUST dc )
objectClasses: ( 1.3.6.1.1.3.1 NAME 'uidObject' DESC 'RFC2377: uid object' SUP top AUXILIARY MUST uid )
objectClasses: ( 0.9.2342.19200300.100.4.4 NAME ( 'pilotPerson' 'newPilotPerson' ) SUP person STRUCTURAL MAY ( userid $ textEncodedORAddress $ rfc822Mailbox $ favouriteDrink $ roomNumber $ userClass $ homeTelephoneNumber $ homePostalAddress $ secretary $ personalTitle $ preferredDeliveryMethod $ businessCategory $ janetMailbox $ otherMailbox $ mobileTelephoneNumber $ pagerTelephoneNumber $ organizationalStatus $ mailPreferenceOption $ personalSignature ) )
objectClasses: ( 0.9.2342.19200300.100.4.5 NAME 'account' SUP top STRUCTURAL MUST userid MAY ( description $ seeAlso $ localityName $ organizationName $ organizationalUnitName $ host ) )
objectClasses: ( 0.9.2342.19200300.100.4.6 NAME 'document' SUP top STRUCTURAL MUST documentIdentifier MAY ( commonName $ description $ seeAlso $ localityName $ organizationName $ organizationalUnitName $ documentTitle $ documentVersion $ documentAuthor $ documentLocation $ documentPublisher ) )
objectClasses: ( 0.9.2342.19200300.100.4.7 NAME 'room' SUP top STRUCTURAL MUST commonName MAY ( roomNumber $ description $ seeAlso $ telephoneNumber ) )
objectClasses: ( 0.9.2342.19200300.100.4.9 NAME 'documentSeries' SUP top STRUCTURAL MUST commonName MAY ( description $ seeAlso $ telephonenumber $ localityName $ organizationName $ organizationalUnitName ) )
objectClasses: ( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top STRUCTURAL MUST domainComponent MAY ( associatedName $ organizationName $ description $ businessCategory $ seeAlso $ searchGuide $ userPassword $ localityName $ stateOrProvinceName $ streetAddress $ physicalDeliveryOfficeName $ postalAddress $ postalCode $ postOfficeBox $ streetAddress $ facsimileTelephoneNumber $ internationalISDNNumber $ telephoneNumber $ teletexTerminalIdentifier $ telexNumber $ preferredDeliveryMethod $ destinationIndicator $ registeredAddress $ x121Address ) )
objectClasses: ( 0.9.2342.19200300.100.4.14 NAME 'RFC822localPart' SUP domain STRUCTURAL MAY ( commonName $ surname $ description $ seeAlso $ telephoneNumber $ physicalDeliveryOfficeName $ postalAddress $ postalCode $ postOfficeBox $ streetAddress $ facsimileTelephoneNumber $ internationalISDNNumber $ telephoneNumber $ teletexTerminalIdentifier $ telexNumber $ preferredDeliveryMethod $ destinationIndicator $ registeredAddress $ x121Address ) )
objectClasses: ( 0.9.2342.19200300.100.4.15 NAME 'dNSDomain' SUP domain STRUCTURAL MAY ( ARecord $ MDRecord $ MXRecord $ NSRecord $ SOARecord $ CNAMERecord ) )
objectClasses: ( 0.9.2342.19200300.100.4.17 NAME 'domainRelatedObject' DESC 'RFC1274: an object related to an domain' SUP top AUXILIARY MUST associatedDomain )
objectClasses: ( 0.9.2342.19200300.100.4.18 NAME 'friendlyCountry' SUP country STRUCTURAL MUST friendlyCountryName )
objectClasses: ( 0.9.2342.19200300.100.4.20 NAME 'pilotOrganization' SUP ( organization $ organizationalUnit ) STRUCTURAL MAY buildingName )
objectClasses: ( 0.9.2342.19200300.100.4.21 NAME 'pilotDSA' SUP dsa STRUCTURAL MAY dSAQuality )
objectClasses: ( 0.9.2342.19200300.100.4.22 NAME 'qualityLabelledData' SUP top AUXILIARY MUST dsaQuality MAY ( subtreeMinimumQuality $ subtreeMaximumQuality ) )
objectClasses: ( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' DESC 'RFC2798: Internet Organizational Person' SUP organizationalPerson STRUCTURAL MAY ( audio $ businessCategory $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ givenName $ homePhone $ homePostalAddress $ initials $ jpegPhoto $ labeledURI $ mail $ manager $ mobile $ o $ pager $ photo $ roomNumber $ secretary $ uid $ userCertificate $ x500uniqueIdentifier $ preferredLanguage $ userSMIMECertificate $ userPKCS12 ) )
objectClasses: ( 1.3.6.1.1.1.2.0 NAME 'posixAccount' DESC 'Abstraction of an account with POSIX attributes' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ loginShell $ gecos $ description ) )
objectClasses: ( 1.3.6.1.1.1.2.1 NAME 'shadowAccount' DESC 'Additional attributes for shadow passwords' SUP top AUXILIARY MUST uid MAY ( userPassword $ shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ shadowInactive $ shadowExpire $ shadowFlag $ description ) )
objectClasses: ( 1.3.6.1.1.1.2.2 NAME 'posixGroup' DESC 'Abstraction of a group of accounts' SUP top STRUCTURAL MUST ( cn $ gidNumber ) MAY ( userPassword $ memberUid $ description ) )
objectClasses: ( 1.3.6.1.1.1.2.3 NAME 'ipService' DESC 'Abstraction an Internet Protocol service' SUP top STRUCTURAL MUST ( cn $ ipServicePort $ ipServiceProtocol ) MAY description )
objectClasses: ( 1.3.6.1.1.1.2.4 NAME 'ipProtocol' DESC 'Abstraction of an IP protocol' SUP top STRUCTURAL MUST ( cn $ ipProtocolNumber $ description ) MAY description )
objectClasses: ( 1.3.6.1.1.1.2.5 NAME 'oncRpc' DESC 'Abstraction of an ONC/RPC binding' SUP top STRUCTURAL MUST ( cn $ oncRpcNumber $ description ) MAY description )
objectClasses: ( 1.3.6.1.1.1.2.6 NAME 'ipHost' DESC 'Abstraction of a host, an IP device' SUP top AUXILIARY MUST ( cn $ ipHostNumber ) MAY ( l $ description $ manager ) )
objectClasses: ( 1.3.6.1.1.1.2.7 NAME 'ipNetwork' DESC 'Abstraction of an IP network' SUP top STRUCTURAL MUST ( cn $ ipNetworkNumber ) MAY ( ipNetmaskNumber $ l $ description $ manager ) )
objectClasses: ( 1.3.6.1.1.1.2.8 NAME 'nisNetgroup' DESC 'Abstraction of a netgroup' SUP top STRUCTURAL MUST cn MAY ( nisNetgroupTriple $ memberNisNetgroup $ description ) )
objectClasses: ( 1.3.6.1.1.1.2.9 NAME 'nisMap' DESC 'A generic abstraction of a NIS map' SUP top STRUCTURAL MUST nisMapName MAY description )
objectClasses: ( 1.3.6.1.1.1.2.10 NAME 'nisObject' DESC 'An entry in a NIS map' SUP top STRUCTURAL MUST ( cn $ nisMapEntry $ nisMapName ) MAY description )
objectClasses: ( 1.3.6.1.1.1.2.11 NAME 'ieee802Device' DESC 'A device with a MAC address' SUP top AUXILIARY MAY macAddress )
objectClasses: ( 1.3.6.1.1.1.2.12 NAME 'bootableDevice' DESC 'A device with boot parameters' SUP top AUXILIARY MAY ( bootFile $ bootParameter ) )
objectClasses: ( 1.3.6.1.4.1.4754.2.99.1 NAME 'pwdPolicyChecker' SUP top AUXILIARY MAY pwdCheckModule )
objectClasses: ( 1.3.6.1.4.1.42.2.27.8.2.1 NAME 'pwdPolicy' SUP top AUXILIARY MUST pwdAttribute MAY ( pwdMinAge $ pwdMaxAge $ pwdInHistory $ pwdCheckQuality $ pwdMinLength $ pwdExpireWarning $ pwdGraceAuthNLimit $ pwdLockout $ pwdLockoutDuration $ pwdMaxFailure $ pwdFailureCountInterval $ pwdMustChange $ pwdAllowUserChange $ pwdSafeModify $ pwdMaxRecordedFailure ) )
objectClasses: ( 1.3.6.1.4.1.14887.1.1.1.1.2 NAME 'groupOfNames' DESC 'RFC2256: a group of names (DNs)' SUP top STRUCTURAL MUST cn MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description $ member $ uniqueMember $ displayName ) )
objectClasses: ( 1.3.6.1.4.1.14887.1.1.1.1.3 NAME 'groupOfUniqueNames' DESC 'RFC2256: a group of unique names (DN and Unique Identifier)' SUP top STRUCTURAL MUST cn MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description $ member $ uniqueMember $ displayName ) )
`
