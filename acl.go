package main

import (
	"log"
	"strings"

	ldap "github.com/openstandia/ldapserver"
	"golang.org/x/xerrors"
)

type LDAPAction int

const (
	AddOps LDAPAction = iota
	ModifyOps
	ModRDNOps
	DeleteOps
	SearchOps
)

func (c LDAPAction) String() string {
	switch c {
	case AddOps:
		return "add"
	case ModifyOps:
		return "modify"
	case ModRDNOps:
		return "modrdn"
	case DeleteOps:
		return "delete"
	case SearchOps:
		return "search"
	default:
		return "unknown"
	}
}

func (s *Server) RequiredAuthz(m *ldap.Message, ops LDAPAction, targetDN *DN) bool {
	session := getAuthSession(m)
	if session.DN != nil {
		authorized := false

		switch ops {
		case AddOps:
			authorized = s.simpleACL.CanWrite(session)
		case ModifyOps:
			authorized = s.simpleACL.CanWrite(session)
		case ModRDNOps:
			authorized = s.simpleACL.CanWrite(session)
		case DeleteOps:
			authorized = s.simpleACL.CanWrite(session)
		case SearchOps:
			authorized = s.simpleACL.CanRead(session)
		}

		log.Printf("info: Authorized: %v, action: %s, authorizedDN: %s, targetDN: %s", authorized, ops.String(), session.DN.DNNormStr(), targetDN.DNNormStr())

		return authorized
	}
	log.Printf("warn: Not Authorized for anonymous. targetDN: %s", targetDN.DNNormStr())

	return false
}

type SimpleACL struct {
	list map[string]*SimpleACLDef
}

type SimpleACLDef struct {
	Scope               SimpleACLScopeSet
	InvisibleAttributes StringSet
}

type SimpleACLScope int

const (
	ReadScope SimpleACLScope = iota
	WriteScope
)

func (c SimpleACLScope) String() string {
	switch c {
	case ReadScope:
		return "R"
	case WriteScope:
		return "W"
	default:
		return "unknown"
	}
}

type SimpleACLScopeSet map[SimpleACLScope]struct{}

func (s SimpleACLScopeSet) Add(scope SimpleACLScope) {
	s[scope] = struct{}{}
}

func (s SimpleACLScopeSet) Contains(scope SimpleACLScope) bool {
	_, ok := s[scope]
	return ok
}

func NewSimpleACL(server *Server) (*SimpleACL, error) {
	m := map[string]*SimpleACLDef{}

	for _, d := range server.config.SimpleACL {
		s := strings.Split(d, ":")
		if len(s) != 3 {
			return nil, xerrors.Errorf("Invalid format. Need <DN(User, Group or empty(everyone))>:<Scope(R, W or RW)>:<Invisible Attributes>: %s", d)
		}

		scopeSet := SimpleACLScopeSet{}
		for _, v := range s[1] {
			s := strings.ToUpper(string(v))

			switch s {
			case "R":
				scopeSet.Add(ReadScope)
			case "W":
				scopeSet.Add(WriteScope)
			default:
				return nil, xerrors.Errorf(`Invalid scope. Need "R", "W": %s`, d)
			}
		}

		ia := strings.Split(s[2], ",")
		iaSet := NewStringSet()
		for _, v := range ia {
			iaSet.Add(strings.ToLower(strings.TrimSpace(v)))
		}

		if s[0] != "" {
			dn, err := server.NormalizeDN(s[0])
			if err != nil {
				return nil, xerrors.Errorf(`Invalid DN format: %s`, d)
			}
			m[dn.DNNormStr()] = &SimpleACLDef{
				Scope:               scopeSet,
				InvisibleAttributes: iaSet,
			}
		} else {
			// For everyone
			m["_DEFAULT_"] = &SimpleACLDef{
				Scope:               scopeSet,
				InvisibleAttributes: iaSet,
			}
		}
	}

	return &SimpleACL{
		list: m,
	}, nil
}

func (s *SimpleACL) CanRead(session *AuthSession) bool {
	if session.IsRoot {
		return true
	}

	if v, ok := s.list[session.DN.DNNormStr()]; ok {
		return v.Scope.Contains(ReadScope)
	}
	for _, m := range session.Groups {
		if v, ok := s.list[m.DNNormStr()]; ok {
			return v.Scope.Contains(ReadScope)
		}
	}
	if v, ok := s.list["_DEFAULT_"]; ok {
		return v.Scope.Contains(ReadScope)
	}
	return false
}

func (s *SimpleACL) CanWrite(session *AuthSession) bool {
	if session.IsRoot {
		return true
	}

	if v, ok := s.list[session.DN.DNNormStr()]; ok {
		return v.Scope.Contains(WriteScope)
	}
	for _, m := range session.Groups {
		if v, ok := s.list[m.DNNormStr()]; ok {
			return v.Scope.Contains(WriteScope)
		}
	}
	if v, ok := s.list["_DEFAULT_"]; ok {
		return v.Scope.Contains(WriteScope)
	}
	return false
}

func (s *SimpleACL) CanVisible(session *AuthSession, attrName string) bool {
	a := strings.ToLower(attrName)

	if session.IsRoot {
		return true
	}

	if v, ok := s.list[session.DN.DNNormStr()]; ok {
		return !v.InvisibleAttributes.Contains(a)
	}
	for _, m := range session.Groups {
		if v, ok := s.list[m.DNNormStr()]; ok {
			return !v.InvisibleAttributes.Contains(a)
		}
	}
	if v, ok := s.list["_DEFAULT_"]; ok {
		return !v.InvisibleAttributes.Contains(a)
	}
	return true
}
