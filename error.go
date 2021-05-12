package main

import (
	"fmt"

	ldap "github.com/openstandia/ldapserver"
)

type LDAPError struct {
	Code      int
	Msg       string
	MatchedDN string
	err       error
}

func (e *LDAPError) Error() string {
	return fmt.Sprintf("LDAPError: %d %s", e.Code, e.Msg)
}

func (e *LDAPError) Unwrap() error {
	return e.err
}

func (e *LDAPError) IsNoSuchObjectError() bool {
	return e.Code == ldap.LDAPResultNoSuchObject
}

func NewSuccess() *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultSuccess,
	}
}

func NewNoSuchAttribute(op, attr string) *LDAPError {
	return &LDAPError{
		Code: 16,
		Msg:  fmt.Sprintf("%s: %s: no such value", op, attr),
	}
}

func NewUndefinedType(attr string) *LDAPError {
	return &LDAPError{
		Code: 17,
		Msg:  fmt.Sprintf("%s: attribute type undefined", attr),
	}
}

func NewMultipleValuesProvidedError(attr string) *LDAPError {
	return &LDAPError{
		Code: 19,
		Msg:  fmt.Sprintf("%s: multiple values provided", attr),
	}
}

func NewMultipleValuesConstraintViolation(attr string) *LDAPError {
	return &LDAPError{
		Code: 19,
		Msg:  fmt.Sprintf("attribute '%s' cannot have multiple values", attr),
	}
}

func NewNoUserModificationAllowedConstraintViolation(attr string) *LDAPError {
	return &LDAPError{
		Code: 19,
		Msg:  fmt.Sprintf("%s: no user modification allowed", attr),
	}
}

func NewTypeOrValueExists(op, attr string, valueidx int) *LDAPError {
	return &LDAPError{
		Code: 20,
		Msg:  fmt.Sprintf("%s: %s: value #%d already exists", op, attr, valueidx),
	}
}

func NewMoreThanOnceError(attr string, valueidx int) *LDAPError {
	return &LDAPError{
		Code: 20,
		Msg:  fmt.Sprintf("%s: value #%d provided more than once", attr, valueidx),
	}
}

func NewInvalidPerSyntax(attr string, valueidx int) *LDAPError {
	return &LDAPError{
		Code: 21,
		Msg:  fmt.Sprintf("%s: value #%d invalid per syntax", attr, valueidx),
	}
}

func NewNoSuchObjectWithMatchedDN(dn string) *LDAPError {
	return &LDAPError{
		Code:      ldap.LDAPResultNoSuchObject,
		MatchedDN: dn,
	}
}

func NewNoSuchObject() *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultNoSuchObject,
	}
}

func NewInvalidDNSyntax() *LDAPError {
	return &LDAPError{
		Code: 34,
		Msg:  fmt.Sprintf("invalid DN"),
	}
}

func NewInvalidCredentials() *LDAPError {
	return &LDAPError{
		Code: 49,
	}
}

func NewInsufficientAccess() *LDAPError {
	return &LDAPError{
		Code: 50,
	}
}

func NewNoGlobalSuperiorKnowledge() *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultUnwillingToPerform,
		Msg:  fmt.Sprintf("no global superior knowledge"),
	}
}

func NewObjectClassViolation() *LDAPError {
	return &LDAPError{
		Code: 65,
		Msg:  fmt.Sprintf("no objectClass attribute"),
	}
}

func NewNotAllowedOnNonLeaf() *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultNotAllowedOnNonLeaf,
		Msg:  fmt.Sprintf("subordinate objects must be deleted first"),
	}
}

func NewAlreadyExists() *LDAPError {
	return &LDAPError{
		Code: 68,
	}
}

func NewUnavailable() *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultUnavailable,
	}
}

func NewOperationsError() *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultOperationsError,
	}
}
