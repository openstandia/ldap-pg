package main

import (
	"fmt"

	ldap "github.com/openstandia/ldapserver"
)

type LDAPError struct {
	Code      int
	Msg       string
	MatchedDN string
	Subtype   string
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

func (e *LDAPError) IsInvalidCredentials() bool {
	return e.Code == ldap.LDAPResultInvalidCredentials
}

func (e *LDAPError) IsAccountLocked() bool {
	return e.Code == ldap.LDAPResultInvalidCredentials && e.Subtype == "Account locked"
}

func (e *LDAPError) IsAccountLocking() bool {
	return e.Code == ldap.LDAPResultInvalidCredentials && e.Subtype == "Account locking"
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
		Code: ldap.LDAPResultInvalidCredentials,
	}
}

func NewAccountLocking() *LDAPError {
	return &LDAPError{
		Code:    ldap.LDAPResultInvalidCredentials,
		Subtype: "Account locking",
	}
}

func NewAccountLocked() *LDAPError {
	return &LDAPError{
		Code:    ldap.LDAPResultInvalidCredentials,
		Subtype: "Account locked",
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
		Code: ldap.LDAPResultObjectClassViolation,
		Msg:  fmt.Sprintf("no objectClass attribute"),
	}
}

func NewObjectClassViolationRequiresAttribute(objectClass, attrName string) *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultObjectClassViolation,
		Msg:  fmt.Sprintf("object class '%s' requires attribute '%s'", objectClass, attrName),
	}
}

func NewObjectClassViolationNoStructural() *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultObjectClassViolation,
		Msg:  fmt.Sprintf("no structural object class provided"),
	}
}

func NewObjectClassViolationNotAllowed(attrName string) *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultObjectClassViolation,
		Msg:  fmt.Sprintf("attribute '%s' not allowed", attrName),
	}
}

func NewObjectClassViolationInvalidStructualChain(oc1, oc2 string) *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultObjectClassViolation,
		Msg:  fmt.Sprintf("invalid structural object class chain (%s/%s)", oc1, oc2),
	}
}

func NewObjectClassModsProhibited(from, to string) *LDAPError {
	return &LDAPError{
		Code: ldap.LDAPResultObjectClassModsProhibited,
		Msg:  fmt.Sprintf(" structural object class modification from '%s' to '%s' not allowed", from, to),
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

type RetryError struct {
	err error
}

func (e *RetryError) Error() string {
	return fmt.Sprintf("RetryError: %v", e.err)
}

func (e *RetryError) Unwrap() error {
	return e.err
}

func NewRetryError(err error) error {
	return &RetryError{
		err: err,
	}
}

type InvalidDNError struct {
	dnNorm string
}

func NewInvalidDNError(dnNorm string) error {
	return &InvalidDNError{dnNorm}
}

func (e *InvalidDNError) Error() string {
	return fmt.Sprintf("InvalidDNError. dn_norm: %s", e.dnNorm)
}
