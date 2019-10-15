package main

import (
	"fmt"
)

type LDAPError struct {
	Code int
	Msg  string
}

func (e *LDAPError) Error() string {
	return fmt.Sprintf("LDAPError: %d %s", e.Code, e.Msg)
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

func NewNoSuchObject() *LDAPError {
	return &LDAPError{
		Code: 32,
	}
}

func NewInvalidDNSyntax() *LDAPError {
	return &LDAPError{
		Code: 34,
		Msg:  fmt.Sprintf("invalid DN"),
	}
}

func NewObjectClassViolation() *LDAPError {
	return &LDAPError{
		Code: 65,
		Msg:  fmt.Sprintf("no objectClass attribute"),
	}
}

func NewAlreadyExists() *LDAPError {
	return &LDAPError{
		Code: 68,
	}
}
