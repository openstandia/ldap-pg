package main

import (
	"fmt"
)

type LDAPError struct {
	Code int
	Msg  string
}

func (e *LDAPError) Error() string {
	return fmt.Sprintf("LDAPError: %d", e.Code)
}

func NewTypeOrValueExists(op, attr string, valueidx int) *LDAPError {
	return &LDAPError{
		Code: 20,
		Msg:  fmt.Sprintf("%s: %s: value #%d already exists", op, attr, valueidx),
	}
}

func NewAlreadyExists(op, attr string, valueidx int) *LDAPError {
	return &LDAPError{
		Code: 68,
	}
}
