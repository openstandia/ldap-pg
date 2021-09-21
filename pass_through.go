package main

import (
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/xerrors"
)

type PassThroughConfig map[string]PassThroughClient

func (p PassThroughConfig) Add(domain string, client PassThroughClient) {
	p[strings.ToLower(domain)] = client
}

func (p PassThroughConfig) Has(domain string) bool {
	_, ok := p[strings.ToLower(domain)]
	return ok
}

func (p PassThroughConfig) Get(domain string) (PassThroughClient, bool) {
	c, ok := p[strings.ToLower(domain)]
	if ok {
		return c, true
	}
	return nil, false
}

type PassThroughClient interface {
	Authenticate(domain, user, password string) (bool, error)
}

type LDAPPassThroughClient struct {
	Server     string
	SearchBase string
	Timeout    int
	Filter     string
	BindDN     string
	Password   string
	Scope      string
}

func (c *LDAPPassThroughClient) Authenticate(domain, user, password string) (bool, error) {
	l, err := ldap.Dial("tcp", c.Server)
	if err != nil {
		return false, xerrors.Errorf("Failed to connect pass-through LDAP server. domain: %s, err: %w", domain, err)
	}
	defer l.Close()

	err = l.Bind(c.BindDN, c.Password)
	if err != nil {
		return false, xerrors.Errorf("Failed to bind pass-through LDAP. Check your configuration. domain: %s, BindDN: %s. err: %w", domain, c.BindDN, err)
	}

	// Resolve scope
	var scope int
	switch strings.ToLower(c.Scope) {
	case "base":
		scope = 0
	case "one":
		scope = 1
	case "sub":
		scope = 2
	default:
		scope = 2
	}

	// Resolve filter
	filter := strings.ReplaceAll(c.Filter, "%u", user)

	search := ldap.NewSearchRequest(
		c.SearchBase,
		scope,
		ldap.NeverDerefAliases,
		0,         // Size Limit
		c.Timeout, // Time Limit
		false,
		filter,         // The filter to apply
		[]string{"dn"}, // A list attributes to retrieve
		nil,
	)
	sr, err := l.Search(search)
	if err != nil {
		if !ldap.IsErrorWithCode(err, 32) {
			return false, xerrors.Errorf("Failed to search an user for pass-through. domain:%s, uid: %s, filter: %s, err: %w", domain, user, filter, err)
		}
		// LDAP Result Code 32 "No Such Object
		return false, xerrors.Errorf("No such object. domain: %s, uid: %s", domain, user)
	}

	if len(sr.Entries) == 0 {
		return false, xerrors.Errorf("No such user. domain: %s, uid: %s", domain, user)
	}
	if len(sr.Entries) > 1 {
		return false, xerrors.Errorf("Duplicate user. domain: %s, uid: %s", domain, user)
	}

	log.Printf("info: Found an user for pass-through. domain: %s, uid: %s", domain, user)

	entry := sr.Entries[0]

	err = l.Bind(entry.DN, password)
	if err != nil {
		if ldap.IsErrorWithCode(err, 49) {
			return false, InvalidCredentials{err}
		}
		return false, xerrors.Errorf("Failed to bind pass-through LDAP. domain: %s, BindDN: %s. err: %w", domain, c.BindDN, err)
	}

	return true, nil
}
