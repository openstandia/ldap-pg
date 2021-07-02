package main

import (
	"context"
	"log"
	"strings"

	"github.com/jsimonetti/pwscheme/ssha"
	"github.com/jsimonetti/pwscheme/ssha256"
	"github.com/jsimonetti/pwscheme/ssha512"
	ldap "github.com/openstandia/ldapserver"
	"golang.org/x/xerrors"
)

func handleBind(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	ctx := context.Background()

	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if r.AuthenticationChoice() == "simple" {
		name := string(r.Name())
		pass := string(r.AuthenticationSimple())

		dn, err := s.NormalizeDN(name)
		if err != nil {
			log.Printf("info: Bind failed. DN: %s err: %s", name, err)
			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid credentials")
			w.Write(res)
			return
		}

		// For rootdn
		if dn.Equal(s.GetRootDN()) {
			if ok := validateCred(s, pass, s.GetRootPW()); !ok {
				log.Printf("info: Bind failed. DN: %s", name)
				res.SetResultCode(ldap.LDAPResultInvalidCredentials)
				res.SetDiagnosticMessage("invalid credentials")
				w.Write(res)
				return
			}
			log.Printf("info: Bind ok. DN: %s", name)

			saveAuthencatedDNAsRoot(m, dn)

			w.Write(res)
			return
		}

		// Anonymous
		if dn.IsAnonymous() {
			log.Printf("info: Bind anonymous user.")

			w.Write(res)
			return
		}

		log.Printf("info: Find bind user. DN: %s", dn.DNNormStr())

		bindCredential, err := s.Repo().FindCredentialByDN(ctx, dn)
		if err != nil {
			var lerr *LDAPError
			if ok := xerrors.As(err, &lerr); ok {
				log.Printf("info: Failed to bind. DN: %s", dn.DNNormStr())
				log.Printf("debug: err: %+v", err)

				res.SetResultCode(lerr.Code)
				res.SetDiagnosticMessage("invalid credentials")
				w.Write(res)
				return
			}

			log.Printf("warn: Failed to find cred by DN: %s, err: %+v", dn.DNNormStr(), err)

			// Return 'invalid credentials' even if the cause is system error.
			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid credentials")
			w.Write(res)
			return
		}

		// If the user doesn't have credentials, always return 'invalid credential'.
		if len(bindCredential.Credential) == 0 {
			log.Printf("info: Bind failed - Not found credentials. DN: %s, err: %s", name, err)

			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid credentials")
			w.Write(res)
			return
		}

		if ok := validateCreds(s, pass, bindCredential.Credential); !ok {
			log.Printf("info: Bind failed - Invalid credentials. DN: %s", name)

			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid credentials")
			w.Write(res)
			return
		}

		saveAuthencatedDN(m, dn, bindCredential.MemberOf)

		// Success
		log.Printf("info: Bind ok. DN: %s", name)

		w.Write(res)
		return

	} else {
		res.SetResultCode(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
	}

	w.Write(res)
}

func validateCreds(s *Server, input string, cred []string) bool {
	for _, v := range cred {
		if ok := validateCred(s, input, v); ok {
			return true
		}
	}
	return false
}

func validateCred(s *Server, input, cred string) bool {
	var ok bool
	var err error
	if len(cred) > 7 && string(cred[0:6]) == "{SSHA}" {
		ok, err = ssha.Validate(input, cred)

	} else if len(cred) > 10 && string(cred[0:9]) == "{SSHA256}" {
		ok, err = ssha256.Validate(input, cred)

	} else if len(cred) > 10 && string(cred[0:9]) == "{SSHA512}" {
		ok, err = ssha512.Validate(input, cred)

	} else if len(cred) > 7 && string(cred[0:6]) == "{SASL}" {
		ok, err = doPassThrough(s, input, cred[6:])
	} else {
		// Plain
		ok = input == cred
	}

	if err != nil {
		if err.Error() == "hash does not match password" {
			log.Printf("info: Invalid bindDN/credential. err: %+v", err)
		} else {
			log.Printf("error: Failed to authenticate. err: %+v", err)
		}
	}

	return ok
}

type InvalidCredentials struct {
	err error
}

func (i InvalidCredentials) Error() string {
	return i.err.Error()
}

func doPassThrough(s *Server, input, passThroughKey string) (bool, error) {
	log.Printf("Handle pass-through authentication: %s", passThroughKey)

	i := strings.LastIndex(passThroughKey, "@")
	if i == -1 {
		return false, xerrors.Errorf("Invalid stored credential. It isn't '<ID>@<DOMAIN>' format. cred: %s", passThroughKey)
	}

	uid := strings.TrimSpace(passThroughKey[:i])
	domain := strings.TrimSpace(passThroughKey[i+1:])

	if uid == "" || domain == "" {
		return false, xerrors.Errorf("Invalid stored credential. It isn't '<ID>@<DOMAIN>' format. cred: %s", passThroughKey)
	}

	if c, ok := s.config.PassThroughConfig.Get(domain); ok {
		return c.Authenticate(domain, uid, input)
	}

	// No pass-through client

	return false, xerrors.Errorf("Invalid domain. domain: %s, uid: %s", domain, uid)
}

func saveAuthencatedDNAsRoot(m *ldap.Message, dn *DN) {
	session := getAuthSession(m)
	if session.DN != nil {
		log.Printf("info: Switching authenticated user: %s -> %s", session.DN.DNNormStr(), dn.DNNormStr())
	}
	session.DN = dn
	session.IsRoot = true
	log.Printf("Saved authenticated DN: %s", dn.DNNormStr())
}

func saveAuthencatedDN(m *ldap.Message, dn *DN, groups []*DN) {
	session := getAuthSession(m)
	if session.DN != nil {
		log.Printf("info: Switching authenticated user: %s -> %s", session.DN.DNNormStr(), dn.DNNormStr())
	}
	session.DN = dn
	session.Groups = groups
	session.IsRoot = false
	log.Printf("Saved authenticated DN: %s", dn.DNNormStr())
}
