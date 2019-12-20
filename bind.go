package main

import (
	"log"
	"strings"

	"github.com/jsimonetti/pwscheme/ssha"
	"github.com/jsimonetti/pwscheme/ssha256"
	"github.com/jsimonetti/pwscheme/ssha512"
	ldap "github.com/openstandia/ldapserver"
	"golang.org/x/xerrors"
)

func handleBind(s *Server, w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	if r.AuthenticationChoice() == "simple" {
		// For rootdn
		name := string(r.Name())
		pass := string(r.AuthenticationSimple())

		dn, err := normalizeDN(name)
		if err != nil {
			log.Printf("info: Bind failed. DN: %s err: %s", name, err)
			res.SetResultCode(ldap.LDAPResultInvalidCredentials)
			res.SetDiagnosticMessage("invalid credentials")
			w.Write(res)
			return
		}

		if dn.Equal(s.GetRootDN()) {
			if ok := validateCred(s, pass, s.GetRootPW()); !ok {
				log.Printf("info: Bind failed. DN: %s", name)
				res.SetResultCode(ldap.LDAPResultInvalidCredentials)
				res.SetDiagnosticMessage("invalid credentials")
				w.Write(res)
				return
			}
			log.Printf("info: Bind ok. DN: %s", name)

			err := saveAuthencatedDN(m, dn)
			if err != nil {
				res.SetResultCode(ldap.LDAPResultInvalidCredentials)
				res.SetDiagnosticMessage("invalid credentials")
				w.Write(res)
				return
			}

			w.Write(res)
			return
		}

		// Anonymous
		if dn.DNNorm == "" {
			log.Printf("info: Bind anonymous user.")

			w.Write(res)
			return
		}

		log.Printf("info: Find bind user. DN: %s", dn.DNNorm)

		bindUserCred, err := findCredByDN(dn)
		if err == nil && len(bindUserCred) > 0 {
			log.Printf("Fetched userPassword: %v", bindUserCred)
			if ok := validateCreds(s, pass, bindUserCred); !ok {
				log.Printf("info: Bind failed. DN: %s", name)
				res.SetResultCode(ldap.LDAPResultInvalidCredentials)
				res.SetDiagnosticMessage("invalid credentials")
				w.Write(res)
				return
			}

			log.Printf("info: Bind ok. DN: %s", name)

			err := saveAuthencatedDN(m, dn)
			if err != nil {
				res.SetResultCode(ldap.LDAPResultInvalidCredentials)
				res.SetDiagnosticMessage("invalid credentials")
				w.Write(res)
				return
			}

			w.Write(res)
			return
		}

		log.Printf("info: Bind failed - Not found. DN: %s, err: %s", name, err)

		res.SetResultCode(ldap.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage("invalid credentials")

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

func saveAuthencatedDN(m *ldap.Message, dn *DN) error {
	session := getAuthSession(m)
	if v, ok := session["dn"]; ok {
		log.Printf("info: Switching authenticated user: %s -> %s", v.DNNorm, dn.DNNorm)
	}
	session["dn"] = dn
	log.Printf("Saved authenticated DN: %s", dn.DNNorm)
	return nil
}
