package main

import (
	"fmt"
	"log"

	"github.com/jsimonetti/pwscheme/ssha"
	"github.com/jsimonetti/pwscheme/ssha256"
	"github.com/jsimonetti/pwscheme/ssha512"
	ldap "github.com/openstandia/ldapserver"
)

type BindHandler struct {
	server *Server
}

func NewBindHandler(s *Server) *BindHandler {
	return &BindHandler{
		server: s,
	}
}

func (h *BindHandler) HandleBind(w ldap.ResponseWriter, m *ldap.Message) {
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

		if dn.Equal(h.server.GetRootDN()) {
			if ok := validateCred(pass, h.server.GetRootPW()); !ok {
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

		log.Printf("info: Find bind user. DN: %s", dn.DNNorm)

		bindUserCred, err := findCredByDN(dn)
		if err == nil && bindUserCred != "" {
			log.Printf("Fetched userPassword: %s", bindUserCred)
			if ok := validateCred(pass, bindUserCred); !ok {
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

func validateCred(input, cred string) bool {
	var ok bool
	var err error
	if len(cred) > 7 && string(cred[0:6]) == "{SSHA}" {
		ok, err = ssha.Validate(input, cred)

	} else if len(cred) > 10 && string(cred[0:9]) == "{SSHA256}" {
		ok, err = ssha256.Validate(input, cred)

	} else if len(cred) > 10 && string(cred[0:9]) == "{SSHA512}" {
		ok, err = ssha512.Validate(input, cred)

	} else if len(cred) > 7 && string(cred[0:6]) == "{SASL}" {
		// TODO implements pass through
		ok, err = ssha.Validate(input, cred)

	} else {
		// Plain
		ok = input == cred
	}

	if err != nil {
		log.Printf("Invalid hash credential: %s", err)
	}

	return ok
}

func saveAuthencatedDN(m *ldap.Message, dn *DN) error {
	session := getAuthSession(m)
	if v, ok := session["dn"]; ok {
		log.Printf("warn: Already authenticated: %s <- %s", v.DNNorm, dn.DNNorm)
		return fmt.Errorf("Already authenticated: %s <- %s", v.DNNorm, dn.DNNorm)
	}
	session["dn"] = dn
	log.Printf("Saved authenticated DN: %s", dn.DNNorm)
	return nil
}
