package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

var (
	fs         = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	dbHostName = fs.String(
		"h",
		"localhost",
		"DB Hostname",
	)
	dbPort = fs.Int(
		"p",
		5432,
		"DB Port",
	)
	dbName = fs.String(
		"d",
		"",
		"DB Name",
	)
	dbUser = fs.String(
		"u",
		"",
		"DB User",
	)
	dbPassword = fs.String(
		"w",
		"",
		"DB Password",
	)
	dbMaxOpenConns = fs.Int(
		"db-max-open-conns",
		5,
		"DB max open connections",
	)
	dbMaxIdleConns = fs.Int(
		"db-max-idle-conns",
		2,
		"DB max idle connections",
	)
	suffix = fs.String(
		"suffix",
		"",
		"Suffix for the LDAP",
	)
	rootdn = fs.String(
		"root-dn",
		"",
		"Root dn for the LDAP",
	)
	rootpw = fs.String(
		"root-pw",
		"",
		"Root password for the LDAP",
	)
	bindAddress = fs.String(
		"b",
		"127.0.0.1:8389",
		"Bind address",
	)
	logLevel = fs.String(
		"log-level",
		"info",
		"Log level, on of: debug, info, warn, error, fatal",
	)
	pprofServer = fs.String(
		"pprof",
		"",
		"Bind address of pprof server (Don't start the server with default)",
	)
	gomaxprocs = fs.Int(
		"gomaxprocs",
		0,
		"GOMAXPROCS (Use CPU num with default)",
	)
	twowayEnabled = fs.Bool(
		"two-way",
		false,
		"Two-way support for member-memberOf association (Default: false)",
	)
	passThroughLDAPDomain = fs.String(
		"pass-through-ldap-domain",
		"",
		"Pass-through/LDAP: Domain for pass-through/LDAP",
	)
	passThroughLDAPServer = fs.String(
		"pass-through-ldap-server",
		"",
		"Pass-through/LDAP: Server address and port (ex. myldap:389)",
	)
	passThroughLDAPSearchBase = fs.String(
		"pass-through-ldap-search-base",
		"",
		"Pass-through/LDAP: Search base",
	)
	passThroughLDAPFilter = fs.String(
		"pass-through-ldap-filter",
		"",
		"Pass-through/LDAP: Filter for finding an user (ex. (cn=%u))",
	)
	passThroughLDAPBindDN = fs.String(
		"pass-through-ldap-bind-dn",
		"",
		"Pass-through/LDAP: Bind DN",
	)
	passThroughLDAPPassword = fs.String(
		"pass-through-ldap-password",
		"",
		"Pass-through/LDAP: Bind password",
	)
	passThroughLDAPScope = fs.String(
		"pass-through-ldap-scope",
		"sub",
		"Pass-through/LDAP: Search scope, on of: base, one, sub (Default: sub)",
	)
	passThroughLDAPTimeout = fs.Int(
		"pass-through-ldap-timeout",
		10,
		"Pass-through/LDAP: Timeout seconds (Default: 10)",
	)
	migrationEnabled = fs.Bool(
		"migration",
		false,
		"Enable migration mode which means LDAP server accepts add/modify operational attributes (Default: false)",
	)
)

func main() {
	fs.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprint(os.Stderr, "ldap-pg.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n\n  %s [options]\n\nOptions:\n\n", exe)
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])

	if len(os.Args) == 1 {
		fs.Usage()
		return
	}

	rootPW := *rootpw
	*rootpw = ""

	passThroughConfig := &PassThroughConfig{}
	if *passThroughLDAPDomain != "" {
		passThroughConfig.Add(*passThroughLDAPDomain, &LDAPPassThroughClient{
			Server:     *passThroughLDAPServer,
			SearchBase: *passThroughLDAPSearchBase,
			Timeout:    *passThroughLDAPTimeout,
			Filter:     *passThroughLDAPFilter,
			BindDN:     *passThroughLDAPBindDN,
			Password:   *passThroughLDAPPassword,
			Scope:      *passThroughLDAPScope,
		})
	}

	NewServer(&ServerConfig{
		DBHostName:        *dbHostName,
		DBPort:            *dbPort,
		DBName:            *dbName,
		DBUser:            *dbUser,
		DBPassword:        *dbPassword,
		DBMaxOpenConns:    *dbMaxOpenConns,
		DBMaxIdleConns:    *dbMaxIdleConns,
		Suffix:            *suffix,
		RootDN:            *rootdn,
		RootPW:            rootPW,
		BindAddress:       *bindAddress,
		PassThroughConfig: passThroughConfig,
		LogLevel:          *logLevel,
		PProfServer:       *pprofServer,
		GoMaxProcs:        *gomaxprocs,
	}).Start()
}
