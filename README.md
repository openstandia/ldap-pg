# ldap-pg

[![GoDoc](https://godoc.org/github.com/openstandia/ldap-pg?status.svg)](https://godoc.org/github.com/openstandia/ldap-pg)

**This repository is heavily under development.**

**ldap-pg** is a LDAP server implementation which uses PostgreSQL as the backend database.

## Features

- Basic LDAP operations
  - Bind
    - [x] PLAIN
    - [x] SSHA
    - [x] SSHA256
    - [x] SSHA512
    - [x] Pass-through authentication (Support `{SASL}foo@domain`)
  - Search
    - [x] base
    - [x] one
    - [x] sub
    - [x] children
  - [x] Add
  - [x] Modify
  - [x] Delete
  - ModifyDN
    - [x] Rename RDN
    - [x] Support deleteoldrdn
    - [x] Support newsuperior
  - [ ] Compare
  - [ ] Extended
- LDAP Controls
  - [x] Simple Paged Results Control
- Support member/memberOf association (like OpenLDAP memberOf overlay)
  - [x] Return memberOf attribute as operational attribute
  - [x] Maintain member/memberOf
  - [x] Search filter using memberOf
- Schema
  - [x] Basic schema processing
  - [ ] More schema processing
  - [x] User defined schema
  - [ ] Multiple RDNs
- Network
  - [ ] SSL/StartTLS
- [ ] Prometheus metrics
- [ ] Auto create/migrate table for PostgreSQL

## Requirement

PostgreSQL 12 or later.

## Install

### From bainary

Please download it from [release page](../../releases).

### From source

`ldap-pg` is written by Golang. Install Golang then build `ldap-pg`:

```
make
```

You can find the binary in `./bin/` directory.

## Usage

### Start `ldap-pg`

```
ldap-pg.

Usage:

  ldap-pg [options]

Options:

  -b string
        Bind address (default "127.0.0.1:8389")
  -d string
        DB Name
  -db-max-idle-conns int
        DB max idle connections (default 2)
  -db-max-open-conns int
        DB max open connections (default 5)
  -gomaxprocs int
        GOMAXPROCS (Use CPU num with default)
  -h string
        DB Hostname (default "localhost")
  -log-level string
        Log level, on of: debug, info, warn, error, alert (default "info")
  -migration
        Enable migration mode which means LDAP server accepts add/modify operational attributes (Default: false)
  -p int
        DB Port (default 5432)
  -pass-through-ldap-bind-dn string
        Pass-through/LDAP: Bind DN
  -pass-through-ldap-domain string
        Pass-through/LDAP: Domain for pass-through/LDAP
  -pass-through-ldap-filter string
        Pass-through/LDAP: Filter for finding an user (ex. (cn=%u))
  -pass-through-ldap-password string
        Pass-through/LDAP: Bind password
  -pass-through-ldap-scope string
        Pass-through/LDAP: Search scope, on of: base, one, sub (Default: sub) (default "sub")
  -pass-through-ldap-search-base string
        Pass-through/LDAP: Search base
  -pass-through-ldap-server string
        Pass-through/LDAP: Server address and port (ex. myldap:389)
  -pass-through-ldap-timeout int
        Pass-through/LDAP: Timeout seconds (Default: 10) (default 10)
  -pprof string
        Bind address of pprof server (Don't start the server with default)
  -root-dn string
        Root dn for the LDAP
  -root-pw string
        Root password for the LDAP
  -s string
        DB Schema
  -schema value
        Additional/overwriting custom schema
  -suffix string
        Suffix for the LDAP
  -u string
        DB User
  -w string
        DB Password
```

#### Example

```
ldap-pg -h localhost -u testuser -w testpass -d testdb \
 -suffix dc=example,dc=com -root-dn cn=Manager -root-pw secret \
 -log-level info

[  info ] 2019/10/03 15:13:37 main.go:169: Setup GOMAXPROCS with NumCPU: 8
[  info ] 2019/10/03 15:13:37 main.go:234: Starting ldap-pg on 127.0.0.1:8389
```

## License

Licensed under the [GPL](/LICENSE) license.
